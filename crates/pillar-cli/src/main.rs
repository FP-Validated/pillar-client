use axum::{body::Body, Router};
use hyper::{
    header::{HeaderValue, CONNECTION},
    server::conn::http1,
    service::service_fn,
    Request,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use pillar_api::{router_with_shutdown, ShutdownSignal};
use pillar_config::load_from_env;
use pillar_runtime::RuntimeServerApp;
use std::{
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpStream},
    signal::unix::{signal, SignalKind},
    sync::{OwnedSemaphorePermit, Semaphore},
    time::{Instant, Sleep},
};
use tower::ServiceExt;
use tracing_subscriber::{fmt, EnvFilter};
mod connections;
mod healthcheck;

const SOCKET_TIMEOUT: Duration = Duration::from_secs(58);
const KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(60);
/// Deadline for the request line and headers, which the socket timeout cannot
/// cover because it only wraps the service call.
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);
/// Absolute ceiling on one connection. It has to exceed `SOCKET_TIMEOUT` so a
/// legitimate slow request is not cut off mid-flight, while still bounding a
/// client that keeps renewing the sliding idle window.
const MAX_CONNECTION_LIFETIME: Duration = Duration::from_secs(300);
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if std::env::args().nth(1).as_deref() == Some("healthcheck") {
        std::process::exit(healthcheck::exit_code());
    }
    init_tracing();
    let config = load_from_env()?;
    let port = config.server_port;
    let max_connections = config.max_connections;
    let shutdown_grace = Duration::from_secs(config.shutdown_grace_seconds);
    let shutdown_withdrawal = config.shutdown_withdrawal;
    let runtime_app = RuntimeServerApp::from_env()
        .await
        .map_err(anyhow::Error::msg)?;
    let image_version = runtime_app.startup_report().image_version.clone();
    println!("{}", runtime_app.startup_report());
    let (app, shutdown_signal) = router_with_shutdown(runtime_app, image_version);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = TcpListener::bind(addr).await?;
    println!("[server]: Server is running at http://localhost:{port}");
    serve(
        listener,
        app,
        max_connections,
        shutdown_grace,
        shutdown_withdrawal,
        shutdown_signal,
    )
    .await?;
    Ok(())
}

/// Resolves when the process is asked to terminate. SIGTERM is what Kubernetes
/// sends on a rolling update; SIGINT is what a local operator sends.
async fn shutdown_requested() -> io::Result<&'static str> {
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;
    tokio::select! {
        _ = sigterm.recv() => Ok("SIGTERM"),
        _ = sigint.recv() => Ok("SIGINT"),
    }
}

async fn serve(
    listener: TcpListener,
    app: Router,
    max_connections: usize,
    shutdown_grace: Duration,
    shutdown_withdrawal: Duration,
    shutdown_signal: ShutdownSignal,
) -> io::Result<()> {
    serve_until(
        listener,
        app,
        max_connections,
        shutdown_grace,
        shutdown_withdrawal,
        shutdown_signal,
        shutdown_requested(),
    )
    .await
}

/// Absolute timeline from the signal at `T0`: new signing is refused and
/// readiness is 503 from `T0`, the listener stays up until `T0 + withdrawal`,
/// and connection drain plus budget close are bounded by `T0 + shutdown_grace`.
/// The withdrawal never extends the grace.
async fn serve_until(
    listener: TcpListener,
    app: Router,
    max_connections: usize,
    shutdown_grace: Duration,
    shutdown_withdrawal: Duration,
    shutdown_signal: ShutdownSignal,
    shutdown: impl Future<Output = io::Result<&'static str>>,
) -> io::Result<()> {
    serve_until_with_lifetime(
        listener,
        app,
        max_connections,
        (shutdown_grace, shutdown_withdrawal),
        shutdown_signal,
        MAX_CONNECTION_LIFETIME,
        shutdown,
    )
    .await
}

async fn serve_until_with_lifetime(
    listener: TcpListener,
    app: Router,
    max_connections: usize,
    shutdown_durations: (Duration, Duration),
    shutdown_signal: ShutdownSignal,
    max_connection_lifetime: Duration,
    shutdown: impl Future<Output = io::Result<&'static str>>,
) -> io::Result<()> {
    let semaphore = Arc::new(Semaphore::new(max_connections));
    let (shutdown_grace, shutdown_withdrawal) = shutdown_durations;
    let connections = connections::Connections::new(shutdown_signal.clone());
    let mut tasks = tokio::task::JoinSet::new();
    let mut shutdown = Box::pin(shutdown);
    let reason = 'accept: loop {
        while tasks.try_join_next().is_some() {}
        let accepted = tokio::select! { accepted = listener.accept() => accepted, signalled = &mut shutdown => break signalled? };
        let (stream, _) = match accepted {
            Ok(connection) => connection,
            Err(error) => {
                tracing::error!(?error, "TCP accept failed; backing off");
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_millis(100)) => {},
                    signalled = &mut shutdown => break 'accept signalled?,
                }
                continue;
            }
        };
        match connection_permit(&semaphore, &connections, &mut shutdown).await? {
            Ok(permit) => spawn_connection(
                &mut tasks,
                &connections,
                &app,
                stream,
                permit,
                max_connection_lifetime,
            ),
            Err(signalled) => {
                drop(stream);
                break 'accept signalled?;
            }
        }
    };
    let started = Instant::now();
    let deadline = started + shutdown_grace;
    let withdrawal_end = started + shutdown_withdrawal.min(shutdown_grace);
    shutdown_signal.trigger();
    if !shutdown_withdrawal.is_zero() {
        let end = tokio::time::sleep_until(withdrawal_end);
        tokio::pin!(end);
        loop {
            while tasks.try_join_next().is_some() {}
            // Biased so continuous accepts can never push the listener past `T0 + W`.
            let accepted = tokio::select! { biased; _ = &mut end => break, accepted = listener.accept() => accepted };
            let (stream, _) = match accepted {
                Ok(connection) => connection,
                Err(error) => {
                    tracing::error!(?error, "TCP accept failed; backing off");
                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_millis(100)) => {},
                        _ = &mut end => break,
                    }
                    continue;
                }
            };
            match connection_permit(&semaphore, &connections, &mut end).await? {
                Ok(permit) => spawn_connection(
                    &mut tasks,
                    &connections,
                    &app,
                    stream,
                    permit,
                    max_connection_lifetime,
                ),
                Err(()) => {
                    drop(stream);
                    break;
                }
            }
        }
    }
    drop(listener);
    connections.drain();
    let drained = tokio::time::timeout_at(deadline, async {
        while tasks.join_next().await.is_some() {}
    })
    .await;
    if drained.is_err() {
        shutdown_signal.close_budgets();
        connections.cancel();
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        tracing::error!(
            signal = reason,
            grace_seconds = shutdown_grace.as_secs_f64(),
            withdrawal_seconds = shutdown_withdrawal.as_secs_f64(),
            "shutdown: grace expired; remaining connection futures cancelled"
        );
    } else {
        tracing::warn!(
            signal = reason,
            "shutdown: active requests drained; idle connections closed"
        );
    }
    Ok(())
}

/// Waits for a connection slot, evicting an idle connection if needed; `stop`
/// wins ties so an elapsed deadline is never starved by free permits.
async fn connection_permit<S>(
    semaphore: &Arc<Semaphore>,
    connections: &connections::Connections,
    mut stop: impl Future<Output = S> + Unpin,
) -> io::Result<Result<OwnedSemaphorePermit, S>> {
    loop {
        if let Ok(permit) = semaphore.clone().try_acquire_owned() {
            return Ok(Ok(permit));
        }
        connections.evict_idle();
        tokio::select! {
            biased;
            stopped = &mut stop => return Ok(Err(stopped)),
            permit = semaphore.clone().acquire_owned() => {
                return permit
                    .map(Ok)
                    .map_err(|_| io::Error::other("connection admission closed"));
            }
            _ = connections.idle_changed() => {}
        }
    }
}

fn spawn_connection(
    tasks: &mut tokio::task::JoinSet<()>,
    connections: &connections::Connections,
    app: &Router,
    stream: TcpStream,
    permit: OwnedSemaphorePermit,
    max_connection_lifetime: Duration,
) {
    let app = app.clone();
    let (registration, control, close) = connections.register();
    tasks.spawn(async move {
        let _permit = permit;
        let _registration = registration;
        if let Err(error) = serve_connection_controlled(
            stream,
            app,
            SOCKET_TIMEOUT,
            KEEP_ALIVE_TIMEOUT,
            HEADER_READ_TIMEOUT,
            max_connection_lifetime,
            Some((control, close)),
        )
        .await
        {
            tracing::debug!(?error, "HTTP connection closed");
        }
    });
}

#[cfg(test)]
async fn serve_connection<I>(
    io: I,
    app: Router,
    request_timeout: Duration,
    keep_alive_timeout: Duration,
    header_read_timeout: Duration,
    max_connection_lifetime: Duration,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    serve_connection_controlled(
        io,
        app,
        request_timeout,
        keep_alive_timeout,
        header_read_timeout,
        max_connection_lifetime,
        None,
    )
    .await
}

async fn serve_connection_controlled<I>(
    io: I,
    app: Router,
    request_timeout: Duration,
    keep_alive_timeout: Duration,
    header_read_timeout: Duration,
    max_connection_lifetime: Duration,
    control: Option<(
        Arc<connections::ConnectionControl>,
        tokio::sync::watch::Receiver<bool>,
    )>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let service_control = control.as_ref().map(|(control, _)| control.clone());
    let service = service_fn(move |request: Request<hyper::body::Incoming>| {
        let app = app.clone();
        let control = service_control.clone();
        async move {
            let context = pillar_core::execution::RequestContext::new(request_timeout);
            let deadline = context
                .deadline
                .expect("socket requests have an absolute deadline");
            if let Some(control) = &control {
                control.start(context.clone());
            }
            let (parts, body) = request.into_parts();
            let mut request = Request::from_parts(parts, Body::new(body));
            request.extensions_mut().insert(pillar_api::SocketRequest);
            let mut response = context
                .clone()
                .scope(tokio::time::timeout_at(deadline, app.oneshot(request)))
                .await;
            if let Some(control) = &control {
                control.idle();
            }
            let draining = control
                .as_ref()
                .is_some_and(|control| control.is_draining());
            if Instant::now() >= deadline || response.is_err() {
                context.timeout();
                if let Ok(Ok(response)) = &mut response {
                    pillar_api::complete_socket_response(response, true);
                }
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "HTTP request exceeded Pillar's 58-second socket timeout",
                ))
            } else {
                match response {
                    Ok(Ok(mut response)) => {
                        pillar_api::complete_socket_response(&mut response, false);
                        if draining {
                            response
                                .headers_mut()
                                .insert(CONNECTION, HeaderValue::from_static("close"));
                        }
                        Ok(response)
                    }
                    Ok(Err(error)) => match error {},
                    Err(_) => unreachable!(),
                }
            }
        }
    });
    // HTTP/1.1 bounds one active request per connection; h2 multiplexing would bypass socket admission.
    let connection = http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(header_read_timeout)
        .serve_connection(
            TokioIo::new(IdleTimeoutIo::new(
                io,
                keep_alive_timeout,
                if control.is_some() {
                    max_connection_lifetime + request_timeout
                } else {
                    max_connection_lifetime
                },
            )),
            service,
        );
    tokio::pin!(connection);
    let lifetime = tokio::time::sleep(max_connection_lifetime);
    tokio::pin!(lifetime);
    if let Some((_, mut close)) = control {
        tokio::select! {
            result = &mut connection => result?,
            _ = &mut lifetime => { connection.as_mut().graceful_shutdown(); connection.await?; }
            _ = close.changed() => { connection.as_mut().graceful_shutdown(); connection.await?; }
        }
    } else {
        connection.await?;
    }
    Ok(())
}

struct IdleTimeoutIo<I> {
    inner: I,
    timeout: Duration,
    deadline: Pin<Box<Sleep>>,
    /// Absolute ceiling for the whole connection. The sliding idle window is
    /// refreshed by every successful read, so on its own it bounds silence but
    /// not lifetime, and a trickling client renews it indefinitely.
    hard_deadline: Pin<Box<Sleep>>,
}

impl<I> IdleTimeoutIo<I> {
    fn new(inner: I, timeout: Duration, max_lifetime: Duration) -> Self {
        Self {
            inner,
            timeout,
            deadline: Box::pin(tokio::time::sleep(timeout)),
            hard_deadline: Box::pin(tokio::time::sleep(max_lifetime)),
        }
    }

    fn reset_deadline(&mut self) {
        self.deadline.as_mut().reset(Instant::now() + self.timeout);
    }

    fn poll_hard_deadline(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.hard_deadline.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "HTTP connection exceeded its maximum lifetime",
            )));
        }
        Poll::Pending
    }

    /// poll_read and poll_write call poll_hard_deadline before touching inner
    /// I/O. The hard ceiling wins over an operation that could otherwise
    /// complete, because it exists to bound a client that keeps renewing the
    /// sliding window. The existing 58-second request timeout means a
    /// legitimate request cannot straddle this ceiling by much.
    fn poll_deadline(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Poll::Ready(result) = self.poll_hard_deadline(cx) {
            return Poll::Ready(result);
        }
        match self.deadline.as_mut().poll(cx) {
            Poll::Ready(()) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "HTTP keep-alive connection timed out",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<I: AsyncRead + Unpin> AsyncRead for IdleTimeoutIo<I> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Poll::Ready(Err(error)) = this.poll_hard_deadline(cx) {
            return Poll::Ready(Err(error));
        }
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(result) => {
                if result.is_ok() {
                    this.reset_deadline();
                }
                Poll::Ready(result)
            }
            Poll::Pending => this.poll_deadline(cx),
        }
    }
}

impl<I: AsyncWrite + Unpin> AsyncWrite for IdleTimeoutIo<I> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let this = self.get_mut();
        if let Poll::Ready(Err(error)) = this.poll_hard_deadline(cx) {
            return Poll::Ready(Err(error));
        }
        match Pin::new(&mut this.inner).poll_write(cx, buf) {
            Poll::Ready(result) => {
                if result.is_ok() {
                    this.reset_deadline();
                }
                Poll::Ready(result)
            }
            Poll::Pending => match this.poll_deadline(cx) {
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) | Poll::Pending => Poll::Pending,
            },
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        // `pillar` is this binary's own target: without it the operator never
        // sees accept failures or the shutdown/drain outcome.
        EnvFilter::new(
            "pillar=info,pillar_api=info,pillar_core=info,pillar_runtime=info,pillar_signer=info,pillar_layerzero=info",
        )
    });
    let _ = fmt()
        .with_env_filter(filter)
        .with_target(true)
        .compact()
        .try_init();
}

#[cfg(test)]
mod tests {
    use super::*;
    include!("phase1_tests.rs");
    use axum::{routing::get, Router};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    async fn open_one_connection(
        app: Router,
        request_timeout: Duration,
        keep_alive_timeout: Duration,
    ) -> (
        SocketAddr,
        tokio::task::JoinHandle<Result<(), Box<dyn std::error::Error + Send + Sync>>>,
    ) {
        open_one_connection_with_deadlines(
            app,
            request_timeout,
            keep_alive_timeout,
            HEADER_READ_TIMEOUT,
            MAX_CONNECTION_LIFETIME,
        )
        .await
    }

    async fn open_one_connection_with_deadlines(
        app: Router,
        request_timeout: Duration,
        keep_alive_timeout: Duration,
        header_read_timeout: Duration,
        max_connection_lifetime: Duration,
    ) -> (
        SocketAddr,
        tokio::task::JoinHandle<Result<(), Box<dyn std::error::Error + Send + Sync>>>,
    ) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            serve_connection(
                stream,
                app,
                request_timeout,
                keep_alive_timeout,
                header_read_timeout,
                max_connection_lifetime,
            )
            .await
        });
        (address, server)
    }

    /// The request timeout wraps the service call, which hyper only makes once
    /// it has parsed a complete request, so a client that never finishes its
    /// headers stayed outside every deadline and held its connection - and one
    /// of the `PILLAR_MAX_CONNECTIONS` permits - for as long as it kept the
    /// socket readable. The sliding idle window cannot close that, because each
    /// trickled byte renews it.
    #[tokio::test]
    async fn header_phase_deadline_closes_a_trickling_client() {
        let app = Router::new().route("/", get(|| async { "ok" }));
        // Only the header deadline is short. The idle window and the lifetime
        // ceiling are far longer than the assertion window, and the trickle
        // outlives it, so nothing else can end this connection: without
        // `header_read_timeout` the server never returns and the wait below
        // fails.
        let (address, server) = open_one_connection_with_deadlines(
            app,
            Duration::from_secs(30),
            Duration::from_secs(20),
            Duration::from_millis(150),
            Duration::from_secs(20),
        )
        .await;
        let mut client = TcpStream::connect(address).await.unwrap();
        client.write_all(b"GET / HTTP/1.1\r\n").await.unwrap();
        let trickle = tokio::spawn(async move {
            for _ in 0..200 {
                tokio::time::sleep(Duration::from_millis(50)).await;
                if client.write_all(b"X-Pad: 1\r\n").await.is_err() {
                    return;
                }
            }
        });
        let served = tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("header deadline must close the connection while the client is still writing")
            .unwrap();
        assert!(
            served.is_err(),
            "an unfinished header phase must end in an error, got {served:?}"
        );
        trickle.abort();
    }

    /// The idle window is refreshed by every successful read, so it bounds
    /// silence rather than lifetime. The absolute ceiling is what bounds a
    /// client that keeps talking without ever completing a request.
    #[tokio::test]
    async fn connection_lifetime_ceiling_closes_a_persistently_busy_client() {
        let app = Router::new().route("/", get(|| async { "ok" }));
        // Only the ceiling is short here, and it is the one deadline a client
        // that keeps writing cannot renew.
        let (address, server) = open_one_connection_with_deadlines(
            app,
            Duration::from_secs(30),
            Duration::from_secs(20),
            Duration::from_secs(20),
            Duration::from_millis(300),
        )
        .await;
        let mut client = TcpStream::connect(address).await.unwrap();
        client.write_all(b"GET / HTTP/1.1\r\n").await.unwrap();
        let trickle = tokio::spawn(async move {
            for _ in 0..400 {
                tokio::time::sleep(Duration::from_millis(25)).await;
                if client.write_all(b"X-Pad: 1\r\n").await.is_err() {
                    return;
                }
            }
        });
        let served = tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("lifetime ceiling must close the connection while the client is still writing")
            .unwrap();
        assert!(
            served.is_err(),
            "a connection past its lifetime ceiling must end in an error, got {served:?}"
        );
        trickle.abort();
    }
    #[tokio::test]
    async fn production_connection_lifetime_drains_an_in_flight_request() {
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let app = Router::new().route(
            "/",
            get({
                let entered = entered.clone();
                let release = release.clone();
                move || {
                    let entered = entered.clone();
                    let release = release.clone();
                    async move {
                        entered.notify_one();
                        release.notified().await;
                        "done"
                    }
                }
            }),
        );
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let (_, shutdown_signal) =
            pillar_api::router_with_shutdown(pillar_api::StaticApp::observed_mainnet(), "test");
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(serve_until_with_lifetime(
            listener,
            app,
            1,
            (Duration::from_secs(5), Duration::ZERO),
            shutdown_signal,
            Duration::from_millis(100),
            async move {
                stopped.await.unwrap();
                Ok("test")
            },
        ));
        let mut client = TcpStream::connect(address).await.unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        entered.notified().await;
        tokio::time::sleep(Duration::from_millis(150)).await;
        release.notify_one();

        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        let response = String::from_utf8(response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
        assert!(
            response.to_ascii_lowercase().contains("connection: close"),
            "{response}"
        );
        assert!(response.ends_with("done"), "{response}");
        stop.send(()).unwrap();
        server.await.unwrap().unwrap();
    }

    #[derive(Clone)]
    struct AlwaysReadyIo {
        reads: Arc<AtomicUsize>,
        writes: Arc<AtomicUsize>,
    }

    impl AsyncRead for AlwaysReadyIo {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            buf.put_slice(b"ready");
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for AlwaysReadyIo {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.writes.fetch_add(1, Ordering::SeqCst);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn hard_deadline_rejects_always_ready_io() {
        tokio::time::pause();
        let reads = Arc::new(AtomicUsize::new(0));
        let writes = Arc::new(AtomicUsize::new(0));
        let io = AlwaysReadyIo {
            reads: Arc::clone(&reads),
            writes: Arc::clone(&writes),
        };
        let mut timed = IdleTimeoutIo::new(io, Duration::from_secs(60), Duration::from_secs(5));
        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut initial = [0; 8];
        let mut initial_buf = ReadBuf::new(&mut initial);
        assert!(matches!(
            Pin::new(&mut timed).poll_read(&mut cx, &mut initial_buf),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(reads.load(Ordering::SeqCst), 1);

        // Past the ceiling, not exactly at it: a timer whose deadline equals
        // the paused clock's new value is not guaranteed to have fired.
        tokio::time::advance(Duration::from_secs(6)).await;

        let mut after_deadline = [0; 8];
        let mut after_deadline_buf = ReadBuf::new(&mut after_deadline);
        let read_result = Pin::new(&mut timed).poll_read(&mut cx, &mut after_deadline_buf);
        assert!(matches!(
            read_result,
            Poll::Ready(Err(ref error)) if error.kind() == io::ErrorKind::TimedOut
        ));
        assert_eq!(reads.load(Ordering::SeqCst), 1);

        let write_result = Pin::new(&mut timed).poll_write(&mut cx, b"still ready");
        assert!(matches!(
            write_result,
            Poll::Ready(Err(ref error)) if error.kind() == io::ErrorKind::TimedOut
        ));
        assert_eq!(writes.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn socket_timeout_closes_without_http_error_envelope() {
        let app = Router::new().route(
            "/",
            get(|| async {
                tokio::time::sleep(Duration::from_millis(200)).await;
                "late"
            }),
        );
        let (address, server) =
            open_one_connection(app, Duration::from_millis(20), Duration::from_secs(1)).await;
        let mut client = TcpStream::connect(address).await.unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), client.read_to_end(&mut response))
            .await
            .expect("timed-out request connection closes")
            .unwrap();
        assert!(
            response.is_empty(),
            "socket timeout must not synthesize an HTTP error envelope"
        );
        assert!(server.await.unwrap().is_err());
    }

    /// The wire protocol this binary speaks must be its own decision. Hyper's
    /// `http2` feature is switched on process-wide by unrelated dependencies
    /// (`aws-smithy-http-client` and `tonic` pull it in for the KMS and storage
    /// clients), and an `auto` builder would then negotiate h2 for free. That
    /// matters because the accept loop holds one semaphore permit per
    /// connection: over h2 a single connection multiplexes unbounded concurrent
    /// streams, so `PILLAR_MAX_CONNECTIONS` would stop bounding in-flight
    /// requests the moment a client sent the h2 preface.
    #[tokio::test]
    async fn http2_prior_knowledge_is_refused() {
        let app = Router::new().route("/", get(|| async { "HEALTHY" }));
        let (address, server) =
            open_one_connection(app, Duration::from_secs(1), Duration::from_secs(1)).await;
        let mut client = TcpStream::connect(address).await.unwrap();
        // The h2 client preface, then an empty SETTINGS frame: what
        // `curl --http2-prior-knowledge` sends to a cleartext port.
        client
            .write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
            .await
            .unwrap();
        client
            .write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let mut response = Vec::new();
        // Closing with the preface unread makes the kernel send RST; bytes read
        // before it stay in `response`, so a reset is still a checked refusal.
        let read = tokio::time::timeout(Duration::from_secs(2), client.read_to_end(&mut response))
            .await
            .expect("an h2 preface must not leave the connection open");
        if let Err(error) = read {
            assert_eq!(error.kind(), io::ErrorKind::ConnectionReset, "{error}");
        }

        let answered_h2 = response.len() >= 9 && response[3] == 4;
        assert!(
            !answered_h2,
            "server negotiated HTTP/2, so one connection permit no longer bounds one \
             in-flight request: {response:02x?}"
        );
        assert!(
            response.is_empty() || response.starts_with(b"HTTP/1.1"),
            "an h2 preface must be refused as a malformed HTTP/1.1 request: {response:02x?}"
        );
        let _ = server.await.unwrap();
    }

    /// The other half of the same invariant: because a connection carries one
    /// request at a time, the connection permit is also the in-flight request
    /// permit. `PILLAR_MAX_CONNECTIONS` is documented as the throughput control,
    /// so a cap of one must let exactly one request run at a time.
    #[tokio::test]
    async fn connection_permit_bounds_one_in_flight_request() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let in_flight = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let app = Router::new().route(
            "/",
            get({
                let in_flight = in_flight.clone();
                let peak = peak.clone();
                move || {
                    let in_flight = in_flight.clone();
                    let peak = peak.clone();
                    async move {
                        let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                        peak.fetch_max(now, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(200)).await;
                        in_flight.fetch_sub(1, Ordering::SeqCst);
                        "HEALTHY"
                    }
                }
            }),
        );

        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let (_router, shutdown_signal) =
            pillar_api::router_with_shutdown(pillar_api::StaticApp::observed_mainnet(), "test");
        tokio::spawn(serve_until(
            listener,
            app,
            1,
            Duration::from_secs(1),
            Duration::ZERO,
            shutdown_signal,
            std::future::pending::<io::Result<&'static str>>(),
        ));

        // `Connection: close` so the answered request hands its permit back
        // instead of parking it in keep-alive for the idle timeout.
        let request = |address| async move {
            let mut client = TcpStream::connect(address).await.unwrap();
            client
                .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            let mut response = Vec::new();
            tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut response))
                .await
                .expect("a queued request is eventually served")
                .unwrap();
            String::from_utf8(response).unwrap()
        };
        let (first, second) = tokio::join!(request(address), request(address));

        assert!(first.starts_with("HTTP/1.1 200 OK"), "{first}");
        assert!(second.starts_with("HTTP/1.1 200 OK"), "{second}");
        assert_eq!(
            peak.load(Ordering::SeqCst),
            1,
            "a connection cap of one must admit one request at a time"
        );
    }

    #[tokio::test]
    async fn keep_alive_timeout_reaps_idle_connection() {
        let app = Router::new().route("/", get(|| async { "HEALTHY" }));
        let (address, server) =
            open_one_connection(app, Duration::from_secs(1), Duration::from_millis(30)).await;
        let mut client = TcpStream::connect(address).await.unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), client.read_to_end(&mut response))
            .await
            .expect("idle keep-alive connection closes")
            .unwrap();
        let response = String::from_utf8(response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.ends_with("HEALTHY"));
        assert!(server.await.unwrap().is_ok());
    }
}

#[cfg(test)]
mod drain_tests;
#[cfg(test)]
mod phase1_review_e2e;
