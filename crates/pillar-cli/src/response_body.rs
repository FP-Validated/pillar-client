use super::*;
use hyper::body::{Body as HttpBody, Bytes, Frame, SizeHint};

pub(super) struct ResponseBody {
    inner: Body,
    control: Arc<connections::ConnectionControl>,
    deadline: Pin<Box<Sleep>>,
    remaining: Option<u64>,
}

impl ResponseBody {
    pub(super) fn new(
        inner: Body,
        control: Arc<connections::ConnectionControl>,
        content_length: Option<u64>,
    ) -> Self {
        let deadline = control.writing();
        let remaining = content_length.or_else(|| inner.size_hint().exact());
        if inner.is_end_stream() || remaining == Some(0) {
            control.body_complete();
        }
        Self {
            inner,
            control,
            remaining,
            deadline: Box::pin(tokio::time::sleep_until(deadline)),
        }
    }
}

impl HttpBody for ResponseBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        let this = self.get_mut();
        if this.deadline.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Some(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "HTTP response write timed out",
            ))));
        }
        let frame = Pin::new(&mut this.inner).poll_frame(cx);
        if let Poll::Ready(Some(Ok(frame))) = &frame {
            if let (Some(remaining), Some(data)) = (&mut this.remaining, frame.data_ref()) {
                *remaining = remaining.saturating_sub(data.len() as u64);
            }
        }
        if matches!(frame, Poll::Ready(None))
            || this.inner.is_end_stream()
            || this.remaining == Some(0)
        {
            this.control.body_complete();
        }
        frame.map(|frame| frame.map(|result| result.map_err(io::Error::other)))
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }
    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}
