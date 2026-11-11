use indexmap::IndexMap;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use tokio::time::Instant;

pub(crate) type Labels = IndexMap<String, String>;

pub(crate) fn normalize_path(path: &str) -> String {
    if path.is_empty() {
        "/".to_string()
    } else if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    }
}

fn label_key(labels: &Labels) -> String {
    let mut entries: Vec<_> = labels.iter().collect();
    entries.sort_by_key(|(key, _)| *key);
    entries
        .into_iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join("\u{1f}")
}

fn render_labels(labels: &Labels) -> String {
    if labels.is_empty() {
        return String::new();
    }
    let mut entries: Vec<_> = labels.iter().collect();
    entries.sort_by_key(|(key, _)| *key);
    let rendered = entries
        .into_iter()
        .map(|(key, value)| {
            let value = value
                .replace('\\', "\\\\")
                .replace('\n', "\\n")
                .replace('"', "\\\"");
            format!("{key}=\"{value}\"")
        })
        .collect::<Vec<_>>()
        .join(",");
    format!("{{{rendered}}}")
}

fn format_number(value: f64) -> String {
    if value.fract() == 0.0 {
        format!("{value:.0}")
    } else {
        format!("{value}")
    }
}

pub(crate) struct CounterMetric {
    name: &'static str,
    help: &'static str,
    values: IndexMap<String, (Labels, f64)>,
}

impl CounterMetric {
    pub(crate) fn new(name: &'static str, help: &'static str) -> Self {
        Self {
            name,
            help,
            values: IndexMap::new(),
        }
    }

    pub(crate) fn inc(&mut self, labels: Labels, value: f64) {
        let key = label_key(&labels);
        if let Some((_, current)) = self.values.get_mut(&key) {
            *current += value;
        } else {
            self.values.insert(key, (labels, value));
        }
    }

    pub(crate) fn render(&self) -> Vec<String> {
        let name = self.name;
        let mut lines = vec![
            format!("# HELP {} {}", name, self.help),
            format!("# TYPE {} counter", name),
        ];
        for (labels, value) in self.values.values() {
            lines.push(format!(
                "{}{} {}",
                name,
                render_labels(labels),
                format_number(*value)
            ));
        }
        lines
    }
}

pub(crate) struct GaugeMetric {
    name: &'static str,
    help: &'static str,
    values: IndexMap<String, (Labels, f64)>,
}

impl GaugeMetric {
    pub(crate) fn new(name: &'static str, help: &'static str) -> Self {
        Self {
            name,
            help,
            values: IndexMap::new(),
        }
    }

    pub(crate) fn set(&mut self, labels: Labels, value: f64) {
        self.values.insert(label_key(&labels), (labels, value));
    }

    pub(crate) fn render(&self) -> Vec<String> {
        let name = self.name;
        let mut lines = vec![
            format!("# HELP {} {}", name, self.help),
            format!("# TYPE {} gauge", name),
        ];
        for (labels, value) in self.values.values() {
            lines.push(format!(
                "{}{} {}",
                name,
                render_labels(labels),
                format_number(*value)
            ));
        }
        lines
    }
}

/// An age that is computed when `/metrics` is scraped, from a timestamp its
/// owner stamps.
///
/// The distinction is the whole point. A loop that computes its own age and
/// writes it into a gauge reports the last value it managed to write, forever,
/// once it stops - and for the provider config refresh that value was `0`,
/// written by the accepting branch, which is the one number meaning "nothing is
/// stale". Deriving the age at scrape time instead means a loop that stopped for
/// any reason - a panic, a hang, an accidental `break` - shows an age that grows
/// without bound, which is what the age was there to reveal.
///
/// Times are `tokio::time::Instant`, so a paused test clock moves them. That clock stops while
/// the host is suspended, so the time spent suspended is added from the host's own count.
#[derive(Clone)]
pub struct AgeSource {
    origin: Instant,
    stamped_millis: Arc<AtomicU64>,
    stamped_suspended_millis: Arc<AtomicU64>,
    suspended_millis: fn() -> u64,
}

impl AgeSource {
    pub(crate) fn started_now() -> Self {
        Self::with_suspension_clock(suspended_millis)
    }

    fn with_suspension_clock(suspended_millis: fn() -> u64) -> Self {
        Self {
            origin: Instant::now(),
            stamped_millis: Arc::new(AtomicU64::new(0)),
            stamped_suspended_millis: Arc::new(AtomicU64::new(suspended_millis())),
            suspended_millis,
        }
    }

    /// Records that the thing being measured just happened.
    pub fn stamp(&self) {
        self.stamped_suspended_millis
            .store((self.suspended_millis)(), Ordering::SeqCst);
        self.stamped_millis
            .store(self.millis_since_origin(), Ordering::SeqCst);
    }

    pub fn age_seconds(&self) -> f64 {
        let stamped = self.stamped_millis.load(Ordering::SeqCst);
        let suspended = (self.suspended_millis)()
            .saturating_sub(self.stamped_suspended_millis.load(Ordering::SeqCst));
        self.millis_since_origin()
            .saturating_sub(stamped)
            .saturating_add(suspended) as f64
            / 1_000.0
    }

    fn millis_since_origin(&self) -> u64 {
        u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}

/// Milliseconds the host has spent suspended since boot: `CLOCK_BOOTTIME` counts suspension and
/// `CLOCK_MONOTONIC`, which `Instant` reads, does not.
#[cfg(target_os = "linux")]
fn suspended_millis() -> u64 {
    use rustix::time::{clock_gettime, ClockId};
    let millis = |time: rustix::time::Timespec| {
        i128::from(time.tv_sec) * 1_000 + i128::from(time.tv_nsec) / 1_000_000
    };
    let gap = millis(clock_gettime(ClockId::Boottime)) - millis(clock_gettime(ClockId::Monotonic));
    u64::try_from(gap).unwrap_or(0)
}

#[cfg(not(target_os = "linux"))]
fn suspended_millis() -> u64 {
    0
}

/// A gauge whose samples are read from [`AgeSource`]s at render time.
pub(crate) struct DerivedAgeGauge {
    name: &'static str,
    help: &'static str,
    label: Option<&'static str>,
    sources: IndexMap<String, AgeSource>,
}

impl DerivedAgeGauge {
    /// A single unlabelled sample.
    pub(crate) fn single(name: &'static str, help: &'static str) -> Self {
        Self {
            name,
            help,
            label: None,
            sources: IndexMap::new(),
        }
    }

    /// One sample per registered key, carried on `label`.
    pub(crate) fn keyed(name: &'static str, help: &'static str, label: &'static str) -> Self {
        Self {
            name,
            help,
            label: Some(label),
            sources: IndexMap::new(),
        }
    }

    /// Registers a source, or returns the one already registered under `key` so
    /// two registrations of the same task cannot render two samples.
    pub(crate) fn register(&mut self, key: &str) -> AgeSource {
        self.sources
            .entry(key.to_string())
            .or_insert_with(AgeSource::started_now)
            .clone()
    }

    pub(crate) fn render(&self) -> Vec<String> {
        let name = self.name;
        let mut lines = vec![
            format!("# HELP {} {}", name, self.help),
            format!("# TYPE {} gauge", name),
        ];
        for (key, source) in &self.sources {
            let labels = match self.label {
                Some(label) => render_labels(&Labels::from([(label.to_string(), key.to_string())])),
                None => String::new(),
            };
            lines.push(format!(
                "{}{} {}",
                name,
                labels,
                format_number(source.age_seconds())
            ));
        }
        lines
    }
}

struct HistogramValue {
    labels: Labels,
    buckets: IndexMap<String, u64>,
    inf_count: u64,
    count: u64,
    sum: f64,
}

pub(crate) struct HistogramMetric {
    name: &'static str,
    help: &'static str,
    buckets: &'static [f64],
    values: IndexMap<String, HistogramValue>,
}

impl HistogramMetric {
    pub(crate) fn new(name: &'static str, help: &'static str, buckets: &'static [f64]) -> Self {
        Self {
            name,
            help,
            buckets,
            values: IndexMap::new(),
        }
    }

    pub(crate) fn series_count(&self) -> usize {
        self.values.len()
    }

    pub(crate) fn has_series(&self, labels: &Labels) -> bool {
        self.values.contains_key(&label_key(labels))
    }

    pub(crate) fn observe(&mut self, labels: Labels, value: f64) {
        let key = label_key(&labels);
        let current = self.values.entry(key).or_insert_with(|| HistogramValue {
            labels,
            buckets: self
                .buckets
                .iter()
                .map(|bucket| (format_number(*bucket), 0))
                .collect(),
            inf_count: 0,
            count: 0,
            sum: 0.0,
        });
        for bucket in self.buckets {
            if value <= *bucket {
                let bucket_label = format_number(*bucket);
                if let Some(count) = current.buckets.get_mut(&bucket_label) {
                    *count += 1;
                }
            }
        }
        current.inf_count += 1;
        current.count += 1;
        current.sum += value;
    }

    pub(crate) fn render(&self) -> Vec<String> {
        let name = self.name;
        let mut lines = vec![
            format!("# HELP {} {}", name, self.help),
            format!("# TYPE {} histogram", name),
        ];
        for value in self.values.values() {
            for (bucket, count) in &value.buckets {
                let mut labels = value.labels.clone();
                labels.insert("le".to_string(), bucket.clone());
                lines.push(format!(
                    "{}_bucket{} {}",
                    name,
                    render_labels(&labels),
                    count
                ));
            }
            let mut inf_labels = value.labels.clone();
            inf_labels.insert("le".to_string(), "+Inf".to_string());
            lines.push(format!(
                "{}_bucket{} {}",
                name,
                render_labels(&inf_labels),
                value.inf_count
            ));
            lines.push(format!(
                "{}_sum{} {}",
                name,
                render_labels(&value.labels),
                value.sum
            ));
            lines.push(format!(
                "{}_count{} {}",
                name,
                render_labels(&value.labels),
                value.count
            ));
        }
        lines
    }
}

#[cfg(test)]
mod tests {
    use super::AgeSource;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SUSPENDED: AtomicU64 = AtomicU64::new(5_000);

    #[tokio::test(start_paused = true)]
    async fn age_counts_host_suspension_since_the_stamp() {
        let source = AgeSource::with_suspension_clock(|| SUSPENDED.load(Ordering::SeqCst));
        tokio::time::advance(std::time::Duration::from_secs(2)).await;
        source.stamp();
        tokio::time::advance(std::time::Duration::from_secs(3)).await;
        SUSPENDED.fetch_add(600_000, Ordering::SeqCst);
        assert_eq!(source.age_seconds(), 603.0);
        source.stamp();
        assert_eq!(source.age_seconds(), 0.0);
    }
}
