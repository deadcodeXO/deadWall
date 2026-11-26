use std::{net::IpAddr, sync::mpsc};

#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct Spec {
    pub continents: Vec<String>,
    pub countries: String,
    pub cidrs: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct IpRange {
    pub v6: bool,
    pub start: u128,
    pub end: u128,
}

impl Spec {
    fn ranges(&self) -> Result<Vec<IpRange>, String> {
        let codes = self
            .countries
            .split(|c: char| c == ',' || c.is_whitespace())
            .filter(|entry| !entry.is_empty())
            .map(str::to_ascii_uppercase)
            .collect::<std::collections::HashSet<_>>();
        let mut ranges = Vec::new();
        for line in self
            .cidrs
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
        {
            ranges.push(cidr(line).ok_or_else(|| format!("Invalid IPv4 or IPv6 CIDR: {line}"))?);
        }
        if !codes.is_empty() || !self.continents.is_empty() {
            ranges.extend(crate::geo::selected_ranges(&codes, &self.continents)?);
        }
        ranges.sort_unstable();
        let mut merged: Vec<IpRange> = Vec::new();
        for range in ranges {
            if let Some(last) = merged.last_mut()
                && last.v6 == range.v6
                && range.start <= last.end.saturating_add(1)
            {
                last.end = last.end.max(range.end);
            } else {
                merged.push(range);
            }
        }
        Ok(merged)
    }
}

fn cidr(text: &str) -> Option<IpRange> {
    let (ip, prefix) = text.split_once('/')?;
    let addr: IpAddr = ip.parse().ok()?;
    let prefix: u32 = prefix.parse().ok()?;
    let (v6, bits, number) = match addr {
        IpAddr::V4(ip) => (false, 32_u32, u128::from(u32::from(ip))),
        IpAddr::V6(ip) => (true, 128_u32, u128::from(ip)),
    };
    let hosts: u32 = bits.checked_sub(prefix)?;
    let hostmask = u128::MAX.checked_shl(hosts).map_or(u128::MAX, |mask| !mask);
    Some(IpRange {
        v6,
        start: number & !hostmask,
        end: number | hostmask,
    })
}

pub struct Worker {
    tx: mpsc::Sender<Spec>,
    pub rx: mpsc::Receiver<Result<usize, String>>,
}

impl Worker {
    pub fn start() -> std::io::Result<Self> {
        let (tx, inbox) = mpsc::channel::<Spec>();
        let (outbox, rx) = mpsc::channel();
        std::thread::Builder::new()
            .name("deadwall-region-filter".into())
            .spawn(move || {
                let mut filter = platform::Filter::default();
                while let Ok(spec) = inbox.recv() {
                    let result = spec.ranges().and_then(|ranges| {
                        filter.apply(&ranges)?;
                        Ok(ranges.len())
                    });
                    if outbox.send(result).is_err() {
                        break;
                    }
                }
            })?;
        Ok(Self { tx, rx })
    }

    pub fn apply(&self, spec: Spec) -> Result<(), String> {
        self.tx.send(spec).map_err(|error| error.to_string())
    }
}

#[cfg(not(windows))]
mod platform {
    #[derive(Default)]
    pub struct Filter;
    impl Filter {
        pub fn apply(&mut self, _: &[super::IpRange]) -> Result<(), String> {
            Err("Geographic blocking is available on Windows.".into())
        }
    }
}

#[cfg(windows)]
#[path = "geo_filter/platform.rs"]
mod platform;
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_and_merges_ipv4_and_ipv6_ranges() {
        let spec = Spec {
            cidrs: "192.0.2.97/25\n192.0.2.128/25\n2001:db8::4/126".into(),
            ..Default::default()
        };
        let result = spec.ranges().unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], cidr("192.0.2.0/24").unwrap());
        assert_eq!(result[1].end - result[1].start, 3);
        assert!(cidr("192.0.2.0/33").is_none());
        assert_eq!(cidr("::/0").unwrap().end, u128::MAX);
    }
}
