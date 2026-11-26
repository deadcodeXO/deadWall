use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    path::{Path, PathBuf},
    time::SystemTime,
};

#[derive(Default)]
pub struct Watch {
    files: HashMap<PathBuf, Option<(u64, SystemTime)>>,
    dns: Option<Vec<String>>,
    proxy: Option<String>,
    wifi: HashSet<String>,
    away_traffic: Option<u64>,
    suspicious: HashSet<IpAddr>,
    reported_hosts: HashSet<IpAddr>,
}

impl Watch {
    pub fn new(data_dir: &Path) -> Self {
        #[cfg(windows)]
        let hosts = std::env::var_os("SystemRoot")
            .map(PathBuf::from)
            .map(|root| root.join("System32/drivers/etc/hosts"));
        #[cfg(not(windows))]
        let hosts = Some(PathBuf::from("/etc/hosts"));
        let mut watch = Self::default();
        if let Some(hosts) = hosts {
            watch.add_file(&hosts);
        }
        if let Ok(file) = std::fs::File::open(data_dir.join("suspicious-ips.txt")) {
            use std::io::{BufRead, BufReader, Read};
            watch.suspicious = BufReader::new(file.take(1_048_576))
                .lines()
                .map_while(Result::ok)
                .filter_map(|line| line.split('#').next()?.trim().parse().ok())
                .collect();
        }
        watch
    }

    pub fn add_file(&mut self, file: &Path) {
        if self.files.len() < 2048 && !self.files.contains_key(file) {
            self.files.insert(file.into(), fingerprint(file));
        }
    }

    pub fn matches_host(&mut self, address: IpAddr) -> bool {
        self.suspicious.contains(&address) && self.reported_hosts.insert(address)
    }

    pub fn tick_activity(&mut self, bytes: u64) -> Option<u64> {
        if platform::idle_ms()? >= 5 * 60 * 1000 {
            let observed = self.away_traffic.get_or_insert(0);
            *observed = observed.saturating_add(bytes);
            None
        } else {
            self.away_traffic.take().filter(|bytes| *bytes > 0)
        }
    }

    pub fn poll(&mut self) -> Vec<(&'static str, String)> {
        let mut alerts = Vec::new();
        for (path, previous) in &mut self.files {
            let current = fingerprint(path);
            if *previous != current {
                alerts.push(("Watched file changed", path.display().to_string()));
                *previous = current;
            }
        }
        if let Some(current) = platform::dns() {
            if self
                .dns
                .as_ref()
                .is_some_and(|previous| *previous != current)
            {
                alerts.push((
                    "DNS configuration changed",
                    if current.is_empty() {
                        "No DNS servers reported".into()
                    } else {
                        current.join(", ")
                    },
                ));
            }
            self.dns = Some(current);
        }
        if let Some(current) = platform::proxy() {
            if self
                .proxy
                .as_ref()
                .is_some_and(|previous| *previous != current)
            {
                alerts.push((
                    "Proxy configuration changed",
                    "The current user's Windows proxy settings changed.".into(),
                ));
            }
            self.proxy = Some(current);
        }
        if let Some(current) = platform::wifi() {
            for ssid in current.difference(&self.wifi) {
                alerts.push(("Wi-Fi security mismatch",format!("Another advertised network named {ssid} advertises different authentication or encryption than the connected network.")));
            }
            self.wifi = current;
        }
        alerts
    }
}

fn fingerprint(path: &Path) -> Option<(u64, SystemTime)> {
    let file = std::fs::metadata(path).ok()?;
    Some((file.len(), file.modified().ok()?))
}

#[cfg(not(windows))]
mod platform {
    pub fn idle_ms() -> Option<u32> {
        None
    }
    pub fn proxy() -> Option<String> {
        None
    }
    pub fn wifi() -> Option<std::collections::HashSet<String>> {
        None
    }
    pub fn dns() -> Option<Vec<String>> {
        let config = std::fs::read_to_string("/etc/resolv.conf").ok()?;
        Some(
            config
                .lines()
                .filter_map(|line| {
                    let mut tokens = line.split_whitespace();
                    (tokens.next()? == "nameserver")
                        .then(|| tokens.next().map(str::to_owned))
                        .flatten()
                })
                .collect(),
        )
    }
}

#[cfg(windows)]
#[path = "watch/platform.rs"]
mod platform;

#[derive(Default)]
pub struct ArpClaims {
    claims: HashMap<std::net::Ipv4Addr, ([u8; 6], std::time::Instant, Option<std::time::Instant>)>,
    pending: Vec<String>,
}

impl ArpClaims {
    pub fn observe(&mut self, ip: std::net::Ipv4Addr, mac: [u8; 6]) {
        use std::time::{Duration, Instant};
        let now = Instant::now();
        if !self.claims.contains_key(&ip) && self.claims.len() >= 4096 {
            return;
        }
        let (previous, last, alerted) = self.claims.entry(ip).or_insert((mac, now, None));
        if *previous != mac
            && now.duration_since(*last) <= Duration::from_secs(30)
            && alerted.is_none_or(|when| now.duration_since(when) >= Duration::from_secs(60))
            && self.pending.len() < 16
        {
            let format_mac = |mac: [u8; 6]| {
                mac.iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<Vec<_>>()
                    .join(":")
            };
            self.pending.push(format!(
                "{ip} was claimed by {} and {} within 30 seconds.",
                format_mac(*previous),
                format_mac(mac)
            ));
            *alerted = Some(now);
        }
        *previous = mac;
        *last = now;
    }

    pub fn alerts(&mut self) -> Vec<String> {
        std::mem::take(&mut self.pending)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn arp_claims_flag_a_conflict_and_limit_repeats() {
        let mut claims = super::ArpClaims::default();
        let ip = "192.0.2.1".parse().unwrap();
        claims.observe(ip, [2, 0, 0, 0, 0, 1]);
        assert!(claims.alerts().is_empty());
        claims.observe(ip, [2, 0, 0, 0, 0, 2]);
        assert_eq!(claims.alerts().len(), 1);
        claims.observe(ip, [2, 0, 0, 0, 0, 1]);
        assert!(claims.alerts().is_empty());
    }
}
