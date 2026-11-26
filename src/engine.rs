use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    path::PathBuf,
    sync::mpsc::{self, Receiver, Sender, TryRecvError},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use sysinfo::{Networks, System};

use crate::{
    devices::{self, Device},
    history::{Dimension, History, Point, UsageRow},
    pcap::{self, Capture},
    processes::{self, Owners, Process, Resources},
    traffic::{self, Flow, Flows, Volume},
};

pub const LIVE_SECONDS: i64 = 120;
const PERIOD: Duration = Duration::from_secs(1);

#[derive(Clone)]
pub enum Source {
    Counters(String),
    Packets(pcap::Adapter),
}

impl Source {
    pub fn name(&self) -> &str {
        match self {
            Self::Counters(name) => name,
            Self::Packets(adapter) => &adapter.label,
        }
    }

    pub fn key(&self) -> String {
        match self {
            Self::Counters(name) => format!("interface:{name}"),
            Self::Packets(adapter) => format!("packet:{}", adapter.name),
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Self::Counters(_) => "interface counters",
            Self::Packets(_) => "packet capture",
        }
    }
}

#[derive(Clone)]
pub struct Row {
    pub flow: Flow,
    pub app: Option<Process>,
    pub volume: Volume,
}

pub struct Sample {
    pub point: Point,
    pub rows: Vec<Row>,
    pub other: Volume,
}

pub struct Alert {
    pub time: i64,
    pub title: String,
    pub detail: String,
}

pub enum Command {
    RefreshSources,
    Select(String),
    Pause(bool),
    History {
        id: u64,
        since: i64,
        width: i64,
    },
    Export {
        since: i64,
    },
    RefreshDevices,
    Usage {
        id: u64,
        from: i64,
        to: i64,
        group: Dimension,
    },
    Stop,
}

pub enum Event {
    Sources(Vec<Source>, Option<String>),
    Selected(Option<String>),
    State(String),
    Storage(String),
    Notice(String),
    Sample(Sample),
    History(u64, Result<Vec<Point>, String>),
    Usage(u64, Result<Vec<UsageRow>, String>),
    Resources(Resources),
    Devices(Result<Vec<Device>, String>),
    Alert(Alert),
}

pub struct Engine {
    pub commands: Sender<Command>,
    pub events: Receiver<Event>,
    task: Option<thread::JoinHandle<()>>,
}

impl Engine {
    pub fn start() -> std::io::Result<Self> {
        let (commands, inbox) = mpsc::channel();
        let (outbox, events) = mpsc::channel();
        let task = thread::Builder::new()
            .name("deadwall-monitor".into())
            .spawn(move || {
                Monitor::new(outbox).run(inbox);
            })?;
        Ok(Self {
            commands,
            events,
            task: Some(task),
        })
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        let _ = self.commands.send(Command::Stop);
        if let Some(task) = self.task.take() {
            let _ = task.join();
        }
    }
}

struct Monitor {
    tx: Sender<Event>,
    networks: Networks,
    system: System,
    resources: Resources,
    hardware: crate::hardware::Platform,
    owners: Owners,
    local: HashSet<IpAddr>,
    sources: Vec<Source>,
    selected: Option<Source>,
    capture: Option<Capture>,
    flows: Flows,
    db: Option<History>,
    archive: Option<Sender<(String, ArchiveRequest)>>,
    paused: bool,
    start: Instant,
    last_totals: Option<Volume>,
    last_recording: Option<bool>,
    seen_apps: HashSet<PathBuf>,
    seen_devices: HashMap<(String, IpAddr), String>,
    rdp_seen: bool,
    arp: crate::watch::ArpClaims,
    watch: crate::watch::Watch,
}

impl Monitor {
    fn new(tx: Sender<Event>) -> Self {
        let path = History::path();
        let db = match History::open(&path) {
            Ok(db) => {
                let _ = tx.send(Event::Storage(path.display().to_string()));
                Some(db)
            }
            Err(error) => {
                let _ = tx.send(Event::Storage(format!("History unavailable: {error}")));
                None
            }
        };
        Self {
            tx: tx.clone(),
            networks: Networks::new_with_refreshed_list(),
            system: System::new(),
            resources: Resources::default(),
            hardware: crate::hardware::Platform::default(),
            owners: Owners::default(),
            local: HashSet::new(),
            sources: Vec::new(),
            selected: None,
            capture: None,
            flows: Flows::default(),
            archive: db
                .as_ref()
                .and_then(|_| start_archive(path.clone(), tx.clone()).ok()),
            db,
            paused: false,
            start: Instant::now(),
            last_totals: None,
            last_recording: None,
            seen_apps: HashSet::new(),
            seen_devices: HashMap::new(),
            rdp_seen: false,
            arp: crate::watch::ArpClaims::default(),
            watch: crate::watch::Watch::new(
                path.parent().unwrap_or_else(|| std::path::Path::new(".")),
            ),
        }
    }

    fn run(mut self, rx: Receiver<Command>) {
        if let Some(db) = &self.db
            && let Ok(alerts) = db.alerts()
        {
            for alert in alerts {
                self.send(Event::Alert(alert));
            }
        }
        self.refresh_sources();
        self.refresh_devices(false);
        let mut telemetry = Instant::now();
        let mut devices = Instant::now();
        loop {
            let command = if self.capture.is_some() {
                rx.try_recv()
            } else {
                rx.recv_timeout(Duration::from_millis(100))
                    .map_err(|error| match error {
                        mpsc::RecvTimeoutError::Timeout => TryRecvError::Empty,
                        mpsc::RecvTimeoutError::Disconnected => TryRecvError::Disconnected,
                    })
            };
            match command {
                Ok(Command::Stop) | Err(TryRecvError::Disconnected) => break,
                Ok(command) => self.command(command),
                Err(TryRecvError::Empty) => {}
            }
            if telemetry.elapsed() >= Duration::from_secs(2) {
                telemetry = Instant::now();
                self.resources = processes::refresh(&mut self.system, self.hardware.read());
                if self.capture.is_some() {
                    self.owners = Owners::read();
                }
                self.send(Event::Resources(Resources {
                    cpu: self.resources.cpu,
                    used_memory: self.resources.used_memory,
                    total_memory: self.resources.total_memory,
                    gpu: self.resources.gpu,
                    disk_rate: self.resources.disk_rate,
                    processes: self.resources.processes.clone(),
                }));
            }
            if devices.elapsed() >= Duration::from_secs(15) {
                devices = Instant::now();
                self.refresh_devices(true);
                for (title, detail) in self.watch.poll() {
                    self.alert(title, detail);
                }
                if let Ok(addresses) = if_addrs::get_if_addrs() {
                    self.local = addresses.into_iter().map(|entry| entry.ip()).collect();
                }
            }
            if self.start.elapsed() >= PERIOD && !self.paused {
                self.sample();
            }
            if !self.drain_capture() && self.capture.is_some() {
                thread::sleep(Duration::from_millis(12));
            }
        }
    }

    fn send(&self, event: Event) {
        let _ = self.tx.send(event);
    }

    fn refresh_sources(&mut self) {
        if let Ok(addresses) = if_addrs::get_if_addrs() {
            self.local = addresses.into_iter().map(|entry| entry.ip()).collect();
        }
        self.networks.refresh(true);
        let (capture_sources, warning) = match pcap::adapters() {
            Ok(adapters) if !adapters.is_empty() => (adapters, None),
            Ok(_) => (Vec::new(), Some("No packet adapters found.".into())),
            Err(error) => (Vec::new(), Some(error)),
        };
        let mut network_names: Vec<_> = self.networks.keys().cloned().collect();
        network_names.sort_by_key(|name| {
            let traffic = self
                .networks
                .get(name)
                .map(|network| {
                    network
                        .total_received()
                        .saturating_add(network.total_transmitted())
                })
                .unwrap_or(0);
            (std::cmp::Reverse(traffic), name.clone())
        });
        self.sources = capture_sources
            .into_iter()
            .map(Source::Packets)
            .chain(network_names.into_iter().map(Source::Counters))
            .collect();
        self.send(Event::Sources(self.sources.clone(), warning));
        if self.selected.is_none() {
            let preferred = self
                .sources
                .iter()
                .find(
                    |entry| matches!(entry, Source::Packets(adapter) if adapter.physical_candidate),
                )
                .or_else(|| {
                    self.sources
                        .iter()
                        .find(|entry| matches!(entry, Source::Counters(_)))
                })
                .or_else(|| self.sources.first())
                .cloned();
            self.select(preferred);
            if self.capture.is_none()
                && matches!(self.selected, Some(Source::Packets(_)))
                && let Some(source) = self
                    .sources
                    .iter()
                    .find(|entry| matches!(entry, Source::Counters(_)))
                    .cloned()
            {
                self.select(Some(source));
            }
        }
    }

    fn select(&mut self, source: Option<Source>) {
        self.capture = None;
        self.selected = source;
        self.arp = crate::watch::ArpClaims::default();
        self.flows = Flows::default();
        self.last_totals = None;
        self.start = Instant::now();
        self.send(Event::Selected(self.selected.as_ref().map(Source::key)));
        self.start_source();
    }

    fn start_source(&mut self) {
        if self.paused {
            self.send(Event::State("Paused".into()));
            return;
        }
        let state = match self.selected.as_ref() {
            Some(Source::Packets(adapter)) => match Capture::open(adapter) {
                Ok(capture) => {
                    self.capture = Some(capture);
                    self.owners = Owners::read();
                    "Capturing packets".into()
                }
                Err(error) => format!("Capture unavailable: {error}"),
            },
            Some(Source::Counters(name)) => {
                self.networks.refresh(true);
                self.last_totals = self.networks.get(name).map(|value| Volume {
                    rx: value.total_received(),
                    tx: value.total_transmitted(),
                });
                "Reading interface counters".into()
            }
            None => "No interfaces available".into(),
        };
        self.send(Event::State(state));
    }

    fn drain_capture(&mut self) -> bool {
        let Some(capture) = &mut self.capture else {
            return false;
        };
        let link = capture.link_type;
        for _ in 0..2048 {
            match capture.next() {
                Ok(Some((data, len))) => {
                    if let Some((ip, mac)) = traffic::arp_claim(data, link) {
                        self.arp.observe(ip, mac);
                    }
                    if let Some((flow, outbound)) = traffic::classify(data, link, &self.local) {
                        self.flows.observe(flow, len, outbound);
                    }
                }
                Ok(None) => return false,
                Err(error) => {
                    self.capture = None;
                    self.send(Event::State(format!("Capture stopped: {error}")));
                    return false;
                }
            }
        }
        true
    }

    fn sample(&mut self) {
        for detail in self.arp.alerts() {
            self.alert("Conflicting ARP claims", detail);
        }
        let duration_ms = self.start.elapsed().as_millis() as i64;
        self.start = Instant::now();
        let Some(source) = &self.selected else { return };
        let source_key = source.key();
        let mut flows = std::mem::take(&mut self.flows);
        if let Source::Counters(name) = source {
            self.networks.refresh(true);
            let totals = self.networks.get(name).map(|value| Volume {
                rx: value.total_received(),
                tx: value.total_transmitted(),
            });
            let previous = std::mem::replace(&mut self.last_totals, totals);
            let (Some(now), Some(last)) = (totals, previous) else {
                return;
            };
            flows.volume = Volume {
                rx: now.rx.saturating_sub(last.rx),
                tx: now.tx.saturating_sub(last.tx),
            };
        } else if self.capture.is_none() && flows.volume.total() == 0 {
            return;
        }
        let end = now_ms();
        let point = Point {
            end,
            first: end,
            duration_ms,
            volume: flows.volume,
        };
        let rows: Vec<_> = flows
            .rows
            .into_iter()
            .map(|(flow, volume)| Row {
                app: self
                    .owners
                    .get(flow)
                    .and_then(|pid| self.resources.processes.get(&pid))
                    .cloned(),
                flow,
                volume,
            })
            .collect();
        self.observe_rows(&rows);
        if let Some(bytes) = self.watch.tick_activity(point.volume.total()) {
            self.alert(
                "While you were away",
                format!("{bytes} bytes observed on the monitored source during inactivity."),
            );
        }
        if let Some(db) = &self.db {
            let result = db.record(&source_key, &point, &rows, flows.other);
            let succeeded = result.is_ok();
            if self.last_recording != Some(succeeded) {
                self.last_recording = Some(succeeded);
                self.send(Event::Storage(match result {
                    Ok(()) => History::path().display().to_string(),
                    Err(error) => format!("History write failed: {error}"),
                }));
            }
        }
        self.send(Event::Sample(Sample {
            point,
            rows,
            other: flows.other,
        }));
    }

    fn observe_rows(&mut self, rows: &[Row]) {
        for row in rows {
            if let Some(path) = row.app.as_ref().and_then(|app| app.path.as_ref())
                && self.seen_apps.len() < 8192
                && self.seen_apps.insert(path.clone())
            {
                self.watch.add_file(path);
                if !self
                    .db
                    .as_ref()
                    .and_then(|db| db.seen_app(path).ok())
                    .unwrap_or(false)
                {
                    self.alert("First network activity", path.display().to_string());
                }
            }
            if self.watch.matches_host(row.flow.remote.ip()) {
                self.alert(
                    "Host matched your watchlist",
                    row.flow.remote.ip().to_string(),
                );
            }
            if row.flow.protocol == 6
                && row.flow.local.port() == 3389
                && row.volume.rx > 0
                && !self.rdp_seen
            {
                self.rdp_seen = true;
                self.alert(
                    "Inbound traffic on the RDP port",
                    format!("{} → {}", row.flow.remote, row.flow.local),
                );
            }
        }
    }

    fn refresh_devices(&mut self, watch: bool) {
        let devices = devices::neighbors();
        if let Ok(devices) = &devices {
            for device in devices {
                let key = (device.interface.clone(), device.address);
                if self.seen_devices.len() >= 8192 && !self.seen_devices.contains_key(&key) {
                    continue;
                }
                match self.seen_devices.insert(key, device.mac.clone()) {
                    None if watch => self.alert(
                        "New neighbor",
                        format!("{} at {}", device.address, device.mac),
                    ),
                    Some(old) if watch && old != device.mac => {
                        self.alert(
                            "Neighbor MAC changed",
                            format!(
                                "{} changed from {} to {} on interface {}",
                                device.address, old, device.mac, device.interface
                            ),
                        );
                    }
                    _ => {}
                }
            }
        }
        self.send(Event::Devices(devices));
    }

    fn alert(&self, title: &'static str, detail: String) {
        let alert = Alert {
            time: now_ms(),
            title: title.into(),
            detail,
        };
        if let Some(db) = &self.db {
            let _ = db.record_alert(&alert);
        }
        self.send(Event::Alert(alert));
    }

    fn archive(&self, request: ArchiveRequest) {
        let Some((archive, source)) = self.archive.as_ref().zip(self.selected.as_ref()) else {
            self.send(request.failed("History source is unavailable.".into()));
            return;
        };
        if let Err(error) = archive.send((source.key(), request)) {
            self.send(error.0.1.failed("History reader disconnected.".into()));
        }
    }
    fn command(&mut self, command: Command) {
        match command {
            Command::RefreshSources => self.refresh_sources(),
            Command::Select(key) => {
                let selected = self
                    .sources
                    .iter()
                    .find(|source| source.key() == key)
                    .cloned();
                self.select(selected);
            }
            Command::Pause(paused) => {
                self.paused = paused;
                self.capture = None;
                self.flows = Flows::default();
                self.last_totals = None;
                self.start = Instant::now();
                self.start_source();
            }
            Command::History { id, since, width } => {
                self.archive(ArchiveRequest::Bandwidth { id, since, width })
            }
            Command::Export { since } => self.archive(ArchiveRequest::Export { since }),
            Command::RefreshDevices => self.refresh_devices(true),
            Command::Usage {
                id,
                from,
                to,
                group,
            } => self.archive(ArchiveRequest::Usage {
                id,
                from,
                to,
                group,
            }),
            Command::Stop => {}
        }
    }
}

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

enum ArchiveRequest {
    Bandwidth {
        id: u64,
        since: i64,
        width: i64,
    },
    Usage {
        id: u64,
        from: i64,
        to: i64,
        group: Dimension,
    },
    Export {
        since: i64,
    },
}

impl ArchiveRequest {
    fn failed(self, error: String) -> Event {
        match self {
            Self::Bandwidth { id, .. } => Event::History(id, Err(error)),
            Self::Usage { id, .. } => Event::Usage(id, Err(error)),
            Self::Export { .. } => Event::Notice(format!("Export failed: {error}")),
        }
    }
}

fn start_archive(
    path: PathBuf,
    tx: Sender<Event>,
) -> std::io::Result<Sender<(String, ArchiveRequest)>> {
    let (sender, receiver) = mpsc::channel::<(String, ArchiveRequest)>();
    thread::Builder::new()
        .name("deadwall-history-reader".into())
        .spawn(move || {
            let database = History::open_reader(&path);
            while let Ok((source, request)) = receiver.recv() {
                let event = match &database {
                    Ok(db) => match request {
                        ArchiveRequest::Bandwidth { id, since, width } => Event::History(
                            id,
                            db.read(&source, since, width)
                                .map_err(|error| error.to_string()),
                        ),
                        ArchiveRequest::Usage {
                            id,
                            from,
                            to,
                            group,
                        } => Event::Usage(
                            id,
                            db.usage(&source, from, to, group)
                                .map_err(|error| error.to_string()),
                        ),
                        ArchiveRequest::Export { since } => {
                            Event::Notice(match export(db, &source, since) {
                                Ok(path) => format!("Exported {}", path.display()),
                                Err(error) => format!("Export failed: {error}"),
                            })
                        }
                    },
                    Err(error) => request.failed(error.clone()),
                };
                if tx.send(event).is_err() {
                    break;
                }
            }
        })?;
    Ok(sender)
}
fn export(db: &History, source: &str, since: i64) -> Result<PathBuf, String> {
    let id = now_ms();
    let path = History::path().with_file_name(format!("deadwall-bandwidth-{id}.csv"));
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|error| error.to_string())?;
    let mut writer = csv::Writer::from_writer(file);
    let result = db.export(source, since, &mut writer);
    match result {
        Ok(()) => Ok(path),
        Err(error) => {
            drop(writer);
            let _ = std::fs::remove_file(path);
            Err(error.to_string())
        }
    }
}
