use crate::{
    devices::Device,
    engine::{self, Alert, Command, Engine, Event, Sample, Source},
    firewall,
    history::{Dimension, Point, UsageRow},
    processes::Resources,
    traffic::Volume,
};
use chrono::{Local, TimeZone};
use eframe::egui::{
    self, Align, Color32, Context, Frame, Grid, Layout, Margin, RichText, ScrollArea, Ui, Vec2,
};
use egui_plot::{Line, Plot, PlotBounds, VLine};
use std::{
    collections::{HashMap, VecDeque},
    path::PathBuf,
    sync::mpsc,
    time::Duration,
};

const BLUE: Color32 = Color32::from_rgb(110, 168, 254);
const GREEN: Color32 = Color32::from_rgb(100, 214, 161);
const PURPLE: Color32 = Color32::from_rgb(185, 155, 242);
const AMBER: Color32 = Color32::from_rgb(233, 191, 114);
const PAGES: [&str; 6] = [
    "Traffic", "Hardware", "Things", "Alerts", "Firewall", "Settings",
];

const RANGES: [(&str, i64, i64); 5] = [
    ("Live", 120, 1),
    ("1 hour", 3600, 5),
    ("24 hours", 86400, 120),
    ("7 days", 604800, 900),
    ("All time", 0, 1),
];
const THEMES: [(&str, [u32; 4]); 4] = [
    ("GitHub Dark", [0x0d1117, 0x10151d, 0x141a23, 0x27313d]),
    ("Nord", [0x242933, 0x282e39, 0x2e3440, 0x434c5e]),
    ("Tokyo Night", [0x1a1b26, 0x1d1e2b, 0x20212f, 0x37384d]),
    ("Daylight", [0xf0f3f8, 0xfafcff, 0xffffff, 0xd9e1ec]),
];

type MapVolumes = HashMap<String, Volume>;
type MapPeers = HashMap<String, Vec<String>>;

const LIGHT: usize = THEMES.len() - 1;

pub struct Desk {
    engine: Engine,
    theme: usize,
    dark_theme: usize,
    logo: egui::TextureHandle,
    icon: std::sync::Arc<egui::IconData>,
    traffic_view: usize,
    firewall_view: usize,
    geo_filter: String,
    geo_lookup: Option<std::net::IpAddr>,
    map_revision: u64,
    live_map: bool,
    map_seconds: u64,
    timeline_grid: bool,
    geo_rules: crate::geo_filter::Spec,
    geo_worker: Option<crate::geo_filter::Worker>,
    geo_pending: bool,
    geo_active: usize,
    #[cfg(windows)]
    window_checked: bool,
    page: usize,
    group: usize,
    range: usize,
    samples: VecDeque<Sample>,
    history: Vec<Point>,
    query: u64,
    usage_query: u64,
    usage_rows: Vec<UsageRow>,
    pending: bool,
    sources: Vec<Source>,
    source: Option<String>,
    capture_notice: Option<String>,
    picked: Option<i64>,
    filter: String,
    state: String,
    storage: String,
    notice: String,
    paused: bool,
    mini: bool,
    inspector: bool,
    resources: Resources,
    resource_samples: VecDeque<[Option<f32>; 3]>,
    devices: Result<Vec<Device>, String>,
    scan_source: Option<std::net::Ipv4Addr>,
    scan_task: Option<mpsc::Receiver<Result<Vec<Device>, String>>>,
    discovered: Vec<Device>,
    alerts: VecDeque<Alert>,
    path: String,
    profiles: i32,
    saved_profiles: Vec<crate::profiles::Profile>,
    profile_name: String,
    profile_apps: String,
    confirm: bool,
    firewall_task: Option<mpsc::Receiver<Result<String, String>>>,
    ask: Option<crate::ask::Ask>,
    ask_confirm: bool,
    ask_count: usize,
}

impl Desk {
    pub fn new(
        context: &eframe::CreationContext<'_>,
        engine: Engine,
        icon: &egui::IconData,
    ) -> Self {
        let ctx = &context.egui_ctx;
        let preference = |key| {
            context
                .storage
                .and_then(|store| store.get_string(key))
                .and_then(|value| value.parse::<usize>().ok())
        };
        let logo = ctx.load_texture(
            "deadwall-brand",
            egui::ColorImage::from_rgba_unmultiplied(
                [icon.width as usize, icon.height as usize],
                &icon.rgba,
            ),
            egui::TextureOptions::LINEAR,
        );
        let mut app = Self {
            engine,
            theme: preference("theme")
                .filter(|theme| *theme < THEMES.len())
                .unwrap_or(LIGHT),
            dark_theme: preference("dark_theme")
                .filter(|theme| *theme < LIGHT)
                .unwrap_or(0),
            logo,
            icon: std::sync::Arc::new(icon.clone()),
            traffic_view: 0,
            firewall_view: 0,
            geo_filter: String::new(),
            geo_lookup: None,
            map_revision: 0,
            live_map: true,
            map_seconds: preference("map_seconds")
                .filter(|value| [15, 30, 60, 120].contains(value))
                .unwrap_or(30) as u64,
            timeline_grid: preference("timeline_grid") != Some(0),
            geo_rules: context
                .storage
                .and_then(|store| store.get_string("geo_rules"))
                .and_then(|text| serde_json::from_str(&text).ok())
                .unwrap_or_default(),
            geo_worker: None,
            geo_pending: false,
            geo_active: 0,
            #[cfg(windows)]
            window_checked: false,
            page: 0,
            group: 0,
            range: 0,
            samples: VecDeque::new(),
            history: Vec::new(),
            query: 0,
            usage_query: 0,
            usage_rows: Vec::new(),
            pending: false,
            sources: Vec::new(),
            source: None,
            capture_notice: None,
            picked: None,
            filter: String::new(),
            state: "Starting monitor".into(),
            storage: String::new(),
            notice: String::new(),
            paused: false,
            mini: false,
            inspector: preference("inspector") == Some(1),
            resources: Resources::default(),
            resource_samples: VecDeque::with_capacity(60),
            devices: Ok(Vec::new()),
            scan_source: None,
            scan_task: None,
            discovered: Vec::new(),
            alerts: VecDeque::new(),
            path: String::new(),
            profiles: 7,
            saved_profiles: Vec::new(),
            profile_name: String::new(),
            profile_apps: String::new(),
            confirm: false,
            firewall_task: None,
            ask: None,
            ask_confirm: false,
            ask_count: 0,
        };
        let mut fonts = egui::FontDefinitions::default();
        fonts.font_data.insert(
            "Inter".into(),
            egui::FontData::from_static(include_bytes!("../assets/Inter.ttf")).into(),
        );
        fonts
            .families
            .entry(egui::FontFamily::Proportional)
            .or_default()
            .insert(0, "Inter".into());
        ctx.set_fonts(fonts);
        app.apply_theme(ctx);
        app.load_profiles();
        app
    }

    fn color(&self, index: usize) -> Color32 {
        let hex = THEMES[self.theme].1[index];
        Color32::from_rgb((hex >> 16) as u8, (hex >> 8) as u8, hex as u8)
    }

    fn apply_theme(&self, ctx: &Context) {
        let mut style = egui::Style::default();
        style.spacing.item_spacing = Vec2::new(9.0, 8.0);
        style.spacing.button_padding = Vec2::new(10.0, 5.0);
        style.spacing.interact_size.y = 29.0;
        style
            .text_styles
            .insert(egui::TextStyle::Heading, egui::FontId::proportional(22.0));
        style
            .text_styles
            .insert(egui::TextStyle::Body, egui::FontId::proportional(13.0));
        style
            .text_styles
            .insert(egui::TextStyle::Button, egui::FontId::proportional(13.0));
        let v = &mut style.visuals;
        let light = self.theme == LIGHT;
        *v = if light {
            egui::Visuals::light()
        } else {
            egui::Visuals::dark()
        };
        v.panel_fill = self.color(0);
        v.window_fill = self.color(1);
        v.extreme_bg_color = self.color(0);
        v.faint_bg_color = self.color(2);
        v.weak_text_color = Some(if light {
            Color32::from_rgb(84, 101, 124)
        } else {
            Color32::from_rgb(149, 164, 188)
        });
        v.widgets.noninteractive.fg_stroke.color = if light {
            Color32::from_rgb(31, 48, 74)
        } else {
            Color32::from_rgb(223, 231, 242)
        };
        v.widgets.noninteractive.bg_stroke.color = self.color(3);
        v.widgets.hovered.weak_bg_fill = self.color(3);
        v.widgets.active.weak_bg_fill = self.color(3);
        v.selection.bg_fill = if light {
            Color32::from_rgb(218, 232, 253)
        } else {
            Color32::from_rgb(37, 58, 83)
        };
        v.selection.stroke = egui::Stroke::new(1.0_f32, accent(light));
        v.widgets.inactive.weak_bg_fill = self.color(2);
        v.widgets.inactive.bg_stroke.color = self.color(3);
        ctx.set_theme(if light {
            egui::Theme::Light
        } else {
            egui::Theme::Dark
        });
        ctx.set_style(style);
        ctx.send_viewport_cmd(egui::ViewportCommand::SetTheme(if light {
            egui::SystemTheme::Light
        } else {
            egui::SystemTheme::Dark
        }));
    }

    fn frame(&self) -> Frame {
        Frame::new()
            .fill(self.color(2))
            .stroke(egui::Stroke::new(1.0_f32, self.color(3)))
            .corner_radius(12)
            .inner_margin(Margin::same(13))
    }

    fn command(&mut self, command: Command) {
        if self.engine.commands.send(command).is_err() {
            self.state = "Monitor disconnected".into();
        }
    }

    fn poll(&mut self) {
        while let Ok(event) = self.engine.events.try_recv() {
            match event {
                Event::Sources(sources, warning) => {
                    self.sources = sources;
                    self.capture_notice = warning;
                }
                Event::Selected(key) => {
                    self.source = key;
                    self.samples.clear();
                    self.picked = None;
                    self.refresh_history();
                }
                Event::State(state) => self.state = state,
                Event::Storage(storage) => self.storage = storage,
                Event::Notice(notice) => self.notice = notice,
                Event::Resources(resources) => {
                    if self.resource_samples.len() == 60 {
                        self.resource_samples.pop_front();
                    }
                    self.resource_samples.push_back([
                        Some(resources.cpu / 100.0),
                        (resources.total_memory > 0)
                            .then(|| resources.used_memory as f32 / resources.total_memory as f32),
                        resources.gpu.map(|gpu| gpu as f32 / 100.0),
                    ]);
                    self.resources = resources;
                }
                Event::Devices(devices) => self.devices = devices,
                Event::Alert(alert) => {
                    self.alerts.push_front(alert);
                    self.alerts.truncate(500);
                }
                Event::Sample(sample) => {
                    let cutoff = sample.point.end - engine::LIVE_SECONDS * 1000;
                    self.samples.push_back(sample);
                    while self
                        .samples
                        .front()
                        .is_some_and(|first| first.point.end < cutoff)
                    {
                        self.samples.pop_front();
                    }
                    if self.picked.is_some_and(|time| time < cutoff) && self.range == 0 {
                        self.picked = None;
                    }
                }
                Event::History(id, result) if id == self.query => {
                    self.pending = false;
                    match result {
                        Ok(points) => self.history = points,
                        Err(error) => self.notice = format!("History unavailable: {error}"),
                    }
                }
                Event::History(_, _) => {}
                Event::Usage(id, result) if id == self.usage_query => match result {
                    Ok(rows) => self.usage_rows = rows,
                    Err(error) => self.notice = format!("Usage history unavailable: {error}"),
                },
                Event::Usage(_, _) => {}
            }
        }
        if let Some(task) = &self.scan_task {
            let result = match task.try_recv() {
                Ok(result) => Some(result),
                Err(mpsc::TryRecvError::Disconnected) => {
                    Some(Err("Discovery worker disconnected.".into()))
                }
                Err(mpsc::TryRecvError::Empty) => None,
            };
            if let Some(result) = result {
                self.scan_task = None;
                match result {
                    Ok(devices) => {
                        self.notice = format!("ARP discovery found {} device(s).", devices.len());
                        self.discovered = devices;
                        self.command(Command::RefreshDevices);
                    }
                    Err(error) => self.notice = error,
                }
            }
        }
        if let Some(task) = &self.firewall_task {
            let result = match task.try_recv() {
                Ok(result) => Some(result),
                Err(mpsc::TryRecvError::Disconnected) => {
                    Some(Err("Firewall worker disconnected.".into()))
                }
                Err(mpsc::TryRecvError::Empty) => None,
            };
            if let Some(result) = result {
                self.notice = result.unwrap_or_else(|error| format!("Firewall: {error}"));
                self.firewall_task = None;
                self.load_profiles();
            }
        }
    }

    fn bounds(&self) -> (i64, i64) {
        let (_, seconds, width) = RANGES[self.range];
        (
            if seconds == 0 {
                0
            } else {
                engine::now_ms() - seconds * 1000
            },
            width * 1000,
        )
    }

    fn refresh_history(&mut self) {
        self.history.clear();
        self.picked = None;
        self.query += 1;
        self.pending = self.range != 0;
        if self.pending {
            let (since, width) = self.bounds();
            self.command(Command::History {
                id: self.query,
                since,
                width,
            });
        }
        self.refresh_usage();
    }

    fn refresh_usage(&mut self) {
        self.usage_query += 1;
        self.usage_rows.clear();
        if self.range == 0
            || !self
                .source
                .as_ref()
                .is_some_and(|key| key.starts_with("packet:"))
        {
            return;
        }
        let (from, to) = self
            .picked
            .and_then(|time| self.history.iter().find(|point| point.end == time))
            .map(|point| (point.first, point.end))
            .unwrap_or((self.bounds().0, i64::MAX));
        self.command(Command::Usage {
            id: self.usage_query,
            from,
            to,
            group: Dimension::ALL[self.group].0,
        });
    }

    fn page(&mut self, page: usize) {
        if self.page != page {
            self.page = page;
            self.filter.clear();
        }
    }

    fn header(&mut self, ctx: &Context) {
        egui::TopBottomPanel::top("header")
            .frame(
                Frame::new()
                    .fill(self.color(1))
                    .inner_margin(Margin::symmetric(15, 10))
                    .stroke(egui::Stroke::new(1.0_f32, self.color(3))),
            )
            .show(ctx, |ui| {
                ui.horizontal_centered(|ui| {
                    ui.add(egui::Image::new((self.logo.id(), Vec2::splat(33.0))).corner_radius(7));
                    ui.label(RichText::new("deadWall").size(17.0).strong());
                    ui.add_space(8.0);
                    let order = [0, 4, 3, 2, 1, 5];
                    let nav_width =
                        ((ui.available_width() - 40.0 - 9.0 * 6.0) / 6.0).clamp(63.0, 122.0);
                    for page in order {
                        let count = (page == 4 && self.ask_count != 0).then_some(self.ask_count);
                        let label = if page == 1 && nav_width < 79.0 {
                            "Usage"
                        } else {
                            PAGES[page]
                        };
                        if nav_button(ui, page, label, self.page == page, count, nav_width)
                            .clicked()
                        {
                            self.page(page);
                        }
                    }
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if theme_button(ui, self.theme == LIGHT).clicked() {
                            if self.theme == LIGHT {
                                self.theme = self.dark_theme;
                            } else {
                                self.dark_theme = self.theme;
                                self.theme = LIGHT;
                            }
                            self.apply_theme(ctx);
                        }
                    });
                });
            });
    }

    fn inspector(&self, ctx: &Context) {
        egui::SidePanel::right("inspector")
            .resizable(false)
            .exact_width(270.0)
            .frame(
                Frame::new()
                    .fill(self.color(1))
                    .inner_margin(Margin::same(16)),
            )
            .show(ctx, |ui| {
                kicker(ui, "SESSION DETAILS");
                ui.heading("Network activity");
                ui.separator();
                self.frame().show(ui, |ui| {
                    ui.set_min_width(ui.available_width());
                    kicker(ui, "SYSTEM RESOURCES");
                    let r = &self.resources;
                    let latest = self.resource_samples.back();
                    let label = |index: usize| {
                        latest.and_then(|sample| sample[index]).map_or_else(
                            || "Unavailable".into(),
                            |value| format!("{:.1}%", value * 100.0),
                        )
                    };
                    metric(ui, "CPU", label(0));
                    sparkline(ui, &self.resource_samples, 0, BLUE);
                    metric(ui, "RAM", label(1));
                    sparkline(ui, &self.resource_samples, 1, GREEN);
                    if r.total_memory > 0 {
                        ui.weak(format!(
                            "{} used of {}",
                            size(r.used_memory as f64),
                            size(r.total_memory as f64)
                        ));
                    }
                    metric(ui, "GPU", label(2));
                    sparkline(ui, &self.resource_samples, 2, PURPLE);
                    if let Some(rate) = r.disk_rate {
                        ui.separator();
                        metric(ui, "Disk I/O", format!("{}/s", size(rate)));
                    }
                });
                let points = self.points();
                let point = self
                    .picked
                    .and_then(|time| points.iter().find(|point| point.end == time).copied())
                    .or_else(|| points.last().copied());
                if let Some(point) = point {
                    self.frame().show(ui, |ui| {
                        ui.set_min_width(ui.available_width());
                        kicker(
                            ui,
                            if self.picked.is_some() {
                                "SELECTED SAMPLE"
                            } else {
                                "LATEST SAMPLE"
                            },
                        );
                        ui.label(clock(point.end, "%b %d · %H:%M:%S"));
                        let (rx, tx) = rates(point);
                        ui.colored_label(BLUE, format!("Receive  {}/s", size(rx)));
                        ui.colored_label(GREEN, format!("Send       {}/s", size(tx)));
                    });
                }
                self.frame().show(ui, |ui| {
                    ui.set_min_width(ui.available_width());
                    kicker(ui, "RECENT ALERTS");
                    if self.alerts.is_empty() {
                        ui.weak("No security alerts recorded.");
                    }
                    for alert in self.alerts.iter().take(3) {
                        ui.label(RichText::new(&alert.title).strong());
                        ui.weak(&alert.detail);
                    }
                });
            });
    }

    fn points(&self) -> Vec<&Point> {
        if self.range == 0 {
            self.samples.iter().map(|value| &value.point).collect()
        } else {
            self.history.iter().collect()
        }
    }

    fn traffic(&mut self, ui: &mut Ui) {
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new("Network traffic").size(25.0).strong());
            ui.separator();
            let previous = self.traffic_view;
            for (index, label) in ["Timeline", "Table", "IP map"].into_iter().enumerate() {
                ui.selectable_value(&mut self.traffic_view, index, label);
            }
            if previous != self.traffic_view {
                if self.traffic_view == 2 {
                    self.group = 4;
                } else if previous == 2 {
                    self.group = 0;
                }
                self.filter.clear();
                self.refresh_usage();
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui.button("Export CSV").clicked() {
                    self.command(Command::Export {
                        since: self.bounds().0,
                    });
                }
                let mut range = self.range;
                egui::ComboBox::from_id_salt("traffic-range")
                    .selected_text(RANGES[range].0)
                    .width(89.0)
                    .show_ui(ui, |ui| {
                        for (index, (label, _, _)) in RANGES.iter().enumerate() {
                            ui.selectable_value(&mut range, index, *label);
                        }
                    });
                if range != self.range {
                    self.range = range;
                    self.refresh_history();
                }
                if self.range != 0 && ui.button("Refresh").clicked() {
                    self.refresh_history();
                }
            });
        });
        if self.traffic_view == 0 {
            let light = self.theme == LIGHT;
            let surface = if light {
                Color32::from_rgb(234, 243, 249)
            } else {
                self.color(2)
            };
            let (rx, tx) = traffic_colors(light);
            let height = (ui.ctx().content_rect().height() * 0.43).clamp(200.0, 390.0);
            let selected = self
                .frame()
                .fill(surface)
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        legend(ui, rx, "Received");
                        legend(ui, tx, "Sent");
                        if self.pending {
                            ui.spinner();
                        }
                    });
                    graph(
                        ui,
                        "main",
                        &self.points(),
                        self.range,
                        self.picked,
                        GraphStyle {
                            height,
                            mini: false,
                            guides: self.timeline_grid,
                        },
                    )
                })
                .inner;
            if let Some(time) = selected {
                self.picked = Some(time);
                self.refresh_usage();
            }
        }
        if let Some(time) = self.picked {
            ui.horizontal(|ui| {
                ui.weak(clock(time, "%b %d · %H:%M:%S"));
                if ui.small_button("Clear selection").clicked() {
                    self.picked = None;
                    self.refresh_usage();
                }
            });
        }
        if self.traffic_view != 2 {
            self.traffic_totals(ui);
        }
        self.breakdown(ui);
    }

    fn traffic_totals(&self, ui: &mut Ui) {
        let points = self.points();
        let selected = self
            .picked
            .and_then(|time| points.iter().find(|point| point.end == time).copied());
        let mut volume = Volume::default();
        if let Some(point) = selected {
            volume = point.volume;
        } else {
            for point in &points {
                add_volume(&mut volume, point.volume);
            }
        }
        let rate = selected.or_else(|| points.last().copied()).map(rates);
        let (rx, tx) = traffic_colors(self.theme == LIGHT);
        self.frame().show(ui, |ui| {
            ui.columns(3, |columns| {
                for (i, (label, bytes, speed, color)) in [
                    ("Received", volume.rx, rate.map(|rates| rates.0), rx),
                    ("Sent", volume.tx, rate.map(|rates| rates.1), tx),
                    (
                        "Total",
                        volume.total(),
                        None,
                        ui_text_color(self.theme == LIGHT),
                    ),
                ]
                .into_iter()
                .enumerate()
                {
                    let ui = &mut columns[i];
                    ui.weak(label);
                    ui.label(
                        RichText::new(size(bytes as f64))
                            .size(21.0)
                            .strong()
                            .color(color),
                    );
                    if let Some(speed) = speed {
                        ui.weak(format!("{}/s", size(speed)));
                    }
                }
            });
        });
    }

    fn breakdown(&mut self, ui: &mut Ui) {
        let previous_group = self.group;
        ui.horizontal_wrapped(|ui| {
            if self.traffic_view != 2 {
                ui.heading("Usage breakdown");
            }
            if self.traffic_view != 2 {
                for (index, (_, label)) in Dimension::ALL.iter().enumerate() {
                    ui.selectable_value(&mut self.group, index, *label);
                }
            }
        });
        if !self
            .source
            .as_ref()
            .is_some_and(|source| source.starts_with("packet:"))
        {
            if self.traffic_view == 2 {
                self.geo_map(ui, &HashMap::new());
                self.traffic_totals(ui);
            }
            ui.weak(
                "Choose a packet capture adapter in Settings for app, host and connection details.",
            );
            return;
        }
        let mut rows = HashMap::<(String, Option<PathBuf>), Volume>::new();
        if self.group != previous_group {
            self.filter.clear();
            self.refresh_usage();
        }
        let mut countries = HashMap::<String, Volume>::new();
        if self.range == 0 {
            for sample in self
                .samples
                .iter()
                .filter(|sample| self.picked.is_none_or(|end| sample.point.end == end))
            {
                if sample.other.total() > 0 {
                    add_volume(
                        rows.entry(("Other flows".into(), None)).or_default(),
                        sample.other,
                    );
                }
                for row in &sample.rows {
                    let app = row.app.as_ref();
                    let path = if self.group == 0 {
                        app.and_then(|a| a.path.clone())
                    } else {
                        None
                    };
                    let label = match self.group {
                        0 => app.map_or("Unknown app", |app| app.name.as_str()).into(),
                        1 => row.flow.remote.ip().to_string(),
                        2 => row.flow.kind().into(),
                        4 => {
                            let code = crate::geo::lookup(row.flow.remote.ip());
                            if let Some(code) = code {
                                add_volume(countries.entry(code.into()).or_default(), row.volume);
                            }
                            code.and_then(crate::geo::country)
                                .map(|country| country.name.as_str())
                                .or(code)
                                .unwrap_or("Unlocated / local")
                                .into()
                        }
                        _ => format!(
                            "{} ↔ {} · {}",
                            row.flow.local,
                            row.flow.remote,
                            row.flow.kind()
                        ),
                    };
                    add_volume(rows.entry((label, path)).or_default(), row.volume);
                }
            }
        } else {
            for ((label, path), volume) in &self.usage_rows {
                let label = if self.group == 4 {
                    if !label.is_empty() {
                        countries.insert(label.clone(), *volume);
                    }
                    crate::geo::country(label)
                        .map(|country| country.name.clone())
                        .unwrap_or_else(|| {
                            if label.is_empty() {
                                "Unlocated / local".into()
                            } else {
                                label.clone()
                            }
                        })
                } else {
                    label.clone()
                };
                rows.insert((label, path.clone()), *volume);
            }
        }
        if self.traffic_view == 2 {
            self.geo_map(ui, &countries);
            self.traffic_totals(ui);
        }
        let mut rows: Vec<_> = rows.into_iter().collect();
        rows.sort_unstable_by(|a, b| b.1.total().cmp(&a.1.total()).then(a.0.cmp(&b.0)));
        if rows.is_empty() {
            ui.weak("No matching packets in the selected window.");
            return;
        }
        ui.add(egui::TextEdit::singleline(&mut self.filter).hint_text("Filter usage"));
        let filter = self.filter.to_lowercase();
        let mut path_selected = None;
        let mut map_address = None;
        self.frame().show(ui, |ui| {
            let widths = [0.60, 0.20, 0.20];
            table_row(ui, &["Name", "Received", "Sent"], &widths, true, false);
            let limit = if self.traffic_view == 0 { 8 } else { 150 };
            for (index, ((label, path), volume)) in rows
                .iter()
                .filter(|((label, _), _)| label.to_lowercase().contains(&filter))
                .take(limit)
                .enumerate()
            {
                let rx = size(volume.rx as f64);
                let tx = size(volume.tx as f64);
                let response = table_row(ui, &[label, &rx, &tx], &widths, false, index % 2 == 0);
                if let Some(path) = path {
                    if response.clicked() {
                        path_selected = Some(path.clone());
                    }
                    response.on_hover_text(path.display().to_string());
                } else {
                    if self.group == 1
                        && let Ok(ip) = label.parse::<std::net::IpAddr>()
                    {
                        response.context_menu(|ui| {
                            if ui.button("Look up on IP map").clicked() {
                                map_address = Some(ip);
                                ui.close();
                            }
                        });
                    }
                    response.on_hover_text(label);
                }
            }
        });
        if self.traffic_view == 0
            && rows.len() > 8
            && ui.button("Open full traffic table").clicked()
        {
            self.traffic_view = 1;
        }
        if let Some(address) = map_address {
            self.traffic_view = 2;
            self.group = 4;
            self.geo_filter = address.to_string();
            self.geo_lookup = Some(address);
            self.filter.clear();
            self.refresh_usage();
        }
        self.open_app_rule(path_selected);
    }

    fn live_peers(&self) -> (MapVolumes, MapPeers) {
        let cutoff = engine::now_ms().saturating_sub((self.map_seconds * 1000) as i64);
        let mut countries = MapVolumes::new();
        let mut ips = HashMap::<std::net::IpAddr, (&crate::engine::Row, Volume, i64)>::new();
        for sample in self
            .samples
            .iter()
            .rev()
            .take_while(|sample| sample.point.end >= cutoff)
        {
            for row in &sample.rows {
                let entry = ips.entry(row.flow.remote.ip()).or_insert((
                    row,
                    Volume::default(),
                    sample.point.end,
                ));
                add_volume(&mut entry.1, row.volume);
            }
        }
        let mut ips: Vec<_> = ips.into_iter().collect();
        ips.sort_unstable_by_key(|(ip, (_, volume, _))| (std::cmp::Reverse(volume.total()), *ip));
        let mut peers = MapPeers::new();
        for (ip, (row, volume, last_seen)) in ips {
            let Some(code) =
                crate::geo::lookup(ip).filter(|code| crate::geo::country(code).is_some())
            else {
                continue;
            };
            add_volume(countries.entry(code.into()).or_default(), volume);
            let application = row
                .app
                .as_ref()
                .map_or("Unknown app", |app| app.name.as_str());
            peers.entry(code.into()).or_default().push(format!(
                "{} · {} · {} · ↓ {} ↑ {} · {}",
                row.flow.remote,
                row.flow.kind(),
                application,
                size(volume.rx as f64),
                size(volume.tx as f64),
                clock(last_seen, "%H:%M:%S")
            ));
        }
        (countries, peers)
    }
    fn geo_map(&mut self, ui: &mut Ui, countries: &HashMap<String, Volume>) {
        let (live_countries, peers) = if self.live_map {
            self.live_peers()
        } else {
            (HashMap::new(), HashMap::new())
        };
        let pin = self
            .geo_lookup
            .and_then(crate::geo::lookup)
            .and_then(crate::geo::country);
        let ocean = if self.theme == LIGHT {
            Color32::from_rgb(233, 244, 251)
        } else {
            Color32::from_rgb(16, 33, 50)
        };
        self.frame().fill(ocean).show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("IP geolocation").strong());
                ui.toggle_value(&mut self.live_map, "Live connections");
                let edit = ui.add(
                    egui::TextEdit::singleline(&mut self.geo_filter)
                        .hint_text("Look up an IPv4 or IPv6 address")
                        .desired_width(218.0),
                );
                if ui.button("Look up").clicked()
                    || (edit.lost_focus() && ui.input(|input| input.key_pressed(egui::Key::Enter)))
                {
                    match self.geo_filter.trim().parse() {
                        Ok(address) => self.geo_lookup = Some(address),
                        Err(_) => {
                            self.geo_lookup = None;
                            self.notice = "Enter a valid IPv4 or IPv6 address.".into();
                        }
                    }
                }
                if ui.button("Reset map").clicked() {
                    self.map_revision = self.map_revision.wrapping_add(1);
                }
                if (!self.filter.is_empty() || self.geo_lookup.is_some())
                    && ui.button("Clear selection").clicked()
                {
                    self.filter.clear();
                    self.geo_lookup = None;
                    self.geo_filter.clear();
                }
            });
            if let Some(message) = crate::geo::status() {
                ui.weak(message);
            } else if let Some(ip) = self.geo_lookup {
                let pin = crate::geo::lookup(ip).and_then(crate::geo::country);
                ui.label(format!(
                    "{ip} · {}",
                    pin.map_or("No country match", |place| place.name.as_str())
                ));
            } else if !self.filter.is_empty() {
                ui.label(format!("Selected country · {}", self.filter));
            }
            if let Some(country) = crate::geo_view::world(
                ui,
                if self.live_map {
                    &live_countries
                } else {
                    countries
                },
                &peers,
                &self.filter,
                pin,
                self.map_revision,
            ) {
                self.filter = country;
                self.geo_lookup = None;
            }
            ui.horizontal_wrapped(|ui| {
                ui.weak(if self.live_map {
                    "Recent IPs grouped by estimated country · Hover for details"
                } else {
                    "Country estimates for the selected time range"
                });
                ui.hyperlink_to("DB-IP · CC BY 4.0", "https://db-ip.com/db/lite.php");
                ui.hyperlink_to("Natural Earth", "https://www.naturalearthdata.com/");
            });
            if self.live_map
                && let Some((_, rows)) = peers.iter().find(|(code, _)| {
                    crate::geo::country(code).is_some_and(|place| place.name == self.filter)
                })
            {
                ui.separator();
                ui.label(
                    RichText::new(format!("{} · {} recent IPs", self.filter, rows.len())).strong(),
                );
                for row in rows.iter().take(8) {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(row);
                    });
                }
                if rows.len() > 8 {
                    ui.weak(format!(
                        "{} additional IPs in the current window",
                        rows.len() - 8
                    ));
                }
            }
        });
    }

    fn open_app_rule(&mut self, path: Option<PathBuf>) {
        if let Some(path) = path {
            self.path = path.display().to_string();
            self.firewall_view = 0;
            self.page(4);
        }
    }

    fn usage(&mut self, ui: &mut Ui) {
        ui.heading("Hardware resources");
        self.frame().show(ui, |ui| {
            ui.columns(3, |columns| {
                for (index, (label, color)) in [
                    ("CPU", accent(self.theme == LIGHT)),
                    ("RAM", traffic_colors(self.theme == LIGHT).0),
                    ("GPU", traffic_colors(self.theme == LIGHT).1),
                ]
                .into_iter()
                .enumerate()
                {
                    let ui = &mut columns[index];
                    let value = self
                        .resource_samples
                        .back()
                        .and_then(|sample| sample[index])
                        .map_or_else(
                            || "Unavailable".into(),
                            |value| format!("{:.1}%", value * 100.0),
                        );
                    metric(ui, label, value);
                    sparkline(ui, &self.resource_samples, index, color);
                }
            });
        });
        ui.heading("Processes");
        ui.weak("CPU is relative to one logical core. Disk I/O covers the latest refresh.");
        let mut processes: Vec<_> = self.resources.processes.values().collect();
        processes.sort_unstable_by(|a, b| b.cpu.total_cmp(&a.cpu).then(b.memory.cmp(&a.memory)));
        ui.add(egui::TextEdit::singleline(&mut self.filter).hint_text("Filter processes"));
        let filter = self.filter.to_lowercase();
        let mut path_selected = None;
        ScrollArea::horizontal().show(ui, |ui| {
            Grid::new("processes")
                .striped(true)
                .min_col_width(73.0)
                .show(ui, |ui| {
                    columns(ui, &["PROCESS", "PID", "CPU", "MEMORY", "DISK I/O", "GPU"]);
                    for p in processes
                        .into_iter()
                        .filter(|p| p.name.to_lowercase().contains(&filter))
                        .take(150)
                    {
                        if let Some(path) = &p.path {
                            if ui
                                .link(&p.name)
                                .on_hover_text(path.display().to_string())
                                .clicked()
                            {
                                path_selected = Some(path.clone());
                            }
                        } else {
                            ui.label(&p.name);
                        }
                        ui.monospace(p.id.to_string());
                        ui.monospace(format!("{:.1}%", p.cpu));
                        ui.monospace(size(p.memory as f64));
                        ui.monospace(size(p.disk as f64));
                        ui.monospace(
                            p.gpu
                                .map_or_else(|| "—".into(), |value| format!("{value:.1}%")),
                        );
                        ui.end_row();
                    }
                });
        });
        self.open_app_rule(path_selected);
    }

    fn things(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            ui.heading("Things");
            if ui.button("Refresh neighbors").clicked() {
                self.command(Command::RefreshDevices);
            }
        });
        ui.weak("Devices learned by the operating system through ARP or IPv6 neighbor discovery.");
        if cfg!(windows) {
            ui.horizontal_wrapped(|ui| {
                let label = self
                    .scan_source
                    .map_or_else(|| "Select local IPv4 address".into(), |ip| ip.to_string());
                egui::ComboBox::from_id_salt("scan-address")
                    .selected_text(label)
                    .show_ui(ui, |ui| {
                        for ip in crate::devices::scan_sources() {
                            ui.selectable_value(&mut self.scan_source, Some(ip), ip.to_string());
                        }
                    });
                if ui
                    .add_enabled(
                        self.scan_task.is_none() && self.scan_source.is_some(),
                        egui::Button::new("Scan local subnet"),
                    )
                    .clicked()
                    && let Some(source) = self.scan_source
                {
                    let (sender, receiver) = mpsc::sync_channel(1);
                    match std::thread::Builder::new()
                        .name("deadwall-lan-discovery".into())
                        .spawn(move || {
                            let _ = sender.send(crate::devices::scan(source));
                        }) {
                        Ok(_) => self.scan_task = Some(receiver),
                        Err(error) => self.notice = error.to_string(),
                    }
                }
                if self.scan_task.is_some() {
                    ui.spinner();
                }
            });
        }
        match &self.devices {
            Err(error) => {
                ui.colored_label(AMBER, error);
            }
            Ok(devices) if devices.is_empty() && self.discovered.is_empty() => {
                ui.weak("No devices in the neighbor table.");
            }
            Ok(devices) => {
                let mut devices: Vec<_> = devices
                    .iter()
                    .chain(self.discovered.iter().filter(|found| {
                        !devices
                            .iter()
                            .any(|known| known.address == found.address && known.mac == found.mac)
                    }))
                    .collect();
                devices.sort_unstable_by_key(|device| (&device.interface, device.address));
                Grid::new("neighbors")
                    .striped(true)
                    .min_col_width(100.0)
                    .show(ui, |ui| {
                        columns(ui, &["IP ADDRESS", "MAC ADDRESS", "INTERFACE"]);
                        for device in devices {
                            ui.monospace(device.address.to_string());
                            ui.monospace(&device.mac);
                            ui.monospace(&device.interface);
                            ui.end_row();
                        }
                    });
            }
        }
    }

    fn alerts(&self, ui: &mut Ui) {
        ui.heading("Security alerts");
        if self.alerts.is_empty() {
            ui.weak("No security alerts recorded.");
        }
        for alert in &self.alerts {
            self.frame().show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.horizontal(|ui| {
                    ui.label(RichText::new(&alert.title).strong());
                    ui.weak(clock(alert.time, "%b %d · %H:%M:%S"));
                });
                ui.label(&alert.detail);
            });
        }
    }

    fn firewall(&mut self, ui: &mut Ui) {
        ui.heading("Firewall");
        if !cfg!(windows) {
            ui.weak("Firewall controls are available on Windows.");
            return;
        }
        ui.horizontal_wrapped(|ui| {
            for (index, label) in ["Running processes", "Rule sets", "Connection modes"]
                .into_iter()
                .enumerate()
            {
                if ui
                    .selectable_value(&mut self.firewall_view, index, label)
                    .changed()
                {
                    self.filter.clear();
                }
            }
            if self.firewall_task.is_some() {
                ui.spinner();
            }
        });
        ui.weak("Windows Defender Firewall · Applying or removing rules requires elevation.");
        ui.horizontal(|ui| {
            for (bit, label) in [(1, "Domain"), (2, "Private"), (4, "Public")] {
                let mut selected = self.profiles & bit != 0;
                if ui.checkbox(&mut selected, label).changed() {
                    self.profiles ^= bit;
                    self.confirm = false;
                }
            }
        });
        if self.firewall_view == 0 {
            egui::CollapsingHeader::new("Rule by executable path")
                .default_open(!self.path.trim().is_empty())
                .show(ui, |ui| self.manual_rule(ui));
            self.firewall_processes(ui);
            return;
        }
        if self.firewall_view == 1 {
            self.named_profiles(ui);
            return;
        }

        self.frame().show(ui,|ui|{
            ui.set_min_width(ui.available_width());
            kicker(ui,"LOCKDOWN");
            ui.label("Block all inbound and outbound traffic on the selected profiles. This can disconnect remote access.");
            ui.checkbox(&mut self.confirm,"Confirm network lockdown");
            ui.horizontal(|ui|{
                let ready=self.firewall_task.is_none() && self.profiles!=0;
                if ui.add_enabled(ready && self.confirm,egui::Button::new("Enable lockdown")).clicked(){
                    self.confirm=false;
                    self.firewall_change(None,true);
                }
                if ui.add_enabled(ready,egui::Button::new("Remove lockdown")).clicked(){self.firewall_change(None,false);}
            });
        });
        ui.weak("Use the same profile selection to remove an existing rule.");
        self.ask_to_connect(ui);
        if self.firewall_task.is_some() {
            ui.spinner();
        }
    }

    fn manual_rule(&mut self, ui: &mut Ui) {
        self.frame().show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            kicker(ui, "APPLICATION RULES");
            ui.add(
                egui::TextEdit::singleline(&mut self.path)
                    .hint_text(r"C:\Path\Application.exe")
                    .desired_width(f32::INFINITY),
            );
            ui.horizontal(|ui| {
                let ready = self.firewall_task.is_none()
                    && !self.path.trim().is_empty()
                    && self.profiles != 0;
                for (block, label) in [(true, "Block app"), (false, "Remove app block")] {
                    if ui.add_enabled(ready, egui::Button::new(label)).clicked() {
                        self.firewall_change(Some(PathBuf::from(self.path.trim())), block);
                    }
                }
            });
        });
    }

    fn firewall_processes(&mut self, ui: &mut Ui) {
        ui.horizontal_wrapped(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.filter)
                    .hint_text("Search by process, PID, or path")
                    .desired_width(265.0),
            );
            ui.weak("Right-click a row for firewall actions.");
        });
        let query = self.filter.trim().to_lowercase();
        let mut rows: Vec<_> =
            self.resources
                .processes
                .values()
                .filter(|process| {
                    query.is_empty()
                        || process.name.to_lowercase().contains(&query)
                        || process.id.to_string().contains(&query)
                        || process.path.as_ref().is_some_and(|path| {
                            path.to_string_lossy().to_lowercase().contains(&query)
                        })
                })
                .collect();
        rows.sort_unstable_by(|a, b| {
            a.name
                .to_ascii_lowercase()
                .cmp(&b.name.to_ascii_lowercase())
                .then(a.id.cmp(&b.id))
        });
        let mut action = None;
        let ready = self.firewall_task.is_none() && self.profiles != 0;
        self.frame().show(ui, |ui| {
            let widths = if ui.available_width() >= 700.0 {
                [0.27, 0.11, 0.62]
            } else {
                [0.34, 0.14, 0.52]
            };
            table_row(
                ui,
                &["Application", "PID", "Executable path"],
                &widths,
                true,
                false,
            );
            if rows.is_empty() {
                ui.weak("No matching running processes.");
            }
            for (index, process) in rows.iter().enumerate() {
                let path = process.path.as_ref();
                let path_text = path
                    .map(|path| path.to_string_lossy())
                    .unwrap_or_else(|| "Unavailable".into());
                let pid = process.id.to_string();
                let row = ui
                    .push_id(process.id, |ui| {
                        table_row(
                            ui,
                            &[&process.name, &pid, &path_text],
                            &widths,
                            false,
                            index % 2 == 0,
                        )
                    })
                    .inner;
                row.context_menu(|ui| {
                    ui.label(RichText::new(&process.name).strong());
                    ui.weak(format!("PID {}", process.id));
                    ui.separator();
                    if let Some(path) = path {
                        for (blocked, label) in [
                            (true, "Block inbound and outbound"),
                            (false, "Remove application block"),
                        ] {
                            if ui.add_enabled(ready, egui::Button::new(label)).clicked() {
                                action = Some((path.clone(), blocked));
                                ui.close();
                            }
                        }
                        ui.separator();
                        if ui.button("Copy executable path").clicked() {
                            ui.ctx().copy_text(path.display().to_string());
                            ui.close();
                        }
                    } else {
                        ui.weak("Executable path unavailable");
                    }
                    if ui.button("Copy PID").clicked() {
                        ui.ctx().copy_text(pid.clone());
                        ui.close();
                    }
                });
                row.on_hover_text(path_text);
            }
        });
        if let Some((path, blocked)) = action {
            self.firewall_change(Some(path), blocked);
        }
    }

    fn ask_to_connect(&mut self, ui: &mut Ui) {
        let frame = self.frame();
        frame.show(ui,|ui| {
            ui.set_min_width(ui.available_width());
            kicker(ui,"ASK TO CONNECT");
            if self.ask.is_some() {
                ui.horizontal(|ui| {
                    ui.colored_label(GREEN,"Outbound approvals active");
                    if ui.button("Stop Ask to Connect").clicked(){ self.ask=None; }
                });
                if self.ask.is_none() {return;}
                let ask=self.ask.as_mut().expect("active session");
                let requests=ask.pending();
                if requests.is_empty(){ui.weak("No pending connection requests.");}
                let mut decision=None;
                for (index,request) in requests.iter().enumerate() {
                    ui.label(&request.path);
                    ui.horizontal(|ui| {
                        if ui.button("Allow for this session").clicked(){decision=Some((index,true));}
                        if ui.button("Keep blocked").clicked(){decision=Some((index,false));}
                    });
                }
                if let Some((index,allow))=decision {
                    self.notice=match ask.decide(index,allow) {
                        Ok(()) if allow=>"Connection allowed for this session. The app can retry.".into(),
                        Ok(())=>"Connection kept blocked.".into(),
                        Err(error)=>error,
                    };
                }
            } else {
                ui.label("Require approval for outbound connections on all profiles until this session ends. This can interrupt DNS, DHCP or remote access. Start from the local desktop.");
                ui.checkbox(&mut self.ask_confirm,"Confirm outbound approval mode");
                if ui.add_enabled(self.ask_confirm,egui::Button::new("Start Ask to Connect")).clicked(){
                    self.ask_confirm=false;
                    match crate::ask::Ask::new(){
                        Ok(ask)=>self.ask=Some(ask),
                        Err(error)=>self.notice=format!("Ask to Connect: {error}"),
                    }
                }
            }
        });
    }

    fn profile_store() -> Result<crate::profiles::Profiles, String> {
        crate::profiles::Profiles::open(
            &crate::history::History::path().with_file_name("firewall-profiles.sqlite3"),
        )
    }

    fn load_profiles(&mut self) {
        match Self::profile_store().and_then(|db| db.list()) {
            Ok(profiles) => self.saved_profiles = profiles,
            Err(error) => self.notice = format!("Firewall profiles: {error}"),
        }
    }

    fn named_profiles(&mut self, ui: &mut Ui) {
        self.frame().show(ui,|ui|{
            ui.set_min_width(ui.available_width());
            kicker(ui,"SAVED FIREWALL PROFILES");
            ui.weak("Save an app block list for the Windows categories selected above. Profile rules are applied and removed together.");
            ui.add(egui::TextEdit::singleline(&mut self.profile_name).hint_text("Profile name"));
            ui.add(egui::TextEdit::multiline(&mut self.profile_apps).desired_rows(3).hint_text("One full executable path per line"));
            ui.horizontal_wrapped(|ui|{
                if ui.button("Use application path").clicked() && !self.path.trim().is_empty(){
                    if !self.profile_apps.is_empty(){self.profile_apps.push('\n');}
                    self.profile_apps.push_str(self.path.trim());
                }
                let ready=self.firewall_task.is_none() && !self.profile_name.trim().is_empty() && !self.profile_apps.trim().is_empty();
                if ui.add_enabled(ready,egui::Button::new("Save profile")).clicked(){
                    match Self::profile_store().and_then(|db|db.save(&self.profile_name,self.profiles,&self.profile_apps)){
                        Ok(profile)=>{
                            self.notice=format!("Saved profile {}",profile.name);
                            self.profile_name.clear();
                            self.profile_apps.clear();
                            self.load_profiles();
                        }
                        Err(error)=>self.notice=error,
                    }
                }
            });
            let mut action=None;
            for profile in &self.saved_profiles {
                ui.separator();
                ui.label(RichText::new(&profile.name).strong());
                let categories=[(1,"Domain"),(2,"Private"),(4,"Public")].into_iter().filter_map(|(bit,name)|(profile.categories&bit!=0).then_some(name)).collect::<Vec<_>>().join(", ");
                ui.weak(format!("{} executable(s) · {categories}",profile.apps.len()));
                ui.collapsing("Executables",|ui|{for path in &profile.apps {ui.label(path.display().to_string());}});
                ui.horizontal_wrapped(|ui|{
                    for (index,label) in ["Apply","Remove rules","Remove rules and delete profile"].into_iter().enumerate(){
                        if ui.add_enabled(self.firewall_task.is_none(),egui::Button::new(label)).clicked(){
                            action=Some((profile.clone(),index));
                        }
                    }
                });
            }
            if let Some((profile,action))=action{
                self.start_firewall(move||{
                    let message=firewall::apply_profile(&profile,action==0)?;
                    if action==2 {
                        Self::profile_store()?.delete(&profile.id)?;
                        Ok(format!("Deleted profile {}",profile.name))
                    } else {
                        Ok(message)
                    }
                });
            }
        });
    }

    fn firewall_change(&mut self, path: Option<PathBuf>, blocked: bool) {
        let change = firewall::Change {
            path,
            profiles: self.profiles,
            blocked,
        };
        self.start_firewall(move || change.apply());
    }

    fn start_firewall(&mut self, job: impl FnOnce() -> Result<String, String> + Send + 'static) {
        let (tx, rx) = mpsc::sync_channel(1);
        match std::thread::Builder::new()
            .name("deadwall-firewall".into())
            .spawn(move || {
                let _ = tx.send(job());
            }) {
            Ok(_) => self.firewall_task = Some(rx),
            Err(error) => self.notice = error.to_string(),
        }
    }

    fn geographic_filtering(&mut self, ui: &mut Ui) {
        self.frame().show(ui,|ui|{
            ui.set_min_width(ui.available_width());
            ui.label(RichText::new("Geographic filtering").strong());
            if !cfg!(windows){ui.weak("Available on Windows.");return;}
            ui.weak("Block inbound and outbound connections by remote address. Applies to all apps while deadWall is running. Applying requires elevation.");
            ui.horizontal_wrapped(|ui|{
                for (code,label) in [("AF","Africa"),("AS","Asia"),("EU","Europe"),("NA","North America"),("OC","Oceania"),("SA","South America"),("AN","Antarctica")]{
                    let selected=self.geo_rules.continents.iter().any(|entry|entry==code);
                    if ui.selectable_label(selected,label).clicked(){
                        if selected{self.geo_rules.continents.retain(|entry|entry!=code);}
                        else{self.geo_rules.continents.push(code.into());}
                    }
                }
            });
            ui.label("Countries");
            ui.add(egui::TextEdit::singleline(&mut self.geo_rules.countries).hint_text("ISO country codes, separated by commas").desired_width(320.0));
            ui.label("IP ranges");
            ui.add(egui::TextEdit::multiline(&mut self.geo_rules.cidrs).hint_text("One IPv4 or IPv6 CIDR per line").desired_rows(3).desired_width(360.0));
            ui.horizontal_wrapped(|ui|{
                if ui.add_enabled(!self.geo_pending,egui::Button::new("Apply filters")).clicked(){
                    self.apply_geo(self.geo_rules.clone());
                }
                if ui.add_enabled(!self.geo_pending && self.geo_active!=0,egui::Button::new("Turn off")).clicked(){
                    self.apply_geo(crate::geo_filter::Spec::default());
                }
                if self.geo_pending {ui.spinner();}
                else if self.geo_active>0 {ui.label(format!("Active · {} ranges",self.geo_active));}
                else{ui.weak("Off");}
            });
        });
    }

    fn apply_geo(&mut self, spec: crate::geo_filter::Spec) {
        if self.geo_worker.is_none() {
            match crate::geo_filter::Worker::start() {
                Ok(worker) => self.geo_worker = Some(worker),
                Err(error) => {
                    self.notice = error.to_string();
                    return;
                }
            }
        }
        if let Some(worker) = &self.geo_worker {
            match worker.apply(spec) {
                Ok(()) => self.geo_pending = true,
                Err(error) => self.notice = error,
            }
        }
    }
    fn settings(&mut self, ui: &mut Ui) {
        ui.heading("Settings");
        kicker(ui, "NETWORK SOURCE");
        let mut selected = self.source.clone();
        let label = self
            .sources
            .iter()
            .find(|entry| selected.as_ref().is_some_and(|key| entry.key() == *key))
            .map_or_else(
                || "Select an adapter".into(),
                |entry| format!("{} · {}", entry.name(), entry.kind()),
            );
        egui::ComboBox::from_id_salt("sources")
            .selected_text(label)
            .width(ui.available_width().min(520.0))
            .show_ui(ui, |ui| {
                for source in &self.sources {
                    let key = source.key();
                    ui.selectable_value(
                        &mut selected,
                        Some(key.clone()),
                        format!("{} · {}", source.name(), source.kind()),
                    )
                    .on_hover_text(key);
                }
            });
        if selected != self.source
            && let Some(key) = selected
        {
            self.command(Command::Select(key));
        }
        ui.horizontal(|ui| {
            if ui.button("Refresh adapters").clicked() {
                self.command(Command::RefreshSources);
            }
            if ui
                .add_enabled(self.source.is_some(), egui::Button::new("Reopen source"))
                .clicked()
                && let Some(key) = self.source.clone()
            {
                self.command(Command::Select(key));
            }
        });
        if let Some(warning) = &self.capture_notice {
            ui.colored_label(AMBER, warning);
        }
        ui.separator();
        kicker(ui, "THEME");
        ui.horizontal(|ui| {
            let old = self.theme;
            for (index, (name, _)) in THEMES.iter().enumerate() {
                ui.selectable_value(&mut self.theme, index, *name);
            }
            if old != self.theme {
                if self.theme != LIGHT {
                    self.dark_theme = self.theme;
                }
                self.apply_theme(ui.ctx());
            }
        });
        ui.separator();
        kicker(ui, "DISPLAY");
        ui.checkbox(&mut self.inspector, "Show system inspector on wide windows");
        ui.checkbox(
            &mut self.timeline_grid,
            "Show horizontal timeline guide lines",
        );
        ui.horizontal(|ui| {
            ui.label("Live map activity window");
            egui::ComboBox::from_id_salt("map-seconds")
                .selected_text(format!("{} seconds", self.map_seconds))
                .show_ui(ui, |ui| {
                    for seconds in [15, 30, 60, 120] {
                        ui.selectable_value(
                            &mut self.map_seconds,
                            seconds,
                            format!("{seconds} seconds"),
                        );
                    }
                });
        });
        ui.separator();
        self.geographic_filtering(ui);
        ui.separator();
        kicker(ui, "LOCAL HISTORY");
        ui.label(&self.storage);
    }
}

impl eframe::App for Desk {
    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        storage.set_string("theme", self.theme.to_string());
        storage.set_string("dark_theme", self.dark_theme.to_string());
        storage.set_string("map_seconds", self.map_seconds.to_string());
        storage.set_string("timeline_grid", usize::from(self.timeline_grid).to_string());
        storage.set_string("inspector", usize::from(self.inspector).to_string());
        if let Ok(rules) = serde_json::to_string(&self.geo_rules) {
            storage.set_string("geo_rules", rules);
        }
    }

    fn update(&mut self, ctx: &Context, _frame: &mut eframe::Frame) {
        #[cfg(windows)]
        if !self.window_checked {
            self.window_checked = true;
            crate::window::fit_restored_window(_frame);
        }
        self.poll();
        if let Some(worker) = &self.geo_worker {
            match worker.rx.try_recv() {
                Ok(Ok(count)) => {
                    self.geo_pending = false;
                    self.geo_active = count;
                    self.notice = if count == 0 {
                        "Geographic filtering is off.".into()
                    } else {
                        format!("Geographic filtering active · {count} address ranges")
                    };
                }
                Ok(Err(error)) => {
                    self.geo_pending = false;
                    self.notice = error;
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.geo_pending = false;
                    self.geo_active = 0;
                    self.geo_worker = None;
                    self.notice = "Geographic filtering worker stopped.".into();
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
        self.ask_count = self.ask.as_mut().map_or(0, |ask| ask.pending().len());
        ctx.request_repaint_after(Duration::from_millis(240));
        self.header(ctx);
        if self.inspector && ctx.content_rect().width() >= 960.0 {
            self.inspector(ctx);
        }
        egui::CentralPanel::default()
            .frame(
                Frame::new()
                    .fill(self.color(0))
                    .inner_margin(Margin::symmetric(22, 17)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    let source = self.sources.iter().find(|source| {
                        self.source
                            .as_ref()
                            .is_some_and(|active| source.key() == *active)
                    });
                    status_dot(
                        ui,
                        if self.state.starts_with("Capturing") || self.state.starts_with("Reading")
                        {
                            GREEN
                        } else {
                            AMBER
                        },
                    );
                    let name = source.map_or("Local monitor", Source::name);
                    ui.add_sized(
                        [ui.available_width().min(290.0), 28.0],
                        egui::Label::new(RichText::new(name).weak()).truncate(),
                    )
                    .on_hover_text(&self.state);
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        ui.toggle_value(&mut self.inspector, "Inspector");
                        if ui
                            .button(if self.paused { "Resume" } else { "Pause" })
                            .clicked()
                        {
                            self.paused = !self.paused;
                            self.command(Command::Pause(self.paused));
                        }
                        ui.toggle_value(&mut self.mini, "Mini graph");
                    });
                });
                ui.separator();
                if !self.notice.is_empty() {
                    ui.horizontal_wrapped(|ui| {
                        if ui.small_button("Dismiss").clicked() {
                            self.notice.clear();
                        }
                        ui.label(&self.notice);
                    });
                }
                ScrollArea::vertical()
                    .id_salt(self.page)
                    .auto_shrink([false, false])
                    .show(ui, |ui| match self.page {
                        0 => self.traffic(ui),
                        1 => self.usage(ui),
                        2 => self.things(ui),
                        3 => self.alerts(ui),
                        4 => self.firewall(ui),
                        _ => self.settings(ui),
                    });
            });
        if self.mini {
            let points: Vec<_> = self.samples.iter().map(|sample| &sample.point).collect();
            let mut close = false;
            ctx.show_viewport_immediate(
                egui::ViewportId::from_hash_of("deadwall-mini"),
                egui::ViewportBuilder::default()
                    .with_title("deadWall · Live")
                    .with_icon(self.icon.clone())
                    .with_inner_size([354.0, 150.0])
                    .with_always_on_top(),
                |ctx, class| {
                    close = ctx.input(|input| input.viewport().close_requested());
                    let paint = |ui: &mut Ui| {
                        graph(
                            ui,
                            "mini",
                            &points,
                            0,
                            None,
                            GraphStyle {
                                height: 110.0,
                                mini: true,
                                guides: false,
                            },
                        );
                    };
                    if class == egui::ViewportClass::Embedded {
                        let mut open = !close;
                        egui::Window::new("Live bandwidth")
                            .open(&mut open)
                            .show(ctx, paint);
                        close = !open;
                    } else {
                        egui::CentralPanel::default().show(ctx, paint);
                    }
                },
            );
            if close {
                self.mini = false;
            }
        }
    }
}

fn add_volume(total: &mut Volume, delta: Volume) {
    total.rx += delta.rx;
    total.tx += delta.tx;
}

fn kicker(ui: &mut Ui, text: &str) {
    ui.label(RichText::new(text).monospace().size(11.0).weak());
}

fn columns(ui: &mut Ui, titles: &[&str]) {
    for title in titles {
        kicker(ui, title);
    }
    ui.end_row();
}

fn clock(ms: i64, format: &str) -> String {
    Local
        .timestamp_millis_opt(ms)
        .single()
        .map_or_else(|| ms.to_string(), |time| time.format(format).to_string())
}

fn size(bytes: f64) -> String {
    if bytes < 1024.0 {
        format!("{bytes:.0} B")
    } else if bytes < 1024.0_f64.powi(2) {
        format!("{:.1} KiB", bytes / 1024.0)
    } else if bytes < 1024.0_f64.powi(3) {
        format!("{:.1} MiB", bytes / 1024.0_f64.powi(2))
    } else {
        format!("{:.2} GiB", bytes / 1024.0_f64.powi(3))
    }
}

fn rates(point: &Point) -> (f64, f64) {
    let seconds = point.duration_ms.max(1) as f64 / 1000.0;
    (
        point.volume.rx as f64 / seconds,
        point.volume.tx as f64 / seconds,
    )
}

struct GraphStyle {
    height: f32,
    mini: bool,
    guides: bool,
}

fn graph(
    ui: &mut Ui,
    id: &str,
    points: &[&Point],
    range: usize,
    selected: Option<i64>,
    style: GraphStyle,
) -> Option<i64> {
    let GraphStyle {
        height,
        mini,
        guides,
    } = style;
    let (receive, send) = traffic_colors(!ui.visuals().dark_mode);
    let now = points.last().map_or_else(engine::now_ms, |point| point.end);
    let live = range == 0;
    let x = |time: i64| time as f64 / 1000.0;
    let mut down = Vec::new();
    let mut up = Vec::new();
    let mut max = 1024.0_f64;
    for point in points {
        let (rx, tx) = rates(point);
        max = max.max(rx).max(tx);
        down.push([x(point.end), rx]);
        up.push([x(point.end), tx]);
    }
    let axis = if range <= 1 {
        "%H:%M:%S"
    } else {
        "%b %d %H:%M"
    };
    let plot = Plot::new((id, range))
        .height(height)
        .show_axes(!mini)
        .show_grid([false, guides])
        .grid_spacing(egui::Rangef::new(34.0, 400.0))
        .show_background(false)
        .allow_drag(!live && !mini)
        .allow_zoom(!live && !mini)
        .allow_scroll(!live && !mini)
        .include_y(0.0)
        .x_axis_formatter(move |mark, _| clock((mark.value * 1000.0) as i64, axis))
        .y_axis_formatter(|mark, _| format!("{}/s", size(mark.value.max(0.0))))
        .label_formatter(|name, point| {
            format!(
                "{name} {}/s\n{}",
                size(point.y),
                clock((point.x * 1000.0) as i64, "%b %d %H:%M:%S")
            )
        })
        .show(ui, |plot| {
            if live {
                plot.set_plot_bounds(PlotBounds::from_min_max(
                    [x(now - engine::LIVE_SECONDS * 1000), 0.0],
                    [x(now), max * 1.13],
                ));
            }
            plot.line(
                Line::new("Receive", down)
                    .color(receive)
                    .width(2.0_f32)
                    .fill(0.0_f32)
                    .fill_alpha(0.34_f32),
            );
            plot.line(
                Line::new("Send", up)
                    .color(send)
                    .width(1.8_f32)
                    .fill(0.0_f32)
                    .fill_alpha(0.27_f32),
            );
            if let Some(time) = selected {
                plot.vline(VLine::new("Selection", x(time)).color(AMBER));
            }
            plot.pointer_coordinate()
        });
    if mini || !plot.response.clicked() {
        return None;
    }
    let clicked = (plot.inner?.x * 1000.0) as i64;
    points
        .iter()
        .min_by_key(|point| point.end.abs_diff(clicked))
        .map(|point| point.end)
}

fn metric(ui: &mut Ui, title: &str, value: String) {
    ui.horizontal(|ui| {
        ui.label(title);
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            ui.label(RichText::new(value).monospace().strong());
        });
    });
}

fn sparkline(ui: &mut Ui, history: &VecDeque<[Option<f32>; 3]>, index: usize, color: Color32) {
    let (rect, response) =
        ui.allocate_exact_size(Vec2::new(ui.available_width(), 36.0), egui::Sense::hover());
    response.on_hover_text("Last two minutes · fixed 0–100% scale");
    let painter = ui.painter();
    painter.rect_filled(rect, 3.0, ui.visuals().extreme_bg_color);
    let chart = rect.shrink2(Vec2::new(4.0, 3.0));
    for fraction in [0.0, 0.5, 1.0] {
        let y = egui::lerp(chart.y_range(), fraction);
        painter.hline(
            chart.x_range(),
            y,
            egui::Stroke::new(1.0_f32, color.gamma_multiply(0.18)),
        );
    }
    let start = 60 - history.len();
    let points: Vec<_> = history
        .iter()
        .enumerate()
        .map(|(offset, values)| {
            let value = values[index]?;
            let x = egui::lerp(chart.x_range(), (start + offset) as f32 / 59.0);
            let y = egui::lerp(chart.y_range(), 1.0 - value.clamp(0.0, 1.0));
            Some(egui::pos2(x, y))
        })
        .collect();
    if points.len() > 1 {
        let mut fill = egui::Mesh::default();
        for pair in points.windows(2) {
            let [Some(first), Some(second)] = pair else {
                continue;
            };
            let vertex = fill.vertices.len() as u32;
            for point in [first, second] {
                fill.colored_vertex(*point, color.gamma_multiply(0.22));
                fill.colored_vertex(egui::pos2(point.x, chart.bottom()), Color32::TRANSPARENT);
            }
            fill.add_triangle(vertex, vertex + 1, vertex + 2);
            fill.add_triangle(vertex + 1, vertex + 3, vertex + 2);
        }
        painter.add(egui::Shape::mesh(fill));
        for segment in points.split(|point| point.is_none()) {
            if segment.len() > 1 {
                painter.add(egui::Shape::line(
                    segment.iter().flatten().copied().collect(),
                    egui::Stroke::new(1.5_f32, color),
                ));
            }
        }
    }
    if let Some(Some(&end)) = points.last().map(Option::as_ref) {
        painter.circle_filled(end, 2.1, color);
    }
}

fn status_dot(ui: &mut Ui, color: Color32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(8.0), egui::Sense::hover());
    ui.painter().circle_filled(rect.center(), 3.0, color);
}

fn legend(ui: &mut Ui, color: Color32, label: &str) {
    ui.horizontal(|ui| {
        let (rect, _) = ui.allocate_exact_size(Vec2::new(13.0, 8.0), egui::Sense::hover());
        ui.painter().hline(
            rect.x_range(),
            rect.center().y,
            egui::Stroke::new(2.0_f32, color),
        );
        ui.label(RichText::new(label).color(color).size(12.0));
    });
}

fn nav_button(
    ui: &mut Ui,
    page: usize,
    label: &str,
    selected: bool,
    count: Option<usize>,
    width: f32,
) -> egui::Response {
    let (rect, response) = ui.allocate_exact_size(Vec2::new(width, 35.0), egui::Sense::click());
    response.widget_info(|| {
        egui::WidgetInfo::selected(egui::WidgetType::SelectableLabel, true, selected, label)
    });
    let painter = ui.painter();
    let ink = if selected {
        accent(!ui.visuals().dark_mode)
    } else {
        ui.visuals().weak_text_color()
    };
    if selected || response.hovered() {
        let fill = if selected {
            ui.visuals().selection.bg_fill
        } else {
            ui.visuals().faint_bg_color
        };
        painter.rect_filled(rect, 7.0, fill);
    }
    if selected {
        let bar = egui::Rect::from_min_size(
            rect.left_center() + Vec2::new(0.0, -8.0),
            Vec2::new(2.5, 16.0),
        );
        painter.rect_filled(bar, 1.0, BLUE);
    }
    if response.has_focus() {
        painter.rect_stroke(
            rect,
            7.0,
            egui::Stroke::new(1.0_f32, BLUE),
            egui::StrokeKind::Inside,
        );
    }
    let origin = egui::pos2(rect.min.x + 7.0, rect.center().y - 8.0);
    let path: &[(f32, f32)] = match page {
        0 => &[
            (0.0, 9.0),
            (3.0, 9.0),
            (6.0, 3.0),
            (9.0, 13.0),
            (12.0, 7.0),
            (16.0, 7.0),
        ],
        1 => &[
            (2.0, 4.0),
            (2.0, 14.0),
            (15.0, 14.0),
            (15.0, 3.0),
            (12.0, 3.0),
            (12.0, 11.0),
            (9.0, 11.0),
            (9.0, 6.0),
            (6.0, 6.0),
            (6.0, 11.0),
        ],
        2 => &[
            (6.0, 14.0),
            (10.0, 14.0),
            (8.0, 14.0),
            (8.0, 11.0),
            (2.0, 11.0),
            (2.0, 3.0),
            (14.0, 3.0),
            (14.0, 11.0),
            (8.0, 11.0),
        ],
        3 => &[
            (7.0, 15.0),
            (9.0, 15.0),
            (12.0, 12.0),
            (14.0, 12.0),
            (12.0, 9.0),
            (12.0, 5.0),
            (10.0, 2.0),
            (6.0, 2.0),
            (4.0, 5.0),
            (4.0, 9.0),
            (2.0, 12.0),
            (14.0, 12.0),
        ],
        4 => &[
            (8.0, 1.0),
            (14.0, 4.0),
            (13.0, 10.0),
            (8.0, 15.0),
            (3.0, 10.0),
            (2.0, 4.0),
            (8.0, 1.0),
        ],
        _ => &[
            (2.0, 4.0),
            (14.0, 4.0),
            (10.0, 4.0),
            (10.0, 2.0),
            (10.0, 6.0),
            (10.0, 4.0),
            (2.0, 4.0),
            (2.0, 12.0),
            (14.0, 12.0),
            (6.0, 12.0),
            (6.0, 10.0),
            (6.0, 14.0),
        ],
    };
    let stroke = egui::Stroke::new(1.3_f32, ink);
    for pair in path.windows(2) {
        let [(x1, y1), (x2, y2)] = pair else {
            continue;
        };
        painter.line_segment(
            [origin + Vec2::new(*x1, *y1), origin + Vec2::new(*x2, *y2)],
            stroke,
        );
    }
    painter.text(
        rect.left_center() + Vec2::new(28.0, 0.0),
        egui::Align2::LEFT_CENTER,
        label,
        egui::FontId::proportional(12.0),
        ink,
    );
    if count.is_some() && width < 102.0 {
        painter.circle_filled(rect.right_top() + Vec2::new(-5.0, 5.0), 2.0, AMBER);
    } else if let Some(count) = count {
        painter.text(
            rect.right_center() - Vec2::new(10.0, 0.0),
            egui::Align2::RIGHT_CENTER,
            count.to_string(),
            egui::FontId::monospace(11.0),
            AMBER,
        );
    }
    response
}

fn accent(light: bool) -> Color32 {
    if light {
        Color32::from_rgb(40, 87, 164)
    } else {
        BLUE
    }
}

fn theme_button(ui: &mut Ui, light: bool) -> egui::Response {
    let label = if light {
        "Switch to dark mode"
    } else {
        "Switch to light mode"
    };
    let (rect, response) = ui.allocate_exact_size(Vec2::splat(35.0), egui::Sense::click());
    response.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Button, true, label));
    let painter = ui.painter();
    let center = rect.center();
    let fill = if response.hovered() {
        ui.visuals().selection.bg_fill
    } else {
        ui.visuals().faint_bg_color
    };
    painter.circle_filled(center, 16.0, fill);
    painter.circle_stroke(
        center,
        16.0,
        egui::Stroke::new(
            1.0_f32,
            if response.has_focus() {
                accent(light)
            } else {
                ui.visuals().widgets.noninteractive.bg_stroke.color
            },
        ),
    );
    let ink = accent(light);
    let stroke = egui::Stroke::new(1.5_f32, ink);
    if light {
        painter.circle_filled(center, 7.2, ink);
        painter.circle_filled(center + Vec2::new(3.7, -3.4), 6.3, fill);
    } else {
        painter.circle_stroke(center, 4.0, stroke);
        for i in 0..8 {
            let ray = Vec2::angled(i as f32 * std::f32::consts::FRAC_PI_4);
            painter.line_segment([center + ray * 6.1, center + ray * 8.2], stroke);
        }
    }
    response.on_hover_text(label)
}

fn traffic_colors(light: bool) -> (Color32, Color32) {
    if light {
        (
            Color32::from_rgb(0, 116, 131),
            Color32::from_rgb(119, 73, 177),
        )
    } else {
        (
            Color32::from_rgb(67, 212, 205),
            Color32::from_rgb(189, 153, 252),
        )
    }
}

fn ui_text_color(light: bool) -> Color32 {
    if light {
        Color32::from_rgb(31, 48, 74)
    } else {
        Color32::from_rgb(223, 231, 242)
    }
}

fn table_row(
    ui: &mut Ui,
    cells: &[&str],
    widths: &[f32],
    header: bool,
    stripe: bool,
) -> egui::Response {
    let (rect, response) = ui.allocate_exact_size(
        Vec2::new(ui.available_width(), if header { 30.0 } else { 28.0 }),
        if header {
            egui::Sense::hover()
        } else {
            egui::Sense::click()
        },
    );
    if !ui.is_rect_visible(rect) {
        return response;
    }
    let visuals = ui.visuals();
    let painter = ui.painter();
    if header || stripe || response.hovered() {
        let color = if response.hovered() && !header {
            visuals.selection.bg_fill
        } else if header {
            visuals.extreme_bg_color
        } else {
            visuals
                .widgets
                .inactive
                .bg_stroke
                .color
                .gamma_multiply(0.27)
        };
        painter.rect_filled(rect, 5.0, color);
    }
    let mut left = rect.left();
    for (text, fraction) in cells.iter().zip(widths) {
        let right = left + rect.width() * fraction;
        let clip = egui::Rect::from_min_max(
            egui::pos2(left + 9.0, rect.top()),
            egui::pos2(right - 6.0, rect.bottom()),
        );
        let font = egui::FontId::proportional(if header { 11.5 } else { 12.5 });
        let color = if header {
            visuals.weak_text_color()
        } else {
            visuals.text_color()
        };
        let galley = painter.layout_job({
            let mut job = egui::text::LayoutJob::simple_singleline(text.to_string(), font, color);
            job.wrap.max_width = clip.width().max(0.0);
            job.wrap.max_rows = 1;
            job
        });
        painter.with_clip_rect(clip).galley(
            egui::pos2(clip.left(), rect.center().y - galley.size().y / 2.0),
            galley,
            color,
        );
        left = right;
    }
    response
}
