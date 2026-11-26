#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

#[path = "../../../src/ask.rs"]
mod ask;
#[path = "../../../src/devices.rs"]
mod devices;
#[path = "../../../src/engine.rs"]
mod engine;
#[path = "../../../src/firewall.rs"]
mod firewall;
#[path = "../../../src/geo.rs"]
mod geo;
#[path = "../../../src/geo_filter.rs"]
mod geo_filter;
#[path = "../../../src/hardware.rs"]
mod hardware;
#[path = "../../../src/history.rs"]
mod history;
#[path = "../../../src/pcap.rs"]
mod pcap;
#[path = "../../../src/processes.rs"]
mod processes;
#[path = "../../../src/profiles.rs"]
mod profiles;
#[path = "../../../src/traffic.rs"]
mod traffic;
#[path = "../../../src/watch.rs"]
mod watch;

mod desktop;
use desktop::{open_publisher_site, set_minimize_to_tray};
use engine::{Command, Engine, Event};
use serde_json::{Value, json};
use std::{
    collections::VecDeque,
    path::PathBuf,
    sync::{Arc, Mutex, mpsc},
};
use tauri::{AppHandle, Manager, State};

type Reply = Result<Value, String>;
type AskJob = (String, Option<usize>, mpsc::Sender<Reply>);
struct Backend {
    commands: mpsc::Sender<Command>,
    updates: Arc<Mutex<VecDeque<Event>>>,
    filters: Mutex<geo_filter::Worker>,
    ask: mpsc::Sender<AskJob>,
    firewall: Mutex<()>,
    recent: Arc<Mutex<VecDeque<Value>>>,
}

fn point(p: history::Point) -> Value {
    json!({"end":p.end,"first":p.first,"duration":p.duration_ms,"rx":p.volume.rx,"tx":p.volume.tx})
}

fn event(event: Event) -> Value {
    let (kind, data) = match event {
        Event::Sources(list, warning) => (
            "sources",
            json!({"list":list.iter().map(|s|json!({"key":s.key(),"name":s.name(),"kind":s.kind()})).collect::<Vec<_>>(),"warning":warning}),
        ),
        Event::Selected(key) => ("selected", json!(key)),
        Event::State(status) => ("state", json!(status)),
        Event::Storage(path) => ("storage", json!(path)),
        Event::Notice(message) => ("notice", json!(message)),
        Event::Sample(s) => {
            let rows=s.rows.into_iter().map(|r|{
                let country=geo::lookup(r.flow.remote.ip());
                json!({"host":r.flow.remote.ip(),"remote":r.flow.remote,"local":r.flow.local,"type":r.flow.kind(),"app":r.app.as_ref().map(|p|&p.name),"path":r.app.as_ref().and_then(|p|p.path.as_ref()),
                "country":country,"rx":r.volume.rx,"tx":r.volume.tx})
            }).collect::<Vec<_>>();
            (
                "sample",
                json!({"point":point(s.point),"rows":rows,"other":{"rx":s.other.rx,"tx":s.other.tx}}),
            )
        }
        Event::History(id, result) => (
            "history",
            json!({"id":id,"result":result.map(|points|points.into_iter().map(point).collect::<Vec<_>>())}),
        ),
        Event::Usage(id, result) => (
            "usage",
            json!({"id":id,"result":result.map(|rows|rows.into_iter().map(|((label,path),v)|json!({"label":label,"path":path,"rx":v.rx,"tx":v.tx})).collect::<Vec<_>>())}),
        ),
        Event::Resources(r) => (
            "resources",
            json!({"cpu":r.cpu,"memory":r.used_memory,"capacity":r.total_memory,"gpu":r.gpu,"disk":r.disk_rate,"processes":r.processes.into_values().map(|p|json!({"pid":p.id,"name":p.name,"path":p.path,"cpu":p.cpu,"memory":p.memory,"disk":p.disk,"gpu":p.gpu})).collect::<Vec<_>>()}),
        ),
        Event::Devices(result) => ("devices", json!(result.map(device_rows))),
        Event::Alert(a) => (
            "alert",
            json!({"time":a.time,"title":a.title,"detail":a.detail}),
        ),
    };
    json!({"kind":kind,"data":data})
}

impl Drop for Backend {
    fn drop(&mut self) {
        let _ = self.commands.send(Command::Stop);
    }
}

fn collect(
    engine: Engine,
    updates: Arc<Mutex<VecDeque<Event>>>,
    recent: Arc<Mutex<VecDeque<Value>>>,
) -> std::io::Result<()> {
    std::thread::Builder::new()
        .name("deadwall-ui-events".into())
        .spawn(move || {
            // Keep the queue bounded when the hidden WebView stops polling.
            while let Ok(update) = engine.events.recv() {
                let (Ok(mut queue), Ok(mut points)) = (updates.lock(), recent.lock()) else {
                    break;
                };
                match &update {
                    Event::Selected(_) => {
                        points.clear();
                        queue.retain(|entry| {
                            !matches!(entry, Event::Sample(_) | Event::Selected(_))
                        });
                    }
                    Event::Sample(sample) => {
                        if points.len() == engine::LIVE_SECONDS as usize {
                            points.pop_front();
                        }
                        if queue
                            .iter()
                            .filter(|entry| matches!(entry, Event::Sample(_)))
                            .count()
                            >= engine::LIVE_SECONDS as usize
                            && let Some(index) = queue
                                .iter()
                                .position(|entry| matches!(entry, Event::Sample(_)))
                        {
                            queue.remove(index);
                        }
                        points.push_back(point(sample.point.clone()));
                    }
                    Event::Alert(_) => {
                        if queue
                            .iter()
                            .filter(|entry| matches!(entry, Event::Alert(_)))
                            .count()
                            >= 500
                            && let Some(index) = queue
                                .iter()
                                .position(|entry| matches!(entry, Event::Alert(_)))
                        {
                            queue.remove(index);
                        }
                    }
                    _ => {
                        let kind = std::mem::discriminant(&update);
                        queue.retain(|entry| std::mem::discriminant(entry) != kind);
                    }
                }
                queue.push_back(update);
            }
        })?;
    Ok(())
}

#[tauri::command]
fn poll(state: State<'_, Backend>) -> Result<Vec<Value>, String> {
    let queued: Vec<_> = state
        .updates
        .lock()
        .map_err(|e| e.to_string())?
        .drain(..)
        .collect();
    let mut updates: Vec<_> = queued.into_iter().map(event).collect();
    let filters = state.filters.lock().map_err(|e| e.to_string())?;
    updates.extend(
        filters
            .rx
            .try_iter()
            .map(|result| json!({"kind":"filter","data":result})),
    );
    Ok(updates)
}
#[derive(serde::Deserialize)]
struct MonitorOptions {
    key: Option<String>,
    paused: Option<bool>,
    id: Option<u64>,
    from: Option<i64>,
    to: Option<i64>,
    width: Option<i64>,
    group: Option<usize>,
}

#[tauri::command]
fn monitor(
    state: State<'_, Backend>,
    action: String,
    options: MonitorOptions,
) -> Result<(), String> {
    let MonitorOptions {
        key,
        paused,
        id,
        from,
        to,
        width,
        group,
    } = options;
    let since = from.unwrap_or(0);
    let command = match action.as_str() {
        "sources" => Command::RefreshSources,
        "source" => Command::Select(key.ok_or("Select an adapter")?),
        "pause" => Command::Pause(paused.ok_or("Missing pause state")?),
        "history" => Command::History {
            id: id.unwrap_or_default(),
            since,
            width: width.unwrap_or(1000),
        },
        "usage" => Command::Usage {
            id: id.unwrap_or_default(),
            from: since,
            to: to.unwrap_or(i64::MAX),
            group: history::Dimension::ALL
                .get(group.unwrap_or(0))
                .ok_or("Unknown traffic group")?
                .0,
        },
        "export" => Command::Export { since },
        "devices" => Command::RefreshDevices,
        _ => return Err("Unknown monitor command".into()),
    };
    state.commands.send(command).map_err(|e| e.to_string())
}

fn device_rows(rows: Vec<devices::Device>) -> Vec<Value> {
    rows.into_iter()
        .map(|d| json!({"address":d.address,"mac":d.mac,"interface":d.interface}))
        .collect()
}

#[tauri::command]
fn scan_sources() -> Vec<std::net::Ipv4Addr> {
    devices::scan_sources()
}
#[tauri::command]
async fn scan(source: std::net::Ipv4Addr) -> Result<Vec<Value>, String> {
    tauri::async_runtime::spawn_blocking(move || devices::scan(source).map(device_rows))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn firewall_change(
    app: AppHandle,
    path: Option<PathBuf>,
    profiles: i32,
    blocked: bool,
) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<Backend>();
        let _guard = state.firewall.lock().map_err(|e| e.to_string())?;
        firewall::Change {
            path,
            profiles,
            blocked,
        }
        .apply()
    })
    .await
    .map_err(|e| e.to_string())?
}
fn store() -> Result<profiles::Profiles, String> {
    profiles::Profiles::open(&history::History::path().with_file_name("firewall-profiles.sqlite3"))
}
#[tauri::command]
async fn profile(
    app: AppHandle,
    action: String,
    name: Option<String>,
    categories: Option<i32>,
    paths: Option<String>,
    id: Option<String>,
) -> Reply {
    tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<Backend>();
        let _guard = state.firewall.lock().map_err(|e| e.to_string())?;
        let db = store()?;
        match action.as_str() {
            "list" => {}
            "save" => {
                db.save(
                    &name.unwrap_or_default(),
                    categories.unwrap_or_default(),
                    &paths.unwrap_or_default(),
                )?;
            }
            "apply" | "remove" | "delete" => {
                let profile = db
                    .list()?
                    .into_iter()
                    .find(|profile| Some(&profile.id) == id.as_ref())
                    .ok_or("Profile not found")?;
                firewall::apply_profile(&profile, action == "apply")?;
                if action == "delete" {
                    db.delete(&profile.id)?;
                }
            }
            _ => return Err("Unknown profile action".into()),
        }
        Ok(json!(db.list()?))
    })
    .await
    .map_err(|e| e.to_string())?
}

fn ask_worker() -> std::io::Result<mpsc::Sender<AskJob>> {
    let (sender, receiver) = mpsc::channel::<AskJob>();
    std::thread::Builder::new()
        .name("deadwall-approval".into())
        .spawn(move || {
            let mut ask = None::<ask::Ask>;
            while let Ok((action, index, reply)) = receiver.recv() {
                let result = (|| {
                    match action.as_str() {
                        "list" => {}
                        "start" => {
                            if ask.is_none() {
                                ask = Some(ask::Ask::new()?);
                            }
                        }
                        "stop" => ask = None,
                        "allow" | "deny" => ask
                            .as_mut()
                            .ok_or("Connection approvals are off")?
                            .decide(index.ok_or("No request selected")?, action == "allow")?,
                        _ => return Err("Unknown approval action".into()),
                    }
                    let active = ask.is_some();
                    let requests = ask
                        .as_mut()
                        .map(|value| {
                            value
                                .pending()
                                .iter()
                                .map(|request| request.path.clone())
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default();
                    Ok(json!({"active":active,"requests":requests}))
                })();
                let _ = reply.send(result);
            }
        })?;
    Ok(sender)
}
#[tauri::command]
async fn approval(app: AppHandle, action: String, index: Option<usize>) -> Reply {
    tauri::async_runtime::spawn_blocking(move || {
        let (tx, rx) = mpsc::channel();
        app.state::<Backend>()
            .ask
            .send((action, index, tx))
            .map_err(|e| e.to_string())?;
        rx.recv().map_err(|e| e.to_string())?
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
fn geographic_filter(state: State<'_, Backend>, spec: geo_filter::Spec) -> Result<(), String> {
    state.filters.lock().map_err(|e| e.to_string())?.apply(spec)
}
#[tauri::command]
fn locate(address: std::net::IpAddr) -> Value {
    json!(geo::lookup(address).and_then(|code|geo::country(code).map(|c|json!({"code":code,"name":c.name,"continent":c.continent,"latitude":c.latitude,"longitude":c.longitude}))))
}
#[tauri::command]
fn mini_points(state: State<'_, Backend>) -> Reply {
    Ok(json!(*state.recent.lock().map_err(|e| e.to_string())?))
}

#[tauri::command]
fn mini(app: AppHandle) -> Result<(), String> {
    if let Some(window) = app.get_webview_window("mini") {
        window.set_focus().map_err(|e| e.to_string())?;
        return Ok(());
    }
    tauri::WebviewWindowBuilder::new(
        &app,
        "mini",
        tauri::WebviewUrl::App("index.html?mini=1".into()),
    )
    .title("deadWall · Live")
    .inner_size(410.0, 210.0)
    .always_on_top(true)
    .build()
    .map_err(|e| e.to_string())?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    geo::start_loading();
    let engine = Engine::start()?;
    let commands = engine.commands.clone();
    let updates = Arc::new(Mutex::new(VecDeque::new()));
    let recent = Arc::new(Mutex::new(VecDeque::new()));
    collect(engine, updates.clone(), recent.clone())?;
    let backend = Backend {
        commands,
        updates,
        filters: Mutex::new(geo_filter::Worker::start()?),
        ask: ask_worker()?,
        firewall: Mutex::new(()),
        recent,
    };
    tauri::Builder::default()
        .manage(backend)
        .manage(desktop::TraySetting::default())
        .setup(|app| {
            if let Some(window) = app.get_webview_window("main") {
                desktop::watch(window, app.state::<desktop::TraySetting>().inner().clone())?;
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            poll,
            monitor,
            scan_sources,
            scan,
            firewall_change,
            profile,
            approval,
            geographic_filter,
            locate,
            mini,
            mini_points,
            set_minimize_to_tray,
            open_publisher_site
        ])
        .run(tauri::generate_context!())?;
    Ok(())
}
