#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

mod ask;
mod devices;
mod engine;
mod firewall;
mod geo;
mod geo_filter;
mod geo_view;
mod hardware;
mod history;
mod pcap;
mod processes;
mod profiles;
mod traffic;
mod ui;
mod watch;
mod window;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    geo::start_loading();
    let engine = engine::Engine::start()?;
    let artwork = image::load_from_memory(include_bytes!("../assets/deadwall.png"))?;
    let icon = artwork.thumbnail_exact(128, 128).into_rgba8();
    let icon = eframe::egui::IconData {
        width: icon.width(),
        height: icon.height(),
        rgba: icon.into_raw(),
    };
    let options = eframe::NativeOptions {
        #[cfg(windows)]
        renderer: eframe::Renderer::Wgpu,
        viewport: eframe::egui::ViewportBuilder::default()
            .with_app_id("deadWall")
            .with_icon(icon.clone())
            .with_inner_size([1280.0, 800.0])
            .with_min_inner_size([740.0, 570.0]),
        ..Default::default()
    };
    eframe::run_native(
        "deadWall",
        options,
        Box::new(move |context| Ok(Box::new(ui::Desk::new(context, engine, &icon)))),
    )?;
    Ok(())
}
