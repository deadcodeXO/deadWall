use crate::geo::{Country, country};
use std::collections::HashMap;

pub fn world(
    ui: &mut eframe::egui::Ui,
    volumes: &HashMap<String, crate::traffic::Volume>,
    peers: &HashMap<String, Vec<String>>,
    selected: &str,
    pin: Option<&Country>,
    revision: u64,
) -> Option<String> {
    use eframe::egui::Color32;
    use egui_plot::{Plot, PlotImage, PlotPoint, Points};
    let dark = ui.visuals().dark_mode;
    let dot = if dark {
        Color32::from_rgb(109, 213, 208)
    } else {
        Color32::from_rgb(0, 112, 125)
    };
    let height = (ui.ctx().content_rect().height() * 0.45).clamp(245.0, 510.0);
    let texture = map_texture(ui, dark);
    let response = Plot::new(("world", revision))
        .height(height)
        .include_x(-180.0)
        .include_x(180.0)
        .include_y(-90.0)
        .include_y(90.0)
        .data_aspect(1.0)
        .show_axes(false)
        .show_grid(false)
        .show_background(false)
        .label_formatter(|name, _| name.to_string())
        .show(ui, |plot| {
            if let Some(texture) = &texture {
                plot.image(
                    PlotImage::new(
                        "World map",
                        texture.id(),
                        PlotPoint::new(0.0, 0.0),
                        [360.0, 180.0],
                    )
                    .allow_hover(false),
                );
            }
            if let Some(pin) = pin
                && let (Some(x), Some(y)) = (pin.longitude, pin.latitude)
            {
                plot.points(
                    Points::new(format!("Lookup · {}", pin.name), vec![[x, y]])
                        .radius(10.0_f32)
                        .color(Color32::from_rgb(211, 119, 76)),
                );
            }
            let pointer = plot.pointer_coordinate();
            let mut nearest = None::<(f64, String)>;
            for (code, volume) in volumes {
                if let Some(place) = country(code)
                    && let (Some(lon), Some(lat)) = (place.longitude, place.latitude)
                {
                    plot.points(
                        Points::new(
                            marker_label(place, *volume, peers.get(code)),
                            vec![[lon, lat]],
                        )
                        .radius(if place.name == selected {
                            8.0_f32
                        } else {
                            5.5_f32
                        })
                        .color(dot),
                    );
                    if let Some(pointer) = pointer {
                        let delta = (plot.screen_from_plot(pointer)
                            - plot.screen_from_plot(egui_plot::PlotPoint::new(lon, lat)))
                        .length() as f64;
                        if delta <= 11.0
                            && nearest
                                .as_ref()
                                .is_none_or(|(distance, _)| delta < *distance)
                        {
                            nearest = Some((delta, place.name.clone()));
                        }
                    }
                }
            }
            nearest.map(|(_, name)| name)
        });
    if response.response.clicked() {
        response.inner
    } else {
        None
    }
}

fn marker_label(
    place: &Country,
    volume: crate::traffic::Volume,
    peers: Option<&Vec<String>>,
) -> String {
    let mut label = format!(
        "{} ({})\nReceived {} B · Sent {} B",
        place.name, place.continent, volume.rx, volume.tx
    );
    if let Some(peers) = peers {
        for peer in peers.iter().take(6) {
            label.push('\n');
            label.push_str(peer);
        }
        if peers.len() > 6 {
            label.push_str(&format!("\n+ {} more IPs", peers.len() - 6));
        }
    }
    label
}
fn map_texture(ui: &eframe::egui::Ui, dark: bool) -> Option<eframe::egui::TextureHandle> {
    use eframe::egui::{ColorImage, Id, TextureHandle, TextureOptions};
    let key = Id::new(("basemap", dark));
    if let Some(texture) = ui.ctx().data(|data| data.get_temp::<TextureHandle>(key)) {
        return Some(texture);
    }
    let bytes = if dark {
        include_bytes!("../assets/world-dark.png").as_slice()
    } else {
        include_bytes!("../assets/world-light.png").as_slice()
    };
    let rgba = image::load_from_memory(bytes).ok()?.into_rgba8();
    let image = ColorImage::from_rgba_unmultiplied(
        [rgba.width() as usize, rgba.height() as usize],
        rgba.as_raw(),
    );
    let texture = ui.ctx().load_texture(
        if dark {
            "World · dark"
        } else {
            "World · light"
        },
        image,
        TextureOptions::LINEAR,
    );
    ui.ctx()
        .data_mut(|data| data.insert_temp(key, texture.clone()));
    Some(texture)
}
