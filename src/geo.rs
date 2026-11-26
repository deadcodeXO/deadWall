use std::{collections::HashMap, net::IpAddr, sync::OnceLock};

use flate2::read::GzDecoder;
use serde::Deserialize;

type CountryCode = [u8; 2];

#[derive(Deserialize)]
pub struct Country {
    pub name: String,
    pub continent: String,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
}

struct Database {
    ranges: Vec<(u128, u128, CountryCode)>,
    v4_end: usize,
    countries: HashMap<String, Country>,
}

static DB: OnceLock<Result<Database, String>> = OnceLock::new();

pub fn start_loading() {
    let _ = std::thread::Builder::new()
        .name("deadwall-geography".into())
        .spawn(|| {
            DB.get_or_init(|| Database::load().map_err(|error| error.to_string()));
        });
}

impl Database {
    fn load() -> Result<Self, Box<dyn std::error::Error>> {
        let compressed = include_bytes!("../assets/dbip-country-lite-2026-11.csv.gz");
        let mut input = csv::ReaderBuilder::new()
            .has_headers(false)
            .from_reader(GzDecoder::new(&compressed[..]));
        let mut ranges = Vec::new();
        for record in input.records() {
            let row = record?;
            let start: IpAddr = row.get(0).ok_or("Missing start IP")?.parse()?;
            let end: IpAddr = row.get(1).ok_or("Missing end IP")?.parse()?;
            let code: CountryCode = row
                .get(2)
                .ok_or("Missing country code")?
                .as_bytes()
                .try_into()?;
            ranges.push((start.is_ipv6(), ip_number(start), ip_number(end), code));
        }
        ranges.sort_unstable_by_key(|range| (range.0, range.1));
        let v4_end = ranges.partition_point(|range| !range.0);
        Ok(Self {
            ranges: ranges
                .into_iter()
                .map(|(_, start, end, code)| (start, end, code))
                .collect(),
            v4_end,
            countries: serde_json::from_str(include_str!("../assets/country-metadata.json"))?,
        })
    }
}

fn ip_number(ip: IpAddr) -> u128 {
    match ip {
        IpAddr::V4(addr) => u128::from(u32::from(addr)),
        IpAddr::V6(addr) => u128::from(addr),
    }
}

fn db() -> Option<&'static Database> {
    DB.get().and_then(|loaded| loaded.as_ref().ok())
}

pub fn status() -> Option<&'static str> {
    match DB.get() {
        Some(Ok(_)) => None,
        Some(Err(error)) => Some(error),
        None => Some("Loading the offline country database."),
    }
}

pub fn lookup(ip: IpAddr) -> Option<&'static str> {
    let ip = ip.to_canonical();
    let database = db()?;
    let ranges = if ip.is_ipv4() {
        &database.ranges[..database.v4_end]
    } else {
        &database.ranges[database.v4_end..]
    };
    let ip = ip_number(ip);
    let index = ranges
        .partition_point(|range| range.0 <= ip)
        .checked_sub(1)?;
    let (_, end, ref code) = ranges[index];
    (ip <= end)
        .then(|| std::str::from_utf8(code).ok())
        .flatten()
}

pub fn country(code: &str) -> Option<&'static Country> {
    db()?.countries.get(code)
}

pub fn selected_ranges(
    codes: &std::collections::HashSet<String>,
    continents: &[String],
) -> Result<Vec<crate::geo_filter::IpRange>, String> {
    let db = db().ok_or_else(|| {
        status()
            .unwrap_or("Offline geography unavailable")
            .to_string()
    })?;
    for code in codes {
        if !db.countries.contains_key(code) {
            return Err(format!("Unknown country: {code}"));
        }
    }
    Ok(db
        .ranges
        .iter()
        .enumerate()
        .filter_map(|(index, (start, end, code))| {
            let code = std::str::from_utf8(code).ok()?;
            let selected = codes.contains(code)
                || db
                    .countries
                    .get(code)
                    .is_some_and(|country| continents.contains(&country.continent));
            selected.then_some(crate::geo_filter::IpRange {
                v6: index >= db.v4_end,
                start: *start,
                end: *end,
            })
        })
        .collect())
}
#[cfg(test)]
mod tests {
    #[test]
    fn bundled_map_and_ip_ranges_load() {
        let data = super::Database::load().unwrap();
        assert!(data.v4_end > 10000);
        for asset in [
            include_bytes!("../assets/world-light.png").as_slice(),
            include_bytes!("../assets/world-dark.png").as_slice(),
        ] {
            assert_eq!(image::load_from_memory(asset).unwrap().width(), 1800);
        }
        assert!(data.countries["CA"].latitude.is_some());
    }
}
