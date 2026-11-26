use std::{
    fs,
    path::{Path, PathBuf},
};

use rusqlite::{Connection, params};

use crate::{
    engine::{Alert, Row},
    traffic::Volume,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dimension {
    App,
    Host,
    Type,
    Connection,
    Country,
}

impl Dimension {
    pub const ALL: [(Self, &'static str); 5] = [
        (Self::App, "App"),
        (Self::Host, "Host"),
        (Self::Type, "Traffic type"),
        (Self::Connection, "Connection"),
        (Self::Country, "Country"),
    ];
}

pub type UsageRow = ((String, Option<PathBuf>), Volume);

#[derive(Clone, Debug)]
pub struct Point {
    pub end: i64,
    pub first: i64,
    pub duration_ms: i64,
    pub volume: Volume,
}

pub struct History(Connection);

impl History {
    pub fn path() -> PathBuf {
        #[cfg(windows)]
        let base = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);
        #[cfg(target_os = "macos")]
        let base = std::env::var_os("HOME")
            .map(|home| PathBuf::from(home).join("Library/Application Support"));
        #[cfg(all(not(windows), not(target_os = "macos")))]
        let base = std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/share"))
            });
        base.unwrap_or_else(std::env::temp_dir)
            .join("deadWall")
            .join("history.sqlite3")
    }

    pub fn open_reader(path: &Path) -> Result<Self, String> {
        let db = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|error| error.to_string())?;
        db.busy_timeout(std::time::Duration::from_millis(250))
            .map_err(|error| error.to_string())?;
        Ok(Self(db))
    }

    pub fn open(path: &Path) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        let db = Connection::open(path).map_err(|error| error.to_string())?;
        db.busy_timeout(std::time::Duration::from_millis(150))
            .map_err(|error| error.to_string())?;
        db.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             CREATE TABLE IF NOT EXISTS bandwidth (
               source TEXT NOT NULL,
               end_ms INTEGER NOT NULL,
               duration_ms INTEGER NOT NULL,
               rx INTEGER NOT NULL,
               tx INTEGER NOT NULL,
               PRIMARY KEY(source, end_ms)
             ) WITHOUT ROWID;
             CREATE TABLE IF NOT EXISTS flow_usage (
               source TEXT NOT NULL,
               end_ms INTEGER NOT NULL,
               ordinal INTEGER NOT NULL,
               app TEXT NOT NULL,
               path TEXT,
               host TEXT NOT NULL,
               kind TEXT NOT NULL,
               association TEXT NOT NULL,
               country TEXT NOT NULL,
               rx INTEGER NOT NULL,
               tx INTEGER NOT NULL,
               PRIMARY KEY(source, end_ms, ordinal)
             ) WITHOUT ROWID;
             CREATE TABLE IF NOT EXISTS security_alerts (
               id INTEGER PRIMARY KEY,
               observed_ms INTEGER NOT NULL,
               title TEXT NOT NULL,
               detail TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS seen_application_paths (
               path TEXT PRIMARY KEY
             ) WITHOUT ROWID;",
        )
        .map_err(|error| error.to_string())?;
        Ok(Self(db))
    }

    pub fn record(
        &self,
        source: &str,
        point: &Point,
        rows: &[Row],
        overflow: Volume,
    ) -> rusqlite::Result<()> {
        let transaction = self.0.unchecked_transaction()?;
        transaction.execute(
            "INSERT INTO bandwidth VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(source, end_ms) DO UPDATE SET
               duration_ms=excluded.duration_ms, rx=excluded.rx, tx=excluded.tx",
            params![
                source,
                point.end,
                point.duration_ms,
                point.volume.rx,
                point.volume.tx
            ],
        )?;
        if !rows.is_empty() || overflow.total() > 0 {
            let mut statement = transaction.prepare_cached(
                "INSERT OR REPLACE INTO flow_usage VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            )?;
            for (index, row) in rows.iter().enumerate() {
                let app = row
                    .app
                    .as_ref()
                    .map_or("Unknown app", |app| app.name.as_str());
                let path = row
                    .app
                    .as_ref()
                    .and_then(|app| app.path.as_ref())
                    .and_then(|path| path.to_str());
                let remote = row.flow.remote.ip();
                let country = crate::geo::lookup(remote).unwrap_or("");
                let association = format!(
                    "{} ↔ {} · {}",
                    row.flow.local,
                    row.flow.remote,
                    row.flow.kind()
                );
                statement.execute(params![
                    source,
                    point.end,
                    index,
                    app,
                    path,
                    remote.to_string(),
                    row.flow.kind(),
                    association,
                    country,
                    row.volume.rx,
                    row.volume.tx
                ])?;
            }
            if overflow.total() > 0 {
                statement.execute(params![
                    source,
                    point.end,
                    rows.len(),
                    "Other flows",
                    None::<&str>,
                    "Other flows",
                    "Other flows",
                    "Other flows",
                    "",
                    overflow.rx,
                    overflow.tx
                ])?;
            }
        }
        transaction.commit()
    }

    pub fn usage(
        &self,
        source: &str,
        from: i64,
        to: i64,
        group: Dimension,
    ) -> rusqlite::Result<Vec<UsageRow>> {
        let (field, path) = match group {
            Dimension::App => ("app", "path"),
            Dimension::Host => ("host", "NULL"),
            Dimension::Type => ("kind", "NULL"),
            Dimension::Connection => ("association", "NULL"),
            Dimension::Country => ("country", "NULL"),
        };
        let sql = format!(
            "SELECT {field}, {path}, SUM(rx), SUM(tx)
            FROM flow_usage WHERE source=?1 AND end_ms BETWEEN ?2 AND ?3
            GROUP BY 1,2 ORDER BY SUM(rx)+SUM(tx) DESC, 1, 2 LIMIT 150"
        );
        let mut statement = self.0.prepare_cached(&sql)?;
        statement
            .query_map(params![source, from, to], |row| {
                let path = row.get::<_, Option<String>>(1)?.map(PathBuf::from);
                Ok((
                    (row.get(0)?, path),
                    Volume {
                        rx: row.get(2)?,
                        tx: row.get(3)?,
                    },
                ))
            })?
            .collect()
    }

    pub fn export(
        &self,
        source: &str,
        since: i64,
        writer: &mut csv::Writer<std::fs::File>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut statement = self.0.prepare(
            "SELECT end_ms,duration_ms,rx,tx FROM bandwidth WHERE source=?1 AND end_ms>=?2 ORDER BY end_ms"
        )?;
        let mut rows = statement.query(params![source, since])?;
        writer.write_record([
            "end_unix_ms",
            "observed_duration_ms",
            "rx_bytes",
            "tx_bytes",
        ])?;
        while let Some(row) = rows.next()? {
            let [end, duration, rx, tx] =
                [row.get::<_, i64>(0)?, row.get(1)?, row.get(2)?, row.get(3)?];
            writer.write_record([
                end.to_string(),
                duration.to_string(),
                rx.to_string(),
                tx.to_string(),
            ])?;
        }
        writer.flush()?;
        Ok(())
    }

    pub fn seen_app(&self, path: &Path) -> rusqlite::Result<bool> {
        self.0
            .execute(
                "INSERT OR IGNORE INTO seen_application_paths VALUES (?1)",
                [path.to_string_lossy().as_ref()],
            )
            .map(|previously_unknown| previously_unknown == 0)
    }

    pub fn record_alert(&self, alert: &Alert) -> rusqlite::Result<()> {
        self.0.execute(
            "INSERT INTO security_alerts (observed_ms,title,detail) VALUES (?1,?2,?3)",
            params![alert.time, alert.title, alert.detail],
        )?;
        Ok(())
    }

    pub fn alerts(&self) -> rusqlite::Result<Vec<Alert>> {
        let mut statement = self.0.prepare(
            "SELECT observed_ms,title,detail FROM (SELECT * FROM security_alerts ORDER BY id DESC LIMIT 500) ORDER BY id"
        )?;
        statement
            .query_map([], |row| {
                Ok(Alert {
                    time: row.get(0)?,
                    title: row.get(1)?,
                    detail: row.get(2)?,
                })
            })?
            .collect()
    }

    pub fn read(&self, source: &str, since: i64, width: i64) -> rusqlite::Result<Vec<Point>> {
        let earliest = self
            .0
            .query_row(
                "SELECT MIN(end_ms) FROM bandwidth WHERE source=?1 AND end_ms>=?2",
                params![source, since],
                |row| row.get::<_, Option<i64>>(0),
            )?
            .unwrap_or(since);
        let latest = self
            .0
            .query_row(
                "SELECT MAX(end_ms) FROM bandwidth WHERE source=?1",
                [source],
                |row| row.get::<_, Option<i64>>(0),
            )?
            .unwrap_or(earliest);
        let bucket = width.max((latest.saturating_sub(earliest)) / 960).max(1);
        let mut statement = self.0.prepare_cached(
            "SELECT MAX(end_ms), SUM(duration_ms), SUM(rx), SUM(tx), MIN(end_ms)
             FROM bandwidth WHERE source=?1 AND end_ms>=?2
             GROUP BY end_ms / ?3 ORDER BY 1",
        )?;
        statement
            .query_map(params![source, since, bucket], |row| {
                Ok(Point {
                    end: row.get(0)?,
                    first: row.get(4)?,
                    duration_ms: row.get(1)?,
                    volume: Volume {
                        rx: row.get(2)?,
                        tx: row.get(3)?,
                    },
                })
            })?
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges_keep_sources_separate() {
        let db = History::open(Path::new(":memory:")).unwrap();
        let mut point = Point {
            end: 1000,
            first: 1000,
            duration_ms: 1000,
            volume: Volume { rx: 400, tx: 200 },
        };
        db.record("a", &point, &[], Volume::default()).unwrap();
        point.end = 2000;
        db.record("a", &point, &[], Volume::default()).unwrap();
        db.record("b", &point, &[], Volume::default()).unwrap();
        let points = db.read("a", 0, 3000).unwrap();
        assert_eq!(points.len(), 1);
        assert_eq!(points[0].volume.rx, 800);
        assert_eq!(points[0].duration_ms, 2000);
        assert_eq!(db.read("b", 2001, 1).unwrap().len(), 0);
    }

    #[test]
    fn packet_breakdown_uses_the_requested_source_dimension_and_time() {
        let history = History::open(Path::new(":memory:")).unwrap();
        let point = Point {
            end: 1000,
            first: 1000,
            duration_ms: 1000,
            volume: Volume { rx: 80, tx: 40 },
        };
        let rows = [Row {
            flow: crate::traffic::Flow {
                local: "10.0.0.2:50400".parse().unwrap(),
                remote: "192.0.2.17:443".parse().unwrap(),
                protocol: 6,
            },
            app: None,
            volume: point.volume,
        }];
        history
            .record("packet:a", &point, &rows, Volume::default())
            .unwrap();
        let details = history
            .usage("packet:a", 1000, 1000, Dimension::Host)
            .unwrap();
        assert_eq!(details[0].0.0, "192.0.2.17");
        assert_eq!(details[0].1.rx, 80);
        assert_eq!(
            history
                .usage("packet:a", 1000, 1000, Dimension::Type)
                .unwrap()[0]
                .0
                .0,
            "HTTPS port"
        );
        assert!(
            history
                .usage("packet:a", 1001, 2000, Dimension::Host)
                .unwrap()
                .is_empty()
        );
        assert!(
            history
                .usage("packet:b", 0, 2000, Dimension::Host)
                .unwrap()
                .is_empty()
        );
    }
}
