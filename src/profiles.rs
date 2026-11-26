use std::path::{Path, PathBuf};

use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Profile {
    pub id: String,
    pub name: String,
    pub categories: i32,
    pub apps: Vec<PathBuf>,
}

pub struct Profiles(Connection);

impl Profiles {
    pub fn open(path: &Path) -> Result<Self, String> {
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        let db = Connection::open(path).map_err(|error| error.to_string())?;
        db.execute_batch("CREATE TABLE IF NOT EXISTS profiles (id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE COLLATE NOCASE, document TEXT NOT NULL)")
            .map_err(|error|error.to_string())?;
        Ok(Self(db))
    }

    pub fn list(&self) -> Result<Vec<Profile>, String> {
        let mut statement = self
            .0
            .prepare("SELECT document FROM profiles ORDER BY name COLLATE NOCASE")
            .map_err(|error| error.to_string())?;
        statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|error| error.to_string())?
            .map(|row| {
                let row = row.map_err(|error| error.to_string())?;
                serde_json::from_str(&row).map_err(|error| error.to_string())
            })
            .collect()
    }

    pub fn save(&self, name: &str, categories: i32, apps: &str) -> Result<Profile, String> {
        let name = name.trim();
        if name.is_empty() || name.chars().count() > 60 {
            return Err("Enter a profile name between 1 and 60 characters.".into());
        }
        if categories == 0 || categories & !7 != 0 {
            return Err("Choose at least one Windows firewall category.".into());
        }
        let mut paths = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for line in apps.lines().map(str::trim).filter(|line| !line.is_empty()) {
            let path = PathBuf::from(line);
            if !path.is_absolute() || line.contains('\0') {
                return Err(format!("Enter a full executable path: {line}"));
            }
            if seen.insert(line.to_lowercase()) {
                paths.push(path);
            }
            if paths.len() > 128 {
                return Err("A profile supports up to 128 executable paths.".into());
            }
        }
        if paths.is_empty() {
            return Err("Add at least one executable path.".into());
        }
        let mut bytes = [0; 16];
        getrandom::fill(&mut bytes).map_err(|error| error.to_string())?;
        let profile = Profile {
            id: format!("{:032x}", u128::from_be_bytes(bytes)),
            name: name.into(),
            categories,
            apps: paths,
        };
        let document = serde_json::to_string(&profile).map_err(|error| error.to_string())?;
        self.0
            .execute(
                "INSERT INTO profiles VALUES (?1,?2,?3)",
                params![profile.id, profile.name, document],
            )
            .map_err(|error| error.to_string())?;
        Ok(profile)
    }

    pub fn delete(&self, id: &str) -> Result<(), String> {
        self.0
            .execute("DELETE FROM profiles WHERE id=?1", [id])
            .map_err(|error| error.to_string())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profiles_keep_distinct_ids_and_validate_before_saving() {
        let db = Profiles::open(Path::new(":memory:")).unwrap();
        let path = if cfg!(windows) {
            r"C:\test.exe"
        } else {
            "/test.exe"
        };
        let first = db.save("Work", 2, path).unwrap();
        let second = db.save("Travel", 4, path).unwrap();
        assert_ne!(first.id, second.id);
        assert!(db.save("work", 2, path).is_err());
        assert!(db.save("Invalid", 2, "relative.exe").is_err());
        assert_eq!(db.list().unwrap().len(), 2);
        db.delete(&first.id).unwrap();
        assert_eq!(db.list().unwrap()[0].id, second.id);
    }
}
