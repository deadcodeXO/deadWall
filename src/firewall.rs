use std::path::PathBuf;

pub struct Change {
    pub path: Option<PathBuf>,
    pub profiles: i32,
    pub blocked: bool,
}

impl Change {
    pub fn apply(self) -> Result<String, String> {
        platform::apply(std::slice::from_ref(&self), None)?;
        let target = self
            .path
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "Lockdown".into());
        Ok(format!(
            "{} · {}",
            if self.blocked {
                "Block rules applied"
            } else {
                "Block rules removed"
            },
            target
        ))
    }
}

#[cfg(not(windows))]
mod platform {
    pub fn apply(_: &[super::Change], _: Option<&str>) -> Result<(), String> {
        Err("Firewall controls are available on Windows.".into())
    }
}

#[cfg(windows)]
mod platform {
    use std::{os::windows::ffi::OsStrExt, path::Path};

    use windows::{
        Win32::{
            Foundation::VARIANT_TRUE,
            NetworkManagement::WindowsFirewall::*,
            System::Com::{
                CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx,
                CoUninitialize,
            },
        },
        core::BSTR,
    };

    struct Apartment;

    impl Drop for Apartment {
        fn drop(&mut self) {
            // Matches the initialization on this thread.
            unsafe { CoUninitialize() };
        }
    }

    fn name(path: Option<&Path>, profiles: i32, inbound: bool, scope: Option<&str>) -> BSTR {
        let mut hash = 0xcbf29ce484222325u64;
        if let Some(path) = path {
            for byte in path.as_os_str().encode_wide().flat_map(u16::to_le_bytes) {
                hash = (hash ^ u64::from(byte)).wrapping_mul(0x100000001b3);
            }
        }
        let prefix = if path.is_some() { "app" } else { "lockdown" };
        let scope = scope.map_or_else(String::new, |id| format!("profile-{id}-"));
        BSTR::from(format!(
            "deadWall-{scope}{prefix}-{hash:016x}-{profiles}-{}",
            if inbound { "in" } else { "out" }
        ))
    }

    pub fn apply(changes: &[super::Change], scope: Option<&str>) -> Result<(), String> {
        const NOT_FOUND: i32 = 0x80070002u32 as i32;
        const ELEMENT_NOT_FOUND: i32 = 0x80070490u32 as i32;
        if scope.is_some_and(|scope| {
            scope.len() != 32 || !scope.bytes().all(|byte| byte.is_ascii_hexdigit())
        }) {
            return Err("Invalid saved firewall profile ID.".into());
        }
        let mut plan = Vec::new();
        for change in changes {
            if change.profiles == 0 || change.profiles & !7 != 0 {
                return Err("Choose one or more Windows firewall categories.".into());
            }
            let path = change.path.as_deref();
            let application = path
                .map(|value| {
                    if !value.is_absolute() || (change.blocked && !value.is_file()) {
                        return Err(format!("Executable is unavailable: {}", value.display()));
                    }
                    let wide: Vec<_> = value.as_os_str().encode_wide().collect();
                    if wide.contains(&0) {
                        return Err("Invalid executable path.".into());
                    }
                    Ok(BSTR::from_wide(&wide))
                })
                .transpose()?;
            for inbound in [true, false] {
                plan.push((
                    name(path, change.profiles, inbound, scope),
                    change.profiles,
                    inbound,
                    change.blocked,
                    application.clone(),
                ));
            }
        }
        // COM objects are released before the apartment on this worker thread.
        unsafe {
            CoInitializeEx(None, COINIT_APARTMENTTHREADED)
                .ok()
                .map_err(|error| error.to_string())?;
            let _apartment = Apartment;
            let policy: INetFwPolicy2 = CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER)
                .map_err(|error| error.to_string())?;
            let rules = policy.Rules().map_err(|error| error.to_string())?;
            let group = BSTR::from("deadWall");
            enum Edit {
                Add(BSTR, INetFwRule),
                Remove(BSTR, INetFwRule),
                Enable(INetFwRule),
            }
            let mut operations = Vec::new();
            for (name, profiles, inbound, block, application) in plan {
                let existing = match rules.Item(&name) {
                    Ok(rule) if rule.Grouping().map_err(|error| error.to_string())? == group => {
                        Some(rule)
                    }
                    Ok(_) => {
                        return Err("A matching rule name is owned by another application.".into());
                    }
                    Err(error) if matches!(error.code().0, NOT_FOUND | ELEMENT_NOT_FOUND) => None,
                    Err(error) => return Err(error.to_string()),
                };
                match (block, existing) {
                    (true, None) => {
                        let rule: INetFwRule =
                            CoCreateInstance(&NetFwRule, None, CLSCTX_INPROC_SERVER)
                                .map_err(|error| error.to_string())?;
                        let configure = (|| -> windows::core::Result<()> {
                            rule.SetName(&name)?;
                            rule.SetGrouping(&group)?;
                            rule.SetProfiles(profiles)?;
                            rule.SetDirection(if inbound {
                                NET_FW_RULE_DIR_IN
                            } else {
                                NET_FW_RULE_DIR_OUT
                            })?;
                            rule.SetAction(NET_FW_ACTION_BLOCK)?;
                            rule.SetProtocol(NET_FW_IP_PROTOCOL_ANY.0)?;
                            if let Some(application) = application {
                                rule.SetApplicationName(&application)?;
                            }
                            rule.SetEnabled(VARIANT_TRUE)
                        })();
                        configure.map_err(|error| error.to_string())?;
                        operations.push(Edit::Add(name, rule));
                    }
                    (true, Some(rule))
                        if rule.Enabled().map_err(|error| error.to_string())? != VARIANT_TRUE =>
                    {
                        operations.push(Edit::Enable(rule))
                    }
                    (false, Some(rule)) => operations.push(Edit::Remove(name, rule)),
                    _ => {}
                }
            }
            for (index, edit) in operations.iter().enumerate() {
                let applied = match edit {
                    Edit::Add(_, rule) => rules.Add(rule),
                    Edit::Remove(name, _) => rules.Remove(name),
                    Edit::Enable(rule) => rule.SetEnabled(VARIANT_TRUE),
                };
                if let Err(error) = applied {
                    let mut message = error.to_string();
                    for prior in operations[..index].iter().rev() {
                        let restored = match prior {
                            Edit::Add(name, _) => rules.Remove(name),
                            Edit::Remove(_, rule) => rules.Add(rule),
                            Edit::Enable(rule) => {
                                rule.SetEnabled(windows::Win32::Foundation::VARIANT_FALSE)
                            }
                        };
                        if let Err(error) = restored {
                            message.push_str(&format!(" · Rollback failed: {error}"));
                        }
                    }
                    return Err(message);
                }
            }
        }
        Ok(())
    }
}

pub fn apply_profile(profile: &crate::profiles::Profile, block: bool) -> Result<String, String> {
    let changes: Vec<_> = profile
        .apps
        .iter()
        .map(|path| Change {
            path: Some(path.clone()),
            profiles: profile.categories,
            blocked: block,
        })
        .collect();
    platform::apply(&changes, Some(&profile.id))?;
    Ok(format!(
        "{} profile {}",
        if block { "Applied" } else { "Removed" },
        profile.name
    ))
}
