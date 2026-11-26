use std::net::IpAddr;

#[derive(Clone)]
pub struct Device {
    pub address: IpAddr,
    pub mac: String,
    pub interface: String,
}

#[cfg(windows)]
pub fn neighbors() -> Result<Vec<Device>, String> {
    use std::{
        net::{Ipv4Addr, Ipv6Addr},
        ptr,
    };
    use windows_sys::Win32::{
        NetworkManagement::IpHelper::{FreeMibTable, GetIpNetTable2, MIB_IPNET_TABLE2},
        Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, NlnsIncomplete, NlnsUnreachable},
    };
    let mut table = ptr::null_mut::<MIB_IPNET_TABLE2>();
    // Windows owns and sizes the returned flexible array. The returned table is freed once.
    unsafe {
        let status = GetIpNetTable2(AF_UNSPEC, &mut table);
        if status != 0 || table.is_null() {
            return Err(format!("Windows neighbor table unavailable ({status})"));
        }
        let count = (*table).NumEntries as usize;
        let first = ptr::addr_of!((*table).Table)
            .cast::<windows_sys::Win32::NetworkManagement::IpHelper::MIB_IPNET_ROW2>();
        let devices = std::slice::from_raw_parts(first, count)
            .iter()
            .filter_map(|row| {
                if (row.State == NlnsIncomplete || row.State == NlnsUnreachable)
                    || row.PhysicalAddressLength != 6
                {
                    return None;
                }
                let address = match row.Address.si_family {
                    AF_INET => IpAddr::V4(Ipv4Addr::from(
                        row.Address.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes(),
                    )),
                    AF_INET6 => IpAddr::V6(Ipv6Addr::from(row.Address.Ipv6.sin6_addr.u.Byte)),
                    _ => return None,
                };
                if address.is_multicast()
                    || address.is_unspecified()
                    || address.is_loopback()
                    || matches!(address, IpAddr::V4(addr) if addr.is_broadcast())
                    || row.PhysicalAddress[0] & 1 != 0
                    || row.PhysicalAddress[..6] == [0; 6]
                {
                    return None;
                }
                let mac = row.PhysicalAddress[..6]
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<Vec<_>>()
                    .join(":");
                Some(Device {
                    address,
                    mac,
                    interface: row.InterfaceIndex.to_string(),
                })
            })
            .collect();
        FreeMibTable(table.cast());
        Ok(devices)
    }
}

#[cfg(target_os = "linux")]
pub fn neighbors() -> Result<Vec<Device>, String> {
    let text = std::fs::read_to_string("/proc/net/arp").map_err(|error| error.to_string())?;
    Ok(text
        .lines()
        .skip(1)
        .filter_map(|line| {
            let [address, _, flags, mac, _, interface] = line
                .split_whitespace()
                .collect::<Vec<_>>()
                .try_into()
                .ok()?;
            let flags = u32::from_str_radix(flags.trim_start_matches("0x"), 16).ok()?;
            if flags & 2 == 0 {
                return None;
            }
            Some(Device {
                address: address.parse().ok()?,
                mac: mac.into(),
                interface: interface.into(),
            })
        })
        .collect())
}

#[cfg(all(not(windows), not(target_os = "linux")))]
pub fn neighbors() -> Result<Vec<Device>, String> {
    Err("Neighbor inventory is available on Windows and Linux.".into())
}

#[cfg(windows)]
pub fn scan_sources() -> Vec<std::net::Ipv4Addr> {
    if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .filter(|entry| !entry.is_loopback())
        .filter_map(|entry| match entry.addr {
            if_addrs::IfAddr::V4(v4) if v4.prefixlen <= 30 && !v4.ip.is_link_local() => Some(v4.ip),
            _ => None,
        })
        .collect()
}

#[cfg(windows)]
pub fn scan(source: std::net::Ipv4Addr) -> Result<Vec<Device>, String> {
    use std::{
        net::Ipv4Addr,
        sync::atomic::{AtomicU32, Ordering},
    };
    use windows_sys::Win32::NetworkManagement::IpHelper::SendARP;
    let interfaces = if_addrs::get_if_addrs().map_err(|error| error.to_string())?;
    let (iface, v4) = interfaces
        .iter()
        .find_map(|entry| match &entry.addr {
            if_addrs::IfAddr::V4(v4)
                if v4.ip == source && !source.is_loopback() && v4.prefixlen <= 30 =>
            {
                Some((&entry.name, v4))
            }
            _ => None,
        })
        .ok_or("The selected directly connected interface is unavailable.")?;
    let mask = u32::from(v4.netmask) | 0xffffff00;
    let network = u32::from(source) & mask;
    let broadcast = network | !mask;
    let cursor = AtomicU32::new(network + 1);
    let results = std::sync::Mutex::new(Vec::new());
    std::thread::scope(|scope| {
        for _ in 0..12 {
            scope.spawn(|| {
                loop {
                    let current = cursor.fetch_add(1, Ordering::Relaxed);
                    if current >= broadcast {
                        break;
                    }
                    let ip = Ipv4Addr::from(current);
                    if ip == source {
                        continue;
                    }
                    let mut mac = [0u32; 2];
                    let mut length = 6;
                    // SendARP issues only an address-resolution request on the directly connected network.
                    let status = unsafe {
                        SendARP(
                            u32::from_ne_bytes(ip.octets()),
                            u32::from_ne_bytes(source.octets()),
                            mac.as_mut_ptr().cast(),
                            &mut length,
                        )
                    };
                    if status == 0 && length == 6 {
                        let first = mac[0].to_ne_bytes();
                        let second = mac[1].to_ne_bytes();
                        let mac = [first[0], first[1], first[2], first[3], second[0], second[1]]
                            .iter()
                            .map(|byte| format!("{byte:02x}"))
                            .collect::<Vec<_>>()
                            .join(":");
                        if let Ok(mut output) = results.lock() {
                            output.push(Device {
                                address: ip.into(),
                                mac,
                                interface: iface.to_string(),
                            });
                        }
                    }
                }
            });
        }
    });
    let mut devices = results.into_inner().map_err(|error| error.to_string())?;
    devices.sort_unstable_by_key(|device| device.address);
    Ok(devices)
}

#[cfg(not(windows))]
pub fn scan_sources() -> Vec<std::net::Ipv4Addr> {
    Vec::new()
}

#[cfg(not(windows))]
pub fn scan(_: std::net::Ipv4Addr) -> Result<Vec<Device>, String> {
    Err("Active ARP discovery is available on Windows.".into())
}
