use std::{collections::HashMap, net::SocketAddr, path::PathBuf};

use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

use crate::traffic::Flow;

#[derive(Clone, Debug)]
pub struct Process {
    pub id: u32,
    pub name: String,
    pub path: Option<PathBuf>,
    pub cpu: f32,
    pub memory: u64,
    pub disk: u64,
    pub gpu: Option<f64>,
}

#[derive(Default)]
pub struct Resources {
    pub cpu: f32,
    pub used_memory: u64,
    pub total_memory: u64,
    pub gpu: Option<f64>,
    pub disk_rate: Option<f64>,
    pub processes: HashMap<u32, Process>,
}

pub fn refresh(system: &mut System, counters: crate::hardware::Counters) -> Resources {
    system.refresh_cpu_usage();
    system.refresh_memory();
    system.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::nothing()
            .with_cpu()
            .with_memory()
            .with_disk_usage()
            .with_exe(UpdateKind::OnlyIfNotSet),
    );
    let processes = system
        .processes()
        .iter()
        .map(|(pid, value)| {
            let disk = value.disk_usage();
            let id = pid.as_u32();
            (
                id,
                Process {
                    id,
                    name: value.name().to_string_lossy().into_owned(),
                    path: value
                        .exe()
                        .filter(|path| path.is_absolute())
                        .map(PathBuf::from),
                    cpu: value.cpu_usage(),
                    memory: value.memory(),
                    disk: disk.read_bytes + disk.written_bytes,
                    gpu: counters.process_gpu.get(&id).copied(),
                },
            )
        })
        .collect();
    Resources {
        cpu: system.global_cpu_usage(),
        used_memory: system.used_memory(),
        total_memory: system.total_memory(),
        gpu: counters.gpu,
        disk_rate: counters.disk_rate,
        processes,
    }
}

#[derive(Default)]
pub struct Owners {
    tcp: HashMap<(SocketAddr, SocketAddr), Option<u32>>,
    udp: HashMap<SocketAddr, Option<u32>>,
}

impl Owners {
    pub fn get(&self, flow: Flow) -> Option<u32> {
        match flow.protocol {
            6 => self.tcp.get(&(flow.local, flow.remote)).copied().flatten(),
            17 => {
                let wildcard = SocketAddr::new(
                    if flow.local.is_ipv4() {
                        std::net::Ipv4Addr::UNSPECIFIED.into()
                    } else {
                        std::net::Ipv6Addr::UNSPECIFIED.into()
                    },
                    flow.local.port(),
                );
                self.udp
                    .get(&flow.local)
                    .or_else(|| self.udp.get(&wildcard))
                    .copied()
                    .flatten()
            }
            _ => None,
        }
    }

    #[cfg(not(windows))]
    pub fn read() -> Self {
        Self::default()
    }

    #[cfg(windows)]
    pub fn read() -> Self {
        use std::net::{Ipv4Addr, Ipv6Addr};
        use windows_sys::Win32::{
            NetworkManagement::IpHelper::*,
            Networking::WinSock::{AF_INET, AF_INET6},
        };

        fn insert<K: std::hash::Hash + Eq>(map: &mut HashMap<K, Option<u32>>, key: K, pid: u32) {
            map.entry(key)
                .and_modify(|old| {
                    if *old != Some(pid) {
                        *old = None;
                    }
                })
                .or_insert((pid != 0).then_some(pid));
        }
        let mut owners = Self::default();
        let addr4 = |ip: u32, port: u32| {
            SocketAddr::new(
                Ipv4Addr::from(ip.to_ne_bytes()).into(),
                u16::from_be(port as u16),
            )
        };
        let addr6 = |ip: [u8; 16], port: u32| {
            SocketAddr::new(Ipv6Addr::from(ip).into(), u16::from_be(port as u16))
        };
        for row in rows::<MIB_TCPROW_OWNER_PID>(|ptr, len| unsafe {
            GetExtendedTcpTable(ptr, len, 0, AF_INET.into(), TCP_TABLE_OWNER_PID_ALL, 0)
        }) {
            insert(
                &mut owners.tcp,
                (
                    addr4(row.dwLocalAddr, row.dwLocalPort),
                    addr4(row.dwRemoteAddr, row.dwRemotePort),
                ),
                row.dwOwningPid,
            );
        }
        for row in rows::<MIB_TCP6ROW_OWNER_PID>(|ptr, len| unsafe {
            GetExtendedTcpTable(ptr, len, 0, AF_INET6.into(), TCP_TABLE_OWNER_PID_ALL, 0)
        }) {
            insert(
                &mut owners.tcp,
                (
                    addr6(row.ucLocalAddr, row.dwLocalPort),
                    addr6(row.ucRemoteAddr, row.dwRemotePort),
                ),
                row.dwOwningPid,
            );
        }
        for row in rows::<MIB_UDPROW_OWNER_PID>(|ptr, len| unsafe {
            GetExtendedUdpTable(ptr, len, 0, AF_INET.into(), UDP_TABLE_OWNER_PID, 0)
        }) {
            insert(
                &mut owners.udp,
                addr4(row.dwLocalAddr, row.dwLocalPort),
                row.dwOwningPid,
            );
        }
        for row in rows::<MIB_UDP6ROW_OWNER_PID>(|ptr, len| unsafe {
            GetExtendedUdpTable(ptr, len, 0, AF_INET6.into(), UDP_TABLE_OWNER_PID, 0)
        }) {
            insert(
                &mut owners.udp,
                addr6(row.ucLocalAddr, row.dwLocalPort),
                row.dwOwningPid,
            );
        }
        owners
    }
}

#[cfg(windows)]
fn rows<T: Copy>(fetch: impl Fn(*mut core::ffi::c_void, &mut u32) -> u32) -> Vec<T> {
    use std::mem::{align_of, size_of};

    let mut size = 0;
    fetch(std::ptr::null_mut(), &mut size);
    let offset = size_of::<u32>().next_multiple_of(align_of::<T>());
    for _ in 0..3 {
        if size < offset as u32 || size > 32 * 1024 * 1024 {
            break;
        }
        let mut buffer = vec![0u64; (size as usize).div_ceil(8)];
        let result = fetch(buffer.as_mut_ptr().cast(), &mut size);
        if result == 122 {
            continue;
        }
        if result != 0 || size as usize > buffer.len() * 8 || (size as usize) < offset {
            break;
        }
        let count = (buffer[0] as u32 as usize).min((size as usize - offset) / size_of::<T>());
        let ptr = buffer.as_ptr().cast::<u8>();
        // The API fills a count followed by contiguous C rows. The bounds above include padding.
        return (0..count)
            .map(|i| unsafe {
                ptr.add(offset + i * size_of::<T>())
                    .cast::<T>()
                    .read_unaligned()
            })
            .collect();
    }
    Vec::new()
}
