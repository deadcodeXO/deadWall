use std::{
    collections::HashSet,
    net::{Ipv4Addr, Ipv6Addr},
    ptr,
};
use windows_sys::Win32::{
    Foundation::GlobalFree,
    NetworkManagement::{IpHelper::*, WiFi::*},
    Networking::{
        WinHttp::{WINHTTP_CURRENT_USER_IE_PROXY_CONFIG, WinHttpGetIEProxyConfigForCurrentUser},
        WinSock::*,
    },
    System::SystemInformation::GetTickCount,
    UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO},
};

pub fn idle_ms() -> Option<u32> {
    let mut input = LASTINPUTINFO {
        cbSize: std::mem::size_of::<LASTINPUTINFO>() as u32,
        dwTime: 0,
    };
    // GetLastInputInfo fills the size-tagged struct for the current interactive session.
    unsafe {
        (GetLastInputInfo(&mut input) != 0).then(|| GetTickCount().wrapping_sub(input.dwTime))
    }
}

pub fn proxy() -> Option<String> {
    // WinHTTP allocates the optional output strings with GlobalAlloc.
    unsafe {
        let mut config = WINHTTP_CURRENT_USER_IE_PROXY_CONFIG::default();
        if WinHttpGetIEProxyConfigForCurrentUser(&mut config) == 0 {
            return None;
        }
        let mut parts = vec![config.fAutoDetect.to_string()];
        for ptr in [
            config.lpszAutoConfigUrl,
            config.lpszProxy,
            config.lpszProxyBypass,
        ] {
            if ptr.is_null() {
                parts.push(String::new());
            } else {
                let len = (0..).take_while(|&index| *ptr.add(index) != 0).count();
                parts.push(String::from_utf16_lossy(std::slice::from_raw_parts(
                    ptr, len,
                )));
                GlobalFree(ptr.cast());
            }
        }
        Some(parts.join("\n"))
    }
}

pub fn dns() -> Option<Vec<String>> {
    let mut size = 15000;
    for _ in 0..3 {
        if size > 1_048_576 {
            return None;
        }
        let mut buffer = vec![0u64; (size as usize).div_ceil(8)];
        let start = buffer.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        // Returned linked records point into this aligned buffer and remain valid during traversal.
        unsafe {
            let status = GetAdaptersAddresses(
                AF_UNSPEC.into(),
                GAA_FLAG_SKIP_UNICAST
                    | GAA_FLAG_SKIP_ANYCAST
                    | GAA_FLAG_SKIP_MULTICAST
                    | GAA_FLAG_SKIP_FRIENDLY_NAME,
                ptr::null(),
                start,
                &mut size,
            );
            if status == 111 {
                continue;
            }
            if status != 0 {
                return None;
            }
            let mut servers = Vec::new();
            let mut adapter = start;
            while let Some(row) = adapter.as_ref() {
                if row.OperStatus == 1 {
                    let mut server = row.FirstDnsServerAddress;
                    while let Some(dns) = server.as_ref() {
                        let address = dns.Address.lpSockaddr;
                        let len = dns.Address.iSockaddrLength as usize;
                        let ip = match address.as_ref().map(|value| value.sa_family) {
                            Some(AF_INET) if len >= std::mem::size_of::<SOCKADDR_IN>() => Some(
                                Ipv4Addr::from(
                                    (*address.cast::<SOCKADDR_IN>())
                                        .sin_addr
                                        .S_un
                                        .S_addr
                                        .to_ne_bytes(),
                                )
                                .to_string(),
                            ),
                            Some(AF_INET6) if len >= std::mem::size_of::<SOCKADDR_IN6>() => Some(
                                Ipv6Addr::from((*address.cast::<SOCKADDR_IN6>()).sin6_addr.u.Byte)
                                    .to_string(),
                            ),
                            _ => None,
                        };
                        if let Some(ip) = ip {
                            servers.push(ip);
                        }
                        server = dns.Next;
                    }
                }
                adapter = row.Next;
            }
            return Some(servers);
        }
    }
    None
}

pub fn wifi() -> Option<HashSet<String>> {
    use std::ffi::c_void;
    struct Memory(*const c_void);
    impl Drop for Memory {
        fn drop(&mut self) {
            // The allocation belongs to a WLAN API output parameter.
            unsafe {
                WlanFreeMemory(self.0);
            }
        }
    }
    struct Client(windows_sys::Win32::Foundation::HANDLE);
    impl Drop for Client {
        fn drop(&mut self) {
            // This guard exclusively owns the WLAN session.
            unsafe {
                WlanCloseHandle(self.0, ptr::null());
            }
        }
    }
    let mut anomalies = HashSet::new();
    // The WLAN service creates and sizes the interface and network lists.
    unsafe {
        let mut handle = ptr::null_mut();
        if WlanOpenHandle(2, ptr::null(), &mut 0, &mut handle) != 0 {
            return None;
        }
        let client = Client(handle);
        let mut interfaces = ptr::null_mut();
        if WlanEnumInterfaces(client.0, ptr::null(), &mut interfaces) != 0 || interfaces.is_null() {
            return None;
        }
        let _interfaces = Memory(interfaces.cast());
        let interfaces = std::slice::from_raw_parts(
            ptr::addr_of!((*interfaces).InterfaceInfo).cast::<WLAN_INTERFACE_INFO>(),
            (*interfaces).dwNumberOfItems as usize,
        );
        for interface in interfaces {
            if interface.isState != wlan_interface_state_connected {
                continue;
            }
            let mut networks = ptr::null_mut();
            if WlanGetAvailableNetworkList(
                client.0,
                &interface.InterfaceGuid,
                0,
                ptr::null(),
                &mut networks,
            ) != 0
                || networks.is_null()
            {
                continue;
            }
            let _networks = Memory(networks.cast());
            let list = std::slice::from_raw_parts(
                ptr::addr_of!((*networks).Network).cast::<WLAN_AVAILABLE_NETWORK>(),
                (*networks).dwNumberOfItems as usize,
            );
            for active in list.iter().filter(|net| {
                net.dwFlags & WLAN_AVAILABLE_NETWORK_CONNECTED != 0 && net.bSecurityEnabled != 0
            }) {
                let len =
                    (active.dot11Ssid.uSSIDLength as usize).min(active.dot11Ssid.ucSSID.len());
                let ssid = &active.dot11Ssid.ucSSID[..len];
                if !ssid.is_empty()
                    && list.iter().any(|net| {
                        (net.bSecurityEnabled == 0
                            || net.dot11DefaultAuthAlgorithm != active.dot11DefaultAuthAlgorithm
                            || net.dot11DefaultCipherAlgorithm
                                != active.dot11DefaultCipherAlgorithm)
                            && net.dot11Ssid.uSSIDLength as usize == len
                            && &net.dot11Ssid.ucSSID[..len] == ssid
                    })
                {
                    anomalies.insert(String::from_utf8_lossy(ssid).into_owned());
                }
            }
        }
    }
    Some(anomalies)
}
