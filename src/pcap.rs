use std::{
    ffi::{CStr, CString, c_char, c_int, c_long, c_void},
    ptr::{self, NonNull},
};

use libloading::Library;

const ERRBUF_SIZE: usize = 256;
const SNAPLEN: usize = 256;

#[repr(C)]
struct Interface {
    next: *const Interface,
    name: *const c_char,
    description: *const c_char,
    addresses: *const c_void,
    flags: u32,
}

#[repr(C)]
struct PacketHeader {
    seconds: c_long,
    microseconds: c_long,
    captured_len: u32,
    original_len: u32,
}

#[derive(Clone)]
pub struct Adapter {
    pub name: String,
    pub label: String,
    pub physical_candidate: bool,
}

struct Api {
    _library: Library,
    find_devices: unsafe extern "C" fn(*mut *const Interface, *mut c_char) -> c_int,
    free_devices: unsafe extern "C" fn(*const Interface),
    open_live: unsafe extern "C" fn(*const c_char, c_int, c_int, c_int, *mut c_char) -> *mut c_void,
    set_nonblock: unsafe extern "C" fn(*mut c_void, c_int, *mut c_char) -> c_int,
    datalink: unsafe extern "C" fn(*mut c_void) -> c_int,
    next: unsafe extern "C" fn(*mut c_void, *mut *const PacketHeader, *mut *const u8) -> c_int,
    get_error: unsafe extern "C" fn(*mut c_void) -> *const c_char,
    close: unsafe extern "C" fn(*mut c_void),
}

impl Api {
    fn load() -> Result<Self, String> {
        let library = load_library()?;
        // Each signature matches the public libpcap C ABI. The library outlives every symbol.
        unsafe {
            macro_rules! symbol {
                ($name:literal) => {
                    *library
                        .get(concat!($name, "\0").as_bytes())
                        .map_err(|e| e.to_string())?
                };
            }
            Ok(Self {
                find_devices: symbol!("pcap_findalldevs"),
                free_devices: symbol!("pcap_freealldevs"),
                open_live: symbol!("pcap_open_live"),
                set_nonblock: symbol!("pcap_setnonblock"),
                datalink: symbol!("pcap_datalink"),
                next: symbol!("pcap_next_ex"),
                get_error: symbol!("pcap_geterr"),
                close: symbol!("pcap_close"),
                _library: library,
            })
        }
    }
}

#[cfg(windows)]
fn load_library() -> Result<Library, String> {
    use std::{ffi::OsString, os::windows::ffi::OsStringExt, path::PathBuf};
    use windows_sys::Win32::System::LibraryLoader::{
        LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR, LOAD_LIBRARY_SEARCH_SYSTEM32,
    };

    use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;

    let mut path = [0u16; 32768];
    // The OS writes at most the supplied buffer length.
    let length = unsafe { GetSystemDirectoryW(path.as_mut_ptr(), path.len() as u32) } as usize;
    if length == 0 || length >= path.len() {
        return Err("Cannot resolve the Windows system directory".into());
    }
    let path = PathBuf::from(OsString::from_wide(&path[..length])).join("Npcap/wpcap.dll");
    // Load only from the system-managed Npcap directory and search system directories for dependencies.
    unsafe {
        libloading::os::windows::Library::load_with_flags(
            path,
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32,
        )
    }
    .map(Into::into)
    .map_err(|error| format!("Npcap unavailable ({error}). Install Npcap to capture packets."))
}

#[cfg(not(windows))]
fn load_library() -> Result<Library, String> {
    #[cfg(target_os = "macos")]
    let names = ["/usr/lib/libpcap.A.dylib", "/usr/lib/libpcap.dylib"];
    #[cfg(not(target_os = "macos"))]
    let names = ["libpcap.so.1", "libpcap.so.0.8", "libpcap.so"];
    for name in names {
        // These are the platform library names, resolved by the native loader.
        if let Ok(library) = unsafe { Library::new(name) } {
            return Ok(library);
        }
    }
    Err("libpcap unavailable. Install the platform libpcap package.".into())
}

pub fn adapters() -> Result<Vec<Adapter>, String> {
    let api = Api::load()?;
    let mut head = ptr::null();
    let mut error = [0; ERRBUF_SIZE];
    // libpcap owns the resulting list until free_devices is called.
    unsafe {
        if (api.find_devices)(&mut head, error.as_mut_ptr()) != 0 {
            return Err(message(error.as_ptr()));
        }
        let mut result = Vec::new();
        let mut current = head;
        while let Some(entry) = current.as_ref() {
            let name = message(entry.name);
            if entry.addresses.is_null() || name == "any" || name.is_empty() {
                current = entry.next;
                continue;
            }
            let description = message(entry.description);
            result.push(Adapter {
                label: if description.is_empty() {
                    name.clone()
                } else {
                    description
                },
                physical_candidate: entry.flags & 1 == 0
                    && entry.flags & 2 != 0
                    && entry.flags & 0x30 != 0x20,
                name,
            });
            current = entry.next;
        }
        if !head.is_null() {
            (api.free_devices)(head);
        }
        Ok(result)
    }
}

// All callers pass a libpcap-owned or zero-initialized error string for the duration of this call.
unsafe fn message(value: *const c_char) -> String {
    if value.is_null() {
        String::new()
    } else {
        unsafe { CStr::from_ptr(value) }
            .to_string_lossy()
            .into_owned()
    }
}

pub struct Capture {
    api: Api,
    handle: NonNull<c_void>,
    pub link_type: c_int,
}

impl Capture {
    pub fn open(adapter: &Adapter) -> Result<Self, String> {
        let api = Api::load()?;
        let name = CString::new(adapter.name.as_str()).map_err(|e| e.to_string())?;
        let mut error = [0; ERRBUF_SIZE];
        // The handle is owned by Capture as soon as open_live returns successfully.
        unsafe {
            let handle =
                (api.open_live)(name.as_ptr(), SNAPLEN as c_int, 0, 20, error.as_mut_ptr());
            let handle = NonNull::new(handle).ok_or_else(|| message(error.as_ptr()))?;
            let link_type = (api.datalink)(handle.as_ptr());
            let capture = Self {
                api,
                handle,
                link_type,
            };
            if (capture.api.set_nonblock)(handle.as_ptr(), 1, error.as_mut_ptr()) != 0 {
                return Err(message(error.as_ptr()));
            }
            if !matches!(link_type, 0 | 1 | 12 | 101 | 108 | 113 | 276) {
                return Err(format!("Unsupported capture link type {link_type}"));
            }
            Ok(capture)
        }
    }

    pub fn next(&mut self) -> Result<Option<(&[u8], u32)>, String> {
        let mut header = ptr::null();
        let mut data = ptr::null();
        // A successful read borrows packet bytes until the next read or handle close.
        unsafe {
            match (self.api.next)(self.handle.as_ptr(), &mut header, &mut data) {
                1 if !header.is_null() && !data.is_null() => {
                    let header = &*header;
                    let len = header.captured_len as usize;
                    if len > SNAPLEN || header.captured_len > header.original_len {
                        return Err("Capture driver returned an invalid packet length".into());
                    }
                    Ok(Some((
                        std::slice::from_raw_parts(data, len),
                        header.original_len,
                    )))
                }
                0 => Ok(None),
                -1 => Err(message((self.api.get_error)(self.handle.as_ptr()))),
                _ => Err("Capture ended unexpectedly".into()),
            }
        }
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        // This is the sole owner of the live libpcap handle.
        unsafe { (self.api.close)(self.handle.as_ptr()) };
    }
}
