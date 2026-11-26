use std::collections::HashMap;

#[derive(Default)]
pub struct Counters {
    pub gpu: Option<f64>,
    pub disk_rate: Option<f64>,
    pub process_gpu: HashMap<u32, f64>,
}

#[cfg(not(windows))]
#[derive(Default)]
pub struct Platform;

#[cfg(not(windows))]
impl Platform {
    pub fn read(&mut self) -> Counters {
        Counters::default()
    }
}

#[cfg(windows)]
pub use windows::Platform;

#[cfg(windows)]
mod windows {
    use super::*;
    use std::ptr;
    use windows_sys::Win32::System::Performance::*;

    pub struct Platform {
        query: PDH_HQUERY,
        gpu: PDH_HCOUNTER,
        disk: PDH_HCOUNTER,
    }

    impl Default for Platform {
        fn default() -> Self {
            let mut result = Self {
                query: ptr::null_mut(),
                gpu: ptr::null_mut(),
                disk: ptr::null_mut(),
            };
            // PDH owns the counter handles and releases them with their parent query.
            unsafe {
                if PdhOpenQueryW(ptr::null(), 0, &mut result.query) == 0 {
                    let gpu = windows_sys::w!(r"\GPU Engine(*)\Utilization Percentage");
                    let disk = windows_sys::w!(r"\PhysicalDisk(_Total)\Disk Bytes/sec");
                    PdhAddEnglishCounterW(result.query, gpu, 0, &mut result.gpu);
                    PdhAddEnglishCounterW(result.query, disk, 0, &mut result.disk);
                    PdhCollectQueryData(result.query);
                }
            }
            result
        }
    }

    impl Drop for Platform {
        fn drop(&mut self) {
            if !self.query.is_null() {
                // This struct exclusively owns the query.
                unsafe {
                    PdhCloseQuery(self.query);
                }
            }
        }
    }

    impl Platform {
        pub fn read(&mut self) -> Counters {
            let mut values = Counters::default();
            if self.query.is_null() {
                return values;
            }
            // PDH returns data into aligned buffers owned by this call.
            unsafe {
                if PdhCollectQueryData(self.query) != 0 {
                    return values;
                }
                if !self.disk.is_null() {
                    let mut item = PDH_FMT_COUNTERVALUE::default();
                    if PdhGetFormattedCounterValue(
                        self.disk,
                        PDH_FMT_DOUBLE,
                        ptr::null_mut(),
                        &mut item,
                    ) == 0
                    {
                        values.disk_rate = number(item);
                    }
                }
                if self.gpu.is_null() {
                    return values;
                }
                let (mut size, mut count) = (0, 0);
                let status = PdhGetFormattedCounterArrayW(
                    self.gpu,
                    PDH_FMT_DOUBLE,
                    &mut size,
                    &mut count,
                    ptr::null_mut(),
                );
                if status != PDH_MORE_DATA || size > 8_388_608 || size == 0 {
                    return values;
                }
                let mut buffer = vec![0u64; (size as usize).div_ceil(8)];
                let array = buffer.as_mut_ptr().cast::<PDH_FMT_COUNTERVALUE_ITEM_W>();
                if PdhGetFormattedCounterArrayW(
                    self.gpu,
                    PDH_FMT_DOUBLE,
                    &mut size,
                    &mut count,
                    array,
                ) != 0
                    || count as usize
                        > buffer.len() * 8 / std::mem::size_of::<PDH_FMT_COUNTERVALUE_ITEM_W>()
                {
                    return values;
                }
                let mut engines = HashMap::<String, f64>::new();
                for item in std::slice::from_raw_parts(array, count as usize) {
                    if item.szName.is_null() {
                        continue;
                    }
                    let Some(utilization) = number(item.FmtValue) else {
                        continue;
                    };
                    let len = (0..).take_while(|&i| *item.szName.add(i) != 0).count();
                    let name =
                        String::from_utf16_lossy(std::slice::from_raw_parts(item.szName, len));
                    let Some((pid, engine)) = name
                        .strip_prefix("pid_")
                        .and_then(|rest| rest.split_once('_'))
                    else {
                        continue;
                    };
                    if let Ok(pid) = pid.parse::<u32>() {
                        let process = values.process_gpu.entry(pid).or_default();
                        *process = process.max(utilization);
                    }
                    *engines.entry(engine.to_owned()).or_default() += utilization;
                }
                values.gpu = engines
                    .into_values()
                    .reduce(f64::max)
                    .map(|value| value.clamp(0.0, 100.0));
            }
            values
        }
    }

    fn number(item: PDH_FMT_COUNTERVALUE) -> Option<f64> {
        if item.CStatus > 1 {
            return None;
        }
        // The caller requests PDH_FMT_DOUBLE, so this union contains a double.
        let value = unsafe { item.Anonymous.doubleValue };
        (value.is_finite() && value >= 0.0).then_some(value)
    }
}
