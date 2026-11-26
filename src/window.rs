#[cfg(windows)]
pub fn fit_restored_window(frame: &eframe::Frame) {
    use raw_window_handle::{HasWindowHandle, RawWindowHandle};
    use windows_sys::Win32::{
        Foundation::RECT,
        Graphics::Gdi::{
            GetMonitorInfoW, MONITOR_DEFAULTTONEAREST, MONITORINFO, MonitorFromWindow,
        },
        UI::WindowsAndMessaging::{
            GetWindowRect, IsZoomed, SWP_NOACTIVATE, SWP_NOZORDER, SetWindowPos,
        },
    };

    let Ok(handle) = frame.window_handle() else {
        return;
    };
    let RawWindowHandle::Win32(handle) = handle.as_raw() else {
        return;
    };
    let hwnd = handle.hwnd.get() as windows_sys::Win32::Foundation::HWND;
    // The HWND is borrowed from the current frame and used on its owning event-loop thread.
    unsafe {
        if IsZoomed(hwnd) != 0 {
            return;
        }
        let monitor = MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST);
        let mut info = MONITORINFO {
            cbSize: std::mem::size_of::<MONITORINFO>() as u32,
            ..Default::default()
        };
        let mut window = RECT::default();
        if monitor.is_null()
            || GetMonitorInfoW(monitor, &mut info) == 0
            || GetWindowRect(hwnd, &mut window) == 0
        {
            return;
        }
        if let Some([x, y, width, height]) = fit(
            [window.left, window.top, window.right, window.bottom],
            [
                info.rcWork.left,
                info.rcWork.top,
                info.rcWork.right,
                info.rcWork.bottom,
            ],
        ) {
            SetWindowPos(
                hwnd,
                std::ptr::null_mut(),
                x,
                y,
                width,
                height,
                SWP_NOZORDER | SWP_NOACTIVATE,
            );
        }
    }
}

#[cfg(any(windows, test))]
fn fit(window: [i32; 4], work: [i32; 4]) -> Option<[i32; 4]> {
    let [left, top, right, bottom] = window;
    let [x, y, end_x, end_y] = work;
    let (window_width, window_height) = (right - left, bottom - top);
    let (work_width, work_height) = (end_x - x, end_y - y);
    if window_width <= 0 || window_height <= 0 || work_width <= 0 || work_height <= 0 {
        return None;
    }
    // Allow the invisible resize border around Windows' decorated windows.
    let margin = 8;
    if left >= x - margin
        && top >= y - margin
        && right <= end_x + margin
        && bottom <= end_y + margin
    {
        return None;
    }
    let width = window_width.min(work_width);
    let height = window_height.min(work_height);
    Some([
        left.clamp(x, end_x - width),
        top.clamp(y, end_y - height),
        width,
        height,
    ])
}

#[cfg(test)]
mod tests {
    #[test]
    fn restores_an_oversized_window_on_a_smaller_offset_monitor() {
        assert_eq!(
            super::fit([100, 25, 2600, 1400], [-1920, 0, 0, 1030]),
            Some([-1920, 0, 1920, 1030])
        );
        assert_eq!(
            super::fit([-1000, 25, -100, 830], [-1920, 0, 0, 1030]),
            None
        );
    }
}
