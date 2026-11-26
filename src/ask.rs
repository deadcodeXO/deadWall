#[cfg(windows)]
pub use windows::Ask;

#[cfg(not(windows))]
pub struct Ask;

#[cfg(not(windows))]
impl Ask {
    pub fn new() -> Result<Self, String> {
        Err("Ask to Connect is available on Windows.".into())
    }
    pub fn pending(&mut self) -> &[Request] {
        &[]
    }
    pub fn decide(&mut self, _: usize, _: bool) -> Result<(), String> {
        Err("Ask to Connect is available on Windows.".into())
    }
}

pub struct Request {
    #[cfg(windows)]
    app: Vec<u8>,
    pub path: String,
}

#[cfg(windows)]
mod windows {
    use super::Request;
    use std::{
        collections::HashSet,
        ffi::c_void,
        ptr,
        sync::{
            atomic::{AtomicU64, Ordering},
            mpsc::{self, Receiver, SyncSender},
        },
    };
    use windows_sys::{
        Win32::{
            Foundation::HANDLE, NetworkManagement::WindowsFilteringPlatform::*,
            System::Rpc::RPC_C_AUTHN_WINNT,
        },
        core::GUID,
    };

    const SUBLAYER: GUID = GUID::from_u128(0xc74dc48c_80f4_476d_ae83_fe73bf5b7a85);
    const LAYERS: [GUID; 2] = [
        FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    ];

    struct Events {
        accepted_filters: [AtomicU64; 2],
        sender: SyncSender<Vec<u8>>,
    }

    pub struct Ask {
        engine: HANDLE,
        subscription: HANDLE,
        context: Option<Box<Events>>,
        receiver: Receiver<Vec<u8>>,
        pending: Vec<Request>,
        decided: HashSet<Vec<u8>>,
    }

    impl Ask {
        pub fn new() -> Result<Self, String> {
            let (sender, receiver) = mpsc::sync_channel(64);
            let mut ask = Self {
                engine: ptr::null_mut(),
                subscription: ptr::null_mut(),
                context: Some(Box::new(Events {
                    accepted_filters: [AtomicU64::new(0), AtomicU64::new(0)],
                    sender,
                })),
                receiver,
                pending: Vec::new(),
                decided: HashSet::new(),
            };
            let session = FWPM_SESSION0 {
                displayData: display(windows_sys::w!("deadWall Ask to Connect")),
                flags: FWPM_SESSION_FLAG_DYNAMIC,
                txnWaitTimeoutInMSec: 1000,
                ..Default::default()
            };
            // An engine session owns its dynamic filters. Connection attempts are received via the
            // bounded callback queue while this session exists.
            unsafe {
                check(FwpmEngineOpen0(
                    ptr::null(),
                    RPC_C_AUTHN_WINNT,
                    ptr::null(),
                    &session,
                    &mut ask.engine,
                ))?;
                let mut option = ptr::null_mut();
                check(FwpmEngineGetOption0(
                    ask.engine,
                    FWPM_ENGINE_COLLECT_NET_EVENTS,
                    &mut option,
                ))?;
                let enabled = !option.is_null()
                    && (*option).r#type == FWP_UINT32
                    && (*option).Anonymous.uint32 == 1;
                FwpmFreeMemory0((&mut option as *mut *mut FWP_VALUE0).cast());
                if !enabled {
                    return Err("Windows Filtering Platform event collection is disabled.".into());
                }
                let context = &**ask.context.as_ref().expect("context created");
                check(FwpmNetEventSubscribe0(
                    ask.engine,
                    &FWPM_NET_EVENT_SUBSCRIPTION0::default(),
                    Some(on_event),
                    (context as *const Events).cast(),
                    &mut ask.subscription,
                ))?;
                ask.transaction(|| {
                    let sublayer = FWPM_SUBLAYER0 {
                        subLayerKey: SUBLAYER,
                        displayData: display(windows_sys::w!("deadWall connection approval")),
                        weight: 0x7000,
                        ..Default::default()
                    };
                    check(FwpmSubLayerAdd0(ask.engine, &sublayer, ptr::null_mut()))?;
                    for (index, layer) in LAYERS.iter().copied().enumerate() {
                        let mut flags = FWPM_FILTER_CONDITION0 {
                            fieldKey: FWPM_CONDITION_FLAGS,
                            matchType: FWP_MATCH_FLAGS_NONE_SET,
                            conditionValue: FWP_CONDITION_VALUE0 {
                                r#type: FWP_UINT32,
                                Anonymous: FWP_CONDITION_VALUE0_0 {
                                    uint32: FWP_CONDITION_FLAG_IS_LOOPBACK,
                                },
                            },
                        };
                        let id = ask.add_filter(layer, FWP_ACTION_BLOCK, 1, &mut flags)?;
                        context.accepted_filters[index].store(id, Ordering::Release);
                    }
                    Ok(())
                })?;
            }
            Ok(ask)
        }

        pub fn pending(&mut self) -> &[Request] {
            for _ in 0..64 {
                let Ok(app) = self.receiver.try_recv() else {
                    break;
                };
                if self.decided.contains(&app)
                    || self.pending.iter().any(|request| request.app == app)
                    || self.pending.len() >= 128
                {
                    continue;
                }
                let words: Vec<_> = app
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                    .take_while(|&word| word != 0)
                    .collect();
                let path = String::from_utf16_lossy(&words);
                if !path.is_empty() {
                    self.pending.push(Request { app, path });
                }
            }
            &self.pending
        }

        pub fn decide(&mut self, index: usize, allow: bool) -> Result<(), String> {
            if self.decided.len() >= 4096 {
                return Err("The session reached its decision limit. Restart Ask to Connect to clear decisions.".into());
            }
            let request = self
                .pending
                .get(index)
                .ok_or("This connection request has expired.")?;
            if allow {
                let mut blob = FWP_BYTE_BLOB {
                    size: request.app.len() as u32,
                    data: request.app.as_ptr().cast_mut(),
                };
                self.transaction(|| {
                    for layer in LAYERS {
                        let mut condition = FWPM_FILTER_CONDITION0 {
                            fieldKey: FWPM_CONDITION_ALE_APP_ID,
                            matchType: FWP_MATCH_EQUAL,
                            conditionValue: FWP_CONDITION_VALUE0 {
                                r#type: FWP_BYTE_BLOB_TYPE,
                                Anonymous: FWP_CONDITION_VALUE0_0 {
                                    byteBlob: &mut blob,
                                },
                            },
                        };
                        self.add_filter(layer, FWP_ACTION_PERMIT, 15, &mut condition)?;
                    }
                    Ok(())
                })?;
            }
            self.decided.insert(self.pending.remove(index).app);
            Ok(())
        }

        fn transaction(&self, edit: impl FnOnce() -> Result<(), String>) -> Result<(), String> {
            // The closure uses the same session and all objects are rolled back on error.
            unsafe {
                check(FwpmTransactionBegin0(self.engine, 0))?;
                let result = edit().and_then(|()| check(FwpmTransactionCommit0(self.engine)));
                if result.is_err() {
                    FwpmTransactionAbort0(self.engine);
                }
                result
            }
        }

        fn add_filter(
            &self,
            layer: GUID,
            action: u32,
            weight: u8,
            condition: &mut FWPM_FILTER_CONDITION0,
        ) -> Result<u64, String> {
            let filter = FWPM_FILTER0 {
                displayData: display(windows_sys::w!("deadWall connection approval")),
                layerKey: layer,
                subLayerKey: SUBLAYER,
                weight: FWP_VALUE0 {
                    r#type: FWP_UINT8,
                    Anonymous: FWP_VALUE0_0 { uint8: weight },
                },
                numFilterConditions: 1,
                filterCondition: condition,
                action: FWPM_ACTION0 {
                    r#type: action,
                    ..Default::default()
                },
                ..Default::default()
            };
            let mut id = 0;
            // Windows copies the filter and condition before returning.
            unsafe {
                check(FwpmFilterAdd0(
                    self.engine,
                    &filter,
                    ptr::null_mut(),
                    &mut id,
                ))?;
            }
            Ok(id)
        }
    }

    impl Drop for Ask {
        fn drop(&mut self) {
            // Unsubscribe before freeing the callback context. Closing the dynamic session also
            // removes all filters and permits created by this connection approval session.
            unsafe {
                if self.engine.is_null() {
                    return;
                }
                let unsubscribed = self.subscription.is_null()
                    || FwpmNetEventUnsubscribe0(self.engine, self.subscription) == 0;
                let closed = FwpmEngineClose0(self.engine) == 0;
                if !unsubscribed
                    && !closed
                    && let Some(context) = self.context.take()
                {
                    Box::leak(context);
                }
            }
        }
    }

    unsafe extern "system" fn on_event(context: *mut c_void, event: *const FWPM_NET_EVENT1) {
        // The WFP callback owns these borrowed pointers for the duration of the call.
        unsafe {
            let Some(event) = event.as_ref() else {
                return;
            };
            if event.r#type != FWPM_NET_EVENT_TYPE_CLASSIFY_DROP
                || event.header.flags & FWPM_NET_EVENT_FLAG_APP_ID_SET == 0
            {
                return;
            }
            let Some(drop) = event.Anonymous.classifyDrop.as_ref() else {
                return;
            };
            let Some(context) = context.cast::<Events>().as_ref() else {
                return;
            };
            if !context
                .accepted_filters
                .iter()
                .any(|id| id.load(Ordering::Acquire) == drop.filterId && drop.filterId != 0)
            {
                return;
            }
            let blob = event.header.appId;
            if blob.data.is_null() || blob.size < 4 || blob.size > 32768 || blob.size % 2 != 0 {
                return;
            }
            let bytes = std::slice::from_raw_parts(blob.data, blob.size as usize).to_vec();
            let _ = context.sender.try_send(bytes);
        }
    }

    fn display(name: *const u16) -> FWPM_DISPLAY_DATA0 {
        FWPM_DISPLAY_DATA0 {
            name: name.cast_mut(),
            description: ptr::null_mut(),
        }
    }
    fn check(status: u32) -> Result<(), String> {
        if status == 0 {
            Ok(())
        } else {
            Err(format!(
                "Windows Filtering Platform returned 0x{status:08x} ({})",
                std::io::Error::from_raw_os_error(status as i32)
            ))
        }
    }
}
