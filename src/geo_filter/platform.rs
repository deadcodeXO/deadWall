use std::ptr;
use windows_sys::{
    Win32::{
        Foundation::HANDLE, NetworkManagement::WindowsFilteringPlatform::*,
        System::Rpc::RPC_C_AUTHN_WINNT,
    },
    core::GUID,
};

use super::IpRange;

const SUBLAYER: GUID = GUID::from_u128(0x4aec38a9_a2f8_4384_b22b_0b7254a94543);

#[derive(Default)]
pub struct Filter {
    engine: HANDLE,
    ids: Vec<u64>,
}

impl Filter {
    pub fn apply(&mut self, ranges: &[IpRange]) -> Result<(), String> {
        if ranges.is_empty() && self.engine.is_null() {
            return Ok(());
        }
        // All operations run on the filter worker. Windows copies condition buffers during each call.
        unsafe {
            if self.engine.is_null() {
                let session = FWPM_SESSION0 {
                    flags: FWPM_SESSION_FLAG_DYNAMIC,
                    txnWaitTimeoutInMSec: 5000,
                    ..Default::default()
                };
                check(FwpmEngineOpen0(
                    ptr::null(),
                    RPC_C_AUTHN_WINNT,
                    ptr::null(),
                    &session,
                    &mut self.engine,
                ))?;
                let layer = FWPM_SUBLAYER0 {
                    subLayerKey: SUBLAYER,
                    displayData: display(),
                    weight: 0x7100,
                    ..Default::default()
                };
                if let Err(error) = check(FwpmSubLayerAdd0(self.engine, &layer, ptr::null_mut())) {
                    self.close();
                    return Err(error);
                }
            }
            check(FwpmTransactionBegin0(self.engine, 0))?;
            let result = (|| {
                for &id in &self.ids {
                    check(FwpmFilterDeleteById0(self.engine, id))?;
                }
                let mut ids = Vec::with_capacity(ranges.len().saturating_mul(2));
                for range in ranges {
                    let mut low = FWP_BYTE_ARRAY16 {
                        byteArray16: range.start.to_be_bytes(),
                    };
                    let mut high = FWP_BYTE_ARRAY16 {
                        byteArray16: range.end.to_be_bytes(),
                    };
                    let (mut value, layers) = if range.v6 {
                        (
                            FWP_RANGE0 {
                                valueLow: FWP_VALUE0 {
                                    r#type: FWP_BYTE_ARRAY16_TYPE,
                                    Anonymous: FWP_VALUE0_0 {
                                        byteArray16: &mut low,
                                    },
                                },
                                valueHigh: FWP_VALUE0 {
                                    r#type: FWP_BYTE_ARRAY16_TYPE,
                                    Anonymous: FWP_VALUE0_0 {
                                        byteArray16: &mut high,
                                    },
                                },
                            },
                            [
                                FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                                FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
                            ],
                        )
                    } else {
                        let value = |ip| FWP_VALUE0 {
                            r#type: FWP_UINT32,
                            Anonymous: FWP_VALUE0_0 { uint32: ip as u32 },
                        };
                        (
                            FWP_RANGE0 {
                                valueLow: value(range.start),
                                valueHigh: value(range.end),
                            },
                            [
                                FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                                FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
                            ],
                        )
                    };
                    let mut conditions = [
                        FWPM_FILTER_CONDITION0 {
                            fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                            matchType: FWP_MATCH_RANGE,
                            conditionValue: FWP_CONDITION_VALUE0 {
                                r#type: FWP_RANGE_TYPE,
                                Anonymous: FWP_CONDITION_VALUE0_0 {
                                    rangeValue: &mut value,
                                },
                            },
                        },
                        FWPM_FILTER_CONDITION0 {
                            fieldKey: FWPM_CONDITION_FLAGS,
                            matchType: FWP_MATCH_FLAGS_NONE_SET,
                            conditionValue: FWP_CONDITION_VALUE0 {
                                r#type: FWP_UINT32,
                                Anonymous: FWP_CONDITION_VALUE0_0 {
                                    uint32: FWP_CONDITION_FLAG_IS_LOOPBACK,
                                },
                            },
                        },
                    ];
                    for key in layers {
                        let filter = FWPM_FILTER0 {
                            displayData: display(),
                            layerKey: key,
                            subLayerKey: SUBLAYER,
                            weight: FWP_VALUE0 {
                                r#type: FWP_UINT8,
                                Anonymous: FWP_VALUE0_0 { uint8: 8 },
                            },
                            filterCondition: conditions.as_mut_ptr(),
                            numFilterConditions: conditions.len() as u32,
                            action: FWPM_ACTION0 {
                                r#type: FWP_ACTION_BLOCK,
                                ..Default::default()
                            },
                            ..Default::default()
                        };
                        let mut id = 0;
                        check(FwpmFilterAdd0(
                            self.engine,
                            &filter,
                            ptr::null_mut(),
                            &mut id,
                        ))?;
                        ids.push(id);
                    }
                }
                check(FwpmTransactionCommit0(self.engine))?;
                Ok(ids)
            })();
            match result {
                Ok(ids) => {
                    self.ids = ids;
                    if ranges.is_empty() {
                        self.close();
                    }
                    Ok(())
                }
                Err(error) => {
                    FwpmTransactionAbort0(self.engine);
                    Err(error)
                }
            }
        }
    }

    fn close(&mut self) {
        if !self.engine.is_null() {
            // Closing this exclusively owned dynamic session removes its filters.
            unsafe {
                FwpmEngineClose0(self.engine);
            }
            self.engine = ptr::null_mut();
        }
    }
}

impl Drop for Filter {
    fn drop(&mut self) {
        self.close();
    }
}

fn display() -> FWPM_DISPLAY_DATA0 {
    FWPM_DISPLAY_DATA0 {
        name: windows_sys::w!("deadWall geographic filtering").cast_mut(),
        description: ptr::null_mut(),
    }
}

fn check(status: u32) -> Result<(), String> {
    if status == 0 {
        Ok(())
    } else {
        Err(format!(
            "Windows Filtering Platform 0x{status:08x}: {}",
            std::io::Error::from_raw_os_error(status as i32)
        ))
    }
}
