//! Retrieve secondary record data — FUN_081b103c at load address 0x081b103c.
//!
//! True extent [0x081b103c, 0x081b1068), 44 bytes; next word is a new push.
//! Raw A32 decoding verifies two inbound and two outbound plain BLs, zero
//! predicated BLs. Acquire the record manager, then call its secondary-record
//! data operation with the caller's 64-bit key and data/length output pointers.
//! Return the operation's failure flag unchanged (both callers discard it).
//!
//! The retail operation at 0x081c88d0 ignores the key: it selects the current
//! secondary registration and invokes virtual slot +0x4c with the two outputs.
//! Missing registration or nonzero virtual result yields one; zero yields zero.
//! Deliberate deviations: set its unused r1 argument to zero rather than retain
//! getter scratch state. Keep the retail getter because the Rust constructor
//! is incomplete. Host operations replace retail addresses; no device execution.

#[derive(Clone, Copy)]
pub struct RecordSecondaryDataOps {
    pub manager_get: unsafe extern "C" fn() -> *mut u8,
    pub data_get: unsafe extern "C" fn(*mut u8, u32, u64, *mut *mut u8, *mut u32) -> u32,
}

#[cfg(not(target_os = "none"))]
pub static mut RECORD_SECONDARY_DATA_OPS: Option<RecordSecondaryDataOps> = None;

/// # Safety
/// Retail manager state must be initialized. Output pointers must satisfy the
/// current secondary record's virtual +0x4c contract. Host callers must install
/// operations and hold exclusive access to the operation table.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn record_secondary_data_get(
    key: u64, data: *mut *mut u8, length: *mut u32,
) -> u32 {
    #[cfg(target_os = "none")]
    let ops = RecordSecondaryDataOps {
        manager_get: core::mem::transmute(0x081c_83b4usize),
        data_get: core::mem::transmute(0x081c_88d0usize),
    };
    #[cfg(not(target_os = "none"))]
    let ops = core::ptr::addr_of!(RECORD_SECONDARY_DATA_OPS).read()
        .expect("install secondary-record host operations");
    (ops.data_get)((ops.manager_get)(), 0, key, data, length)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::cell::RefCell;

    struct CurrentRecord { present: bool, failure: u32, bytes: [u8; 3] }
    std::thread_local! {
        static RECORD: RefCell<CurrentRecord> = RefCell::new(CurrentRecord {
            present: false, failure: 0, bytes: [0x41, 0, 0xff],
        });
    }
    unsafe extern "C" fn manager_get() -> *mut u8 {
        RECORD.with(|r| r.as_ptr().cast())
    }
    // Host reference for the verified retail operation: current registration,
    // not key lookup; absent registration never dereferences the outputs.
    unsafe extern "C" fn current_data_get(
        manager: *mut u8, _: u32, _: u64, data: *mut *mut u8, length: *mut u32,
    ) -> u32 {
        let record = &mut *manager.cast::<CurrentRecord>();
        if !record.present { return 1; }
        data.write(record.bytes.as_mut_ptr());
        length.write(record.bytes.len() as u32);
        u32::from(record.failure != 0)
    }

    #[test]
    fn absent_current_record_allows_null_outputs_and_leaves_existing_outputs_untouched() {
        unsafe {
            let saved = core::ptr::addr_of!(RECORD_SECONDARY_DATA_OPS).read();
            RECORD_SECONDARY_DATA_OPS = Some(RecordSecondaryDataOps {
                manager_get, data_get: current_data_get,
            });
            RECORD.with(|r| r.borrow_mut().present = false);
            assert_eq!(record_secondary_data_get(u64::MAX, core::ptr::null_mut(), core::ptr::null_mut()), 1);
            let mut byte = 0x72u8;
            let original = &mut byte as *mut u8;
            let mut data = original;
            let mut length = 0x1234_5678;
            assert_eq!(record_secondary_data_get(0, &mut data, &mut length), 1);
            assert_eq!(data, original);
            assert_eq!(length, 0x1234_5678);
            RECORD_SECONDARY_DATA_OPS = saved;
        }
        current_record_data_is_key_independent_even_when_virtual_operation_fails();
    }

    fn current_record_data_is_key_independent_even_when_virtual_operation_fails() {
        unsafe {
            let saved = core::ptr::addr_of!(RECORD_SECONDARY_DATA_OPS).read();
            RECORD_SECONDARY_DATA_OPS = Some(RecordSecondaryDataOps {
                manager_get, data_get: current_data_get,
            });
            for failure in [0, 1, u32::MAX] {
                RECORD.with(|r| { let mut r = r.borrow_mut(); r.present = true; r.failure = failure; });
                for key in [0, 1, 0xffff_ffff, 0x1_0000_0000, u64::MAX] {
                    let mut data = core::ptr::null_mut();
                    let mut length = 0;
                    assert_eq!(record_secondary_data_get(key, &mut data, &mut length), u32::from(failure != 0));
                    assert_eq!(core::slice::from_raw_parts(data, length as usize), &[0x41, 0, 0xff]);
                }
            }
            RECORD_SECONDARY_DATA_OPS = saved;
        }
    }
}
