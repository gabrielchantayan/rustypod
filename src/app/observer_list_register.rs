//! `observer_list_register` — original: `FUN_0812d718` @ 0x0812d718
//! (116 bytes, 0x0812d718..0x0812d78c; **4 plain `bl` call sites and 0
//! predicated `bl` call sites**).
//!
//! Allocates a 16-byte observer-list record from the context's embedded
//! allocator at +0x28, writes the supplied key and value at +0x08/+0x0c,
//! then inserts it after the intrusive-list anchor at +0x38. The anchor's
//! successor is repaired first; the context's registration count at +0x3c
//! increments with ARM's wrapping arithmetic.
//!
//! Raw ARM has one outbound direct `bl`, to `FUN_083dcb1c` @ 0x083dcb1c.
//! That allocator has no verified Rust identity or port. Target builds call
//! its fixed address; host tests use a replaceable ABI seam. The literal
//! `adds r0,#8; stmne` condition is retained: it suppresses key/value stores
//! only when the allocation result is exactly -8, although the following list
//! operations still require a valid record as they do in retailOS.

/// ABI of the unrecovered record allocator `FUN_083dcb1c`.
pub type ObserverRecordAlloc = unsafe extern "C" fn(*mut u32, u32, u32, u32, u32) -> *mut u32;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn observer_record_alloc() -> ObserverRecordAlloc {
    core::mem::transmute(0x083d_cb1cusize)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_observer_record_alloc(
    _allocator: *mut u32,
    _zero: u32,
    _value: u32,
    _mode: u32,
    _anchor: u32,
) -> *mut u32 {
    panic!("observer_list_register requires an observer-record allocator seam on host")
}

/// Host replacement for the unported observer-record allocator.
#[cfg(not(target_os = "none"))]
pub static mut OBSERVER_RECORD_ALLOC: ObserverRecordAlloc = missing_observer_record_alloc;

#[inline(always)]
unsafe fn allocate_observer_record(
    allocator: *mut u32,
    value: u32,
    mode: u32,
    anchor: u32,
) -> *mut u32 {
    #[cfg(target_os = "none")]
    {
        observer_record_alloc()(allocator, 0, value, mode, anchor)
    }
    #[cfg(not(target_os = "none"))]
    {
        core::ptr::read_volatile(core::ptr::addr_of!(OBSERVER_RECORD_ALLOC))(
            allocator, 0, value, mode, anchor,
        )
    }
}

/// Registers `key` and `value` in `context`'s observer list.
///
/// `context` must contain the target-width allocator state at +0x28, a valid
/// intrusive-list anchor pointer at +0x38, and its wrapping count at +0x3c.
/// The allocator result and the anchor's successor must be valid writable
/// 16-byte records. No null or bounds checks are added.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn observer_list_register(
    context: *mut u32,
    key: u32,
    value: u32,
    mode: u32,
) {
    let anchor = *context.add(14);
    let record = allocate_observer_record(context.add(10), value, mode, anchor);
    let payload = record.wrapping_add(2);
    if !payload.is_null() {
        *payload = key;
        *payload.add(1) = value;
    }

    *record = anchor;
    let successor = *(anchor as usize as *mut u32).add(1);
    *record.add(1) = successor;
    *(successor as usize as *mut u32) = record as usize as u32;
    *((anchor as usize as *mut u32).add(1)) = record as usize as u32;
    *context.add(15) = (*context.add(15)).wrapping_add(1);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, try_map_u32_slab};

    static TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    static mut ALLOCATED_RECORD: *mut u32 = core::ptr::null_mut();
    static mut ALLOC_CALL: (*mut u32, u32, u32, u32, u32) = (core::ptr::null_mut(), 1, 1, 1, 1);

    unsafe extern "C" fn record_alloc(
        allocator: *mut u32,
        zero: u32,
        value: u32,
        mode: u32,
        anchor: u32,
    ) -> *mut u32 {
        ALLOC_CALL = (allocator, zero, value, mode, anchor);
        ALLOCATED_RECORD
    }

    #[test]
    fn inserts_after_anchor_and_preserves_target_width_abi() {
        let _guard = TEST_LOCK.lock();
        let Some(base) = try_map_u32_slab(hints::OBSERVER_LIST_REGISTER, 0x1000) else {
            return;
        };
        unsafe {
            let context = base.cast::<u32>();
            let anchor = context.add(32);
            let successor = context.add(40);
            let record = context.add(48);
            *context.add(14) = anchor as usize as u32;
            *context.add(15) = u32::MAX;
            *anchor.add(1) = successor as usize as u32;
            *successor = anchor as usize as u32;
            ALLOCATED_RECORD = record;
            OBSERVER_RECORD_ALLOC = record_alloc;

            observer_list_register(context, 0x1122_3344, 0x5566_7788, 0x99aa_bbcc);

            assert_eq!(ALLOC_CALL, (context.add(10), 0, 0x5566_7788, 0x99aa_bbcc, anchor as usize as u32));
            assert_eq!(*record, anchor as usize as u32);
            assert_eq!(*record.add(1), successor as usize as u32);
            assert_eq!(*record.add(2), 0x1122_3344);
            assert_eq!(*record.add(3), 0x5566_7788);
            assert_eq!(*successor, record as usize as u32);
            assert_eq!(*anchor.add(1), record as usize as u32);
            assert_eq!(*context.add(15), 0);
            OBSERVER_RECORD_ALLOC = missing_observer_record_alloc;
        }
    }
}
