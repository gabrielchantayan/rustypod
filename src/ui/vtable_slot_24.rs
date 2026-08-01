//! `ui_dispatch_vtable_slot_24` — original: `FUN_0811f5a8` @ `0x0811f5a8`
//! (16 bytes).
//!
//! Given a UI dispatch record, the retailOS thunk loads its object pointer from
//! byte offset `+0x04`, loads that object's vtable, then tail-dispatches the
//! method at vtable byte offset `+0x24`. The four raw ARM instructions are
//! `ldr r0,[r0,#4]; ldr r2,[r0]; ldr r2,[r2,#0x24]; bx r2`: consequently the
//! incoming `r1` is forwarded unchanged, while `r2` becomes the method address
//! and `r3` and the virtual method's return value are preserved.
//!
//! Callers use this as an opaque UI data-provider slot-`+0x24` operation. The
//! target implementation remains unported; this module deliberately models only
//! the dispatch seam. Deviations: none.

/// ARM-byte offset of the object pointer in the dispatch record.
const DISPATCH_RECORD_OBJECT_OFFSET: usize = 0x04;

/// ARM-byte offset of the dispatched method in the UI object's vtable.
const VTABLE_SLOT_24_OFFSET: usize = 0x24;

/// ABI of the slot-`+0x24` method after the thunk replaces `r2` with its own
/// address. `r1` and `r3` remain the caller's register arguments.
type UiDataProviderSlot24 = unsafe extern "C" fn(*mut u8, usize, usize, usize) -> usize;

/// Tail-dispatches a UI data-provider's vtable slot `+0x24`.
///
/// Original: `FUN_0811f5a8` @ `0x0811f5a8` (16 bytes). The record and its
/// object are unchecked ARM-layout pointers. The object pointer is read from
/// byte offset `+0x04`, rather than from a host-sized struct field.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ui_dispatch_vtable_slot_24(
    dispatch_record: *mut u8,
    forwarded_r1: usize,
    _discarded_r2: usize,
    forwarded_r3: usize,
) -> usize {
    #[cfg(target_os = "none")]
    let object = unsafe {
        dispatch_record
            .add(DISPATCH_RECORD_OBJECT_OFFSET)
            .cast::<*mut u8>()
            .read()
    };
    #[cfg(not(target_os = "none"))]
    let object = unsafe {
        dispatch_record
            .add(DISPATCH_RECORD_OBJECT_OFFSET)
            .cast::<*mut u8>()
            .read_unaligned()
    };
    let vtable = unsafe { object.cast::<*const u8>().read() };
    #[cfg(target_os = "none")]
    let method = unsafe {
        vtable
            .add(VTABLE_SLOT_24_OFFSET)
            .cast::<UiDataProviderSlot24>()
            .read()
    };
    #[cfg(not(target_os = "none"))]
    let method = unsafe {
        vtable
            .add(VTABLE_SLOT_24_OFFSET)
            .cast::<UiDataProviderSlot24>()
            .read_unaligned()
    };

    unsafe { method(object, forwarded_r1, method as usize, forwarded_r3) }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::ptr;
    use std::sync::Mutex;

    static DISPATCH_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: usize = 0;
    static mut RECEIVED_OBJECT: *mut u8 = ptr::null_mut();
    static mut RECEIVED_R1: usize = 0;
    static mut RECEIVED_R2: usize = 0;
    static mut RECEIVED_R3: usize = 0;

    unsafe extern "C" fn recording_slot_24(
        object: *mut u8,
        r1: usize,
        r2: usize,
        r3: usize,
    ) -> usize {
        unsafe {
            CALLS += 1;
            RECEIVED_OBJECT = object;
            RECEIVED_R1 = r1;
            RECEIVED_R2 = r2;
            RECEIVED_R3 = r3;
        }
        0xcafe_babe
    }

    fn reset_recording() {
        unsafe {
            CALLS = 0;
            RECEIVED_OBJECT = ptr::null_mut();
            RECEIVED_R1 = 0;
            RECEIVED_R2 = 0;
            RECEIVED_R3 = 0;
        }
    }

    #[repr(align(8))]
    struct AlignedBytes<const N: usize>([u8; N]);

    fn write_pointer(storage: &mut [u8], offset: usize, value: *mut u8) {
        unsafe {
            storage
                .as_mut_ptr()
                .add(offset)
                .cast::<*mut u8>()
                .write_unaligned(value);
        }
    }

    #[test]
    fn dispatches_slot_24_and_transfers_the_object_pointer() {
        let _guard = DISPATCH_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        reset_recording();

        let mut dispatch_record = AlignedBytes::<32>([0xa5; 32]);
        let mut object = AlignedBytes::<32>([0x5a; 32]);
        let mut vtable = AlignedBytes::<64>([0x3c; 64]);
        write_pointer(&mut dispatch_record.0, DISPATCH_RECORD_OBJECT_OFFSET, object.0.as_mut_ptr());
        write_pointer(&mut object.0, 0, vtable.0.as_mut_ptr());
        unsafe {
            vtable
                .0
                .as_mut_ptr()
                .add(VTABLE_SLOT_24_OFFSET)
                .cast::<UiDataProviderSlot24>()
                .write_unaligned(recording_slot_24);
        }

        let result = unsafe {
            ui_dispatch_vtable_slot_24(
                dispatch_record.0.as_mut_ptr(),
                0x1111_2222,
                0x3333_4444,
                0x5555_6666,
            )
        };

        assert_eq!(result, 0xcafe_babe, "the virtual return value is preserved");
        unsafe {
            assert_eq!(CALLS, 1, "only vtable slot +0x24 is invoked");
            assert_eq!(RECEIVED_OBJECT, object.0.as_mut_ptr(), "r0 becomes the record's +0x04 object");
            assert_eq!(RECEIVED_R1, 0x1111_2222, "r1 is forwarded unchanged");
            assert_eq!(RECEIVED_R2, recording_slot_24 as usize, "the thunk overwrites r2");
            assert_eq!(RECEIVED_R3, 0x5555_6666, "r3 is forwarded unchanged");
        }
    }
}
