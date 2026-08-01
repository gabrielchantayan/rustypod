//! `ui_dispatch_vtable_slot_20` — original: `FUN_0811f598` @ `0x0811f598`
//! (16 bytes).
//!
//! Given a UI dispatch record, the retailOS thunk loads its object pointer from
//! byte offset `+0x04`, loads that object's vtable, then tail-dispatches the
//! method at vtable byte offset `+0x20`.  The four raw ARM instructions are
//! `ldr r0,[r0,#4]; ldr r1,[r0]; ldr r1,[r1,#0x20]; bx r1`: consequently the
//! incoming `r1` is discarded and replaced with the method address, while
//! `r2`, `r3`, and the virtual method's return value are preserved.
//!
//! Callers use this as the UI data-provider's slot-`+0x20` query. The target
//! implementation remains unported; this module deliberately models only the
//! dispatch seam. Deviations: none.

/// ARM-byte offset of the object pointer in the dispatch record.
const DISPATCH_RECORD_OBJECT_OFFSET: usize = 0x04;

/// ARM-byte offset of the queried method in the UI object's vtable.
const VTABLE_SLOT_20_OFFSET: usize = 0x20;

/// ABI of the slot-`+0x20` method after the thunk has replaced `r1` with its
/// own address. `r2` and `r3` remain the caller's register arguments.
type UiDataProviderSlot20 = unsafe extern "C" fn(*mut u8, usize, usize, usize) -> usize;

/// Tail-dispatches a UI data-provider's vtable slot `+0x20`.
///
/// Original: `FUN_0811f598` @ `0x0811f598` (16 bytes). The record and its
/// object are unchecked ARM-layout pointers. The object pointer is read from
/// byte offset `+0x04`, rather than from a host-sized struct field.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ui_dispatch_vtable_slot_20(
    dispatch_record: *mut u8,
    _discarded_r1: usize,
    forwarded_r2: usize,
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
    let method = unsafe {
        vtable
            .add(VTABLE_SLOT_20_OFFSET)
            .cast::<UiDataProviderSlot20>()
            .read()
    };

    unsafe { method(object, method as usize, forwarded_r2, forwarded_r3) }
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

    unsafe extern "C" fn recording_slot_20(
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
    fn dispatches_slot_20_with_the_object_and_tail_call_registers() {
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
                .add(VTABLE_SLOT_20_OFFSET)
                .cast::<UiDataProviderSlot20>()
                .write_unaligned(recording_slot_20);
        }

        let result = unsafe {
            ui_dispatch_vtable_slot_20(
                dispatch_record.0.as_mut_ptr(),
                0x1111_2222,
                0x3333_4444,
                0x5555_6666,
            )
        };

        assert_eq!(result, 0xcafe_babe, "the virtual return value is preserved");
        unsafe {
            assert_eq!(CALLS, 1, "only slot +0x20 is invoked");
            assert_eq!(RECEIVED_OBJECT, object.0.as_mut_ptr());
            assert_eq!(RECEIVED_R1, recording_slot_20 as usize, "the thunk overwrites r1");
            assert_eq!(RECEIVED_R2, 0x3333_4444, "r2 is forwarded unchanged");
            assert_eq!(RECEIVED_R3, 0x5555_6666, "r3 is forwarded unchanged");
        }
    }

    #[test]
    fn dispatch_record_uses_the_arm_plus_four_object_word() {
        let _guard = DISPATCH_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        reset_recording();

        let mut dispatch_record = AlignedBytes::<32>([0; 32]);
        let mut object = AlignedBytes::<32>([0; 32]);
        let mut vtable = AlignedBytes::<64>([0; 64]);
        write_pointer(&mut dispatch_record.0, DISPATCH_RECORD_OBJECT_OFFSET, object.0.as_mut_ptr());
        write_pointer(&mut object.0, 0, vtable.0.as_mut_ptr());
        unsafe {
            vtable
                .0
                .as_mut_ptr()
                .add(VTABLE_SLOT_20_OFFSET)
                .cast::<UiDataProviderSlot20>()
                .write_unaligned(recording_slot_20);
            ui_dispatch_vtable_slot_20(dispatch_record.0.as_mut_ptr(), 0, 0, 0);
            assert_eq!(RECEIVED_OBJECT, object.0.as_mut_ptr());
            assert_eq!(CALLS, 1);
        }
    }
}
