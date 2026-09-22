//! `ui_dispatch_slot_20_result_is_zero` — original: `FUN_0827a154` @
//! `0x0827a154` (40 bytes; true extent `0x0827a154..0x0827a17c`; one plain
//! `bl`, no predicated `bl`).
//!
//! The retailOS wrapper loads a UI dispatch record from the state object's ARM
//! word at `+0x10`. A null record returns zero without dispatching. Otherwise
//! it calls that record's vtable slot `+0x20` thunk and returns one when the
//! slot result is zero; a nonzero slot result passes through unchanged. The
//! wrapper preserves its incoming r1-r3 for the thunk, whose slot-`+0x20`
//! implementation discards r1. Deliberate deviations: host builds use an
//! unaligned pointer load so byte-accurate ARM-layout fixtures work on hosts;
//! firmware builds use the original aligned word load.

use super::vtable_slot_20::ui_dispatch_vtable_slot_20;

const STATE_DISPATCH_RECORD_OFFSET: usize = 0x10;

/// Calls the UI dispatch record's slot `+0x20` query and maps a zero result to
/// one.
///
/// Original: `FUN_0827a154` @ `0x0827a154` (40 bytes). `state` is an unchecked
/// ARM-layout pointer; its dispatch-record field is at byte offset `+0x10`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ui_dispatch_slot_20_result_is_zero(
    state: *mut u8,
    forwarded_r1: usize,
    forwarded_r2: usize,
    forwarded_r3: usize,
) -> usize {
    #[cfg(target_os = "none")]
    let dispatch_record = unsafe {
        state
            .add(STATE_DISPATCH_RECORD_OFFSET)
            .cast::<*mut u8>()
            .read()
    };
    #[cfg(not(target_os = "none"))]
    let dispatch_record = unsafe {
        state
            .add(STATE_DISPATCH_RECORD_OFFSET)
            .cast::<*mut u8>()
            .read_unaligned()
    };

    if dispatch_record.is_null() {
        return 0;
    }

    let result = unsafe {
        ui_dispatch_vtable_slot_20(dispatch_record, forwarded_r1, forwarded_r2, forwarded_r3)
    };
    if result == 0 { 1 } else { result }
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
    static mut RECEIVED_R2: usize = 0;
    static mut RECEIVED_R3: usize = 0;
    static mut SLOT_RESULT: usize = 0;

    type UiDataProviderSlot20 = unsafe extern "C" fn(*mut u8, usize, usize, usize) -> usize;

    #[repr(align(8))]
    struct AlignedBytes<const N: usize>([u8; N]);

    unsafe extern "C" fn recording_slot_20(
        object: *mut u8,
        _method: usize,
        forwarded_r2: usize,
        forwarded_r3: usize,
    ) -> usize {
        unsafe {
            CALLS += 1;
            RECEIVED_OBJECT = object;
            RECEIVED_R2 = forwarded_r2;
            RECEIVED_R3 = forwarded_r3;
            SLOT_RESULT
        }
    }

    fn reset_recording(result: usize) {
        unsafe {
            CALLS = 0;
            RECEIVED_OBJECT = ptr::null_mut();
            RECEIVED_R2 = 0;
            RECEIVED_R3 = 0;
            SLOT_RESULT = result;
        }
    }

    fn write_pointer(storage: &mut [u8], offset: usize, value: *mut u8) {
        unsafe {
            storage
                .as_mut_ptr()
                .add(offset)
                .cast::<*mut u8>()
                .write_unaligned(value);
        }
    }

    fn make_state_and_dispatch_record(
        state: &mut AlignedBytes<32>,
        dispatch_record: &mut AlignedBytes<32>,
        object: &mut AlignedBytes<32>,
        vtable: &mut AlignedBytes<64>,
    ) {
        write_pointer(&mut state.0, STATE_DISPATCH_RECORD_OFFSET, dispatch_record.0.as_mut_ptr());
        write_pointer(&mut dispatch_record.0, 4, object.0.as_mut_ptr());
        write_pointer(&mut object.0, 0, vtable.0.as_mut_ptr());
        unsafe {
            vtable
                .0
                .as_mut_ptr()
                .add(0x20)
                .cast::<UiDataProviderSlot20>()
                .write_unaligned(recording_slot_20);
        }
    }

    #[test]
    fn null_dispatch_record_returns_zero_without_calling_the_slot() {
        let _guard = DISPATCH_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        reset_recording(0);
        let mut state = AlignedBytes::<32>([0; 32]);

        let result = unsafe { ui_dispatch_slot_20_result_is_zero(state.0.as_mut_ptr(), 1, 2, 3) };

        assert_eq!(result, 0);
        assert_eq!(unsafe { CALLS }, 0);
    }

    #[test]
    fn zero_slot_result_becomes_one_and_forwards_register_arguments() {
        let _guard = DISPATCH_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        reset_recording(0);
        let mut state = AlignedBytes::<32>([0; 32]);
        let mut dispatch_record = AlignedBytes::<32>([0; 32]);
        let mut object = AlignedBytes::<32>([0; 32]);
        let mut vtable = AlignedBytes::<64>([0; 64]);
        make_state_and_dispatch_record(&mut state, &mut dispatch_record, &mut object, &mut vtable);

        let result = unsafe {
            ui_dispatch_slot_20_result_is_zero(
                state.0.as_mut_ptr(),
                0x1111_2222,
                0x3333_4444,
                0x5555_6666,
            )
        };

        assert_eq!(result, 1);
        unsafe {
            assert_eq!(CALLS, 1);
            assert_eq!(RECEIVED_OBJECT, object.0.as_mut_ptr());
            assert_eq!(RECEIVED_R2, 0x3333_4444);
            assert_eq!(RECEIVED_R3, 0x5555_6666);
        }
    }

    #[test]
    fn nonzero_slot_result_passes_through_unchanged() {
        let _guard = DISPATCH_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        reset_recording(0xfeed_cafe);
        let mut state = AlignedBytes::<32>([0; 32]);
        let mut dispatch_record = AlignedBytes::<32>([0; 32]);
        let mut object = AlignedBytes::<32>([0; 32]);
        let mut vtable = AlignedBytes::<64>([0; 64]);
        make_state_and_dispatch_record(&mut state, &mut dispatch_record, &mut object, &mut vtable);

        let result = unsafe { ui_dispatch_slot_20_result_is_zero(state.0.as_mut_ptr(), 0, 0, 0) };

        assert_eq!(result, 0xfeed_cafe);
        assert_eq!(unsafe { CALLS }, 1);
    }
}
