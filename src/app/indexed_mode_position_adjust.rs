//! `indexed_mode_position_adjust` — `FUN_082202ec` at `0x082202ec`.
//! 112 bytes, `0x082202ec..0x0822035c`; the next entry resets fields.
//! Raw A32 decoding finds three plain outbound BLs, zero predicated BLs;
//! two plain inbound BLs, zero predicated BLs.
//!
//! Reject negative indices and disabled state bit 0 at +0x8a4. Resolve an
//! indexed position through the object word at +0x8a8; reject failed lookup
//! and UINT32_MAX. If it differs from the active backend position, dispatch
//! mode zero with the wrapping difference and return one, ignoring the
//! dispatcher's result. Otherwise return zero.
//!
//! Deviations: Ghidra's unused third/fourth arguments are omitted (raw code
//! never reads r3 or incoming r2). The unported resolver at 0x082109b4 is a
//! fixed-address ARM call with a replaceable host seam; its class identity
//! is unknown. Initialize its output locally; retail reads it only on success.

use super::mode_selected_position::mode_selected_position;
use super::mode_selected_position_set::mode_selected_position_set;

type ResolveIndexedPosition = unsafe extern "C" fn(u32, *mut u32, i32) -> u32;

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_resolver(_: u32, _: *mut u32, _: i32) -> u32 {
    panic!("retail indexed-position resolver requires a host replacement")
}

#[cfg(not(target_arch = "arm"))]
static mut RESOLVE_INDEXED_POSITION: ResolveIndexedPosition = missing_resolver;

#[inline(always)]
unsafe fn resolve_indexed_position(object: u32, output: *mut u32, index: i32) -> u32 {
    #[cfg(target_arch = "arm")]
    let resolve: ResolveIndexedPosition = core::mem::transmute(0x0821_09b4usize);
    #[cfg(not(target_arch = "arm"))]
    let resolve = core::ptr::read_volatile(core::ptr::addr_of!(RESOLVE_INDEXED_POSITION));
    resolve(object, output, index)
}

/// # Safety
/// For nonnegative indices, `state` must be readable through +0x8a4.
/// Enabled states also require an aligned object word at +0x8a8 and valid
/// resolver/backend objects satisfying the retail callees' requirements.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn indexed_mode_position_adjust(state: *mut u8, index: i32) -> u32 {
    if index < 0 || state.add(0x8a4).read() & 1 == 0 {
        return 0;
    }
    let object = state.add(0x8a8).cast::<u32>().read();
    let mut position = 0;
    if resolve_indexed_position(object, &mut position, index) == 0 || position == u32::MAX {
        return 0;
    }
    let active = mode_selected_position(state);
    if position == active {
        return 0;
    }
    let _ = mode_selected_position_set(state, 0, position.wrapping_sub(active));
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::mode_selected_position_set::{
        MODE_SELECTED_POSITION_SET_CLEAR, MODE_SELECTED_POSITION_SET_SET,
        MODE_SELECTED_POSITION_SET_TEST_LOCK,
    };
    use core::sync::atomic::{AtomicU32, Ordering};

    static RESULT: AtomicU32 = AtomicU32::new(0);
    static SUCCESS: AtomicU32 = AtomicU32::new(0);
    static CALLS: AtomicU32 = AtomicU32::new(0);
    static DELTA: AtomicU32 = AtomicU32::new(0);
    static SET_CALLS: AtomicU32 = AtomicU32::new(0);

    unsafe extern "C" fn resolve(object: u32, output: *mut u32, index: i32) -> u32 {
        assert_eq!(object, 0x12345678);
        assert_eq!(index, i32::MAX);
        CALLS.fetch_add(1, Ordering::SeqCst);
        if SUCCESS.load(Ordering::SeqCst) != 0 {
            output.write(RESULT.load(Ordering::SeqCst));
        }
        SUCCESS.load(Ordering::SeqCst)
    }

    unsafe extern "C" fn set(_: *mut u8, mode: u32, delta: u32) -> u32 {
        assert_eq!(mode, 0);
        DELTA.store(delta, Ordering::SeqCst);
        SET_CALLS.fetch_add(1, Ordering::SeqCst);
        0 // Adjustment success deliberately does not depend on setter success.
    }

    #[repr(C, align(4))]
    struct State([u8; 0x8ac]);

    #[test]
    fn lookup_rejection_and_wrapping_adjustments() {
        let _lock = MODE_SELECTED_POSITION_SET_TEST_LOCK.lock();
        unsafe {
            let saved = RESOLVE_INDEXED_POSITION;
            let clear = MODE_SELECTED_POSITION_SET_CLEAR;
            let set_path = MODE_SELECTED_POSITION_SET_SET;
            RESOLVE_INDEXED_POSITION = resolve;
            MODE_SELECTED_POSITION_SET_CLEAR = set;
            MODE_SELECTED_POSITION_SET_SET = set;
            assert_eq!(indexed_mode_position_adjust(core::ptr::null_mut(), -1), 0);
            for backend in [0u8, 1] {
                for (enabled, success, position, active, expected) in [
                    (0x80, 1, 7, 3, 0),
                    (1, 0, 7, 3, 0),
                    (1, 1, u32::MAX, 3, 0),
                    (1, 1, 7, 7, 0),
                    (0x81, 2, 0, 1, 1),
                    (1, 1, 0x80000000, 0, 1),
                    (1, 1, 0, u32::MAX, 1),
                ] {
                    let mut state = State([0; 0x8ac]);
                    let p = state.0.as_mut_ptr();
                    p.add(0x8a4).write(enabled);
                    p.add(0x8a8).cast::<u32>().write(0x12345678);
                    p.add(0x5f8).write(backend);
                    p.add(if backend == 0 { 0x5e4 } else { 0x2ec }).cast::<u32>().write(active);
                    RESULT.store(position, Ordering::SeqCst);
                    SUCCESS.store(success, Ordering::SeqCst);
                    CALLS.store(0, Ordering::SeqCst);
                    SET_CALLS.store(0, Ordering::SeqCst);
                    let before = state.0;
                    assert_eq!(indexed_mode_position_adjust(p, i32::MAX), expected);
                    assert_eq!(CALLS.load(Ordering::SeqCst), u32::from(enabled & 1 != 0));
                    assert_eq!(SET_CALLS.load(Ordering::SeqCst), expected);
                    if expected != 0 {
                        assert_eq!(DELTA.load(Ordering::SeqCst), position.wrapping_sub(active));
                    }
                    assert_eq!(state.0, before);
                }
            }
            RESOLVE_INDEXED_POSITION = saved;
            MODE_SELECTED_POSITION_SET_CLEAR = clear;
            MODE_SELECTED_POSITION_SET_SET = set_path;
        }
    }
}
