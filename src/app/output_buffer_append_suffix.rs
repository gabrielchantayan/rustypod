//! `output_buffer_append_suffix` — `FUN_08123c14` @ **0x08123c14**.
//! True extent [0x08123c14,0x08123c20): eight instruction bytes and a
//! four-byte literal; next function starts with LDR at 0x08123c20.
//! Two plain incoming BLs (0x080b5920, 0x08152174), zero predicated
//! incoming BLs; zero outgoing plain or predicated BLs, one tail B to
//! 0x08123c58. Raw words: e59f1000 ea00000e 083e9413.
//!
//! Append the firmware-resident suffix to the existing output state without
//! resetting it. The literal bytes are e1 1e ff 2f e1 04 00; do not infer XML
//! text from the callers. Ghidra merges the independent appender into this
//! wrapper. Deliberate deviation: dispatch through the existing volatile
//! OUTPUT_BUFFER_APPEND_C_STRING seam instead of a direct tail B. No new seam.

use super::output_buffer_reset::OutputBufferState;
use super::output_buffer_write_dictionary_close::OUTPUT_BUFFER_APPEND_C_STRING;

const SUFFIX: *const u8 = 0x083e_9413usize as *const u8;
type AppendCStringFn = unsafe extern "C" fn(*mut OutputBufferState, *const u8);

#[inline(always)]
unsafe fn append_with(state: *mut OutputBufferState, append: AppendCStringFn) {
    unsafe { append(state, SUFFIX) };
}

/// Append the retail firmware suffix, preserving existing output and counters.
///
/// # Safety
/// `state` must satisfy the installed appender's retail output-buffer contract.
/// The firmware literal must remain mapped at its load address.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn output_buffer_append_suffix(state: *mut OutputBufferState) {
    unsafe {
        let append = core::ptr::read_volatile(core::ptr::addr_of!(OUTPUT_BUFFER_APPEND_C_STRING));
        append_with(state, append);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    // Independent appender model using the verified firmware literal, not a
    // new port of 0x08123c58. Preserve its strict fit and wrapping arithmetic.
    unsafe extern "C" fn append_reference(state: *mut OutputBufferState, text: *const u8) {
        assert_eq!(text, SUFFIX);
        let state = unsafe { &mut *state };
        if 7 < state.capacity.wrapping_sub(state.write_count) {
            let dst = state.data.wrapping_add(state.write_count) as *mut u8;
            unsafe { core::ptr::copy_nonoverlapping(b"\xe1\x1e\xff/\xe1\x04\0".as_ptr(), dst, 7) };
            state.write_count = state.write_count.wrapping_add(6);
        } else {
            state.overflow_count = state.overflow_count.wrapping_add(6);
        }
    }

    #[test]
    fn retains_old_output_at_strict_fit_boundary_and_wraps_overflow() {
        let Some(data) = try_map_u32_slab(hints::OUTPUT_BUFFER_APPEND_SUFFIX, 0x1000) else {
            assert!(note_missing_u32_fixture("app/output_buffer_append_suffix"));
            return;
        };
        for capacity in [0, 3, 9, 10, 11, u32::MAX] {
            for overflow in [0, 17, u32::MAX - 2] {
                unsafe {
                    core::ptr::write_bytes(data, 0xa5, 16);
                    core::ptr::copy_nonoverlapping(b"old\0".as_ptr(), data, 4);
                    let mut state = OutputBufferState {
                        header: 0x12345678, data: data as usize as u32, capacity,
                        write_count: 3, overflow_count: overflow,
                    };
                    append_with(&mut state, append_reference);
                    assert_eq!((state.header, state.data, state.capacity),
                        (0x12345678, data as usize as u32, capacity));
                    if 7 < capacity.wrapping_sub(3) {
                        assert_eq!(core::slice::from_raw_parts(data, 11), b"old\xe1\x1e\xff/\xe1\x04\0\xa5");
                        assert_eq!((state.write_count, state.overflow_count), (9, overflow));
                    } else {
                        assert_eq!(core::slice::from_raw_parts(data, 5), b"old\0\xa5");
                        assert_eq!((state.write_count, state.overflow_count), (3, overflow.wrapping_add(6)));
                    }
                }
            }
        }
    }
}
