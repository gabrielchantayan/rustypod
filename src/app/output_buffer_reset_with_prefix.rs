//! `output_buffer_reset_with_prefix` — `FUN_08123c38` @ **0x08123c38**.
//! True extent [0x08123c38,0x08123c58): 28 instruction bytes and a four-byte
//! literal. Two plain incoming BLs (0x080b54e8, 0x081502c8), no predicated
//! incoming BLs; one plain outgoing BL to reset, no predicated outgoing BLs,
//! and a tail B to the independent appender at 0x08123c58.
//!
//! Reset backing byte and both counters, then append the firmware prefix at
//! 0x083e9365. Raw prefix bytes are ff 2f e1 04 00; retain the literal pointer
//! rather than infer text from callers. Ghidra merges the appender's body.
//! Deliberate deviation: Rust calls the existing volatile append seam and
//! returns instead of the retail tail branch. No new seam or copied appender.

use super::output_buffer_reset::{output_buffer_reset, OutputBufferState};
use super::output_buffer_write_dictionary_close::OUTPUT_BUFFER_APPEND_C_STRING;

const PREFIX: *const u8 = 0x083e_9365usize as *const u8;
type AppendCStringFn = unsafe extern "C" fn(*mut OutputBufferState, *const u8);

#[inline(always)]
unsafe fn reset_with(state: *mut OutputBufferState, append: AppendCStringFn) {
    unsafe {
        output_buffer_reset(state);
        append(state, PREFIX);
    }
}

/// Reset the output buffer and append its firmware-resident prefix.
///
/// # Safety
/// `state.data` must designate writable backing storage even for capacity zero.
/// The installed append seam must accept the retail state layout and firmware
/// prefix pointer; the target firmware must remain mapped at its load address.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn output_buffer_reset_with_prefix(state: *mut OutputBufferState) {
    unsafe {
        let append = core::ptr::read_volatile(core::ptr::addr_of!(OUTPUT_BUFFER_APPEND_C_STRING));
        reset_with(state, append);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    // Reference behavior of the independent retail appender for the verified
    // literal bytes. Exercises reset-before-append, strict fit, and overflow.
    unsafe extern "C" fn append_reference(state: *mut OutputBufferState, text: *const u8) {
        assert_eq!(text, PREFIX);
        let state = unsafe { &mut *state };
        let data = state.data as *mut u8;
        assert_eq!(unsafe { data.read() }, 0);
        assert_eq!(state.write_count, 0);
        assert_eq!(state.overflow_count, 0);
        if 5 < state.capacity.wrapping_sub(state.write_count) {
            unsafe { core::ptr::copy_nonoverlapping(b"\xff/\xe1\x04\0".as_ptr(), data, 5) };
            state.write_count = 4;
        } else {
            state.overflow_count = 4;
        }
    }

    #[test]
    fn discards_old_output_before_prefix_fit_or_overflow() {
        let Some(data) = try_map_u32_slab(hints::OUTPUT_BUFFER_RESET_WITH_PREFIX, 0x1000) else {
            assert!(note_missing_u32_fixture("app/output_buffer_reset_with_prefix"));
            return;
        };
        for capacity in [0, 1, 4, 5, 6, u32::MAX] {
            unsafe {
                core::ptr::write_bytes(data, 0xa5, 16);
                let mut state = OutputBufferState {
                    header: 0x12345678, data: data as usize as u32, capacity,
                    write_count: u32::MAX, overflow_count: u32::MAX,
                };
                reset_with(&mut state, append_reference);
                assert_eq!(state.header, 0x12345678);
                assert_eq!(state.data, data as usize as u32);
                assert_eq!(state.capacity, capacity);
                if capacity > 5 {
                    assert_eq!(core::slice::from_raw_parts(data, 6), b"\xff/\xe1\x04\0\xa5");
                    assert_eq!((state.write_count, state.overflow_count), (4, 0));
                } else {
                    assert_eq!(core::slice::from_raw_parts(data, 2), &[0, 0xa5]);
                    assert_eq!((state.write_count, state.overflow_count), (0, 4));
                }
            }
        }
    }
}
