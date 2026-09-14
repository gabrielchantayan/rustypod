//! `output_buffer_reset` — original: `FUN_08123c20` @ load address
//! **0x08123c20** (24 bytes).
//!
//! Raw `osos.dec` contains exactly six ARM instructions from `ldr r2,[r0,#4]`
//! at 0x08123c20 through `bx lr` at 0x08123c34; the separately linked
//! constructor helper starts at 0x08123c38. Decoding every aligned ARM
//! B/BL-immediate word in the image finds six direct `bl` call sites, all
//! unconditional: 0x080b57a4, 0x080b5840, 0x080b58f4, 0x08123c40,
//! 0x08123cd8, and 0x081502c0. One additional unconditional tail `b` at
//! 0x08123680 reaches this function; there are no predicated call sites.
//!
//! ## Algorithm
//!
//! Writes a NUL byte through the target-width data pointer at +4, then clears
//! the two u32 counters at +12 and +16. The concrete owner type is not yet
//! recovered, so this port names only the observed output-buffer reset
//! behavior.
//!
//! ## Deliberate deviations
//!
//! None. The ARM routine has no NULL guards for either pointer; callers must
//! provide writable state and a writable data byte.

/// Target-width prefix consumed by `output_buffer_reset`.
///
/// `data` remains a u32 rather than a host pointer so every field preserves
/// the ARM layout on 64-bit host tests as well as on the target.
#[repr(C)]
pub struct OutputBufferState {
    pub header: u32,
    pub data: u32,
    pub capacity: u32,
    pub write_count: u32,
    pub overflow_count: u32,
}

/// output_buffer_reset — original: `FUN_08123c20` @ 0x08123c20
/// (24 bytes; 6 unconditional direct `bl` call sites, plus one unconditional
/// tail `b`, binary-scanned).
///
/// NUL-terminates the buffer designated by `state.data`, then clears the
/// write and overflow counters. `header` and `capacity` are not accessed.
///
/// # Safety
///
/// `state` must be writable and `state.data` must contain a writable,
/// target-width pointer to at least one byte.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.output_buffer_reset")]
pub unsafe extern "C" fn output_buffer_reset(state: *mut OutputBufferState) {
    let data = unsafe { (*state).data as *mut u8 };
    unsafe {
        data.write(0);
        (*state).write_count = 0;
        (*state).overflow_count = 0;
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::{output_buffer_reset, OutputBufferState};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::{LazyLock, Mutex};

    const FIXTURE_LEN: usize = 0x1000;
    static DATA: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::OUTPUT_BUFFER_RESET, FIXTURE_LEN).map(|pointer| pointer as usize)
    });
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn nul_terminates_data_and_clears_only_the_two_counters() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some(data) = *DATA else {
            assert!(note_missing_u32_fixture("app/output_buffer_reset"));
            return;
        };
        let data = data as *mut u8;
        unsafe {
            core::ptr::write_bytes(data, 0xa5, FIXTURE_LEN);
            let mut state = OutputBufferState {
                header: 0x1122_3344,
                data: data.add(37) as usize as u32,
                capacity: 0x5566_7788,
                write_count: u32::MAX,
                overflow_count: 0x1234_5678,
            };

            output_buffer_reset(&mut state);

            assert_eq!(*data.add(36), 0xa5);
            assert_eq!(*data.add(37), 0);
            assert_eq!(*data.add(38), 0xa5);
            assert_eq!(state.header, 0x1122_3344);
            assert_eq!(state.capacity, 0x5566_7788);
            assert_eq!(state.write_count, 0);
            assert_eq!(state.overflow_count, 0);
        }
    }
}
