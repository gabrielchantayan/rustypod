//! Text buffer construction — `FUN_08123cb4` @ `0x08123cb4`.
//!
//! True extent [0x08123cb4, 0x08123ce8): 52 bytes, comprising 48
//! instruction bytes and the vtable literal 0x08982fd8. The next real
//! function is BX LR at 0x08123ce8. Whole-image aligned A32 decoding
//! finds two incoming plain BLs (0x080b54dc, 0x08152390), zero predicated
//! incoming BLs; one outgoing plain BL at 0x08123cd8 to 0x08123c20,
//! zero predicated outgoing BLs.
//!
//! Install the vtable, backing-buffer address and capacity, clear both
//! counters, store the mode byte at +20, then NUL-terminate the backing
//! buffer and reset counters through the ported output_buffer_reset.
//! Return the original object. No behavioral deviations; even zero
//! capacity requires a writable backing byte. Target pointers stay u32.

use super::output_buffer_reset::{output_buffer_reset, OutputBufferState};

pub const TEXT_BUFFER_VTABLE: u32 = 0x0898_2fd8;

/// Requires a four-byte-aligned writable object of at least 21 bytes and
/// a target-width backing address naming at least one writable byte.
/// The object and backing byte must not overlap.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn text_buffer_construct(
    object: *mut u8, data: u32, capacity: u32, mode: u8,
) -> *mut u8 {
    let state = object.cast::<OutputBufferState>();
    (*state).header = TEXT_BUFFER_VTABLE;
    (*state).data = data;
    (*state).capacity = capacity;
    (*state).write_count = 0;
    (*state).overflow_count = 0;
    object.add(20).write(mode);
    output_buffer_reset(state);
    object
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::{LazyLock, Mutex};

    static DATA: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::TEXT_BUFFER_CONSTRUCT, 0x1000).map(|p| p as usize)
    });
    static LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn initializes_exact_prefix_and_terminates_even_zero_capacity() {
        let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let Some(data) = *DATA else {
            assert!(note_missing_u32_fixture("app/text_buffer_construct"));
            return;
        };
        for capacity in [0u32, 1, 0x3500, u32::MAX] {
            for mode in [0u8, 1, 0x80, 0xff] {
                let mut words = [0xa5a5_a5a5u32; 8];
                let base = words.as_mut_ptr().cast::<u8>();
                let backing = data as *mut u8;
                let address = (data + 37) as u32;
                let mut expected = [0xa5u8; 32];
                expected[4..8].copy_from_slice(&TEXT_BUFFER_VTABLE.to_ne_bytes());
                expected[8..12].copy_from_slice(&address.to_ne_bytes());
                expected[12..16].copy_from_slice(&capacity.to_ne_bytes());
                expected[16..24].fill(0);
                expected[24] = mode;
                unsafe {
                    core::ptr::write_bytes(backing, 0x5a, 0x1000);
                    assert_eq!(text_buffer_construct(base.add(4), address, capacity, mode), base.add(4));
                    assert_eq!(core::slice::from_raw_parts(base, 32), &expected);
                    assert_eq!(*backing.add(36), 0x5a);
                    assert_eq!(*backing.add(37), 0);
                    assert_eq!(*backing.add(38), 0x5a);
                }
            }
        }
    }
}
