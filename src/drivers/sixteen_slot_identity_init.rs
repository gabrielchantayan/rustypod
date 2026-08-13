//! Sixteen-slot byte identity-table initialization.
//!
//! `initialize_sixteen_byte_identity_slots` — original: `FUN_0802dda8` @
//! `0x0802dda8` (36 bytes). Reference:
//! `/home/gabe/Programming/ipod-decomp/decomp/c/001/0802dda8_FUN_0802dda8.c`;
//! raw ARM is `0x0802dda8..0x0802ddcc`.
//!
//! The wrapper invokes the recovered byte identity-table initializer at
//! `0x0802b9ec` exactly sixteen times, once for every consecutive 0x100-byte
//! slot beginning at its argument. Each initialized slot maps byte `n` to `n`.

use super::byte_identity_slot_init::{
    initialize_byte_identity_slot, BYTE_IDENTITY_SLOT_BYTES,
};

/// Number of consecutive byte identity slots initialized by the retail wrapper.
pub const BYTE_IDENTITY_SLOT_COUNT: usize = 16;

/// Runs the retail loop against one ABI-compatible slot initializer.
///
/// Keeping the loop separate makes its call sequence directly observable in
/// host tests while the public export binds it to the recovered helper.
#[inline(always)]
unsafe fn initialize_slots(
    base: *mut u8,
    initialize_slot: unsafe extern "C" fn(*mut u8),
) {
    for slot_index in 0..BYTE_IDENTITY_SLOT_COUNT {
        initialize_slot(base.add(slot_index * BYTE_IDENTITY_SLOT_BYTES));
    }
}

/// initialize_sixteen_byte_identity_slots — original: `FUN_0802dda8` @
/// `0x0802dda8` (36 bytes).
///
/// Calls [`initialize_byte_identity_slot`] at `base + slot_index * 0x100` for
/// every `slot_index` in `0..16`, in ascending order. This preserves the
/// retail wrapper's direct 16-call initialization contract without creating a
/// second helper ABI.
///
/// # Safety
///
/// `base` must designate the first byte of at least sixteen contiguous
/// 0x100-byte slots, each writable by the retail initializer.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn initialize_sixteen_byte_identity_slots(base: *mut u8) {
    initialize_slots(base, initialize_byte_identity_slot);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use core::ptr::addr_of_mut;
    use std::sync::Mutex;

    static SLOT_INITIALIZER_TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut RECORDED_SLOT_OFFSETS: std::vec::Vec<usize> = std::vec::Vec::new();

    unsafe extern "C" fn record_identity_slot(slot: *mut u8) {
        let base = unsafe { addr_of_mut!(TEST_BASE).read() };
        unsafe {
            RECORDED_SLOT_OFFSETS.push(slot as usize - base as usize);
            for byte_index in 0..BYTE_IDENTITY_SLOT_BYTES {
                slot.add(byte_index).write(byte_index as u8);
            }
        }
    }

    static mut TEST_BASE: *mut u8 = core::ptr::null_mut();

    fn reset_recording(base: *mut u8) {
        unsafe {
            RECORDED_SLOT_OFFSETS.clear();
            TEST_BASE = base;
        }
    }

    fn recorded_offsets() -> std::vec::Vec<usize> {
        unsafe { RECORDED_SLOT_OFFSETS.clone() }
    }

    use super::*;

    #[test]
    fn calls_the_initializer_for_all_sixteen_slots_in_ascending_256_byte_order() {
        let _guard = SLOT_INITIALIZER_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let mut bytes = [0xa5u8; BYTE_IDENTITY_SLOT_COUNT * BYTE_IDENTITY_SLOT_BYTES + 2];
        let base = unsafe { bytes.as_mut_ptr().add(1) };
        reset_recording(base);

        unsafe { initialize_slots(base, record_identity_slot) };

        assert_eq!(
            recorded_offsets(),
            (0..BYTE_IDENTITY_SLOT_COUNT)
                .map(|slot_index| slot_index * BYTE_IDENTITY_SLOT_BYTES)
                .collect::<std::vec::Vec<_>>(),
            "the wrapper invokes the ABI-compatible initializer at every slot in order",
        );
        assert_eq!(bytes[0], 0xa5, "byte before the first slot");
        assert_eq!(bytes[bytes.len() - 1], 0xa5, "byte after the final slot");
        for (byte_offset, &value) in bytes[1..bytes.len() - 1].iter().enumerate() {
            assert_eq!(
                value,
                (byte_offset % BYTE_IDENTITY_SLOT_BYTES) as u8,
                "identity entry at base + {byte_offset:#x}",
            );
        }
    }
}
