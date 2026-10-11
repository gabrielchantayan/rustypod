//! Compact retailOS SHA-1 context initialization.
//!
//! `sha1_init_compact` — original: `FUN_08065698` @ 0x08065698.
//! True extent [0x08065698, 0x080656ec): 64 instruction bytes followed by
//! 20 literal bytes holding the standard SHA-1 IV. The next function starts
//! with PUSH at 0x080656ec. Independent whole-image A32 decoding finds two
//! incoming plain BLs (0x08104120, 0x08104128), zero incoming predicated BLs,
//! and zero outgoing plain or predicated BLs.
//!
//! Writes the five SHA-1 state words at +0x00..+0x10, clears the low/high
//! bit counts at +0x14/+0x18 and buffered-byte count at +0x5c, then returns
//! one. Leaves the sixteen buffer words at +0x1c..+0x58 untouched. The caller
//! at 0x081040e8 initializes two consecutive 96-byte contexts this way.
//! This layout is distinct from the 352-byte `sha1_init` context.
//! Deliberate deviation: volatile aligned stores retain the firmware's write
//! order and prevent LLVM substituting libc builtins; no behavioral deviation.

/// Initializes the state and counters of a compact 96-byte SHA-1 context.
///
/// # Safety
/// `context` must be aligned and writable for 24 u32 words. NULL is not
/// accepted. Previous contents need not be initialized; the buffer remains
/// untouched and must not be read until separately initialized.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn sha1_init_compact(context: *mut u32) -> u32 {
    unsafe {
        context.add(0).write_volatile(0x6745_2301);
        context.add(1).write_volatile(0xefcd_ab89);
        context.add(2).write_volatile(0x98ba_dcfe);
        context.add(3).write_volatile(0x1032_5476);
        context.add(4).write_volatile(0xc3d2_e1f0);
        context.add(5).write_volatile(0);
        context.add(6).write_volatile(0);
        context.add(23).write_volatile(0);
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resets_state_and_counters_preserving_buffer_and_neighbors() {
        for seed in [0, u32::MAX, 0x8000_0000, 0xdead_beef] {
            let mut storage = [0u32; 26];
            for (index, word) in storage.iter_mut().enumerate() {
                *word = seed.wrapping_add((index as u32).wrapping_mul(0x1020_3041));
            }
            let mut expected = storage;
            expected[1..6].copy_from_slice(&[
                0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476, 0xc3d2_e1f0,
            ]);
            expected[6] = 0;
            expected[7] = 0;
            expected[24] = 0;
            assert_eq!(unsafe { sha1_init_compact(storage.as_mut_ptr().add(1)) }, 1);
            assert_eq!(storage, expected);
        }
    }

    #[test]
    fn initializes_only_defined_fields_in_uninitialized_storage() {
        let mut storage = core::mem::MaybeUninit::<[u32; 24]>::uninit();
        let words = storage.as_mut_ptr().cast::<u32>();
        assert_eq!(unsafe { sha1_init_compact(words) }, 1);
        // Do not assume_init: the sixteen buffer words are still uninitialized.
        for (index, expected) in [
            (0, 0x6745_2301), (1, 0xefcd_ab89), (2, 0x98ba_dcfe),
            (3, 0x1032_5476), (4, 0xc3d2_e1f0), (5, 0), (6, 0), (23, 0),
        ] {
            assert_eq!(unsafe { words.add(index).read() }, expected);
        }
    }
}
