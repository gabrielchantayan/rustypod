//! Legacy retailOS SHA-1 context initialization.
//!
//! `sha1_init_legacy` — original: `FUN_080651d0` @ 0x080651d0.
//! True extent [0x080651d0, 0x08065224): 64 instruction bytes ending in
//! BX LR, then five IV literals (20 bytes), before the next PUSH. Whole-image
//! A32 decoding verifies two incoming plain BLs (0x08064f7c, 0x0827360c),
//! zero incoming predicated BLs, and zero outgoing plain or predicated BLs.
//!
//! Installs the standard five-word SHA-1 IV, clears the low/high bit counts
//! at +0x14/+0x18 and buffered-byte count at +0x5c, and returns one. Preserves
//! the sixteen block-buffer words at +0x1c..+0x58. The one-shot caller uses
//! a 96-byte stack context; the other caller passes its owner's payload +4.
//! This is the compact layout, not the 352-byte `sha1_init` layout.
//! Deliberate deviation: volatile aligned stores preserve firmware write order
//! and prevent builtin substitution. Identical bodies may be folded with
//! `sha1_init_compact` by LLVM; both exported entry points remain intentional.

/// Initializes a legacy 96-byte SHA-1 context without touching its buffer.
///
/// # Safety
/// `context` must be non-null, aligned, and writable for 24 u32 words.
/// Previous contents need not be initialized. The preserved buffer must not
/// be read until separately initialized.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn sha1_init_legacy(context: *mut u32) -> u32 {
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
    fn resets_dirty_state_and_counters_without_overwriting_buffer_or_neighbors() {
        for seed in [0u32, u32::MAX, 0x8000_0000, 0xdead_beef] {
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
            assert_eq!(unsafe { sha1_init_legacy(storage.as_mut_ptr().add(1)) }, 1);
            assert_eq!(storage, expected);
            // Reinitialization must reset dirty counters without clearing buffered data.
            storage[6] = u32::MAX;
            storage[7] = u32::MAX;
            storage[24] = 63;
            assert_eq!(unsafe { sha1_init_legacy(storage.as_mut_ptr().add(1)) }, 1);
            assert_eq!(storage, expected);
        }
    }

    #[test]
    fn initializes_defined_fields_without_reading_uninitialized_buffer() {
        let mut storage = core::mem::MaybeUninit::<[u32; 24]>::uninit();
        let words = storage.as_mut_ptr().cast::<u32>();
        assert_eq!(unsafe { sha1_init_legacy(words) }, 1);
        for (index, expected) in [
            (0, 0x6745_2301), (1, 0xefcd_ab89), (2, 0x98ba_dcfe),
            (3, 0x1032_5476), (4, 0xc3d2_e1f0), (5, 0), (6, 0), (23, 0),
        ] {
            assert_eq!(unsafe { words.add(index).read() }, expected);
        }
    }
}
