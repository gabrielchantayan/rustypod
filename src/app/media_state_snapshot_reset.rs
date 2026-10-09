//! Media-state snapshot reset — FUN_080fe6a4 @ 0x080fe6a4.
//! True extent: 84 bytes, [0x080fe6a4, 0x080fe6f8); next ARM function
//! starts with push {r3, lr}. Raw whole-image scan: two inbound plain BLs
//! (0x082068d4, 0x08206cd0), no predicated inbound BLs. Body: two plain
//! BLs to 0x08037db8, no predicated BLs; that veneer targets 0x2200027c,
//! the IRAM mirror of ported memzero_aligned @ 0x0800027c.
//!
//! Clear two header words, four 0x60-byte records, four 8-byte records,
//! the word at +0x1a8 and flag bytes +0x1ac..+0x1af. Set +0x1b1 and
//! +0x1b2 to 0xff, clear +0x1b3, and leave +0x1b0 untouched. The caller
//! at 0x082068c4 fills this snapshot from its embedded state at +0x464.
//! Deliberate deviation: invoke the existing Rust zero-fill through a
//! volatile function pointer to prevent LLVM builtin substitution. Its
//! returned pointer is ignored, as in firmware. No layout deviations.

use crate::libc::memzero::memzero_aligned;

/// # Safety
/// `snapshot` must be word-aligned and writable for 0x1b4 bytes.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn media_state_snapshot_reset(snapshot: *mut u8) {
    snapshot.cast::<u32>().write(0);
    snapshot.add(4).cast::<u32>().write(0);
    let zero = core::ptr::read_volatile(
        &(memzero_aligned as unsafe extern "C" fn(*mut u8, usize) -> *mut u8),
    );
    zero(snapshot.add(8), 0x180);
    zero(snapshot.add(0x188), 0x20);
    snapshot.add(0x1a8).cast::<u32>().write(0);
    snapshot.add(0x1ac).write(0);
    snapshot.add(0x1ad).write(0);
    snapshot.add(0x1ae).write(0);
    snapshot.add(0x1af).write(0);
    snapshot.add(0x1b1).write(0xff);
    snapshot.add(0x1b3).write(0);
    snapshot.add(0x1b2).write(0xff);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clears_records_preserves_reserved_byte_and_surrounding_storage() {
        #[repr(align(4))]
        struct Storage([u8; 0x1bc]);
        for seed in [0u8, 0x5a, 0xff] {
            let mut storage = Storage([seed; 0x1bc]);
            for (i, byte) in storage.0.iter_mut().enumerate() {
                *byte = seed.wrapping_add(i as u8);
            }
            let mut expected = storage.0;
            // Independent byte-range model of the raw ARM stores.
            expected[4..4 + 0x1b0].fill(0);
            expected[4 + 0x1b1] = 0xff;
            expected[4 + 0x1b2] = 0xff;
            expected[4 + 0x1b3] = 0;
            unsafe { media_state_snapshot_reset(storage.0.as_mut_ptr().add(4)); }
            assert_eq!(storage.0, expected);
            // Repeated reset must retain a newly supplied reserved byte.
            storage.0[4 + 0x1b0] = !seed;
            expected[4 + 0x1b0] = !seed;
            unsafe { media_state_snapshot_reset(storage.0.as_mut_ptr().add(4)); }
            assert_eq!(storage.0, expected);
        }
    }
}
