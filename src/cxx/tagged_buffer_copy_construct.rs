//! Tagged-buffer copy construction — retailOS `FUN_0827c18c` at load address
//! `0x0827c18c` (68 bytes, `0x0827c18c..0x0827c1d0`). Raw words end with
//! pop {r4,r5,r6,pc}; the next function starts with mov r1,#255.
//! One internal plain BL calls tagged_buffer_release; no predicated internal
//! BL. Two inbound calls are BLNE (0x083e4268, 0x083e8e60), zero plain BL.
//!
//! Initialize destination byte +0 to 0xff and words +8/+c to zero, release
//! that empty destination, then copy source byte +0 and the two payload words.
//! Return destination; bytes +1..+7 remain untouched. Self-copy consequently
//! yields an empty buffer, not the original value.
//!
//! Deliberate deviations: use the existing Rust release port directly and
//! aligned volatile u32 accesses instead of ARM LDRD/STRD. Both payload words
//! are loaded before either store, retaining the original overlap behavior.

use crate::cxx::tagged_buffer_release::{tagged_buffer_release, TAGGED_BUFFER_EMPTY};

/// # Safety
/// Both pointers must address four aligned, accessible target-width words;
/// destination must be writable. Source and destination may alias.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn tagged_buffer_copy_construct(
    destination: *mut u8,
    source: *const u8,
) -> *mut u8 {
    destination.write_volatile(TAGGED_BUFFER_EMPTY);
    let words = destination.cast::<u32>();
    words.add(2).write_volatile(0);
    words.add(3).write_volatile(0);
    tagged_buffer_release(destination);
    destination.write_volatile(source.read_volatile());
    let allocation = source.cast::<u32>().add(2).read_volatile();
    let trailing = source.cast::<u32>().add(3).read_volatile();
    words.add(2).write_volatile(allocation);
    words.add(3).write_volatile(trailing);
    destination
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copies_all_states_and_payloads_without_touching_padding_or_releasing_old_payload() {
        for state in 0..=255u32 {
            let source = [0x1122_3300 | state, 0x5566_7788, 0x99aa_bbcc, 0xddee_ff00];
            let mut destination = [0xa5a5_a503u32, 0xdead_beef, 0x1234_5678, 0xffff_ffff];
            let pointer = destination.as_mut_ptr().cast();
            assert_eq!(unsafe { tagged_buffer_copy_construct(pointer, source.as_ptr().cast()) }, pointer);
            assert_eq!(destination, [0xa5a5_a500 | state, 0xdead_beef, source[2], source[3]]);
        }
    }

    #[test]
    fn self_copy_observes_initialization_before_reading_source() {
        let mut buffer = [0x1122_3304u32, 0x5566_7788, 0x99aa_bbcc, 0xddee_ff00];
        let pointer = buffer.as_mut_ptr().cast();
        unsafe { tagged_buffer_copy_construct(pointer, pointer); }
        assert_eq!(buffer, [0x1122_33ff, 0x5566_7788, 0, 0]);
    }

    #[test]
    fn overlapping_payload_loads_precede_both_payload_stores() {
        let mut buffer = [0x1122_3301u32, 0x5566_7788, 0x99aa_bbcc, 0xddee_ff00, 0x1234_5678];
        let source = buffer.as_ptr().cast();
        let destination = unsafe { buffer.as_mut_ptr().add(1).cast() };
        unsafe { tagged_buffer_copy_construct(destination, source); }
        assert_eq!(buffer, [0x1122_3301, 0x5566_7701, 0x99aa_bbcc, 0x99aa_bbcc, 0]);
    }
}
