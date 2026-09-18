//! `vtable_two_pair_metadata_construct` — original: `FUN_081fadc4` @
//! **0x081fadc4** (96 bytes of ARM instructions, followed by its three-word
//! literal pool at 0x081fae24..0x081fae2c).
//!
//! # Extent and reachability, binary-verified
//!
//! The executable body runs from 0x081fadc4 through 0x081fae20; the next
//! separately linked function begins at 0x081fae30, after this function's
//! three literal words. Decoding every aligned ARM B/BL word in `osos.dec`
//! finds four direct inbound calls (0x081dcd48, 0x081dce0c, 0x0820b88c, and
//! 0x0820fd44), all unconditional `bl`; there are no predicated `bl` forms.
//!
//! # Algorithm
//!
//! First construct the 20-byte common two-pair base at `this`, preserving the
//! two source-pair arguments. Replace its vtable with 0x08990af8, write the
//! caller's fourth argument at byte 20, initialize the following ten control
//! words to `0, 1, 0, 1, 0, 0, 0, 0, 0, 0`, then write the literal pair
//! `(0x0010b6c3, 0x00015180)` at bytes 64 and 68. The constructor returns
//! `this`.
//!
//! # Deliberate deviations
//!
//! Calls the existing Rust ports for the two direct BL targets instead of
//! introducing duplicate seams. Volatile ordered writes preserve the retail
//! store order for the derived record fields.

use super::vtable_two_pair_base_construct::vtable_two_pair_base_construct;
use crate::util::u32_pair_store::store_u32_pair;

/// Vtable literal installed after common base construction.
pub const METADATA_VTABLE_ADDRESS: u32 = 0x0899_0af8;
const PAIR_FIRST: u32 = 0x0010_b6c3;
const PAIR_SECOND: u32 = 0x0001_5180;

/// Constructs the 72-byte vtable-backed metadata record and returns `this`.
///
/// # Safety
///
/// `this` must be four-byte aligned and writable for 72 bytes. Both source
/// pairs must meet [`vtable_two_pair_base_construct`]'s readable, aligned
/// eight-byte requirement. The retail constructor has no null or bounds
/// guards.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.vtable_two_pair_metadata_construct")]
#[inline(never)]
pub unsafe extern "C" fn vtable_two_pair_metadata_construct(
    this: *mut u8,
    src_pair_at_4: *const u8,
    src_pair_at_12: *const u8,
    metadata: u32,
) -> *mut u8 {
    let record = unsafe { vtable_two_pair_base_construct(this, src_pair_at_4, src_pair_at_12) };
    let words = record.cast::<u32>();

    unsafe {
        words.write_volatile(METADATA_VTABLE_ADDRESS);
        words.add(6).write_volatile(0);
        words.add(7).write_volatile(1);
        words.add(5).write_volatile(metadata);
        words.add(8).write_volatile(0);
        words.add(9).write_volatile(1);
        words.add(10).write_volatile(0);
        words.add(11).write_volatile(0);
        words.add(12).write_volatile(0);
        words.add(13).write_volatile(0);
        words.add(14).write_volatile(0);
        words.add(15).write_volatile(0);
        store_u32_pair(words.add(16), PAIR_FIRST, PAIR_SECOND);
    }

    record
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(align(4))]
    struct AlignedRecord([u32; 18]);

    #[test]
    fn constructs_every_word_and_returns_this() {
        let pair_at_4 = [0x1111_2222, 0x3333_4444];
        let pair_at_12 = [0x5555_6666, 0x7777_8888];
        let mut record = AlignedRecord([0xdead_beef; 18]);
        let this = record.0.as_mut_ptr().cast::<u8>();

        let returned = unsafe {
            vtable_two_pair_metadata_construct(
                this,
                pair_at_4.as_ptr().cast(),
                pair_at_12.as_ptr().cast(),
                u32::MAX,
            )
        };

        assert_eq!(returned, this);
        assert_eq!(record.0, [
            METADATA_VTABLE_ADDRESS,
            pair_at_4[0], pair_at_4[1], pair_at_12[0], pair_at_12[1],
            u32::MAX, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, PAIR_FIRST, PAIR_SECOND,
        ]);
    }

    #[test]
    fn source_alias_observes_base_vtable_store_before_copy() {
        let mut record = AlignedRecord([
            0xaaaa_aaaa, 0xbbbb_bbbb, 0xcccc_cccc, 0xdddd_dddd, 0xeeee_eeee,
            0xffff_ffff, 0x1111_1111, 0x2222_2222, 0x3333_3333, 0x4444_4444,
            0x5555_5555, 0x6666_6666, 0x7777_7777, 0x8888_8888, 0x9999_9999,
            0x1234_5678, 0x9abc_def0, 0x0fed_cba9,
        ]);
        let this = record.0.as_mut_ptr().cast::<u8>();

        unsafe { vtable_two_pair_metadata_construct(this, this, this.add(4), 0) };

        assert_eq!(record.0[1..5], [0x0898_1718; 4]);
        assert_eq!(record.0[0], METADATA_VTABLE_ADDRESS);
    }
}
