//! Bounded target-width word bit-set membership.
//!
//! `bounded_word_bit_set_contains` — original: `FUN_0803f358` at load address
//! **0x0803f358** (**72 bytes**, 0x0803f358..0x0803f3a0; the distinct next
//! function begins `push {r4, r5, r6, r7, r8, r9, sl, lr}` at 0x0803f3a0).
//! A decode of every ARM B/BL word in `osos.dec` finds **six direct `bl` call
//! sites and no direct `b` sites**, all unconditional: 0x0803f7fc,
//! 0x0803f85c, 0x0803fb28, 0x0803fbb0, 0x080823e0, and 0x080823f4.
//!
//! The two-word record contains a target-width pointer to its word bitmap and
//! a signed word count. A negative bit index, or an index whose `index >> 5`
//! is not below that count, returns zero. Otherwise the selected bit of the
//! selected word is tested and normalized to exactly zero or one. The retail
//! body has no NULL guard; a non-negative accepted index requires valid record
//! and bitmap storage. Deliberate deviations: none.

/// Target layout consumed by [`bounded_word_bit_set_contains`].
#[repr(C)]
pub struct BoundedWordBitSet {
    /// +0x00: target-width address of the first bitmap word.
    pub words: u32,
    /// +0x04: number of readable bitmap words; compared as signed by ARM.
    pub word_count: i32,
}

const _: [u8; 0x00] = [0; core::mem::offset_of!(BoundedWordBitSet, words)];
const _: [u8; 0x04] = [0; core::mem::offset_of!(BoundedWordBitSet, word_count)];
const _: [u8; 0x08] = [0; core::mem::size_of::<BoundedWordBitSet>()];

/// Tests `bit_index` in a bounded target-width word bitmap.
///
/// # Safety
///
/// For a non-negative `bit_index` whose word index is smaller than
/// `(*set).word_count`, `set` and the addressed word in `(*set).words` must
/// be valid to read. This matches the original's no-guard contract.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn bounded_word_bit_set_contains(
    set: *const BoundedWordBitSet,
    bit_index: i32,
) -> u32 {
    if bit_index < 0 {
        return 0;
    }

    let word_index = bit_index >> 5;
    if (*set).word_count <= word_index {
        return 0;
    }

    let word = ((*set).words as usize as *const u32).add(word_index as usize).read();
    ((word & (1u32 << (bit_index & 31))) != 0) as u32
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{bounded_word_bit_set_contains, BoundedWordBitSet};
    use std::sync::{LazyLock, Mutex};

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static WORDS: LazyLock<Option<usize>> = LazyLock::new(|| {
        crate::testing::try_map_u32_slab(
            crate::testing::hints::BOUNDED_WORD_BIT_SET_CONTAINS,
            0x1000,
        )
        .map(|words| words as usize)
    });

    fn mapped_words() -> Option<*mut u32> {
        (*WORDS).map(|words| words as *mut u32)
    }

    #[test]
    fn negative_index_returns_zero_without_dereferencing_the_set() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

        assert_eq!(unsafe { bounded_word_bit_set_contains(core::ptr::null(), -1) }, 0);
        assert_eq!(unsafe { bounded_word_bit_set_contains(core::ptr::null(), i32::MIN) }, 0);
    }

    #[test]
    fn tests_bits_across_word_boundaries_and_normalizes_result() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(words) = mapped_words() else { return };

        unsafe {
            words.write(1 << 31);
            words.add(1).write(1);
            words.add(2).write(0xffff_ffff);
        }
        let set = BoundedWordBitSet { words: words as usize as u32, word_count: 3 };

        assert_eq!(unsafe { bounded_word_bit_set_contains(&set, 0) }, 0);
        assert_eq!(unsafe { bounded_word_bit_set_contains(&set, 31) }, 1);
        assert_eq!(unsafe { bounded_word_bit_set_contains(&set, 32) }, 1);
        assert_eq!(unsafe { bounded_word_bit_set_contains(&set, 63) }, 0);
        assert_eq!(unsafe { bounded_word_bit_set_contains(&set, 95) }, 1);
    }

    #[test]
    fn rejects_word_indices_at_or_past_the_signed_count() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(words) = mapped_words() else { return };

        unsafe { words.write(1); }
        let one_word = BoundedWordBitSet { words: words as usize as u32, word_count: 1 };
        let negative_count = BoundedWordBitSet { words: 0, word_count: -1 };
        let empty = BoundedWordBitSet { words: 0, word_count: 0 };

        assert_eq!(unsafe { bounded_word_bit_set_contains(&one_word, 32) }, 0);
        assert_eq!(unsafe { bounded_word_bit_set_contains(&negative_count, 0) }, 0);
        assert_eq!(unsafe { bounded_word_bit_set_contains(&empty, i32::MAX) }, 0);
    }
}
