//! Checked access to the first word of an owner's eight-byte vector record.
//!
//! Original: FUN_08053228 @ 0x08053228, true extent 68 bytes through
//! 0x0805326c (next independent push prologue). Raw A32 decoding verifies
//! two incoming plain BLs at 0x08066954 and 0x0813bd84, zero predicated
//! incoming BLs, and one outgoing plain BL at 0x08053248 to 0x083d7664.
//! That callee is the existing vector_size_elem8 port, verified from its
//! ldm/sub/asr #3/bx words and names.yaml.
//!
//! Reject null output and negative index before reading the owner. Compare
//! the index unsigned against the arithmetic-shift vector size, then copy
//! only the first word of the selected eight-byte record. Return zero on
//! success or -50 without modifying output on failure. The record's finer
//! meaning is not established by either caller.
//!
//! Deliberate deviation: repr(C) vector pointer fields have native width
//! on hosts, but retain the original +0xee0/+0xee4 layout on ARM. LLVM may
//! replace predicated loads/stores with branches; no algorithmic deviation.

use crate::cxx::templates::{VectorBounds, vector_size_elem8};

#[repr(C)]
pub struct PairVectorOwner {
    pub prefix: [u32; 0xee0 / 4],
    pub records: VectorBounds,
}

/// # Safety
/// After the early checks, owner must reference readable vector bounds.
/// If the unsigned size comparison succeeds, the indexed record's first
/// word must be readable and output must be writable and word-aligned.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn owner_pair_vector_word_at(
    owner: *const PairVectorOwner, index: i32, output: *mut u32,
) -> i32 {
    if output.is_null() || index < 0 {
        return -50;
    }
    let records = core::ptr::addr_of!((*owner).records);
    if index as u32 >= vector_size_elem8(records) as u32 {
        return -50;
    }
    let value = (*records).begin.cast::<u32>().add(index as usize * 2).read();
    output.write(value);
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;

    #[test]
    fn early_rejections_do_not_access_owner_or_output() {
        unsafe {
            assert_eq!(owner_pair_vector_word_at(ptr::null(), 0, ptr::null_mut()), -50);
            let mut output = 0xfeed_beef;
            for index in [-1, i32::MIN] {
                assert_eq!(owner_pair_vector_word_at(ptr::null(), index, &mut output), -50);
                assert_eq!(output, 0xfeed_beef);
            }
        }
    }

    #[test]
    fn record_stride_partial_tail_and_failure_preservation() {
        let mut words = [0x1234_5678u32, 0xdead_beef, 0, 0xffff_ffff, 0x8765_4321, 17];
        let begin = words.as_mut_ptr().cast::<u8>();
        let mut owner = PairVectorOwner {
            prefix: [0xa5a5_a5a5; 0xee0 / 4],
            records: VectorBounds { begin, end: begin },
        };
        unsafe {
            // Independently enumerate the expected complete-record count.
            for (bytes, expected) in [(0, &[][..]), (7, &[][..]),
                (8, &[0x1234_5678][..]), (15, &[0x1234_5678][..]),
                (16, &[0x1234_5678, 0][..]), (24, &[0x1234_5678, 0, 0x8765_4321][..])] {
                owner.records.end = begin.add(bytes);
                for (index, value) in expected.iter().enumerate() {
                    let mut output = 42;
                    assert_eq!(owner_pair_vector_word_at(&owner, index as i32, &mut output), 0);
                    assert_eq!(output, *value);
                }
                for index in [expected.len() as i32, i32::MAX] {
                    let mut output = 0xfeed_beef;
                    assert_eq!(owner_pair_vector_word_at(&owner, index, &mut output), -50);
                    assert_eq!(output, 0xfeed_beef);
                }
            }
            assert_eq!(words, [0x1234_5678, 0xdead_beef, 0, 0xffff_ffff, 0x8765_4321, 17]);
            assert!(owner.prefix.iter().all(|word| *word == 0xa5a5_a5a5));
        }
    }

    #[test]
    fn reversed_bounds_retain_unsigned_size_comparison_and_output_aliasing() {
        let mut words = [11u32, 99, 22, 88];
        let begin = words.as_mut_ptr().cast::<u8>();
        let owner = PairVectorOwner {
            prefix: [0; 0xee0 / 4],
            // -8 >> 3 is -1, compared as UINT_MAX by stock CMP/HI.
            records: VectorBounds { begin: unsafe { begin.add(8) }, end: begin },
        };
        unsafe {
            assert_eq!(owner_pair_vector_word_at(&owner, 0, words.as_mut_ptr()), 0);
            assert_eq!(words, [22, 99, 22, 88]);
        }
    }
}
