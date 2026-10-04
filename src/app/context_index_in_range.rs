//! Context index range predicate.
//!
//! Original `FUN_081f0e90` at 0x081f0e90, 52 bytes, ending at the next
//! independent push at 0x081f0ec4. Whole-image aligned A32 decoding verifies
//! two inbound plain BLs (0x081f0810, 0x081fcba0), zero predicated inbound
//! BLs, and zero outbound BLs of either kind.
//! Read the associated object's signed bound at +0x2b8 through the context's
//! target-width pointer at +0x30. Return one iff the index interpreted as i32
//! is below that bound and is within the context's unsigned inclusive bounds
//! at +0x38 and +0x3c. Loads short-circuit in original order; no NULL guard.
//! Deliberate deviation: structured branches replace predicated return;
//! word indices preserve firmware offsets on hosts without widening pointers.

/// # Safety
/// `context` must point to 16 aligned readable u32 words. Its word at +0x30
/// must contain a valid 32-bit address of at least 175 aligned readable words.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn context_index_in_range(context: *const u32, index: u32) -> u32 {
    let associated = context.add(0x30 / 4).read() as usize as *const i32;
    if index as i32 >= associated.add(0x2b8 / 4).read() {
        return 0;
    }
    if context.add(0x38 / 4).read() > index {
        return 0;
    }
    (index <= context.add(0x3c / 4).read()) as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    #[test]
    fn inclusive_unsigned_range_and_exclusive_signed_bound() {
        let Some(slab) = try_map_u32_slab(hints::CONTEXT_INDEX_IN_RANGE, 0x1000) else {
            assert!(note_missing_u32_fixture("app/context_index_in_range"));
            return;
        };
        unsafe {
            let associated = slab.cast::<i32>();
            let mut context = [0x12345678u32; 16];
            context[12] = associated as usize as u32;
            let values = [0, 1, 2, 7, 8, 9, 0x7fff_fffe, 0x7fff_ffff,
                0x8000_0000, 0x8000_0001, 0xffff_fffe, 0xffff_ffff];
            for bound in [i32::MIN, -2, -1, 0, 1, 8, i32::MAX] {
                associated.add(174).write(bound);
                for lower in values {
                    for upper in values {
                        context[14] = lower;
                        context[15] = upper;
                        let before = context;
                        for index in values {
                            let signed_index = if index & 0x8000_0000 != 0 {
                                index as i64 - 0x1_0000_0000
                            } else { index as i64 };
                            let expected = signed_index < bound as i64
                                && (lower as u64..=upper as u64).contains(&(index as u64));
                            assert_eq!(context_index_in_range(context.as_ptr(), index),
                                expected as u32, "bound={bound} lower={lower:x} upper={upper:x} index={index:x}");
                            assert_eq!(context, before);
                            assert_eq!(associated.add(174).read(), bound);
                        }
                    }
                }
            }
        }
    }
}
