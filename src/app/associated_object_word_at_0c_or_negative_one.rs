//! associated_object_word_at_0c_or_negative_one — original: `FUN_081bd63c` @
//! `0x081bd63c` (24 bytes).
//!
//! Raw ARM words establish the exact 24-byte extent `0x081bd63c..0x081bd653`:
//! `cmp r1,#0; ldrne r0,[r1,#0x244]; cmpne r0,#0; ldrne r0,[r0,#0xc];
//! mvneq r0,#0; bx lr`. The next independently entered function starts at
//! `0x081bd654`. A complete aligned A32 decode of `osos.dec` finds three
//! inbound unconditional plain `bl` instructions at `0x081bd44c`,
//! `0x081bd500`, and `0x081bdc10`, and no predicated inbound `bl` forms.
//!
//! Treats the second argument as an opaque target-width object. If it is
//! non-null, loads its target pointer at +0x244 and then the signed word at
//! +0xc of that associated object; a null first-level or associated pointer
//! returns -1. The first ABI argument is overwritten by the ARM sequence and
//! is deliberately ignored. No deliberate deviations: reads remain unchecked
//! and target pointers remain 32-bit words even when host pointers are wider.

const ASSOCIATED_OBJECT_OFFSET: usize = 0x244;
const VALUE_OFFSET: usize = 0xc;

/// Returns the associated object's signed word at +0xc, or -1 for no object.
///
/// # Safety
///
/// When `object` is non-null, it must be four-byte aligned and readable
/// through +0x244. Its nonzero 32-bit target pointer must identify a
/// four-byte-aligned object readable through +0xc.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn associated_object_word_at_0c_or_negative_one(
    _receiver: *const u8,
    object: *const u8,
) -> i32 {
    if object.is_null() {
        return -1;
    }

    let associated = unsafe { (object.add(ASSOCIATED_OBJECT_OFFSET) as *const u32).read() };
    if associated == 0 {
        return -1;
    }

    unsafe { ((associated as usize as *const u8).add(VALUE_OFFSET) as *const i32).read() }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OBJECT_SIZE: usize = ASSOCIATED_OBJECT_OFFSET + core::mem::size_of::<u32>();
    const ASSOCIATED_OFFSET: usize = 0x300;
    const SLAB_SIZE: usize = ASSOCIATED_OFFSET + VALUE_OFFSET + core::mem::size_of::<i32>();

    #[test]
    fn returns_negative_one_for_null_object_and_null_associated_pointer() {
        assert_eq!(
            unsafe { associated_object_word_at_0c_or_negative_one(core::ptr::null(), core::ptr::null()) },
            -1
        );

        let mut object = [0_u32; OBJECT_SIZE / core::mem::size_of::<u32>()];
        assert_eq!(
            unsafe {
                associated_object_word_at_0c_or_negative_one(
                    core::ptr::null(),
                    object.as_mut_ptr().cast(),
                )
            },
            -1
        );
    }

    #[test]
    fn reads_the_signed_word_through_the_target_width_associated_pointer() {
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::ASSOCIATED_OBJECT_WORD_AT_0C,
            SLAB_SIZE,
        ) else {
            return;
        };
        let associated = unsafe { slab.add(ASSOCIATED_OFFSET) };

        unsafe {
            (slab.add(ASSOCIATED_OBJECT_OFFSET) as *mut u32).write(associated as usize as u32);
            (associated.add(VALUE_OFFSET) as *mut i32).write(i32::MIN);
        }

        assert_eq!(
            unsafe { associated_object_word_at_0c_or_negative_one(core::ptr::null(), slab) },
            i32::MIN
        );
    }
}
