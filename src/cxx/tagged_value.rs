//! `tagged_value_from_optional_word4` — original: `FUN_0828407c` @
//! **0x0828407c**.
//!
//! Raw ARM establishes a 108-byte extent: 96 instruction bytes at
//! 0x0828407c..0x082840d8 followed by the three literal-pool words at
//! 0x082840dc..0x082840e4; 0x082840e8 starts the separate context-scope
//! constructor. Decoding every ARM `B`/`BL` word in `osos.dec` finds exactly
//! 18 direct callers: 18 unconditional `bl`, no predicated `bl`, and no tail
//! `b`.
//!
//! # Algorithm
//!
//! The opaque source record contributes its aligned word at +0x04. A nonzero
//! word constructs the output as kind 1 with that word at +0x08 and zero at
//! +0x0c. A zero word instead lazily initializes the BSS default record at
//! 0x08a126ac through the ADS guard at 0x089ca620, then copies its vtable,
//! kind byte, and +0x08/+0x0c words. In both arms, the padding after `kind`
//! is untouched and `this` returns in r0.
//!
//! The source record's class identity is not recovered: the raw body reads
//! only its word at +0x04, so the structural name deliberately records that
//! contract. Deliberate deviation: the firmware's fixed guard and default
//! addresses use host statics off-target; the vtable remains its opaque
//! target-width address rather than an invented dispatch target.

use crate::runtime::cxa_guard::{cxa_guard_acquire, cxa_guard_release};

/// The opaque vtable literal loaded by all three tagged-value helpers.
pub const TAGGED_VALUE_VTABLE: u32 = 0x089a_76fc;

/// The 16-byte tagged value output by [`tagged_value_from_optional_word4`].
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TaggedValue {
    /// +0x00: opaque vtable pointer.
    pub vtable: u32,
    /// +0x04: discriminator; 0 is the default value and 1 owns `payload`.
    pub kind: u8,
    /// +0x05..+0x07: never written by the original constructors.
    pub padding: [u8; 3],
    /// +0x08: source word selected for kind 1.
    pub payload: u32,
    /// +0x0c: zero for kind 1; copied verbatim from the default otherwise.
    pub auxiliary: u32,
}

const _: [u8; 0x00] = [0; core::mem::offset_of!(TaggedValue, vtable)];
const _: [u8; 0x04] = [0; core::mem::offset_of!(TaggedValue, kind)];
const _: [u8; 0x08] = [0; core::mem::offset_of!(TaggedValue, payload)];
const _: [u8; 0x0c] = [0; core::mem::offset_of!(TaggedValue, auxiliary)];
const _: [u8; 0x10] = [0; core::mem::size_of::<TaggedValue>()];

#[cfg(target_os = "none")]
const DEFAULT_TAGGED_VALUE_GUARD: *mut u32 = 0x089c_a620 as *mut u32;
#[cfg(target_os = "none")]
const DEFAULT_TAGGED_VALUE: *mut TaggedValue = 0x08a1_26ac as *mut TaggedValue;

#[cfg(not(target_os = "none"))]
static mut HOST_DEFAULT_TAGGED_VALUE_GUARD: u32 = 0;
#[cfg(not(target_os = "none"))]
static mut HOST_DEFAULT_TAGGED_VALUE: TaggedValue = TaggedValue {
    vtable: 0,
    kind: 0,
    padding: [0; 3],
    payload: 0,
    auxiliary: 0,
};

/// Runs the original default-value initializer if this is its first use.
unsafe fn default_tagged_value() -> *const TaggedValue {
    #[cfg(target_os = "none")]
    let (guard, value) = (DEFAULT_TAGGED_VALUE_GUARD, DEFAULT_TAGGED_VALUE);
    #[cfg(not(target_os = "none"))]
    let (guard, value) = (
        core::ptr::addr_of_mut!(HOST_DEFAULT_TAGGED_VALUE_GUARD),
        core::ptr::addr_of_mut!(HOST_DEFAULT_TAGGED_VALUE),
    );

    if guard.read() & 1 == 0 && cxa_guard_acquire(guard) != 0 {
        (*value).vtable = TAGGED_VALUE_VTABLE;
        (*value).kind = 0;
        cxa_guard_release(guard);
    }
    value
}

/// Constructs a tagged value from the source's word at byte offset +0x04.
///
/// # Safety
///
/// `this` must point to a writable, four-byte-aligned [`TaggedValue`].
/// `source_words` must point to at least two aligned `u32` words. Neither
/// pointer is NULL-checked, matching the original ARM body.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.tagged_value_from_optional_word4")]
#[inline(never)]
pub unsafe extern "C" fn tagged_value_from_optional_word4(
    this: *mut TaggedValue,
    source_words: *const u32,
) -> *mut TaggedValue {
    let payload = source_words.add(1).read();
    if payload != 0 {
        (*this).vtable = TAGGED_VALUE_VTABLE;
        (*this).kind = 1;
        (*this).payload = payload;
        (*this).auxiliary = 0;
        return this;
    }

    let default = default_tagged_value();
    (*this).vtable = (*default).vtable;
    (*this).kind = (*default).kind;
    (*this).payload = (*default).payload;
    (*this).auxiliary = (*default).auxiliary;
    this
}
/// Compares the payload word pair of two tagged values — original:
/// `FUN_08258d7c` @ `0x08258d7c` (36 bytes).
///
/// Raw ARM contains nine instructions at 0x08258d7c..0x08258d9c; 0x08258da0
/// starts the next function. Decoding every ARM `B`/`BL` word in `osos.dec`
/// finds exactly nine direct callers: nine unconditional `bl`, no predicated
/// `bl`, and no direct tail `b`.
///
/// # Algorithm
///
/// It loads both aligned words at +0x08 and returns false unless they match.
/// Only then does it compare the aligned +0x0c words. The vtable, kind, and
/// padding are ignored. Neither input is NULL-checked. Deliberate deviations:
/// none.
///
/// # Safety
///
/// `left` and `right` must each point to readable, four-byte-aligned
/// [`TaggedValue`] storage. As in the original, the +0x0c word need only be
/// readable when the +0x08 words are equal.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.tagged_value_payload_pair_equal")]
#[inline(never)]
pub unsafe extern "C" fn tagged_value_payload_pair_equal(
    left: *const TaggedValue,
    right: *const TaggedValue,
) -> bool {
    if (*left).payload != (*right).payload {
        return false;
    }
    (*left).auxiliary == (*right).auxiliary
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::STRING_OBJECT_ASSIGN_CSTR_TEST_LOCK as HOST_DEFAULT_LOCK;

    unsafe fn reset_host_default(value: TaggedValue, guard: u32) {
        core::ptr::addr_of_mut!(HOST_DEFAULT_TAGGED_VALUE).write(value);
        core::ptr::addr_of_mut!(HOST_DEFAULT_TAGGED_VALUE_GUARD).write(guard);
    }

    #[test]
    fn nonzero_source_word_builds_kind_one_and_preserves_output_padding() {
        let _guard = HOST_DEFAULT_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        unsafe {
            let source = [0x1234_5678, 0xfeed_face, 0xaaaa_5555];
            let mut destination = [0xdead_beef, 0x93a2_b1c4, 0x1122_3344, 0x5566_7788];
            let this = destination.as_mut_ptr().cast::<TaggedValue>();

            assert_eq!(tagged_value_from_optional_word4(this, source.as_ptr()), this);
            assert_eq!(destination, [TAGGED_VALUE_VTABLE, 0x93a2_b101, 0xfeed_face, 0]);
        }
    }

    #[test]
    fn zero_source_copies_the_lazily_initialized_default() {
        let _guard = HOST_DEFAULT_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        unsafe {
            reset_host_default(
                TaggedValue {
                    vtable: 0,
                    kind: 0xff,
                    padding: [0; 3],
                    payload: 0,
                    auxiliary: 0,
                },
                0,
            );
            let source = [0x1111_1111, 0];
            let mut destination = [0xffff_ffff, 0xa4b3_c2d1, 0xffff_ffff, 0xffff_ffff];
            let this = destination.as_mut_ptr().cast::<TaggedValue>();

            assert_eq!(tagged_value_from_optional_word4(this, source.as_ptr()), this);
            assert_eq!(destination, [TAGGED_VALUE_VTABLE, 0xa4b3_c200, 0, 0]);
        }
    }

    #[test]
    fn initialized_default_is_not_reinitialized_on_later_zero_source_calls() {
        let _guard = HOST_DEFAULT_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        unsafe {
            reset_host_default(
                TaggedValue { vtable: 0, kind: 0, padding: [0; 3], payload: 0, auxiliary: 0 },
                0,
            );
            let source = [0, 0];
            let mut first = TaggedValue { vtable: 0, kind: 0, padding: [0; 3], payload: 0, auxiliary: 0 };
            tagged_value_from_optional_word4(&mut first, source.as_ptr());

            let default = core::ptr::addr_of_mut!(HOST_DEFAULT_TAGGED_VALUE);
            (*default).vtable = 0xface_cafe;
            (*default).kind = 0x7e;
            (*default).payload = 0x1234_5678;
            (*default).auxiliary = 0x8765_4321;
            let mut second = TaggedValue { vtable: 0, kind: 0, padding: [0x61, 0x62, 0x63], payload: 0, auxiliary: 0 };

            tagged_value_from_optional_word4(&mut second, source.as_ptr());
            assert_eq!(second.vtable, 0xface_cafe);
            assert_eq!(second.kind, 0x7e);
            assert_eq!(second.padding, [0x61, 0x62, 0x63], "copy omits padding bytes");
            assert_eq!(second.payload, 0x1234_5678);
            assert_eq!(second.auxiliary, 0x8765_4321);
        }
    }
    #[test]
    fn payload_pair_comparison_ignores_metadata_and_requires_both_words() {
        let left = TaggedValue {
            vtable: 0x089a_76fc,
            kind: 1,
            padding: [0x12, 0x34, 0x56],
            payload: 0x1122_3344,
            auxiliary: 0x5566_7788,
        };
        let matching_pair = TaggedValue {
            vtable: 0xfeed_face,
            kind: 0,
            padding: [0xaa, 0xbb, 0xcc],
            payload: 0x1122_3344,
            auxiliary: 0x5566_7788,
        };
        let auxiliary_mismatch = TaggedValue { auxiliary: 0x5566_7789, ..matching_pair };
        let payload_mismatch = TaggedValue { payload: 0x1122_3345, ..matching_pair };

        unsafe {
            assert!(tagged_value_payload_pair_equal(&left, &matching_pair));
            assert!(!tagged_value_payload_pair_equal(&left, &auxiliary_mismatch));
            assert!(!tagged_value_payload_pair_equal(&left, &payload_mismatch));
        }
    }

}
