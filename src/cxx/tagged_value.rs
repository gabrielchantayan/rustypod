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

use core::mem::MaybeUninit;
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
/// Initializes a tagged value to its default kind — original:
/// `FUN_08258d48` @ `0x08258d48` (24 bytes).
///
/// Raw ARM has five instructions at 0x08258d48..0x08258d58 and its vtable
/// literal at 0x08258d5c; 0x08258d60 starts the separate assignment helper.
/// Thus Ghidra's reported 20-byte code extent omits the trailing literal-pool
/// word. Decoding every ARM `B`/`BL` word in `osos.dec` finds exactly nine
/// direct callers: nine unconditional `bl`, no predicated `bl`, and no tail
/// `b`. No aligned image word equals 0x08258d48, so the function is not
/// reached through a stored function-pointer dispatch.
///
/// # Algorithm
///
/// It stores opaque vtable literal 0x089a76fc at +0x00 and zero at kind byte
/// +0x04, preserving the three padding bytes and the +0x08/+0x0c payload
/// words. It returns `this` in r0. Deliberate deviation: volatile stores
/// preserve the original vtable-then-kind store sequence. The vtable target's
/// class identity is unrecovered and remains an opaque word.
///
/// # Safety
///
/// `this` must point to writable, four-byte-aligned [`TaggedValue`] storage.
/// It is not NULL-checked, matching the original ARM body.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.tagged_value_default_construct")]
#[inline(never)]
pub unsafe extern "C" fn tagged_value_default_construct(this: *mut TaggedValue) -> *mut TaggedValue {
    core::ptr::write_volatile(core::ptr::addr_of_mut!((*this).vtable), TAGGED_VALUE_VTABLE);
    core::ptr::write_volatile(core::ptr::addr_of_mut!((*this).kind), 0);
    this
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

const INDEXED_SOURCE_WRITE_RECORD_WORD: usize = 0x27c / 4;
type IndexedSourceWriteRecord = unsafe extern "C" fn(*mut u32, *mut u8, u32);

/// Host-width model of the one vtable slot reached by
/// [`tagged_value_from_indexed_source`].
///
/// The target's slot is word 159 (`+0x27c`). Native-width function pointers
/// keep the host fixture valid without truncating the dispatched entry.
#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostIndexedSourceVtable {
    pub unresolved_000_to_278: [usize; INDEXED_SOURCE_WRITE_RECORD_WORD],
    pub write_indexed_record: IndexedSourceWriteRecord,
}

/// Host-width object whose first field supplies [`HostIndexedSourceVtable`].
#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostIndexedSource {
    pub vtable: *const HostIndexedSourceVtable,
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn write_indexed_source_record(record: *mut u32, source: *mut u8, index: u32) {
    let vtable = source.cast::<u32>().read() as usize as *const u32;
    let write_record: IndexedSourceWriteRecord =
        core::mem::transmute(vtable.add(INDEXED_SOURCE_WRITE_RECORD_WORD).read() as usize);
    write_record(record, source, index);
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn write_indexed_source_record(record: *mut u32, source: *mut u8, index: u32) {
    let source = source.cast::<HostIndexedSource>();
    let vtable = core::ptr::read_volatile(core::ptr::addr_of!((*source).vtable));
    ((*vtable).write_indexed_record)(record, source.cast(), index);
}

/// Builds a tagged value from the record selected by a source object's vtable.
///
/// `tagged_value_from_indexed_source` — original: `FUN_0813da28` @
/// **0x0813da28** (48 bytes, `0x0813da28..0x0813da54`; the separately linked
/// next function starts at `0x0813da58`).
///
/// Raw ARM allocates an uninitialized five-word temporary record, then invokes
/// the source's vtable slot `+0x27c` as `(record, source, index)`. It passes
/// that record to [`tagged_value_from_optional_word4`], which observes only
/// its word at `+0x04`, and returns `this`. Decoding every ARM `B`/`BL`
/// immediate in `osos.dec` finds exactly nine direct callers: nine
/// unconditional `bl` at 0x0810c92c, 0x08179f00, 0x08179f18, 0x08179f5c,
/// 0x08179f78, 0x0817a09c, 0x0817a0b4, 0x0817a0f8, and 0x0817a114; no
/// predicated `bl` or direct tail `b`.
///
/// The source class and its vtable target are unrecovered, so the port
/// dispatches the raw vtable slot rather than inventing a fixed callee or a
/// seam. Deliberate host deviation: the vtable uses a native-width function
/// pointer, preserving its slot role on 64-bit test hosts.
///
/// # Safety
///
/// `this` must point to writable, four-byte-aligned [`TaggedValue`] storage.
/// `source` must have a readable first vtable word and a callable slot
/// `+0x27c`; that slot must initialize the temporary record through word
/// `+0x04`. Neither pointer nor the slot is NULL-checked, matching retailOS.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.tagged_value_from_indexed_source")]
#[inline(never)]
pub unsafe extern "C" fn tagged_value_from_indexed_source(
    this: *mut TaggedValue,
    source: *mut u8,
    index: u32,
) -> *mut TaggedValue {
    let mut record = MaybeUninit::<[u32; 5]>::uninit();
    write_indexed_source_record(record.as_mut_ptr().cast(), source, index);
    tagged_value_from_optional_word4(this, record.as_ptr().cast())
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

    static mut INDEXED_SOURCE_RECORD: *mut u32 = core::ptr::null_mut();
    static mut INDEXED_SOURCE_ARGUMENT: *mut u8 = core::ptr::null_mut();
    static mut INDEXED_SOURCE_INDEX: u32 = 0;

    unsafe extern "C" fn record_indexed_source(record: *mut u32, source: *mut u8, index: u32) {
        INDEXED_SOURCE_RECORD = record;
        INDEXED_SOURCE_ARGUMENT = source;
        INDEXED_SOURCE_INDEX = index;
        record.write(0x1234_5678);
        record.add(1).write(index | 0x8000_0000);
        record.add(4).write(0xfeed_face);
    }

    static INDEXED_SOURCE_VTABLE: HostIndexedSourceVtable = HostIndexedSourceVtable {
        unresolved_000_to_278: [0; INDEXED_SOURCE_WRITE_RECORD_WORD],
        write_indexed_record: record_indexed_source,
    };

    #[test]
    fn indexed_source_dispatch_forwards_index_and_constructs_tagged_value() {
        let _guard = HOST_DEFAULT_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        unsafe {
            let mut source = HostIndexedSource { vtable: &INDEXED_SOURCE_VTABLE };
            let mut destination = TaggedValue {
                vtable: 0xdead_beef,
                kind: 0xf0,
                padding: [0x21, 0x43, 0x65],
                payload: 0xaaaa_aaaa,
                auxiliary: 0xbbbb_bbbb,
            };
            let this = core::ptr::addr_of_mut!(destination);
            let source_ptr = core::ptr::addr_of_mut!(source).cast::<u8>();
            INDEXED_SOURCE_RECORD = core::ptr::null_mut();
            INDEXED_SOURCE_ARGUMENT = core::ptr::null_mut();
            INDEXED_SOURCE_INDEX = 0;

            assert_eq!(tagged_value_from_indexed_source(this, source_ptr, 0), this);
            assert_eq!(INDEXED_SOURCE_ARGUMENT, source_ptr);
            assert_eq!(INDEXED_SOURCE_INDEX, 0);
            assert_ne!(INDEXED_SOURCE_RECORD.cast::<TaggedValue>(), this);
            assert_eq!(destination.vtable, TAGGED_VALUE_VTABLE);
            assert_eq!(destination.kind, 1);
            assert_eq!(destination.padding, [0x21, 0x43, 0x65]);
            assert_eq!(destination.payload, 0x8000_0000);
            assert_eq!(destination.auxiliary, 0);

            assert_eq!(tagged_value_from_indexed_source(this, source_ptr, u32::MAX), this);
            assert_eq!(INDEXED_SOURCE_ARGUMENT, source_ptr);
            assert_eq!(INDEXED_SOURCE_INDEX, u32::MAX);
            assert_eq!(destination.payload, u32::MAX);
        }
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
    fn default_constructor_sets_only_vtable_and_kind_and_returns_this() {
        let mut destination = [0xdead_beef, 0xa4b3_c2d1, 0x1122_3344, 0x5566_7788];
        let this = destination.as_mut_ptr().cast::<TaggedValue>();

        unsafe {
            assert_eq!(tagged_value_default_construct(this), this);
        }
        assert_eq!(destination, [TAGGED_VALUE_VTABLE, 0xa4b3_c200, 0x1122_3344, 0x5566_7788]);
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
