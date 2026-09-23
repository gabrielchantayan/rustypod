//! Inserts every decoded UTF-8 codepoint into a BitSet resolved through a
//! tagged virtual receiver.
//!
//! `tagged_bit_set_insert_utf8` — original: `FUN_081cddd8` @ **0x081cddd8**
//! (**132 bytes**, 0x081cddd8..0x081cde5c; the next function opens `push
//! {r2,r3,r4,lr}` at 0x081cde5c). The body has **three call instructions**:
//! one indirect `blx` through vtable slot `+0x28`, and two unconditional
//! plain `bl` calls (ported `utf8_next_codepoint` @ 0x08276214 and
//! `bit_set_test` @ 0x082a4ef8); no call is predicated.
//!
//! # Algorithm
//!
//! Clears bit 0 from `tagged_provider`, returns if the resulting pointer is
//! NULL, then obtains a BitSet from its vtable slot `+0x28`. A NULL returned
//! set also returns immediately. Otherwise it walks the NUL-terminated UTF-8
//! input using retailOS's decoder. For each decoded codepoint whose bit is
//! clear, it increments `BitSet::cardinality` and sets that bit. The loop
//! condition tests the cursor's literal byte before decoding, so an invalid
//! or four-byte lead returns codepoint zero, sets bit zero if needed, advances
//! three bytes, and continues from that advanced cursor.
//!
//! # Deliberate deviations
//!
//! The vtable receiver and slot identity are not recovered. This port names
//! only their verified contract and expresses the `blx` as a typed call;
//! target layout assertions retain the ARM word offsets. `unused` is retained
//! because r1 enters the retail ABI but is never read.

use crate::cxx::bit_set::{bit_set_test, BitSet};
use crate::cxx::string_object::utf8_next_codepoint;

const BIT_SET_PROVIDER_SLOT: usize = 0x28 / 4;

/// Unidentified virtual getter at the provider vtable's `+0x28` slot.
pub type TaggedBitSetProviderGet = unsafe extern "C" fn(*mut TaggedBitSetProvider) -> *mut BitSet;

/// Prefix of the virtual table consumed by [`tagged_bit_set_insert_utf8`].
#[repr(C)]
pub struct TaggedBitSetProviderVtable {
    /// `+0x00..+0x24`: unresolved virtual entries.
    pub opaque_00_24: [usize; BIT_SET_PROVIDER_SLOT],
    /// `+0x28`: returns the target BitSet or NULL.
    pub get_bit_set: TaggedBitSetProviderGet,
}

/// Opaque tagged receiver whose first word is a vtable pointer.
#[repr(C)]
pub struct TaggedBitSetProvider {
    pub vtable: *const TaggedBitSetProviderVtable,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x28] = [0; core::mem::offset_of!(TaggedBitSetProviderVtable, get_bit_set)];

/// Inserts decoded codepoints from `text` into the BitSet resolved by
/// `tagged_provider`.
///
/// # Safety
///
/// A nonzero `tagged_provider` must become a valid [`TaggedBitSetProvider`]
/// after bit 0 is cleared, with a callable vtable slot `+0x28`. A non-NULL
/// returned set must have word storage covering every decoded codepoint, and
/// `text` must be a readable NUL-terminated byte sequence. RetailOS validates
/// none of these conditions.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.tagged_bit_set_insert_utf8")]
pub unsafe extern "C" fn tagged_bit_set_insert_utf8(
    tagged_provider: *mut TaggedBitSetProvider,
    _unused: u32,
    text: *const u8,
) {
    let provider = (tagged_provider as usize & !1) as *mut TaggedBitSetProvider;
    if provider.is_null() {
        return;
    }

    let get_bit_set = unsafe { (*(*provider).vtable).get_bit_set };
    let set = unsafe { get_bit_set(provider) };
    if set.is_null() {
        return;
    }

    let mut cursor = text;
    while unsafe { *cursor } != 0 {
        let codepoint = unsafe { utf8_next_codepoint(&mut cursor) };
        let word = codepoint >> 5;
        let bit = codepoint & 31;
        if unsafe { bit_set_test(set, word, bit) } == 0 {
            unsafe {
                (*set).cardinality = (*set).cardinality.wrapping_add(1);
                let words = (*set).words as usize as *mut u32;
                *words.add(word as usize) |= 1 << bit;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use core::ptr;
    use std::sync::{Mutex, MutexGuard};

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut GET_CALLS: u32 = 0;
    static mut RETURNED_SET: *mut BitSet = ptr::null_mut();

    unsafe extern "C" fn get_set(_provider: *mut TaggedBitSetProvider) -> *mut BitSet {
        unsafe { GET_CALLS += 1 };
        unsafe { RETURNED_SET }
    }

    struct Bench {
        _lock: MutexGuard<'static, ()>,
    }

    fn bench() -> Bench {
        let lock = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            GET_CALLS = 0;
            RETURNED_SET = ptr::null_mut();
        }
        Bench { _lock: lock }
    }

    fn provider() -> (TaggedBitSetProviderVtable, TaggedBitSetProvider) {
        (
            TaggedBitSetProviderVtable {
                opaque_00_24: [0; BIT_SET_PROVIDER_SLOT],
                get_bit_set: get_set,
            },
            TaggedBitSetProvider { vtable: ptr::null() },
        )
    }

    #[test]
    fn inserts_unique_decoded_codepoints_and_records_invalid_lead_zero() {
        let _bench = bench();
        let Some(words) = try_map_u32_slab(hints::TAGGED_BIT_SET_INSERT_UTF8, 4096) else {
            assert!(crate::testing::note_missing_u32_fixture("cxx/tagged_bit_set_insert_utf8"));
            return;
        };
        let words = words as *mut u32;
        unsafe { words.write(0) };
        let mut set = BitSet { bit_capacity: 256, cardinality: 0, words: words as usize as u32, heap_tag: 0, reserved: [0; 3] };
        unsafe { RETURNED_SET = &mut set };
        let (vtable, mut provider) = provider();
        provider.vtable = &vtable;
        let tagged = (core::ptr::addr_of_mut!(provider) as usize | 1) as *mut TaggedBitSetProvider;

        unsafe { tagged_bit_set_insert_utf8(tagged, 0xfeed_face, b"A\xc3\xa9A\xf0z\0\0".as_ptr()) };

        unsafe {
            assert_eq!(GET_CALLS, 1);
            assert_eq!(set.cardinality, 3, "duplicate A does not recount; invalid lead inserts codepoint zero");
            assert_eq!(*words, 1, "the invalid lead's zero decode sets bit zero");
            assert_eq!(*words.add(2), 1 << 1, "U+0041 occupies bit 65");
            assert_eq!(*words.add(7), 1 << 9, "U+00e9 occupies bit 233");
        }
    }

    #[test]
    fn null_provider_and_null_virtual_result_leave_text_unread() {
        let _bench = bench();
        unsafe { tagged_bit_set_insert_utf8(ptr::null_mut(), 0, ptr::null()) };
        unsafe { assert_eq!(GET_CALLS, 0) };

        let (vtable, mut provider) = provider();
        provider.vtable = &vtable;
        unsafe { tagged_bit_set_insert_utf8(&mut provider, 0, ptr::null()) };
        unsafe { assert_eq!(GET_CALLS, 1, "virtual getter runs before NULL-set return") };
    }
}
