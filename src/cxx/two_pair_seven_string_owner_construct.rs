//! `two_pair_seven_string_owner_construct` — `FUN_081558ec` @ 0x081558ec.
//! True extent: 100 bytes (96 code bytes, vtable literal at 0x08155950);
//! next function starts at 0x08155954. Raw-word decoding verifies two inbound
//! plain BLs (0x081360ec, 0x081da93c), eight outgoing plain BLs and zero
//! predicated BLs in either direction.
//!
//! Construct the 20-byte two-pair base using incoming r1/r2, replace its
//! vtable with 0x08986a70, construct seven strings at +20..+68, then set
//! bytes +76/+77/+78 to 0/1/0. Return the original object; leave +79 intact.
//! The callers do not initialize r1/r2: the base consumes their incoming
//! register values, not invented defaults. The class identity is unknown.
//!
//! Deliberate deviation: expose those pair sources as explicit arguments.
//! Host builds write each string's two target-width words instead of calling
//! the host-width StringObject constructor, following framework_string_pair_construct.
//! ARM builds call the existing constructor directly; no new firmware seam.

use super::vtable_two_pair_base_construct::vtable_two_pair_base_construct;
#[cfg(target_os = "none")]
use super::string_object::{string_default_construct, StringObject};
#[cfg(not(target_os = "none"))]
use super::string_object::STRING_OBJECT_VTABLE_ADDRESS;

pub const TWO_PAIR_SEVEN_STRING_OWNER_VTABLE: u32 = 0x0898_6a70;

/// Fixed 80-byte firmware layout, including the untouched final padding byte.
#[repr(C)]
pub struct TwoPairSevenStringOwner {
    pub vtable: u32,
    pub first_pair: [u32; 2],
    pub second_pair: [u32; 2],
    pub strings: [[u32; 2]; 7],
    pub flags: [u8; 3],
    pub padding: u8,
}

unsafe fn construct_string(storage: *mut u32) {
    #[cfg(target_os = "none")]
    string_default_construct(storage.cast::<StringObject>());
    #[cfg(not(target_os = "none"))]
    {
        storage.write_volatile(STRING_OBJECT_VTABLE_ADDRESS as u32);
        storage.add(1).write_volatile(0);
    }
}

/// # Safety
/// `this` must designate 80 writable, word-aligned bytes. Both sources must
/// designate eight readable, word-aligned bytes; overlap is allowed and
/// observes the base constructor's ordered stores before string initialization.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn two_pair_seven_string_owner_construct(
    this: *mut TwoPairSevenStringOwner,
    first_pair: *const u8,
    second_pair: *const u8,
) -> *mut TwoPairSevenStringOwner {
    let object = vtable_two_pair_base_construct(this.cast(), first_pair, second_pair)
        .cast::<TwoPairSevenStringOwner>();
    object.cast::<u32>().write_volatile(TWO_PAIR_SEVEN_STRING_OWNER_VTABLE);
    let words = object.cast::<u32>();
    construct_string(words.add(5));
    construct_string(words.add(7));
    construct_string(words.add(9));
    construct_string(words.add(11));
    construct_string(words.add(13));
    construct_string(words.add(15));
    construct_string(words.add(17));
    let bytes = object.cast::<u8>();
    bytes.add(76).write_volatile(0);
    bytes.add(77).write_volatile(1);
    bytes.add(78).write_volatile(0);
    object
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_layout_matches_ordered_reference_with_overlapping_sources() {
        assert_eq!(core::mem::size_of::<TwoPairSevenStringOwner>(), 80);
        // External pairs, self aliases, prior destination aliases, and sources
        // in the string area that will subsequently be overwritten.
        for (first, second) in [(0, 2), (4, 5), (3, 5), (9, 21)] {
            let mut actual = core::array::from_fn::<u32, 26, _>(|i| 0xa500_0000 + i as u32);
            let mut expected = actual;
            expected[4] = 0x0898_1718;
            expected[5] = expected[first];
            expected[6] = expected[first + 1];
            expected[7] = expected[second];
            expected[8] = expected[second + 1];
            expected[4] = TWO_PAIR_SEVEN_STRING_OWNER_VTABLE;
            for i in 0..7 {
                expected[9 + 2 * i] = STRING_OBJECT_VTABLE_ADDRESS as u32;
                expected[10 + 2 * i] = 0;
            }
            expected[23] = (expected[23] & 0xff00_0000) | 0x100;
            let pointer = actual.as_mut_ptr();
            let object = unsafe { pointer.add(4).cast::<TwoPairSevenStringOwner>() };
            let returned = unsafe {
                two_pair_seven_string_owner_construct(
                    object, pointer.add(first).cast(), pointer.add(second).cast(),
                )
            };
            assert_eq!(returned, object);
            assert_eq!(actual, expected, "sources at words {first}/{second}");
        }
    }
}
