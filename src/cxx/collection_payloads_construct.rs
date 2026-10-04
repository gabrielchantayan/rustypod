//! Collection payload-array constructor — `FUN_08210234` @ **0x08210234**.
//!
//! True extent: **40 bytes**, 36 code bytes at `0x08210234..0x08210258`
//! plus vtable literal `0x089a47e8` at `0x08210258`; the next real function
//! is the collection payload destructor at `0x0821025c`. Full-image A32
//! decoding verifies two inbound plain BLs (`0x08119d30`, `0x081b1e24`),
//! zero predicated inbound BLs, and one outbound plain BL to the ported
//! `observable_array_construct` @ `0x08271cec` (zero predicated BLs).
//!
//! Constructs the observable-array base, installs the derived vtable, sets
//! the byte at +0x10 to one, and clears the word at +0x14. All derived stores
//! use the base constructor's returned pointer, which passes through r0.
//! Callers provide 24-byte stack objects used by the collection parser;
//! the matching destructor releases each item's payload. The roles of the
//! extra flag and state word are unresolved, so no stronger names are claimed.
//! Deliberate deviations: none. Target-width fields retain the exact layout
//! on hosts; bytes +0x11..+0x13 remain untouched, with no allocation or guards.

use super::observable_array::{observable_array_construct, ObservableArray};

pub const COLLECTION_PAYLOADS_VTABLE: u32 = 0x089a_47e8;

#[repr(C)]
pub struct CollectionPayloads {
    pub array: ObservableArray,
    pub flag: u8,
    pub padding_11_13: [u8; 3],
    pub state: u32,
}

const _: [u8; 0x10] = [0; core::mem::offset_of!(CollectionPayloads, flag)];
const _: [u8; 0x14] = [0; core::mem::offset_of!(CollectionPayloads, state)];
const _: [u8; 0x18] = [0; core::mem::size_of::<CollectionPayloads>()];

/// Initializes an empty collection payload array and returns its base result.
///
/// # Safety
/// `this` must point to at least 24 writable, word-aligned bytes.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn collection_payloads_construct(
    this: *mut CollectionPayloads,
) -> *mut CollectionPayloads {
    let object = unsafe { observable_array_construct(core::ptr::addr_of_mut!((*this).array)) }
        .cast::<CollectionPayloads>();
    unsafe {
        core::ptr::addr_of_mut!((*object).array.base.vtable).write_volatile(COLLECTION_PAYLOADS_VTABLE);
        core::ptr::addr_of_mut!((*object).flag).write_volatile(1);
        core::ptr::addr_of_mut!((*object).state).write_volatile(0);
    }
    object
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct Fixture {
        leading: u32,
        object: [u32; 6],
        trailing: u32,
    }

    #[test]
    fn resets_dirty_fields_without_touching_padding_or_adjacent_objects() {
        for seed in [0u32, u32::MAX, 0xa5c3_7e92, 0x0102_0304] {
            let mut fixture = Fixture {
                leading: 0x1234_5678,
                object: [seed; 6],
                trailing: 0x8765_4321,
            };
            let pointer = fixture.object.as_mut_ptr().cast::<CollectionPayloads>();
            let mut expected = [seed; 6];
            expected[0] = COLLECTION_PAYLOADS_VTABLE;
            expected[1..4].fill(0);
            // Reference to the ARM STRB: replace only byte +0x10.
            let mut flag_word = seed.to_ne_bytes();
            flag_word[0] = 1;
            expected[4] = u32::from_ne_bytes(flag_word);
            expected[5] = 0;

            for _ in 0..2 {
                let returned = unsafe { collection_payloads_construct(pointer) };
                assert_eq!(returned, pointer);
                assert_eq!(fixture.object, expected);
                assert_eq!(fixture.leading, 0x1234_5678);
                assert_eq!(fixture.trailing, 0x8765_4321);
            }
        }
    }
}
