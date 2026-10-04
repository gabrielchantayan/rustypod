//! Two-pair base with an owned string pair — FUN_08203270 @ 0x08203270.
//! True size: 48 bytes (44 code bytes plus vtable literal), next function
//! 0x082032a0. Two inbound plain BL sites (0x081dcc5c, 0x081dcc8c), zero
//! predicated; three outbound plain BL instructions, zero predicated.
//! Construct the 20-byte base using entry r1/r2 as pair sources, replace its
//! vtable with 0x0899156c, allocate 16 bytes, construct two string objects
//! through 0x0819b5e4, store its return at +20, and return the base object.
//! Deliberate deviations: reuse Rust base/heap ports; the unported string-pair
//! constructor remains an exact-address resident seam with host injection.
//! Pointer fields remain u32 on hosts. No NULL guard or extra initialization.
//! The class name is structural; no concrete application identity is assumed.

use crate::cxx::vtable_two_pair_base_construct::vtable_two_pair_base_construct;
use crate::heap::veneers::operator_new;

pub type StringPairConstruct = unsafe extern "C" fn(*mut u8) -> *mut u8;
#[cfg(not(target_os = "none"))]
pub static mut STRING_PAIR_CONSTRUCT: Option<StringPairConstruct> = None;

/// Construct a 24-byte owner, preserving the base constructor's source aliases.
///
/// # Safety
/// `owner` is aligned writable storage for six u32 words; both sources are
/// aligned readable pairs. The heap and resident string constructor must be
/// initialized. Hosts must install STRING_PAIR_CONSTRUCT. Allocation failure
/// is passed to the constructor without a guard, exactly as in firmware.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn two_pair_string_pair_owner_construct(
    owner: *mut u32, first_pair: *const u32, second_pair: *const u32,
) -> *mut u32 {
    #[cfg(target_os = "none")]
    let nested: StringPairConstruct = core::mem::transmute(0x0819_b5e4usize);
    #[cfg(not(target_os = "none"))]
    let nested = core::ptr::addr_of!(STRING_PAIR_CONSTRUCT).read()
        .expect("install resident string-pair constructor");
    construct(owner, first_pair, second_pair, |size| operator_new(size), nested)
}

unsafe fn construct(
    owner: *mut u32, first_pair: *const u32, second_pair: *const u32,
    allocate: impl FnOnce(usize) -> *mut u8, nested: StringPairConstruct,
) -> *mut u32 {
    let base = vtable_two_pair_base_construct(
        owner.cast(), first_pair.cast(), second_pair.cast(),
    ).cast::<u32>();
    base.write_volatile(0x0899_156c);
    let storage = allocate(16);
    let strings = nested(storage);
    base.add(5).write(strings as usize as u32);
    base
}

#[cfg(test)]
mod tests {
    use super::*;

    // Reference for the resident pair's two eight-byte default constructors.
    unsafe extern "C" fn reference_strings(storage: *mut u8) -> *mut u8 {
        let words = storage.cast::<u32>();
        for offset in [0, 2] {
            words.add(offset).write(0x089a_6044);
            words.add(offset + 1).write(0);
        }
        storage
    }

    #[test]
    fn initializes_nested_strings_and_preserves_neighbors_and_source_aliases() {
        for fill in [0, u32::MAX, 0xa5a5_a5a5] {
            let mut words = [fill; 8];
            let mut strings = [fill; 6];
            let owner = unsafe { words.as_mut_ptr().add(1) };
            let nested = unsafe { strings.as_mut_ptr().add(1).cast::<u8>() };
            let returned = unsafe {
                construct(owner, owner, owner.add(1), |size| {
                    assert_eq!(size, 16);
                    // Allocation must follow the derived-vtable store.
                    assert_eq!(owner.read(), 0x0899_156c);
                    nested
                }, reference_strings)
            };
            assert_eq!(returned, owner);
            // Ordered base copies: first source aliases the base vtable, then
            // the second source aliases the first pair's newly written words.
            assert_eq!(words, [fill, 0x0899_156c, 0x0898_1718, 0x0898_1718,
                0x0898_1718, 0x0898_1718, nested as usize as u32, fill]);
            assert_eq!(strings, [fill, 0x089a_6044, 0, 0x089a_6044, 0, fill]);
        }
    }
}
