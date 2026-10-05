//! Two-pair base with an owned string pair — FUN_08203270 @ 0x08203270.
//! True size: 48 bytes (44 code bytes plus vtable literal), next function
//! 0x082032a0. Two inbound plain BL sites (0x081dcc5c, 0x081dcc8c), zero
//! predicated; three outbound plain BL instructions, zero predicated.
//! Construct the 20-byte base using entry r1/r2 as pair sources, replace its
//! vtable with 0x0899156c, allocate 16 bytes, construct two string objects
//! through 0x0819b5e4, store its return at +20, and return the base object.
//! Deliberate deviations: reuse Rust base/heap/string ports. Host allocation
//! widens to fit StringObjectPair's pointer fields; ARM still allocates 16 bytes.
//! Owner pointer fields remain u32. No NULL guard or extra initialization.
//! The class name is structural; no concrete application identity is assumed.

use crate::cxx::vtable_two_pair_base_construct::vtable_two_pair_base_construct;
use crate::cxx::string_object::{string_object_pair_default_construct, StringObjectPair};
use crate::heap::veneers::operator_new;


/// Construct a 24-byte owner, preserving the base constructor's source aliases.
///
/// # Safety
/// `owner` is aligned writable storage for six u32 words; both sources are
/// aligned readable pairs. The heap must be initialized. Allocation failure
/// is passed to the constructor without a guard, exactly as in firmware.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn two_pair_string_pair_owner_construct(
    owner: *mut u32, first_pair: *const u32, second_pair: *const u32,
) -> *mut u32 {
    construct(owner, first_pair, second_pair, |size| operator_new(size))
}

unsafe fn construct(
    owner: *mut u32, first_pair: *const u32, second_pair: *const u32,
    allocate: impl FnOnce(usize) -> *mut u8,
) -> *mut u32 {
    let base = vtable_two_pair_base_construct(
        owner.cast(), first_pair.cast(), second_pair.cast(),
    ).cast::<u32>();
    base.write_volatile(0x0899_156c);
    let storage = allocate(core::mem::size_of::<StringObjectPair>());
    let strings = string_object_pair_default_construct(storage.cast());
    base.add(5).write(strings as usize as u32);
    base
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn initializes_nested_strings_and_preserves_neighbors_and_source_aliases() {
        for fill in [0, u32::MAX, 0xa5a5_a5a5] {
            let mut words = [fill; 8];
            let mut strings = core::mem::MaybeUninit::<StringObjectPair>::uninit();
            let owner = unsafe { words.as_mut_ptr().add(1) };
            let nested = strings.as_mut_ptr().cast::<u8>();
            let returned = unsafe {
                construct(owner, owner, owner.add(1), |size| {
                    assert_eq!(size, core::mem::size_of::<StringObjectPair>());
                    // Allocation must follow the derived-vtable store.
                    assert_eq!(owner.read(), 0x0899_156c);
                    nested
                })
            };
            assert_eq!(returned, owner);
            // Ordered base copies: first source aliases the base vtable, then
            // the second source aliases the first pair's newly written words.
            assert_eq!(words, [fill, 0x0899_156c, 0x0898_1718, 0x0898_1718,
                0x0898_1718, 0x0898_1718, nested as usize as u32, fill]);
            let strings = unsafe { strings.assume_init() };
            for string in [&strings.first, &strings.second] {
                assert_eq!(string.vtable,
                    core::ptr::addr_of!(crate::cxx::string_object::STRING_OBJECT_VTABLE));
                assert!(string.payload.is_null());
            }
        }
    }
}
