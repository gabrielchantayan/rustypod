//! A framework-rooted object with two embedded string fields.
//!
//! `framework_string_pair_construct` — original: `FUN_0826bff4` @
//! `0x0826bff4` (64-byte true extent: 60 code bytes plus the vtable literal
//! `0x089a59c0` at `0x0826c030`; next function starts at `0x0826c034`).
//! Three unconditional direct `bl` calls and zero predicated `bl` calls were
//! verified by decoding the ARM words in `osos.dec`: one
//! `framework_object_construct`, then two `string_default_construct` calls.
//!
//! Algorithm: construct the framework root, replace its vtable, default
//! construct the two target-layout strings at +0x04 and +0x0c, clear byte
//! +0x14 and words +0x18/+0x20, and store `context` at +0x1c.
//!
//! Deliberate deviation: host builds initialize each embedded string as its
//! two 32-bit target words instead of calling `string_default_construct`.
//! That callee's host pointer fields are eight bytes wide and cannot represent
//! these adjacent eight-byte target fields without overlap. ARM builds call it
//! directly, exactly as the firmware does.

use crate::cxx::observable_array::{framework_object_construct, FrameworkObject};
#[cfg(target_os = "none")]
use crate::cxx::string_object::{string_default_construct, StringObject};
#[cfg(not(target_os = "none"))]
use crate::cxx::string_object::STRING_OBJECT_VTABLE_ADDRESS;

/// Literal-pool vtable word at 0x0826c030.
pub const FRAMEWORK_STRING_PAIR_VTABLE: u32 = 0x089a_59c0;

/// The 36-byte target layout constructed by [`framework_string_pair_construct`].
#[repr(C)]
pub struct FrameworkStringPair {
    pub vtable: u32,
    pub primary_name: [u8; 8],
    pub secondary_name: [u8; 8],
    pub state: u8,
    pub _padding: [u8; 3],
    pub reserved: u32,
    pub context: u32,
    pub flags: u32,
}

#[cfg(target_os = "none")]
unsafe fn default_construct_target_string(storage: *mut u8) {
    string_default_construct(storage.cast::<StringObject>());
}

#[cfg(not(target_os = "none"))]
unsafe fn default_construct_target_string(storage: *mut u8) {
    storage.cast::<u32>().write_volatile(STRING_OBJECT_VTABLE_ADDRESS as u32);
    storage.add(4).cast::<u32>().write_volatile(0);
}

/// Constructs the object in `storage` and returns that same target address.
///
/// # Safety
/// `storage` must designate at least 36 writable, word-aligned target-layout
/// bytes. `context` is copied without ownership or validity checks.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn framework_string_pair_construct(
    storage: *mut FrameworkStringPair,
    context: u32,
) -> *mut FrameworkStringPair {
    let object = framework_object_construct(storage.cast::<FrameworkObject>()).cast::<FrameworkStringPair>();
    object.cast::<u32>().write_volatile(FRAMEWORK_STRING_PAIR_VTABLE);
    let bytes = object.cast::<u8>();
    default_construct_target_string(bytes.add(4));
    default_construct_target_string(bytes.add(12));
    bytes.add(20).write_volatile(0);
    bytes.add(24).cast::<u32>().write_volatile(0);
    bytes.add(28).cast::<u32>().write_volatile(context);
    bytes.add(32).cast::<u32>().write_volatile(0);
    object
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C, align(8))]
    struct Storage([u8; 36]);

    #[test]
    fn constructs_target_layout_and_preserves_only_context() {
        let mut storage = Storage([0xa5; 36]);
        let object = storage.0.as_mut_ptr().cast::<FrameworkStringPair>();

        let returned = unsafe { framework_string_pair_construct(object, 0x1234_5678) };

        assert_eq!(returned, object);
        unsafe {
            assert_eq!(object.cast::<u32>().read_unaligned(), FRAMEWORK_STRING_PAIR_VTABLE);
            assert_eq!(object.cast::<u8>().add(4).cast::<u32>().read_unaligned(), STRING_OBJECT_VTABLE_ADDRESS as u32);
            assert_eq!(object.cast::<u8>().add(8).cast::<u32>().read_unaligned(), 0);
            assert_eq!(object.cast::<u8>().add(12).cast::<u32>().read_unaligned(), STRING_OBJECT_VTABLE_ADDRESS as u32);
            assert_eq!(object.cast::<u8>().add(16).cast::<u32>().read_unaligned(), 0);
            assert_eq!(object.cast::<u8>().add(20).read(), 0);
            assert_eq!(object.cast::<u8>().add(21).read(), 0xa5);
            assert_eq!(object.cast::<u8>().add(24).cast::<u32>().read_unaligned(), 0);
            assert_eq!(object.cast::<u8>().add(28).cast::<u32>().read_unaligned(), 0x1234_5678);
            assert_eq!(object.cast::<u8>().add(32).cast::<u32>().read_unaligned(), 0);
        }
    }
}
