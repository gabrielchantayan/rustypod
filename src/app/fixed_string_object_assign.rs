//! Fixed-literal string assignment, original FUN_0827fa90 @ 0x0827fa90.
//!
//! True extent: 80 bytes through 0x0827fadf (72 code + 8 literal bytes);
//! next real function starts at 0x0827fae0. Three outgoing plain BLs,
//! zero predicated BLs. Copies 16 suffix bytes to the stack, strcpy's a
//! prefix into a 40-byte buffer, appends the suffix, then assigns the result
//! to the second argument's StringObject. The first argument is unused.
//!
//! Deliberate deviation: host builds use the exact osos.dec literal bytes;
//! target builds retain the original addresses, not an inferred path name.
//! Those bytes resemble A32 instructions: no textual identity is established.

use crate::cxx::string_object::{string_object_assign_cstr, StringObject};
use crate::libc::{strcat::strcat, strcpy::strcpy};

#[cfg(not(target_os = "none"))]
const PREFIX: [u8; 2] = [0x01, 0x00];
#[cfg(not(target_os = "none"))]
const SUFFIX: [u32; 4] = [0xe0411002, 0xe0800141, 0xe5951008, 0xe5952000];

/// Assign the concatenated firmware literals. `destination` must be valid;
/// `unused_context` is never dereferenced, including when NULL.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn fixed_string_object_assign(
    _unused_context: *const u8,
    destination: *mut StringObject,
) {
    #[cfg(target_os = "none")]
    let (prefix, suffix) = (0x083ead98 as *const u8, 0x083eadc4 as *const u32);
    #[cfg(not(target_os = "none"))]
    let (prefix, suffix) = (PREFIX.as_ptr(), SUFFIX.as_ptr());

    let suffix_words = [suffix.read(), suffix.add(1).read(),
        suffix.add(2).read(), suffix.add(3).read()];
    let mut buffer = core::mem::MaybeUninit::<[u8; 40]>::uninit();
    let buffer = buffer.as_mut_ptr().cast::<u8>();
    // Keep the existing libc ports as real call boundaries, without zeroing
    // stack bytes that the retail function never initializes.
    let copy = core::ptr::read_volatile(&(strcpy as unsafe extern "C" fn(*mut u8, *const u8) -> *mut u8));
    let append = core::ptr::read_volatile(&(strcat as unsafe extern "C" fn(*mut u8, *const u8) -> *mut u8));
    copy(buffer, prefix);
    append(buffer, suffix_words.as_ptr().cast());
    string_object_assign_cstr(destination, buffer);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::cxx::string_object::{StringObjectAssignCstrOps, STRING_OBJECT_ASSIGN_CSTR_OPS};

    struct Restore(StringObjectAssignCstrOps);
    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe { STRING_OBJECT_ASSIGN_CSTR_OPS = self.0; }
        }
    }

    unsafe extern "C" fn allocate(this: *mut StringObject, size: usize, flags: u32) -> *mut u8 {
        assert_eq!(size, 14);
        assert_eq!(flags, 0);
        (*this).payload
    }
    unsafe extern "C" fn unexpected_clear(_: *mut StringObject) {
        panic!("nonempty literal must not clear the object");
    }

    #[test]
    fn embedded_nuls_bound_copy_and_failed_allocation_preserves_object() {
        let _lock = crate::testing::STRING_OBJECT_ASSIGN_CSTR_TEST_LOCK.lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let _restore = Restore(unsafe { STRING_OBJECT_ASSIGN_CSTR_OPS });
        unsafe {
            STRING_OBJECT_ASSIGN_CSTR_OPS = StringObjectAssignCstrOps {
                allocate_payload: allocate, clear_payload: unexpected_clear,
            };
        }
        let mut storage = [0xa5u8; 16];
        let mut object = StringObject { vtable: core::ptr::null(), payload: storage.as_mut_ptr() };
        unsafe { fixed_string_object_assign(core::ptr::null(), &mut object); }
        assert_eq!(storage, [1, 2, 0x10, 0x41, 0xe0, 0x41, 1, 0x80,
            0xe0, 8, 0x10, 0x95, 0xe5, 0, 0xa5, 0xa5]);
        object.payload = core::ptr::null_mut();
        unsafe { fixed_string_object_assign(usize::MAX as *const u8, &mut object); }
        assert!(object.payload.is_null());
        assert!(object.vtable.is_null());
        assert_eq!(storage[14..], [0xa5, 0xa5]);
    }
}
