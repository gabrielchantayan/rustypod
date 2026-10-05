//! Non-deleting destructor for two consecutive StringObjects.
//!
//! Original `FUN_081991bc` @ 0x081991bc: 40 code bytes plus the four-byte
//! vtable literal at 0x081991e4; next real function starts at 0x081991e8.
//! Raw A32 decoding verifies two outbound plain BLs (0x08277484,
//! 0x08275d74), two inbound plain BLs (0x083d0778, 0x083d07c8), and
//! zero predicated BLs in either direction. Destroy the second string,
//! restore the first string's base vtable, release its payload, return this.
//! No NULL guard and no storage deletion. Deliberate deviation: repr(C)
//! StringObjectPair widens pointers on hosts while preserving ARM +8 layout;
//! the firmware vtable literal uses the existing STRING_OBJECT_VTABLE model.

use crate::cxx::string_object::{StringObjectPair, STRING_OBJECT_VTABLE,
    string_object_destroy, string_object_release_payload};

/// # Safety
/// `this` must point to two initialized strings with releasable payloads.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn string_pair_destroy(this: *mut StringObjectPair) -> *mut StringObjectPair {
    string_object_destroy(core::ptr::addr_of_mut!((*this).second));
    (*this).first.vtable = &STRING_OBJECT_VTABLE;
    string_object_release_payload(core::ptr::addr_of_mut!((*this).first));
    this
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::string_object::{StringObject, DEFAULT_STRING_OBJECT_OPS, STRING_OBJECT_OPS};

    #[test]
    fn releases_each_present_payload_without_deleting_storage() {
        let _strings = crate::cxx::string_object::tests::STRING_OBJECT_OPS_TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let _heap = crate::heap::veneers::tests::mock_heap();
        unsafe {
            let saved = core::ptr::addr_of!(STRING_OBJECT_OPS).read();
            struct Restore(crate::cxx::string_object::StringObjectOps);
            impl Drop for Restore { fn drop(&mut self) { unsafe {
                core::ptr::addr_of_mut!(STRING_OBJECT_OPS).write(self.0);
            } } }
            let _restore = Restore(saved);
            core::ptr::addr_of_mut!(STRING_OBJECT_OPS).write(DEFAULT_STRING_OBJECT_OPS);
            let mut payloads = [1u8, 2];
            let mut calls = 0;
            for (first, second) in [(false, false), (false, true), (true, false), (true, true)] {
                let first_ptr = if first { payloads.as_mut_ptr() } else { core::ptr::null_mut() };
                let second_ptr = if second { payloads.as_mut_ptr().add(1) } else { core::ptr::null_mut() };
                let mut pair = StringObjectPair {
                    first: StringObject { vtable: core::ptr::null(), payload: first_ptr },
                    second: StringObject { vtable: core::ptr::null(), payload: second_ptr },
                };
                assert_eq!(string_pair_destroy(&mut pair), &mut pair as *mut _);
                calls += first as usize + second as usize;
                assert_eq!(crate::heap::veneers::tests::free_log().0, calls);
                if first || second {
                    assert_eq!(crate::heap::veneers::tests::free_log(),
                        (calls, if first { first_ptr } else { second_ptr }, 0x34));
                }
                assert!(pair.first.payload.is_null() && pair.second.payload.is_null());
                assert_eq!(pair.first.vtable, &STRING_OBJECT_VTABLE as *const _);
                assert_eq!(pair.second.vtable, &STRING_OBJECT_VTABLE as *const _);
                string_pair_destroy(&mut pair);
                assert_eq!(crate::heap::veneers::tests::free_log().0, calls);
            }
            assert_eq!(payloads, [1, 2]);
        }
    }
}
