//! Copy construction for the unidentified three-word records used by the
//! `0x083eXXXX` vector helpers.
//!
//! The record is a [`StringObject`] followed by one opaque 32-bit value. The
//! `0x08177604` caller builds these records from a StringObject and list index;
//! the `0x083eXXXX` callers copy them while growing and rearranging vectors.
//! No concrete class identity is established, so its name describes its layout.

use crate::cxx::string_object::{string_object_copy_construct, StringObject};

/// A StringObject followed by the opaque word its copy constructor preserves.
///
/// On ARMv5TE this is 12 bytes: the embedded StringObject at +0 and `value` at
/// +8. `repr(C)` and named fields preserve that layout without applying
/// 32-bit byte offsets to widened host pointers.
#[repr(C)]
pub struct StringWordRecord {
    pub string: StringObject,
    pub value: u32,
}

/// string_word_record_copy_construct — original: `FUN_081f4ffc` @
/// `0x081f4ffc` (24 bytes, six ARM words; the next separately linked function
/// starts at `0x081f5014`). **9 direct `bl` call sites** verified by decoding
/// every ARM `B`/`BL` word in `work/firmware/osos.dec`: four unconditional
/// (`0x083e82a4`, `0x083e82f4`, `0x083e97f8`, `0x083eaa10`) and five `blne`
/// (`0x0817770c`, `0x083e1870`, `0x083e1900`, `0x083e80b0`, `0x083e8b58`).
///
/// Copy-constructs the embedded [`StringObject`] at +0 through the ported
/// [`string_object_copy_construct`] @ `0x082773e0`, then copies the opaque
/// source word at +8 to the destination at +8. It returns the embedded
/// constructor's result, which is the record address because that subobject is
/// first. The function itself has no NULL guard; its five predicated callers
/// gate the call before entering, while four callers enter unconditionally.
///
/// Deliberate deviations: none. The original's +8 accesses use the named
/// `value` field so the 32-bit ARM layout does not overlap widened host pointer
/// fields.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn string_word_record_copy_construct(
    this: *mut StringWordRecord,
    source: *const StringWordRecord,
) -> *mut StringWordRecord {
    string_object_copy_construct(
        core::ptr::addr_of_mut!((*this).string),
        core::ptr::addr_of!((*source).string),
    );
    (*this).value = (*source).value;
    this
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::cxx::string_object::{
        StringObjectAssignCstrOps, StringObjectVtable, DEFAULT_STRING_OBJECT_ASSIGN_CSTR_OPS,
        STRING_OBJECT_ASSIGN_CSTR_OPS, STRING_OBJECT_VTABLE,
    };
    use crate::testing::STRING_OBJECT_ASSIGN_CSTR_TEST_LOCK;
    use core::mem::MaybeUninit;
    use std::sync::MutexGuard;

    static mut COPY_ALLOCATION: Option<(usize, usize, u32)> = None;
    static mut COPY_STORAGE: [u8; 16] = [0; 16];

    unsafe extern "C" fn record_copy_allocation(
        this: *mut StringObject,
        requested_size: usize,
        flags: u32,
    ) -> *mut u8 {
        core::ptr::addr_of_mut!(COPY_ALLOCATION).write(Some((
            this as usize,
            requested_size,
            flags,
        )));
        let storage = core::ptr::addr_of_mut!(COPY_STORAGE).cast::<u8>();
        (*this).payload = storage;
        storage
    }

    unsafe extern "C" fn record_copy_clear(_this: *mut StringObject) {}

    /// Restores the shared virtual assignment seam if a test assertion panics.
    struct CopyAssignOpsGuard {
        _lock: MutexGuard<'static, ()>,
    }

    impl Drop for CopyAssignOpsGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(STRING_OBJECT_ASSIGN_CSTR_OPS)
                    .write_volatile(DEFAULT_STRING_OBJECT_ASSIGN_CSTR_OPS);
            }
        }
    }

    fn copy_assign_bench() -> CopyAssignOpsGuard {
        let lock = STRING_OBJECT_ASSIGN_CSTR_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        unsafe {
            core::ptr::addr_of_mut!(COPY_ALLOCATION).write(None);
            core::ptr::addr_of_mut!(COPY_STORAGE).write([0; 16]);
            core::ptr::addr_of_mut!(STRING_OBJECT_ASSIGN_CSTR_OPS).write_volatile(
                StringObjectAssignCstrOps {
                    allocate_payload: record_copy_allocation,
                    clear_payload: record_copy_clear,
                },
            );
        }
        CopyAssignOpsGuard { _lock: lock }
    }

    #[test]
    fn copies_the_embedded_string_and_trailing_word() {
        let _bench = copy_assign_bench();
        let mut source_text = *b"edge\0";
        let source = StringWordRecord {
            string: StringObject {
                vtable: 0xdead_beefusize as *const StringObjectVtable,
                payload: source_text.as_mut_ptr(),
            },
            value: u32::MAX,
        };
        let mut destination = MaybeUninit::<StringWordRecord>::uninit();
        let destination_ptr = destination.as_mut_ptr();

        unsafe {
            assert_eq!(
                string_word_record_copy_construct(destination_ptr, &source),
                destination_ptr
            );
            let destination = destination.assume_init();
            assert_eq!(destination.string.vtable, &STRING_OBJECT_VTABLE as *const _);
            assert_eq!(destination.string.payload, core::ptr::addr_of_mut!(COPY_STORAGE).cast());
            assert_eq!(&COPY_STORAGE[..5], b"edge\0");
            assert_eq!(destination.value, u32::MAX);
            assert_eq!(
                COPY_ALLOCATION,
                Some((
                    core::ptr::addr_of_mut!((*destination_ptr).string) as usize,
                    5,
                    0,
                ))
            );
        }
    }

    #[test]
    fn self_copy_preserves_payload_without_allocating() {
        let _bench = copy_assign_bench();
        let mut source_text = *b"same\0";
        let mut record = StringWordRecord {
            string: StringObject {
                vtable: 0xdead_beefusize as *const StringObjectVtable,
                payload: source_text.as_mut_ptr(),
            },
            value: 0x89ab_cdef,
        };
        let record_ptr: *mut StringWordRecord = &mut record;

        unsafe {
            assert_eq!(string_word_record_copy_construct(record_ptr, record_ptr), record_ptr);
            assert_eq!(record.string.vtable, &STRING_OBJECT_VTABLE as *const _);
            assert_eq!(record.string.payload, source_text.as_mut_ptr());
            assert_eq!(record.value, 0x89ab_cdef);
            assert_eq!(COPY_ALLOCATION, None);
        }
    }
}
