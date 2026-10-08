//! Selected-entry string constructor — FUN_08131ddc @ 0x08131ddc.
//! True extent: 36 bytes, ending at the independently callable dispatcher
//! @ 0x08131e00. All nine words are code, including the final A32 NOP.
//! Raw census: one outgoing plain BL (string_default_construct), zero
//! predicated BLs; two incoming plain BLs, zero predicated BLs.
//! Default-construct out, then fall through with (owner, entry, out) into
//! the dispatcher: entry byte +4 selects virtual slots +0x168, +0x16c,
//! or +0x164 for kinds 0, 1, or 2; other kinds assign an empty string.
//! Deviation: express fallthrough as a typed call to the unported retail
//! boundary. Host StringObject uses the existing native-pointer model.

use crate::cxx::string_object::{StringObject, string_default_construct};

/// A record's leading opaque word and the dispatch-kind byte at +4.
#[repr(C)]
pub struct SelectedStringEntry {
    pub value: u32,
    pub kind: u8,
    pub padding: [u8; 3],
}

type WriteEntry = unsafe extern "C" fn(*mut u8, *const SelectedStringEntry, *mut StringObject);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_write(_: *mut u8, _: *const SelectedStringEntry, _: *mut StringObject) {
    panic!("selected-entry string dispatcher requires a host implementation");
}

/// Unported dispatcher @ 0x08131e00, not a second implementation of it.
#[cfg(not(target_os = "none"))]
pub static mut SELECTED_ENTRY_STRING_WRITE: WriteEntry = missing_write;

/// Construct a new string, without releasing any previous payload.
/// # Safety
/// out must be writable new-object storage. owner and entry must satisfy
/// the retail dispatcher contract (owner handle at +0x28 and its vtable).
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn selected_entry_string_construct(
    out: *mut StringObject, owner: *mut u8, entry: *const SelectedStringEntry,
) {
    let out = string_default_construct(out);
    #[cfg(target_os = "none")]
    let write: WriteEntry = core::mem::transmute(0x08131e00usize);
    #[cfg(not(target_os = "none"))]
    let write = SELECTED_ENTRY_STRING_WRITE;
    write(owner, entry, out);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::string_object::STRING_OBJECT_VTABLE;
    use core::ptr;

    // A consuming writer: refuses preexisting payloads and emits a string
    // into owner-provided storage. This exercises construction ordering,
    // no-release semantics, and preservation of the writer's result.
    unsafe extern "C" fn write_text(owner: *mut u8, entry: *const SelectedStringEntry, out: *mut StringObject) {
        assert_eq!((*out).vtable, ptr::addr_of!(STRING_OBJECT_VTABLE));
        assert!((*out).payload.is_null());
        if (*entry).kind <= 2 {
            owner.write(b'A' + (*entry).kind);
            owner.add(1).write((*entry).value as u8);
            owner.add(2).write(0);
            (*out).payload = owner;
        }
    }

    #[test]
    fn constructs_over_poison_without_releasing_and_retains_empty_or_written_result() {
        struct Restore(WriteEntry);
        impl Drop for Restore {
            fn drop(&mut self) { unsafe { SELECTED_ENTRY_STRING_WRITE = self.0; } }
        }
        unsafe {
            let _restore = Restore(SELECTED_ENTRY_STRING_WRITE);
            SELECTED_ENTRY_STRING_WRITE = write_text;
            for kind in [0, 1, 2, 3, 255] {
                let mut storage = [0xa5; 4];
                let mut out = StringObject {
                    vtable: ptr::null(), payload: ptr::dangling_mut(),
                };
                let entry = SelectedStringEntry { value: b'!' as u32, kind, padding: [0; 3] };
                selected_entry_string_construct(&mut out, storage.as_mut_ptr(), &entry);
                if kind <= 2 {
                    assert_eq!(out.payload, storage.as_mut_ptr());
                    assert_eq!(storage, [b'A' + kind, b'!', 0, 0xa5]);
                } else {
                    assert!(out.payload.is_null());
                    assert_eq!(storage, [0xa5; 4]);
                }
            }
        }
    }
}
