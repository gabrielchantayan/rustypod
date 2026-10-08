use crate::cxx::string_object::{StringObjectWithBytes, string_object_with_bytes_copy_construct};
use crate::cxx::templates::container_element_at_alias_6908;

/// `indexed_string_bytes_construct` — `FUN_08123fe4` @ 0x08123fe4.
/// True extent: 40 bytes, ending at the next function at 0x0812400c.
/// Raw A32 decoding: two inbound plain BLs (0x081b23f8, 0x0829d748),
/// zero predicated inbound BLs; one internal plain BL at 0x08123ff8,
/// zero predicated BLs, and a tail branch to 0x0814237c.
/// Looks up index in the owner's embedded container at +0x6c, then
/// copy-constructs its leading string and three uninterpreted bytes into
/// destination, returning the constructor's result. No bounds or NULL guards.
/// Deliberate deviations: reuses the callees' host-width pointer layouts and
/// modeled string vtable. Corrects Ghidra's void return and inlined tail call.
///
/// # Safety
/// Owner +0x6c must be a valid container for the supplied index; its element
/// and destination must satisfy string_object_with_bytes_copy_construct.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn indexed_string_bytes_construct(
    destination: *mut StringObjectWithBytes,
    owner: *mut u8,
    index: usize,
) -> *mut StringObjectWithBytes {
    let source = container_element_at_alias_6908(owner.add(0x6c), index);
    string_object_with_bytes_copy_construct(destination, source.cast())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::string_object::{StringObject, STRING_OBJECT_VTABLE};

    type Slot = unsafe extern "C" fn(*mut u8, usize) -> *mut *mut u8;
    #[repr(C)]
    struct Container {
        vtable: *const Slot,
        elements: [*mut u8; 2],
    }
    unsafe extern "C" fn element_slot(container: *mut u8, index: usize) -> *mut *mut u8 {
        core::ptr::addr_of_mut!((*(container as *mut Container)).elements[index & 1])
    }

    #[test]
    fn selected_self_record_preserves_payload_and_raw_bytes() {
        // Container must begin exactly at +0x6c even with host-width pointers.
        // Align the embedded container, not the opaque owner's start.
        #[repr(C, align(8))]
        struct Storage([u8; 0x100]);
        let mut storage = Storage([0xa5; 0x100]);
        let owner = unsafe { storage.0.as_mut_ptr().add(4) };
        let container = unsafe { owner.add(0x6c).cast::<Container>() };
        let vtable = [element_slot as Slot; 17];
        let mut payload = *b"self\0";
        let mut first = StringObjectWithBytes {
            string: StringObject { vtable: core::ptr::null(), payload: payload.as_mut_ptr() },
            bytes: [0, 0x80, 0xff],
        };
        let mut second = StringObjectWithBytes {
            string: StringObject { vtable: core::ptr::null(), payload: core::ptr::null_mut() },
            bytes: [0xff, 0, 0x7f],
        };
        unsafe {
            container.write(Container {
                vtable: vtable.as_ptr(),
                elements: [core::ptr::addr_of_mut!(first).cast(), core::ptr::addr_of_mut!(second).cast()],
            });
            for index in [0, 1, usize::MAX - 1, usize::MAX] {
                let selected = if index & 1 == 0 { &mut first } else { &mut second };
                let bytes = selected.bytes;
                let payload = selected.string.payload;
                let destination = selected as *mut StringObjectWithBytes;
                assert_eq!(indexed_string_bytes_construct(destination, owner, index), destination);
                assert_eq!(selected.bytes, bytes);
                assert_eq!(selected.string.payload, payload);
                assert_eq!(selected.string.vtable, core::ptr::addr_of!(STRING_OBJECT_VTABLE));
            }
        }
        assert_eq!(&storage.0[..4], &[0xa5; 4]);
        assert_eq!(&payload, b"self\0");
    }
}
