use crate::cxx::string_object::{StringObjectWithWordAndFlag, string_object_with_word_and_flag_copy_construct};
use crate::cxx::templates::container_element_at_alias_689c;

/// `indexed_string_word_flag_construct` — `FUN_08123f4c` @ 0x08123f4c.
/// True extent: 40 bytes, ending at the next prologue at 0x08123f74.
/// Raw A32 decoding: two inbound plain BLs (0x081b23b0, 0x0829d6f8),
/// zero predicated inbound BLs; one internal plain BL at 0x08123f60,
/// zero predicated BLs, and a tail branch to 0x0812e738.
/// Looks up index in the owner's embedded container at +0x9c, then
/// copy-constructs its string, opaque word and raw flag into destination,
/// returning the constructor's result. No bounds or NULL guards.
/// Deliberate deviations: reuses the callees' host-width pointer layouts and
/// modeled string vtable. Corrects Ghidra's void return and inlined tail call.
///
/// # Safety
/// Owner +0x9c must be a valid container for index; its element and destination
/// must satisfy string_object_with_word_and_flag_copy_construct.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn indexed_string_word_flag_construct(
    destination: *mut StringObjectWithWordAndFlag,
    owner: *mut u8,
    index: usize,
) -> *mut StringObjectWithWordAndFlag {
    let source = container_element_at_alias_689c(owner.add(0x9c), index);
    string_object_with_word_and_flag_copy_construct(destination, source.cast())
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
    fn record(word: u32, flag: u8) -> StringObjectWithWordAndFlag {
        StringObjectWithWordAndFlag {
            string: StringObject { vtable: core::ptr::null(), payload: core::ptr::null_mut() },
            word, flag, padding: [0x5a; 3],
        }
    }

    #[test]
    fn selected_records_copy_extreme_words_raw_flags_and_preserve_padding() {
        #[repr(C, align(8))]
        struct Storage([u8; 0x100]);
        let mut storage = Storage([0xa5; 0x100]);
        // Align the container at +0x9c, not the opaque owner base.
        let owner = unsafe { storage.0.as_mut_ptr().add(4) };
        let container = unsafe { owner.add(0x9c).cast::<Container>() };
        let vtable = [element_slot as Slot; 17];
        let mut first = record(u32::MAX, 0x80);
        let mut second = record(0x80000000, 0xff);
        unsafe {
            container.write(Container {
                vtable: vtable.as_ptr(),
                elements: [core::ptr::addr_of_mut!(first).cast(), core::ptr::addr_of_mut!(second).cast()],
            });
            for index in [0, 1, u32::MAX as usize - 1, u32::MAX as usize] {
                let expected = if index & 1 == 0 { (u32::MAX, 0x80) } else { (0x80000000, 0xff) };
                let mut destination = record(0, 0);
                destination.padding = [0xa5; 3];
                let result = indexed_string_word_flag_construct(&mut destination, owner, index);
                assert_eq!(result, &mut destination as *mut _);
                assert_eq!((destination.word, destination.flag), expected);
                assert_eq!(destination.padding, [0xa5; 3]);
                assert!(destination.string.payload.is_null());
                assert_eq!(destination.string.vtable, core::ptr::addr_of!(STRING_OBJECT_VTABLE));
            }
            let mut payload = *b"self\0";
            first.string.payload = payload.as_mut_ptr();
            let destination = core::ptr::addr_of_mut!(first);
            assert_eq!(indexed_string_word_flag_construct(destination, owner, 0), destination);
            assert_eq!((first.word, first.flag), (u32::MAX, 0x80));
            assert_eq!(first.padding, [0x5a; 3]);
            assert_eq!(first.string.payload, payload.as_mut_ptr());
            assert_eq!(&payload, b"self\0");
        }
        assert_eq!(&storage.0[..0xa0], &[0xa5; 0xa0]);
    }
}
