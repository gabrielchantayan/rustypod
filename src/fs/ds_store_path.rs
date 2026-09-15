//! Detects the Finder metadata filename in a NUL-terminated path.

use crate::cxx::heap_string::{heap_string_construct_from_cstr, heap_string_destroy, HeapString};
use crate::libc::strlen_safe::strlen_safe;
use crate::libc::strncmp::strncmp;

/// The read-only literal at 0x0809e750 immediately after the function body.
const DS_STORE_NAME: &[u8] = b".DS_Store\0";

/// is_ds_store_path — original: `FUN_0809e718` @ 0x0809e718 (56 bytes;
/// words `e92d4038 e1a01000 e1a0000d eb01b3c2 e3a02000 e28f101c e1a0000d
/// eb07e587 e2904001 13a04001 e1a0000d eb01b326 e1a00004 e8bd8038`).
/// The next real function begins at 0x0809e75c, after the `.DS_Store` literal
/// at 0x0809e750. **Five plain `bl` callers and zero predicated `bl` callers**
/// were verified from the direct caller set; this body makes three
/// unconditional calls: construct, substring search, and destroy.
///
/// Constructs a one-word [`HeapString`] from `path`, searches it from offset
/// zero for the embedded `.DS_Store` literal, destroys the temporary holder,
/// and returns whether the search found a match. The search is substring-based:
/// a path such as `folder/.DS_Store-journal` is accepted.
///
/// Deliberate deviation: the stock substring-search method @ 0x08297d58 is
/// not independently ported, so its verified `strlen`/bounded-`strncmp`
/// algorithm is expressed locally rather than adding an unverified call seam.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn is_ds_store_path(path: *const u8) -> bool {
    let mut holder = HeapString {
        data: core::ptr::null_mut(),
    };
    heap_string_construct_from_cstr(&mut holder, path);

    let data = holder.data;
    let found = if data.is_null() {
        false
    } else {
        let needle_len = strlen_safe(DS_STORE_NAME.as_ptr());
        let data_len = strlen_safe(data);
        if data_len < needle_len {
            false
        } else {
            let mut offset = 0;
            loop {
                if strncmp(data.add(offset), DS_STORE_NAME.as_ptr(), needle_len) == 0 {
                    break true;
                }
                if offset == data_len - needle_len {
                    break false;
                }
                offset += 1;
            }
        }
    };

    heap_string_destroy(&mut holder);
    found
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::veneers::tests::{mock_heap, set_alloc_ret};

    #[test]
    fn recognizes_embedded_ds_store_name_but_not_partial_or_case_variant() {
        let _heap = mock_heap();
        let paths = [
            (b"folder/.DS_Store-journal\0".as_slice(), true),
            (b"folder/.DS_Stor\0".as_slice(), false),
            (b"folder/.ds_store\0".as_slice(), false),
        ];

        for (path, expected) in paths {
            let mut allocation = [0u8; 32];
            set_alloc_ret(allocation.as_mut_ptr());
            assert_eq!(unsafe { is_ds_store_path(path.as_ptr()) }, expected);
        }
    }

    #[test]
    fn empty_and_null_paths_are_not_matches() {
        let _heap = mock_heap();
        let mut allocation = [0u8; 1];
        set_alloc_ret(allocation.as_mut_ptr());

        assert!(!unsafe { is_ds_store_path(b"\0".as_ptr()) });
        assert!(!unsafe { is_ds_store_path(core::ptr::null()) });
    }
}
