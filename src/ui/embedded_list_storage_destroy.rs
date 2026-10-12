//! Destroy embedded list storage — FUN_08048230 @ 0x08048230.
//!
//! True extent: 40 instruction bytes [0x08048230, 0x08048258); the next
//! function starts with PUSH. Raw aligned-word decoding verifies two inbound
//! plain BLs (0x080488c0, 0x0804897c), zero predicated inbound BLs, and one
//! outgoing BLNE to memh_handle_destroy plus one plain BL to bzero.
//!
//! Load the target-width handle word at +0x18, destroy it when nonzero,
//! clear all nine header words (36 bytes), and return zero. No tag or NULL
//! guard is applied to the list itself. Deliberate deviations: Rust uses
//! an ordinary conditional call rather than BLNE; no algorithmic deviations.

use crate::heap::memh_handle::{memh_handle_destroy, MemhHandle};
use crate::libc::bzero::bzero;

/// # Safety
/// `list` must designate 36 aligned writable bytes. Its word at +0x18 must
/// be zero or a live MemhHandle satisfying memh_handle_destroy's contract.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn embedded_list_storage_destroy(list: *mut u8) -> u32 {
    let handle = list.cast::<u32>().add(6).read();
    if handle != 0 {
        memh_handle_destroy(handle as usize as *mut MemhHandle);
    }
    bzero(list, 36);
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heap::memh_handle::MEMH_MAGIC;
    use crate::heap::veneers::tests::{free_log, mock_heap};

    #[test]
    fn absent_handle_clears_exactly_nine_words_and_is_repeatable() {
        let _heap = mock_heap();
        let mut words = [0xa5a5_a5a5u32; 11];
        words[7] = 0;
        unsafe {
            assert_eq!(embedded_list_storage_destroy(words.as_mut_ptr().add(1).cast()), 0);
            assert_eq!(embedded_list_storage_destroy(words.as_mut_ptr().add(1).cast()), 0);
        }
        assert_eq!(&words[1..10], &[0; 9]);
        assert_eq!((words[0], words[10]), (0xa5a5_a5a5, 0xa5a5_a5a5));
        assert_eq!(free_log().0, 0);
    }

    #[test]
    fn handle_magic_and_payload_control_release_but_never_header_clearing() {
        let _heap = mock_heap();
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::EMBEDDED_LIST_STORAGE_DESTROY, 0x1000,
        ) else { return; };
        let handle = slab.cast::<MemhHandle>();
        for (magic, payload, frees) in [(0, 0, 0), (MEMH_MAGIC, 0, 1),
            (MEMH_MAGIC, unsafe { slab.add(0x100) as usize as u32 }, 2)] {
            let before = free_log().0;
            let mut words = [0xdead_beefu32; 11];
            words[7] = handle as usize as u32;
            unsafe {
                handle.write(MemhHandle { payload, magic });
                assert_eq!(embedded_list_storage_destroy(words.as_mut_ptr().add(1).cast()), 0);
                assert_eq!((*handle).magic, 0);
                assert_eq!((*handle).payload, payload);
            }
            assert_eq!(&words[1..10], &[0; 9]);
            assert_eq!((words[0], words[10]), (0xdead_beef, 0xdead_beef));
            assert_eq!(free_log().0 - before, frees);
            if frees != 0 { assert_eq!(free_log().1, handle.cast()); assert_eq!(free_log().2, 4); }
        }
    }
}
