//! `memh_handle_destroy` — original: `FUN_0805d028` @ 0x0805d028
//! (68 bytes: 64 instruction bytes plus its trailing magic literal; 7 direct
//! `bl` call sites: 3 unconditional and 4 `blne`, binary-verified).
//!
//! A MemH handle is `{ payload, "MemH" }`. NULL handles and handles whose
//! second word is not the `"MemH"` magic are ignored. For a matching handle,
//! the destructor releases a non-NULL payload with heap tag 4, clears the
//! magic word, then releases the handle itself with the same tag. The two
//! releases take the already ported `free_tag4` path. No direct tail-branch
//! caller or aligned data-word reference targets this entry; its seven callers
//! are 0x08048240 (`blne`), 0x0805a584, 0x0809e180/0x0809e18c/0x0809e198
//! (`blne`), 0x080a65b0, and 0x080e2818.
//!
//! Deliberate deviation: Rust uses ordinary calls through `free_tag4` rather
//! than the retail `blne` plus tail branch directly to `free_wrapper`;
//! `free_tag4` still dispatches through `HEAP_OPS` with heap tag 4.

use crate::heap::veneers::free_tag4;

/// The second word of a valid managed-buffer handle (`"MemH"` in memory).
pub const MEMH_MAGIC: u32 = 0x4d65_6d48;
const MEMH_HEAP_TAG: usize = 4;

/// Target-width layout of a managed-buffer handle.
///
/// `payload` stays a `u32`, rather than a native pointer, so `magic` remains
/// at +0x04 on 64-bit host tests as it is on the ARM target.
#[repr(C)]
pub struct MemhHandle {
    /// +0x00 — payload allocation, or zero when no payload is owned.
    pub payload: u32,
    /// +0x04 — [`MEMH_MAGIC`] while this handle owns its allocations.
    pub magic: u32,
}

/// Releases the payload and handle of a valid MemH managed-buffer handle.
///
/// # Safety
///
/// A non-NULL `handle` must point to an aligned, readable and writable
/// [`MemhHandle`]. When its magic matches, `payload` must be either zero or
/// a valid target-width heap allocation accepted by `free_tag4`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.memh_handle_destroy")]
pub unsafe extern "C" fn memh_handle_destroy(handle: *mut MemhHandle) {
    if handle.is_null() || (*handle).magic != MEMH_MAGIC {
        return;
    }

    let payload = (*handle).payload;
    if payload != 0 {
        free_tag4(payload as usize as *mut u8);
    }
    (*handle).magic = 0;
    free_tag4(handle.cast());
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::veneers::tests::{free_log, mock_heap};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::LazyLock;

    const FIXTURE_LEN: usize = 0x1000;
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::MEMH_HANDLE_DESTROY, FIXTURE_LEN).map(|pointer| pointer as usize)
    });

    fn fixture(payload: bool, magic: u32) -> Option<*mut MemhHandle> {
        let slab = (*SLAB)? as *mut u8;
        let payload_word = if payload { unsafe { slab.add(0x100) as usize as u32 } } else { 0 };
        unsafe {
            slab.cast::<MemhHandle>().write(MemhHandle {
                payload: payload_word,
                magic,
            });
        }
        Some(slab.cast())
    }

    #[test]
    fn null_handle_does_not_initialize_or_free_the_heap() {
        let _heap = mock_heap();
        unsafe { memh_handle_destroy(core::ptr::null_mut()) };
        assert_eq!(free_log().0, 0);
    }

    #[test]
    fn nonmatching_magic_leaves_the_handle_and_heap_untouched() {
        let _heap = mock_heap();
        let Some(handle) = fixture(true, !MEMH_MAGIC) else {
            note_missing_u32_fixture("heap::memh_handle");
            return;
        };
        let before = unsafe { (handle.read().payload, handle.read().magic) };

        unsafe { memh_handle_destroy(handle) };

        assert_eq!(unsafe { (handle.read().payload, handle.read().magic) }, before);
        assert_eq!(free_log().0, 0);
    }

    #[test]
    fn matching_handle_without_payload_clears_magic_then_frees_itself() {
        let _heap = mock_heap();
        let Some(handle) = fixture(false, MEMH_MAGIC) else {
            note_missing_u32_fixture("heap::memh_handle");
            return;
        };

        unsafe { memh_handle_destroy(handle) };

        assert_eq!(unsafe { handle.read().magic }, 0);
        assert_eq!(free_log(), (1, handle.cast::<u8>(), MEMH_HEAP_TAG));
    }

    #[test]
    fn matching_handle_frees_payload_before_clearing_and_freeing_itself() {
        let _heap = mock_heap();
        let Some(handle) = fixture(true, MEMH_MAGIC) else {
            note_missing_u32_fixture("heap::memh_handle");
            return;
        };
        let payload = unsafe { handle.read().payload as usize as *mut u8 };

        unsafe { memh_handle_destroy(handle) };

        assert_eq!(unsafe { handle.read().magic }, 0);
        assert_eq!(free_log(), (2, handle.cast::<u8>(), MEMH_HEAP_TAG));
        assert_ne!(payload, handle.cast(), "payload and handle are distinct fixture words");
    }
}
