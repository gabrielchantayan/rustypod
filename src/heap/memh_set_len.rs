//! `memh_set_len` — original: `FUN_0805d270` @ 0x0805d270 (168 bytes:
//! 164 instruction bytes plus the trailing `"MemH"` magic literal at
//! 0x0805d318; 5 unconditional `bl` call sites, binary-verified by
//! decoding every ARM B/BL word in osos.dec: 0x0805d22c, 0x08076144,
//! 0x08091718, 0x08091754, 0x080d2d00; zero predicated `bl`, no tail
//! `b`). Ghidra's 168-byte size and the 5-caller count are both correct.
//!
//! Sets the used length of a MemH managed-buffer header
//! `{ payload, "MemH", capacity, length }` (16 bytes, heap tag 4 — the
//! family of [`memh_handle_destroy`](crate::heap::memh_handle::memh_handle_destroy),
//! constructor @ 0x0805d10c). A NULL header or a wrong magic word returns
//! -50 (`mvn r0,#0x31`). Otherwise:
//!
//! - `new_len > capacity`: grow — allocate a new `new_len`-byte payload.
//! - `length <= new_len <= capacity`: just record `length = new_len`.
//! - `new_len < length`: shrink in place (record only) only when the
//!   reallocation would return fewer than 0x800 bytes to the heap
//!   (`capacity - new_len < 0x800`) AND the buffer stays at least half
//!   full (`new_len >= capacity / 2`); otherwise reallocate.
//!
//! Reallocation allocates `new_len` bytes with tag 4 via `malloc_wrapper`
//! @ 0x080eb67c, memmoves `min(length, new_len)` bytes from the old
//! payload through the ROM gateway @ 0x08037e00 (`rom_memmove`), frees the
//! old payload with tag 4 via `free_wrapper` @ 0x080e7970, then stores
//! `capacity = new_len`, `payload = new`. Allocation failure returns -108
//! (`mvn r0,#0x6b`) with the header untouched. Every success path falls
//! through to `length = new_len; return 0`.
//!
//! Deliberate deviations: the copy calls the Rust
//! [`memmove`](crate::libc::memmove::memmove) directly instead of
//! dispatching through the ROM veneer (house precedent, see
//! libc/bcopy_guarded.rs), and malloc/free dispatch through the ported
//! `malloc_wrapper`/`free_wrapper` (HEAP_OPS indirection, documented in
//! heap/veneers.rs) instead of the direct `bl`s. `#[inline(never)]`: 5
//! `bl` call sites on device need a real branch target.

use crate::heap::memh_handle::MEMH_MAGIC;
use crate::heap::veneers::{free_wrapper, malloc_wrapper};
use crate::libc::memmove::memmove;

const MEMH_HEAP_TAG: usize = 4;

/// Error for a NULL header or a non-`"MemH"` magic word (`mvn r0,#0x31`).
const ERR_BAD_HANDLE: i32 = -50;
/// Error for a failed grow/shrink allocation (`mvn r0,#0x6b`).
const ERR_ALLOC_FAILED: i32 = -108;
/// Shrink-realloc only pays off from this many returned bytes upward.
const SHRINK_REALLOC_MIN: u32 = 0x800;

/// Target-width layout of a 16-byte MemH managed-buffer header.
///
/// All fields stay `u32`, rather than native pointers, so `magic` remains
/// at +0x04 on 64-bit host tests as it is on the ARM target.
#[repr(C)]
pub struct MemhBufferHeader {
    /// +0x00 — payload allocation (`capacity` bytes).
    pub payload: u32,
    /// +0x04 — [`MEMH_MAGIC`] while this header owns its allocation.
    pub magic: u32,
    /// +0x08 — allocated payload size in bytes.
    pub capacity: u32,
    /// +0x0C — bytes of payload currently in use.
    pub length: u32,
}

/// Sets the used length of a MemH managed-buffer header, growing or
/// shrinking the payload as described in the module header.
///
/// Returns 0 on success, [`ERR_BAD_HANDLE`] for a NULL header or bad
/// magic, or [`ERR_ALLOC_FAILED`] when the reallocation fails (header
/// left untouched).
///
/// # Safety
///
/// A non-NULL `header` must point to an aligned, readable and writable
/// [`MemhBufferHeader`]. When the magic matches, `payload` must be a
/// valid target-width heap allocation of `capacity` bytes accepted by
/// `free_wrapper`, and `length` must not exceed the true allocation.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn memh_set_len(header: *mut MemhBufferHeader, new_len: u32) -> i32 {
    if header.is_null() || (*header).magic != MEMH_MAGIC {
        return ERR_BAD_HANDLE;
    }

    let capacity = (*header).capacity;
    let length = (*header).length;
    let grow = capacity < new_len;
    // In-place unless shrinking returns >= 0x800 bytes OR drops the
    // buffer below half full — mirroring the original's branch chain:
    // `cap - new_len >= 0x800` reallocates outright; otherwise
    // `new_len >= cap >> 1` stays in place, below that it reallocates.
    let shrink_realloc = !grow
        && length > new_len
        && (capacity - new_len >= SHRINK_REALLOC_MIN || new_len < capacity / 2);

    if grow || shrink_realloc {
        let new_payload = malloc_wrapper(new_len as usize, MEMH_HEAP_TAG);
        if new_payload.is_null() {
            return ERR_ALLOC_FAILED;
        }
        let old_payload = (*header).payload as usize as *mut u8;
        memmove(new_payload, old_payload, core::cmp::min(length, new_len) as usize);
        free_wrapper(old_payload, MEMH_HEAP_TAG);
        (*header).capacity = new_len;
        (*header).payload = new_payload as usize as u32;
    }
    (*header).length = new_len;
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::veneers::tests::{alloc_log, free_log, mock_heap, set_alloc_ret};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::LazyLock;

    const FIXTURE_LEN: usize = 0x4000;
    const PAYLOAD_OFF: usize = 0x100;
    const NEW_PAYLOAD_OFF: usize = 0x2400;
    static SLAB: LazyLock<Option<usize>> =
        LazyLock::new(|| try_map_u32_slab(hints::MEMH_SET_LEN, FIXTURE_LEN).map(|p| p as usize));

    /// Header at slab+0, payload at slab+0x100 pre-filled with a pattern;
    /// mock allocations return slab+0x400.
    fn fixture(capacity: u32, length: u32) -> Option<*mut MemhBufferHeader> {
        let slab = (*SLAB)? as *mut u8;
        unsafe {
            for i in 0..FIXTURE_LEN {
                slab.add(i).write(0xA5);
            }
            for i in 0..capacity as usize {
                slab.add(PAYLOAD_OFF + i).write((i as u8) ^ 0x5A);
            }
            slab.cast::<MemhBufferHeader>().write(MemhBufferHeader {
                payload: slab.add(PAYLOAD_OFF) as usize as u32,
                magic: MEMH_MAGIC,
                capacity,
                length,
            });
            set_alloc_ret(slab.add(NEW_PAYLOAD_OFF));
        }
        Some(slab.cast())
    }

    #[test]
    fn null_header_returns_bad_handle_without_touching_the_heap() {
        let _heap = mock_heap();
        assert_eq!(unsafe { memh_set_len(core::ptr::null_mut(), 4) }, ERR_BAD_HANDLE);
        assert_eq!(alloc_log().0, 0);
        assert_eq!(free_log().0, 0);
    }

    #[test]
    fn wrong_magic_returns_bad_handle_and_leaves_the_header_untouched() {
        let _heap = mock_heap();
        let Some(header) = fixture(0x100, 0x80) else {
            note_missing_u32_fixture("heap::memh_set_len");
            return;
        };
        unsafe { (*header).magic = !MEMH_MAGIC };
        assert_eq!(unsafe { memh_set_len(header, 0x40) }, ERR_BAD_HANDLE);
        assert_eq!(unsafe { (*header).length }, 0x80);
        assert_eq!(alloc_log().0, 0);
        assert_eq!(free_log().0, 0);
    }

    #[test]
    fn length_update_within_capacity_only_records_the_length() {
        let _heap = mock_heap();
        let Some(header) = fixture(0x100, 0x80) else {
            note_missing_u32_fixture("heap::memh_set_len");
            return;
        };
        let payload = unsafe { (*header).payload };
        assert_eq!(unsafe { memh_set_len(header, 0xC0) }, 0);
        let after = unsafe { ((*header).payload, (*header).capacity, (*header).length) };
        assert_eq!(after, (payload, 0x100, 0xC0));
        assert_eq!(alloc_log().0, 0);
        assert_eq!(free_log().0, 0);
    }

    #[test]
    fn shrink_freeing_less_than_0x800_stays_in_place() {
        let _heap = mock_heap();
        let Some(header) = fixture(0x1000, 0xC00) else {
            note_missing_u32_fixture("heap::memh_set_len");
            return;
        };
        // cap - new_len = 0x700 < 0x800, so no realloc even below half full.
        assert_eq!(unsafe { memh_set_len(header, 0x900) }, 0);
        assert_eq!(unsafe { (*header).length }, 0x900);
        assert_eq!(unsafe { (*header).capacity }, 0x1000);
        assert_eq!(alloc_log().0, 0);
        assert_eq!(free_log().0, 0);
    }

    #[test]
    fn shrink_freeing_less_than_0x800_but_below_half_full_reallocates() {
        let _heap = mock_heap();
        let Some(header) = fixture(0x800, 0x700) else {
            note_missing_u32_fixture("heap::memh_set_len");
            return;
        };
        let slab = (*SLAB).unwrap() as *mut u8;
        let old_payload = unsafe { (*header).payload as usize as *mut u8 };

        // cap - new_len = 0x500 < 0x800, but new_len < cap/2: the
        // original's `cmp r5,r0,lsr #1; bcs` falls through to realloc.
        assert_eq!(unsafe { memh_set_len(header, 0x300) }, 0);

        assert_eq!(alloc_log(), (1, 0x300, MEMH_HEAP_TAG));
        assert_eq!(free_log(), (1, old_payload, MEMH_HEAP_TAG));
        let after = unsafe { ((*header).payload, (*header).capacity, (*header).length) };
        assert_eq!(after, (unsafe { slab.add(NEW_PAYLOAD_OFF) as usize as u32 }, 0x300, 0x300));
        // min(length, new_len) = 0x300 pattern bytes copied.
        for i in 0..0x300usize {
            assert_eq!(unsafe { slab.add(NEW_PAYLOAD_OFF + i).read() }, (i as u8) ^ 0x5A);
        }
    }

    #[test]
    fn grow_reallocates_copies_and_frees_the_old_payload() {
        let _heap = mock_heap();
        let Some(header) = fixture(0x40, 0x30) else {
            note_missing_u32_fixture("heap::memh_set_len");
            return;
        };
        let slab = (*SLAB).unwrap() as *mut u8;
        let old_payload = unsafe { (*header).payload as usize as *mut u8 };

        assert_eq!(unsafe { memh_set_len(header, 0x80) }, 0);

        assert_eq!(alloc_log(), (1, 0x80, MEMH_HEAP_TAG));
        assert_eq!(free_log(), (1, old_payload, MEMH_HEAP_TAG));
        let after = unsafe { ((*header).payload, (*header).capacity, (*header).length) };
        assert_eq!(after, (unsafe { slab.add(NEW_PAYLOAD_OFF) as usize as u32 }, 0x80, 0x80));
        // min(length, new_len) = 0x30 pattern bytes copied.
        for i in 0..0x30usize {
            assert_eq!(unsafe { slab.add(NEW_PAYLOAD_OFF + i).read() }, (i as u8) ^ 0x5A);
        }
    }

    #[test]
    fn deep_shrink_reallocates_and_copies_only_new_len_bytes() {
        let _heap = mock_heap();
        let Some(header) = fixture(0x2000, 0x1800) else {
            note_missing_u32_fixture("heap::memh_set_len");
            return;
        };
        let slab = (*SLAB).unwrap() as *mut u8;
        let old_payload = unsafe { (*header).payload as usize as *mut u8 };

        // cap - new_len = 0x1F00 >= 0x800: reallocates outright.
        assert_eq!(unsafe { memh_set_len(header, 0x100) }, 0);

        assert_eq!(alloc_log(), (1, 0x100, MEMH_HEAP_TAG));
        assert_eq!(free_log(), (1, old_payload, MEMH_HEAP_TAG));
        let after = unsafe { ((*header).payload, (*header).capacity, (*header).length) };
        assert_eq!(after, (unsafe { slab.add(NEW_PAYLOAD_OFF) as usize as u32 }, 0x100, 0x100));
        // min(length, new_len) = 0x100 bytes copied, nothing beyond.
        for i in 0..0x100usize {
            assert_eq!(unsafe { slab.add(NEW_PAYLOAD_OFF + i).read() }, (i as u8) ^ 0x5A);
        }
        assert_eq!(unsafe { slab.add(NEW_PAYLOAD_OFF + 0x100).read() }, 0xA5);
    }

    #[test]
    fn failed_grow_alloc_returns_error_and_leaves_the_header_untouched() {
        let _heap = mock_heap();
        let Some(header) = fixture(0x40, 0x30) else {
            note_missing_u32_fixture("heap::memh_set_len");
            return;
        };
        set_alloc_ret(core::ptr::null_mut());

        assert_eq!(unsafe { memh_set_len(header, 0x80) }, ERR_ALLOC_FAILED);

        assert_eq!(alloc_log().0, 1);
        assert_eq!(free_log().0, 0);
        let after = unsafe { ((*header).capacity, (*header).length) };
        assert_eq!(after, (0x40, 0x30));
        assert_eq!(unsafe { (*header).magic }, MEMH_MAGIC);
    }
}
