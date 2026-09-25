//! `memh_handle_release` — original: `FUN_0805a14c` @ 0x0805a14c
//! (52 bytes, 3 inbound plain `bl` call sites, and no predicated `bl` callers,
//! binary-verified).
//!
//! Given a nullable target-width slot containing a MemH handle, decrements the
//! signed halfword reference count at handle +0x18 only when it is in 1..=1000.
//! Reaching zero tail-dispatches to `memh_handle_destroy`; non-positive and
//! saturated counts leave the slot and handle unchanged.
//!
//! Deliberate deviation: Rust uses an ordinary call to the already ported
//! destructor instead of the retail tail branch. The input is a `u32` slot so
//! its target pointer width remains four bytes in host tests.

use crate::heap::memh_handle::{memh_handle_destroy, MemhHandle};

const REFCOUNT_OFFSET: usize = 0x18;
const MAX_RELEASABLE_REFCOUNT: i16 = 1000;

/// Releases one reference held through a target-width MemH handle slot.
///
/// # Safety
///
/// A non-NULL `handle_slot` must point to a readable target-width pointer. A
/// nonzero pointer stored there must designate an aligned, readable and
/// writable MemH handle whose signed reference count is at +0x18.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.memh_handle_release")]
pub unsafe extern "C" fn memh_handle_release(handle_slot: *mut u32) -> *mut u32 {
    if handle_slot.is_null() {
        return handle_slot;
    }

    let handle = handle_slot.read() as usize as *mut MemhHandle;
    let refcount = handle.cast::<u8>().add(REFCOUNT_OFFSET).cast::<i16>();
    let count = refcount.read();
    if count <= 0 {
        return handle_slot;
    }

    if count <= MAX_RELEASABLE_REFCOUNT {
        let count = count - 1;
        refcount.write(count);
        if count == 0 {
            memh_handle_destroy(handle);
        }
    }

    handle_slot
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::memh_handle::MEMH_MAGIC;
    use crate::heap::veneers::tests::{free_log, mock_heap};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::LazyLock;

    const FIXTURE_LEN: usize = 0x1000;
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::MEMH_HANDLE_RELEASE, FIXTURE_LEN).map(|pointer| pointer as usize)
    });

    #[repr(C)]
    struct RefcountedHandle {
        handle: MemhHandle,
        reserved: [u32; 4],
        refcount: i16,
    }

    fn fixture(refcount: i16, magic: u32) -> Option<(*mut u32, *mut RefcountedHandle)> {
        let slab = (*SLAB)? as *mut u8;
        let handle = unsafe { slab.add(0x100).cast::<RefcountedHandle>() };
        unsafe {
            handle.write(RefcountedHandle {
                handle: MemhHandle { payload: 0, magic },
                reserved: [0; 4],
                refcount,
            });
            slab.cast::<u32>().write(handle as usize as u32);
        }
        Some((slab.cast(), handle))
    }

    #[test]
    fn null_slot_is_returned_without_a_read() {
        let _heap = mock_heap();
        let slot = core::ptr::null_mut();
        assert_eq!(unsafe { memh_handle_release(slot) }, slot);
        assert_eq!(free_log().0, 0);
    }

    #[test]
    fn nonpositive_and_saturated_counts_are_unchanged() {
        let _heap = mock_heap();
        for count in [-1, 0, 1001] {
            let Some((slot, handle)) = fixture(count, MEMH_MAGIC) else {
                note_missing_u32_fixture("heap::memh_handle_release");
                return;
            };
            assert_eq!(unsafe { memh_handle_release(slot) }, slot);
            assert_eq!(unsafe { handle.read().refcount }, count);
            assert_eq!(free_log().0, 0);
        }
    }

    #[test]
    fn positive_count_decrements_without_destroying() {
        let _heap = mock_heap();
        let Some((slot, handle)) = fixture(2, MEMH_MAGIC) else {
            note_missing_u32_fixture("heap::memh_handle_release");
            return;
        };

        assert_eq!(unsafe { memh_handle_release(slot) }, slot);
        assert_eq!(unsafe { handle.read().refcount }, 1);
        assert_eq!(free_log().0, 0);
    }

    #[test]
    fn final_reference_decrements_then_destroys_the_handle() {
        let _heap = mock_heap();
        let Some((slot, handle)) = fixture(1, MEMH_MAGIC) else {
            note_missing_u32_fixture("heap::memh_handle_release");
            return;
        };

        assert_eq!(unsafe { memh_handle_release(slot) }, slot);
        assert_eq!(unsafe { handle.read().refcount }, 0);
        assert_eq!(unsafe { handle.read().handle.magic }, 0);
        assert_eq!(free_log(), (1, handle.cast::<u8>(), 4));
    }
}
