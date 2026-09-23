//! Tests whether a Genius request reached its selected item count.
//!
//! `genius_request_selection_is_complete` — original: `FUN_0816ecd8` @
//! **0x0816ecd8** (**52 bytes**, exactly `0x0816ecd8..0x0816ed08`; the next
//! separately linked function begins with `push {r4-r8,lr}` at `0x0816ed0c`).
//!
//! **3 direct `bl` call sites, all unconditional; 0 predicated `bl` call
//! sites.** The function itself has one unconditional `bl`, to the ported
//! `ui_element_reference_target_item_count` at `0x082a5e48`.
//!
//! ## Algorithm
//!
//! A zero byte at request+0x10 returns zero without reading the embedded UI
//! element reference. Otherwise it reads the reference at request+0x14 and
//! returns one exactly when its target item count equals the request's u32
//! selection at +0x08. No deliberate deviations.

use crate::ui::element_reference_item_count::ui_element_reference_target_item_count;

const SELECTION_OFFSET: usize = 0x08;
const ACTIVE_OFFSET: usize = 0x10;
const ELEMENT_REFERENCE_OFFSET: usize = 0x14;

/// Returns whether an active Genius request's selected position equals its
/// current UI-element target item count.
///
/// # Safety
///
/// `request` must be readable through +0x10. If that byte is nonzero, it must
/// also be readable through +0x17 and contain a valid UI element reference at
/// +0x14 as required by [`ui_element_reference_target_item_count`].
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn genius_request_selection_is_complete(request: *const u8) -> u32 {
    if request.add(ACTIVE_OFFSET).read() == 0 {
        return 0;
    }

    let item_count = unsafe {
        ui_element_reference_target_item_count(request.add(ELEMENT_REFERENCE_OFFSET))
    };
    (item_count == request.add(SELECTION_OFFSET).cast::<u32>().read()) as u32
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    static FIXTURE_LOCK: Mutex<()> = Mutex::new(());
    static mut RESOLVE_CALLS: u32 = 0;
    static mut RESOLVE_RESULT: u32 = 0;

    unsafe extern "C" fn resolve_stub(_reference: *const u8) -> u32 {
        RESOLVE_CALLS += 1;
        RESOLVE_RESULT
    }

    fn fixture() -> Option<*mut u8> {
        static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
            try_map_u32_slab(hints::GENIUS_REQUEST_SELECTION_IS_COMPLETE, 0x1000)
                .map(|pointer| pointer as usize)
        });
        SLAB.map(|pointer| pointer as *mut u8)
    }

    unsafe fn setup(selection: u32, item_count: u16, active: u8) -> Option<*mut u8> {
        let request = fixture()?;
        request.write_bytes(0, 0x1000);
        request.add(SELECTION_OFFSET).cast::<u32>().write(selection);
        request.add(ACTIVE_OFFSET).write(active);

        let vtable = request.add(0x40);
        let target = request.add(0x100);
        let collection = request.add(0x200);
        request
            .add(ELEMENT_REFERENCE_OFFSET)
            .cast::<u32>()
            .write(vtable as usize as u32);
        vtable.add(0x0c).cast::<usize>().write(resolve_stub as usize);
        request
            .add(ELEMENT_REFERENCE_OFFSET + 4)
            .cast::<u32>()
            .write(target as usize as u32);
        target.add(0x40).cast::<u32>().write(collection as usize as u32);
        collection.add(0x2e).cast::<u16>().write(item_count);
        Some(request)
    }

    #[test]
    fn inactive_request_short_circuits_before_element_reference_dispatch() {
        let _lock = FIXTURE_LOCK.lock();
        let Some(request) = (unsafe { setup(7, 7, 0) }) else {
            assert!(note_missing_u32_fixture("app/genius_request_selection_is_complete"));
            return;
        };
        unsafe {
            RESOLVE_CALLS = 0;
            assert_eq!(genius_request_selection_is_complete(request), 0);
            assert_eq!(RESOLVE_CALLS, 0);
        }
    }

    #[test]
    fn active_request_requires_exact_item_count_match() {
        let _lock = FIXTURE_LOCK.lock();
        let Some(request) = (unsafe { setup(0x1_0002, 2, 1) }) else {
            assert!(note_missing_u32_fixture("app/genius_request_selection_is_complete"));
            return;
        };
        unsafe {
            RESOLVE_RESULT = 0xffff_ffff;
            RESOLVE_CALLS = 0;
            assert_eq!(genius_request_selection_is_complete(request), 0);
            request.add(SELECTION_OFFSET).cast::<u32>().write(2);
            assert_eq!(genius_request_selection_is_complete(request), 1);
            assert_eq!(RESOLVE_CALLS, 2);
        }
    }

    #[test]
    fn failed_reference_resolution_cannot_complete_nonzero_selection() {
        let _lock = FIXTURE_LOCK.lock();
        let Some(request) = (unsafe { setup(1, 0, 1) }) else {
            assert!(note_missing_u32_fixture("app/genius_request_selection_is_complete"));
            return;
        };
        unsafe {
            RESOLVE_RESULT = 0;
            RESOLVE_CALLS = 0;
            assert_eq!(genius_request_selection_is_complete(request), 0);
            assert_eq!(RESOLVE_CALLS, 1);
        }
    }
}
