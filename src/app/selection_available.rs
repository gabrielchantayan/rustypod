//! `selection_available` — original: `FUN_081ee008` @ **0x081ee008**.
//!
//! Raw ARM words establish the true **64-byte** extent
//! `0x081ee008..0x081ee048`: a 60-byte instruction body ends in `bx lr`, and
//! its literal table base (`0x08a79240`) occupies the trailing word; the next
//! separately entered function begins at `0x081ee048`. Decoding every ARM
//! branch in `osos.dec` finds **3 plain unconditional `bl` callers**
//! (`0x0808cef8`, `0x080d1a84`, `0x0821ecc8`) and **0 predicated `bl` callers**.
//!
//! # Algorithm
//!
//! The selected primary record is 20 bytes wide. Return true when its byte at
//! +0x10 is nonzero. Otherwise select the fallback record using the object's
//! word at +0x1c and return whether that record's +0x10 byte is nonzero. The
//! raw object indices live at +0x24 and +0x1c respectively; neither the object
//! nor either table access is guarded.
//!
//! # Deliberate deviations
//!
//! The anonymous fixed table has no recovered semantic type, so the port uses
//! byte offsets rather than a speculative Rust layout. The target reads its
//! literal base directly; the host uses a test-only replaceable base so its
//! u32-addressable fixture can model both the primary and preceding fallback
//! table.

const RECORD_SIZE: usize = 0x14;
const RECORD_AVAILABLE_OFFSET: usize = 0x10;
const FALLBACK_TABLE_DISPLACEMENT: usize = 0x2a8;
const PRIMARY_INDEX_OFFSET: usize = 0x24;
const FALLBACK_INDEX_OFFSET: usize = 0x1c;
const RECORD_TABLE_ADDRESS: usize = 0x08a7_9240;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn record_table_base() -> *const u8 {
    RECORD_TABLE_ADDRESS as *const u8
}

#[cfg(not(target_os = "none"))]
static mut HOST_RECORD_TABLE_BASE: *const u8 = core::ptr::null();

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn record_table_base() -> *const u8 {
    HOST_RECORD_TABLE_BASE
}

/// selection_available — original: `FUN_081ee008` @ 0x081ee008 (64 bytes;
/// 3 unconditional direct `bl` call sites and no predicated calls).
///
/// Returns whether the selected primary record is available, or, when it is
/// unavailable, whether the selected fallback record is available. `selection`
/// and the fixed table must address readable ARM-layout memory.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn selection_available(selection: *const u8) -> u32 {
    let table = record_table_base();
    let primary_index = selection.add(PRIMARY_INDEX_OFFSET).cast::<u32>().read() as usize;
    if table.add(primary_index * RECORD_SIZE + RECORD_AVAILABLE_OFFSET).read() != 0 {
        return 1;
    }

    let fallback_index = selection.add(FALLBACK_INDEX_OFFSET).cast::<u32>().read() as usize;
    u32::from(
        table
            .sub(FALLBACK_TABLE_DISPLACEMENT)
            .add(fallback_index * RECORD_SIZE + RECORD_AVAILABLE_OFFSET)
            .read()
            != 0,
    )
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr;
    use std::sync::Mutex;

    const FIXTURE_LEN: usize = 0x1000;
    const TABLE_OFFSET: usize = 0x400;
    const SELECTION_OFFSET: usize = 0x800;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    struct Fixture {
        slab: *mut u8,
    }

    impl Fixture {
        fn map() -> Option<Self> {
            try_map_u32_slab(hints::SELECTION_AVAILABLE, FIXTURE_LEN)
                .map(|slab| Self { slab })
        }

        unsafe fn reset(&self) -> *const u8 {
            ptr::write_bytes(self.slab, 0, FIXTURE_LEN);
            let table = self.slab.add(TABLE_OFFSET);
            HOST_RECORD_TABLE_BASE = table;
            self.slab.add(SELECTION_OFFSET)
        }

        unsafe fn set_primary(&self, index: u32, available: u8) {
            self.slab
                .add(TABLE_OFFSET + index as usize * RECORD_SIZE + RECORD_AVAILABLE_OFFSET)
                .write(available);
        }

        unsafe fn set_fallback(&self, index: u32, available: u8) {
            self.slab
                .add(TABLE_OFFSET - FALLBACK_TABLE_DISPLACEMENT
                    + index as usize * RECORD_SIZE + RECORD_AVAILABLE_OFFSET)
                .write(available);
        }
    }

    #[test]
    fn returns_primary_availability_without_consulting_fallback() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(fixture) = Fixture::map() else {
            assert!(note_missing_u32_fixture("app::selection_available"));
            return;
        };
        unsafe {
            let selection = fixture.reset() as *mut u8;
            selection.add(PRIMARY_INDEX_OFFSET).cast::<u32>().write(3);
            selection.add(FALLBACK_INDEX_OFFSET).cast::<u32>().write(4);
            fixture.set_primary(3, 0x80);
            fixture.set_fallback(4, 0);
            assert_eq!(selection_available(selection), 1);
        }
    }

    #[test]
    fn falls_back_when_primary_is_unavailable() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(fixture) = Fixture::map() else {
            assert!(note_missing_u32_fixture("app::selection_available"));
            return;
        };
        unsafe {
            let selection = fixture.reset() as *mut u8;
            selection.add(PRIMARY_INDEX_OFFSET).cast::<u32>().write(7);
            selection.add(FALLBACK_INDEX_OFFSET).cast::<u32>().write(2);
            fixture.set_primary(7, 0);
            fixture.set_fallback(2, 1);
            assert_eq!(selection_available(selection), 1);
            fixture.set_fallback(2, 0);
            assert_eq!(selection_available(selection), 0);
        }
    }
}
