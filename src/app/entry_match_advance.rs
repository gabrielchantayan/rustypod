//! First-or-successor selection for a matchable entry list.

use crate::app::entry_match_first::entry_match_first;
use crate::app::entry_match_successor::entry_match_successor;

/// `entry_match_advance` — original: `FUN_08053afc` @ 0x08053afc.
/// True extent: 24 bytes, 0x08053afc..0x08053b14; the next function
/// starts with push {r4,lr}. Verified inbound calls: two plain BLs
/// (0x081a8d18, 0x081a8e5c), zero predicated BLs. The body has no BL;
/// it ends in BNE to 0x08053bb8 and BEQ to 0x080522bc.
///
/// Raw words: e3500000 012fff1e e3510000 11a00001 1a000029 0afff9e9.
/// Return zero when the container is NULL, without inspecting the entry.
/// Otherwise select the container's first entry when entry is NULL, or the
/// entry's successor when non-NULL. The latter path does not inspect the
/// container. Cursor callers use this to begin or continue list traversal.
/// Deliberate deviation: call the canonical Rust selectors instead of stock
/// tail-branch addresses; target-width results and validation are unchanged.
///
/// # Safety
/// With a non-NULL container and NULL entry, the container must satisfy
/// `entry_match_first`'s contract. With both non-NULL, only the entry must
/// satisfy `entry_match_successor`'s contract; the container is not read.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn entry_match_advance(container: *const u8, entry: *const u8) -> u32 {
    if container.is_null() {
        0
    } else if entry.is_null() {
        unsafe { entry_match_first(container) }
    } else {
        unsafe { entry_match_successor(entry) }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    static SLAB: std::sync::LazyLock<Option<usize>> = std::sync::LazyLock::new(|| {
        crate::testing::try_map_u32_slab(crate::testing::hints::ENTRY_MATCH_ADVANCE, 0x1000)
            .map(|p| p as usize)
    });

    #[test]
    fn null_container_does_not_inspect_entry() {
        assert_eq!(unsafe { entry_match_advance(core::ptr::null(), 1usize as *const u8) }, 0);
        assert_eq!(unsafe { entry_match_advance(core::ptr::null(), core::ptr::null()) }, 0);
    }

    #[test]
    fn first_successor_and_rejected_classes() {
        let _guard = LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let Some(base) = *SLAB else {
            assert!(crate::testing::note_missing_u32_fixture("app::entry_match_advance"));
            return;
        };
        unsafe {
            let base = base as *mut u8;
            core::ptr::write_bytes(base, 0, 0x1000);
            let container = base.add(0x100).cast::<u32>();
            let entry = base.add(0x200).cast::<u32>();
            let target = base.add(0x300).cast::<u32>();
            target.write(0x6974_696c); // 'liti'
            container.add(2).write(target as usize as u32);
            container.add(9).write(entry as usize as u32);
            entry.add(1).write(container as usize as u32);
            assert_eq!(entry_match_advance(container.cast(), core::ptr::null()), entry as usize as u32);
            for successor in [0, 0x2200_aed8, u32::MAX] {
                entry.write(successor);
                // Non-NULL container is merely a gate on the successor path.
                assert_eq!(entry_match_advance(1usize as *const u8, entry.cast()), successor);
            }
            target.write(0x706c_7374); // not 'liti'
            assert_eq!(entry_match_advance(container.cast(), core::ptr::null()), 0);
            assert_eq!(entry_match_advance(container.cast(), entry.cast()), 0);
            target.write(0x6974_696c);
            entry.add(1).write(0);
            assert_eq!(entry_match_advance(container.cast(), entry.cast()), 0);
            container.add(9).write(0);
            assert_eq!(entry_match_advance(container.cast(), core::ptr::null()), 0);
        }
    }
}
