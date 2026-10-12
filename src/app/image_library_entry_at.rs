use crate::app::image_library_first_entry::image_library_first_entry;
use crate::app::liti_class_check::image_library_is_liti_class;
use crate::app::liti_entry_next::liti_entry_next;

/// image_library_entry_at — `FUN_08052560` @ `0x08052560` (88 bytes).
///
/// Raw extent is `0x08052560..0x080525b8`; the next independently called
/// function starts with `mov r2, r0`. Whole-image aligned ARM decoding finds
/// two inbound plain BLs (0x08066730, 0x0813e644), zero predicated BLs.
/// The body has three outbound plain BLs and zero predicated BLs: class check,
/// first-entry accessor, and successor accessor, all existing Rust ports.
///
/// Require a 'liti' database and unsigned index below its +0x14 count. Walk
/// from the +0x18 first entry, returning zero if the chain ends or an entry
/// fails its successor class check. Index zero returns the first entry
/// without validating that entry. Deliberate deviations: canonical Rust
/// callees replace stock calls; target-width fields and behavior are unchanged.
///
/// # Safety
/// A nonnull database must be aligned and readable through word 6. Every
/// traversed nonzero entry must satisfy `liti_entry_next`'s safety contract.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.image_library_entry_at")]
pub unsafe extern "C" fn image_library_entry_at(database: *const u8, mut index: u32) -> u32 {
    if unsafe { image_library_is_liti_class(database) } == 0 {
        return 0;
    }
    if index >= unsafe { database.cast::<u32>().add(5).read() } {
        return 0;
    }
    let mut entry = unsafe { image_library_first_entry(database) };
    while entry != 0 && index != 0 {
        index -= 1;
        entry = unsafe { liti_entry_next(entry as usize as *const u8) };
    }
    entry
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    static SLAB: std::sync::LazyLock<Option<usize>> = std::sync::LazyLock::new(|| {
        crate::testing::try_map_u32_slab(crate::testing::hints::IMAGE_LIBRARY_ENTRY_AT, 0x1000)
            .map(|p| p as usize)
    });

    #[test]
    fn null_and_wrong_class_are_rejected_before_count_access() {
        assert_eq!(unsafe { image_library_entry_at(core::ptr::null(), 0) }, 0);
        let tag = 0u32;
        assert_eq!(unsafe { image_library_entry_at((&tag as *const u32).cast(), 0) }, 0);
    }

    #[test]
    fn unsigned_bounds_chain_end_and_entry_class() {
        let _guard = LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let Some(base) = *SLAB else {
            assert!(crate::testing::note_missing_u32_fixture("app::image_library_entry_at"));
            return;
        };
        unsafe {
            let db = base as *mut u32;
            let first = db.add(32);
            let second = db.add(40);
            let third = db.add(48);
            core::ptr::write_bytes(db, 0, 0x1000 / 4);
            db.write(0x6974_696c);
            db.add(5).write(3);
            db.add(6).write(first as u32);
            first.write(second as u32);
            first.add(1).write(db as u32);
            second.write(third as u32);
            second.add(1).write(db as u32);
            third.add(1).write(db as u32);
            for (index, expected) in [(0, first as u32), (1, second as u32), (2, third as u32), (3, 0), (u32::MAX, 0)] {
                assert_eq!(image_library_entry_at(db.cast(), index), expected);
            }
            db.add(5).write(0);
            assert_eq!(image_library_entry_at(db.cast(), 0), 0);
            db.add(5).write(u32::MAX);
            assert_eq!(image_library_entry_at(db.cast(), 3), 0);
            second.write(0);
            assert_eq!(image_library_entry_at(db.cast(), 2), 0);
            first.add(1).write(0);
            assert_eq!(image_library_entry_at(db.cast(), 0), first as u32);
            assert_eq!(image_library_entry_at(db.cast(), 1), 0);
            db.add(6).write(0);
            assert_eq!(image_library_entry_at(db.cast(), 0), 0);
        }
    }
}
