//! Refresh an object's cached storage extents.
//!
//! `storage_extents_refresh` — `FUN_08136954` @ 0x08136954.
//! True extent: 88 bytes, [0x08136954, 0x081369ac); next entry is push
//! {r4-r9,lr}. Raw A32 decoding verifies three outgoing plain BLs and no
//! predicated BLs; two incoming plain BLs at 0x081be598 and 0x081bfaf4,
//! no predicated incoming BLs. The release helper at 0x081368a0 frees +0x9c
//! only when +0xe8 is nonzero. Afterwards point +0x9c at inline storage
//! +0xa0, set count/capacity/ownership at +0xe0/+0xe4/+0xe8 to 0/8/0,
//! and read the kind byte at +0xec. Kinds 3, 4, 6 translate logical pairs
//! and return zero; all others rebuild extents and return that status.
//!
//! Deviations: reuse the ported translator at 0x08136d80. The unported
//! release and rebuild helpers retain verified firmware-address seams;
//! private injection permits host tests, while unavailable host helpers
//! explicitly panic. Pointer fields remain firmware-width u32. No target
//! behavioral deviation; Ghidra's reported two-call count is corrected.

use core::ptr::{read_volatile, write_volatile};
use super::storage_extents_translate::storage_extents_translate;

type ExtentOperation = unsafe extern "C" fn(*mut u32) -> i32;

#[inline(always)]
unsafe fn refresh_with(object: *mut u32, release: ExtentOperation, rebuild: ExtentOperation) -> i32 {
    release(object);
    write_volatile(object.add(0x9c / 4), object.add(0xa0 / 4) as usize as u32);
    write_volatile(object.add(0xe0 / 4), 0);
    write_volatile(object.add(0xe4 / 4), 8);
    write_volatile(object.add(0xe8 / 4), 0);
    match read_volatile(object.cast::<u8>().add(0xec)) {
        3 | 4 | 6 => {
            storage_extents_translate(object);
            0
        }
        _ => rebuild(object),
    }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_release(_: *mut u32) -> i32 {
    panic!("storage_extents_refresh requires retailOS release helper 0x081368a0")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_rebuild(_: *mut u32) -> i32 {
    panic!("storage_extents_refresh requires retailOS rebuild helper 0x081369ac")
}

/// # Safety
/// `object` must be an aligned writable retailOS storage object through +0xec,
/// with valid backend and extent fields for the selected resident helpers.
/// Owned old storage must be releasable by retailOS; no validation is added.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn storage_extents_refresh(object: *mut u32) -> i32 {
    #[cfg(target_os = "none")]
    let (release, rebuild): (ExtentOperation, ExtentOperation) = (
        core::mem::transmute(0x0813_68a0usize),
        core::mem::transmute(0x0813_69acusize),
    );
    #[cfg(not(target_os = "none"))]
    let (release, rebuild): (ExtentOperation, ExtentOperation) = (unavailable_release, unavailable_rebuild);
    refresh_with(object, release, rebuild)
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn release_old(object: *mut u32) -> i32 {
        // Destroy owned old storage, making ordering errors visible without
        // global allocator hooks. This is a model of the resident release.
        if *object.add(0xe8 / 4) != 0 {
            let old = *object.add(0x9c / 4) as usize as *mut u32;
            *old = 0;
            *old.add(1) = 0;
        }
        -123 // The release result is deliberately ignored by retailOS.
    }

    unsafe extern "C" fn rebuild_empty(object: *mut u32) -> i32 {
        // The resident builder returns zero immediately for zero byte length.
        assert_eq!(*object.add(0x28 / 4), 0);
        0
    }

    #[test]
    fn refresh_releases_old_storage_resets_state_and_translates_only_selected_kinds() {
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::STORAGE_EXTENTS_REFRESH, 0x1000,
        ) else {
            assert!(crate::testing::note_missing_u32_fixture("fs/storage_extents_refresh"));
            return;
        };
        unsafe {
            let object = slab.cast::<u32>();
            let backend = slab.add(0x200).cast::<u32>();
            let old = slab.add(0x800).cast::<u32>();
            for kind in 0..=255u8 {
                for owned in [0, 1, u32::MAX] {
                    for prefix in [0, 1, 8] {
                        core::ptr::write_bytes(slab, 0, 0x1000);
                        *object.add(1) = backend as usize as u32;
                        *backend.add(0x3d0 / 4) = u32::MAX;
                        *backend.add(0x3d4 / 4) = 3;
                        *old = 123;
                        *old.add(1) = 456;
                        *object.add(0x9c / 4) = old as usize as u32;
                        *object.add(0xe0 / 4) = 99;
                        *object.add(0xe4 / 4) = 17;
                        *object.add(0xe8 / 4) = owned;
                        object.cast::<u8>().add(0xec).write(kind);
                        for i in 0..8 {
                            *object.add(0x3c / 4 + i * 2) = if i < prefix { i as u32 + 1 } else { 0 };
                            *object.add(0x3c / 4 + i * 2 + 1) = u32::MAX;
                            *object.add(0xa0 / 4 + i * 2) = 0xdead_beef;
                            *object.add(0xa0 / 4 + i * 2 + 1) = 0xdead_beef;
                        }
                        let mut expected = [0u32; 0xf0 / 4];
                        core::ptr::copy_nonoverlapping(object, expected.as_mut_ptr(), expected.len());
                        expected[0x9c / 4] = object.add(0xa0 / 4) as usize as u32;
                        expected[0xe0 / 4] = if matches!(kind, 3 | 4 | 6) { prefix as u32 } else { 0 };
                        expected[0xe4 / 4] = 8;
                        expected[0xe8 / 4] = 0;
                        if matches!(kind, 3 | 4 | 6) {
                            for i in 0..prefix {
                                expected[0xa0 / 4 + i * 2] = (i as u32 + 1).wrapping_mul(3).wrapping_add(u32::MAX);
                                expected[0xa0 / 4 + i * 2 + 1] = u32::MAX.wrapping_mul(3);
                            }
                        }
                        assert_eq!(refresh_with(object, release_old, rebuild_empty), 0);
                        assert_eq!(core::slice::from_raw_parts(object, expected.len()), &expected);
                        assert_eq!((*old, *old.add(1)), if owned != 0 { (0, 0) } else { (123, 456) });
                    }
                }
            }
        }
    }
}
