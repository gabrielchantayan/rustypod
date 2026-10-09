//! Refreshes the FreeType owner's cached outline renderer.
//!
//! `ft_refresh_outline_module` — `FUN_080ccdf0` @ `0x080ccdf0`.
//! True extent: 32 bytes through `0x080cce10`, comprising 28 executable
//! bytes and the class literal at `0x080cce0c`. Verified whole-image A32 BL
//! scan: 2 plain incoming calls, no predicated calls; 1 plain outgoing call
//! to `ft_linked_module_find_by_class` at `0x0804ced4`.
//!
//! Find the first linked module with class `0x6f75746c` ('outl'), starting
//! from the owner's list head with no cursor, then overwrite owner+0xa4
//! with that module or zero. Called after renderer insertion/removal.
//! No behavioral deviations. Pointer fields remain aligned target-width
//! u32 words on hosts; unlike the lookup, this wrapper requires a non-null
//! owner because retail unconditionally stores the result.

use core::ptr;
use super::linked_module_find_by_class::ft_linked_module_find_by_class;

const OUTLINE_MODULE_CLASS: u32 = 0x6f75_746c;
const OWNER_OUTLINE_MODULE_OFFSET: usize = 0xa4;

/// Refreshes the cached first outline module, clearing a stale cache on a miss.
///
/// # Safety
/// `owner` must be non-null, word-aligned, readable through +0x9f and writable
/// at +0xa4..+0xa8. Its target-width linked records and modules must be readable
/// for the lookup, and resulting module addresses must fit in u32.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ft_refresh_outline_module(owner: *mut u8) {
    let module = ft_linked_module_find_by_class(owner, OUTLINE_MODULE_CLASS, ptr::null_mut());
    owner.add(OWNER_OUTLINE_MODULE_OFFSET).cast::<u32>()
        .write_volatile(module as usize as u32);
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::FT_REFRESH_OUTLINE_MODULE, 0x1000).map(|p| p as usize)
    });
    static LOCK: Mutex<()> = Mutex::new(());

    unsafe fn word(base: *mut u8, offset: usize, value: u32) {
        base.add(offset).cast::<u32>().write(value);
    }

    #[test]
    fn refreshes_first_match_after_removal_and_clears_stale_cache() {
        let _lock = LOCK.lock();
        let Some(address) = *FIXTURE else {
            assert!(note_missing_u32_fixture("ft/refresh_outline_module"));
            return;
        };
        let base = address as *mut u8;
        unsafe {
            base.write_bytes(0, 0x1000);
            // Three records: a non-outline module followed by two outline modules.
            for (record, next, module, class) in [
                (0x200, 0x220, 0x400, 7),
                (0x220, 0x240, 0x440, OUTLINE_MODULE_CLASS),
                (0x240, 0, 0x480, OUTLINE_MODULE_CLASS),
            ] {
                word(base, record + 4, if next == 0 { 0 } else { (address + next) as u32 });
                word(base, record + 8, (address + module) as u32);
                word(base, module + 0x18, class);
            }
            word(base, 0x9c, (address + 0x200) as u32);
            word(base, 0xa0, 0x1234_5678);
            word(base, 0xa8, 0x8765_4321);
            word(base, 0xa4, 0xdead_beef);
            ft_refresh_outline_module(base);
            assert_eq!(base.add(0xa4).cast::<u32>().read(), (address + 0x440) as u32);
            // Remove the first match; selection must restart from the list head.
            word(base, 0x204, (address + 0x240) as u32);
            ft_refresh_outline_module(base);
            assert_eq!(base.add(0xa4).cast::<u32>().read(), (address + 0x480) as u32);
            word(base, 0x204, 0);
            ft_refresh_outline_module(base);
            assert_eq!(base.add(0xa4).cast::<u32>().read(), 0);
            // Empty list also overwrites a stale cache.
            word(base, 0x9c, 0);
            word(base, 0xa4, 0xdead_beef);
            ft_refresh_outline_module(base);
            assert_eq!(base.add(0xa4).cast::<u32>().read(), 0);
            assert_eq!(base.add(0xa0).cast::<u32>().read(), 0x1234_5678);
            assert_eq!(base.add(0xa8).cast::<u32>().read(), 0x8765_4321);
        }
    }
}
