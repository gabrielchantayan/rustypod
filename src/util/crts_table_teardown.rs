//! crts_table_teardown — FUN_080d86b0 @ 0x080d86b0, 160 bytes.
//!
//! Raw code ends at pop {r4-r8,pc} @ 0x080d874c; the next function
//! starts at 0x080d8750. Whole-image ARM decoding verifies two inbound
//! plain BL calls (0x0809e1a4, 0x080e27e4), zero predicated callers.
//! Outbound calls: three plain BLs and one BLHI, to the ported tag guard
//! and free. Reject invalid tags with -50. Unless forced, require both
//! flags 0x04 and 0x08. When both arrays exist, scan all 65536 u16 counts,
//! freeing the corresponding u32 pointer only for counts greater than one;
//! then free and clear the pointer array before freeing and clearing the
//! count array. Finally clear flag 0x04 and set 0x40, even if an array is
//! absent. Other fields and flags are preserved.
//!
//! Deliberate deviations: no behavioral deviations. Target pointers remain
//! u32 words on hosts. A volatile function-pointer load retains the existing
//! free port as a call boundary instead of inlining its allocator dispatch.
//! The inlined internal implementation lets host tests observe releases.

use crate::util::crts_object::CrtsObject;
use crate::util::crts_tag::crts_has_tag;

type FreePort = unsafe extern "C" fn(*mut u8);
static FREE_PORT: FreePort = crate::runtime::malloc_rt::free;

#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn crts_table_teardown(this: *mut CrtsObject, force: u32) -> i32 {
    teardown(this, force, |pointer| {
        core::ptr::read_volatile(core::ptr::addr_of!(FREE_PORT))(pointer)
    })
}

#[inline(always)]
unsafe fn teardown(this: *mut CrtsObject, force: u32, mut release: impl FnMut(*mut u8)) -> i32 {
    if crts_has_tag(this.cast()) == 0 {
        return -50;
    }
    if force == 0 && (*this).flags & 0x0c != 0x0c {
        return 0;
    }
    let entries = (*this).opaque_14[0] as usize as *const u32;
    if !entries.is_null() {
        let counts = (*this).opaque_14[1] as usize as *const u16;
        if !counts.is_null() {
            for index in 0..0x10000 {
                if counts.add(index).read() > 1 {
                    release(entries.add(index).read() as usize as *mut u8);
                }
            }
            release((*this).opaque_14[0] as usize as *mut u8);
            (*this).opaque_14[0] = 0;
            release((*this).opaque_14[1] as usize as *mut u8);
            (*this).opaque_14[1] = 0;
        }
    }
    (*this).flags = ((*this).flags & !4) | 0x40;
    0
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::util::crts_tag::CRTS_TAG;
    use std::vec::Vec;

    fn object(flags: u32) -> CrtsObject {
        CrtsObject { tag: CRTS_TAG, flags, handle_08: 0, handle_0c: 0,
            handle_10: 0, opaque_14: [0; 17] }
    }

    #[test]
    fn invalid_and_ineligible_objects_are_untouched() {
        unsafe {
            assert_eq!(teardown(core::ptr::null_mut(), 1, |_| panic!("release")), -50);
            let mut bad = object(12);
            bad.tag = 0;
            assert_eq!(teardown(&mut bad, 1, |_| panic!("release")), -50);
            assert_eq!(bad.flags, 12);
            for flags in [0, 4, 8, 0xffff_fff3] {
                let mut value = object(flags);
                value.opaque_14[0] = 1;
                value.opaque_14[1] = 1;
                assert_eq!(teardown(&mut value, 0, |_| panic!("release")), 0);
                assert_eq!(value.flags, flags);
                assert_eq!(&value.opaque_14[..2], &[1, 1]);
            }
        }
    }

    #[test]
    fn missing_arrays_preserve_ownership_but_update_flags() {
        for (entries, counts) in [(0, 0), (0, 1), (1, 0)] {
            for (flags, force) in [(12, 0), (0x8000_0000, 7)] {
                let mut value = object(flags);
                value.opaque_14[..2].copy_from_slice(&[entries, counts]);
                assert_eq!(unsafe { teardown(&mut value, force, |_| panic!("release")) }, 0);
                assert_eq!(value.flags, (flags & !4) | 0x40);
                assert_eq!(&value.opaque_14[..2], &[entries, counts]);
            }
        }
    }

    #[test]
    fn scans_unsigned_counts_through_last_slot_and_clears_arrays_in_order() {
        let Some(base) = crate::testing::try_map_u32_slab(
            crate::testing::hints::CRTS_TABLE_TEARDOWN, 0x60000) else {
            assert!(crate::testing::note_missing_u32_fixture("util/crts_table_teardown"));
            return;
        };
        unsafe {
            core::ptr::write_bytes(base, 0, 0x60000);
            let entries = base.cast::<u32>();
            let counts = base.add(0x40000).cast::<u16>();
            for (index, count, pointer) in [(0, 0, 0x1000), (1, 1, 0x2000),
                (2, 2, 0x3000), (3, 0x8000, 0x4000), (65535, 0xffff, 0x5000)] {
                entries.add(index).write(pointer);
                counts.add(index).write(count);
            }
            let mut value = object(0x8000_000c);
            value.opaque_14[0] = entries as usize as u32;
            value.opaque_14[1] = counts as usize as u32;
            value.opaque_14[2] = 0xabcdef;
            let owner = &mut value as *mut CrtsObject;
            let mut freed = Vec::new();
            assert_eq!(teardown(owner, 0, |p| {
                if p == counts.cast() { assert_eq!((*owner).opaque_14[0], 0); }
                assert_eq!((*owner).opaque_14[1], counts as usize as u32);
                freed.push(p as usize);
            }), 0);
            assert_eq!(freed, [0x3000, 0x4000, 0x5000, entries as usize, counts as usize]);
            assert_eq!(&value.opaque_14[..3], &[0, 0, 0xabcdef]);
            assert_eq!(value.flags, 0x8000_0048);
            assert_eq!(teardown(owner, 0, |_| panic!("repeat release")), 0);
        }
    }
}
