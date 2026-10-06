//! `owner_link_has_secondary` — FUN_08168340 @ 0x08168340, true size 16 bytes.
//!
//! Raw words: e5900024 e3500000 13a00001 e12fff1e. The next real
//! function starts at 0x08168350 (the secondary-link setter). Whole-image
//! aligned A32 decoding verifies two incoming plain BLs (0x08168498,
//! 0x081684dc), zero predicated BLs; the body has no calls.
//! Read the aligned owner word at +0x24 and return exactly 0 or 1 for
//! absence or presence. The setter stores a link and invokes its vtable
//! slot +0x10; this query never dereferences the stored link.
//! Deliberate deviations: none. Word indexing retains firmware offsets
//! on hosts without widening the opaque 32-bit link identity.

/// # Safety
/// `owner` must point to at least ten aligned, initialized readable u32
/// words. Word nine must not be mutated during this call.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn owner_link_has_secondary(owner: *const u32) -> u32 {
    u32::from(owner.add(9).read() != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distinguishes_absence_from_every_single_bit_identity() {
        let mut owner = [u32::MAX; 10];
        owner[9] = 0;
        assert_eq!(unsafe { owner_link_has_secondary(owner.as_ptr()) }, 0);
        for bit in 0..32 {
            owner[9] = 1 << bit;
            assert_eq!(unsafe { owner_link_has_secondary(owner.as_ptr()) }, 1);
        }
        for link in [0x0800_1234, 0xffff_ffff] {
            owner[9] = link;
            assert_eq!(unsafe { owner_link_has_secondary(owner.as_ptr()) }, 1);
        }
    }

    #[test]
    fn observes_secondary_link_changes_not_primary_or_neighbors() {
        let mut owner = [0u32; 11];
        for (primary, secondary, following, expected) in [
            (0, 0, u32::MAX, 0),
            (u32::MAX, 0, 0, 0),
            (0, 0x8000_0000, 0, 1),
            (u32::MAX, 1, u32::MAX, 1),
            (1, 0, 1, 0),
        ] {
            owner[8] = primary;
            owner[9] = secondary;
            owner[10] = following;
            let before = owner;
            assert_eq!(unsafe { owner_link_has_secondary(owner.as_ptr()) }, expected);
            assert_eq!(owner, before);
        }
    }
}
