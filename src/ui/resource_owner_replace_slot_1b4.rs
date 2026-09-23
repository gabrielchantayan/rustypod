//! Replaces the resource held in a fixed owner slot.
//!
//! `resource_owner_replace_slot_1b4` — original: `FUN_081ca490` @
//! **0x081ca490**. Raw `osos.dec` establishes the true **28-byte** extent
//! `0x081ca490..0x081ca4ab`; the next real function begins at `0x081ca4ac`.
//! The body has one plain unconditional `bl` and no predicated `bl` calls.
//! Whole-image A32 branch decoding finds three inbound plain `bl` call sites
//! and no predicated direct call sites.
//!
//! # Algorithm
//!
//! Select the owner fields at offsets `0x1b4`, `0xfc`, and `0xf8` as the
//! resource slot, initializer context, and selector slot respectively, then
//! delegate their replacement to `replace_owned_resource` with `selector`.
//!
//! # Deliberate deviations
//!
//! The stock wrapper lays its fifth ABI argument on the stack before its
//! direct `bl`; Rust expresses that same five-argument call normally.

/// # Safety
/// `owner` must address an object with writable target-width fields at offsets
/// `0x1b4` and `0xf8`; its `0xfc` field must be valid as the initializer
/// context required by `replace_owned_resource`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn resource_owner_replace_slot_1b4(owner: *mut u8, selector: u32) {
    crate::ui::replace_owned_resource::replace_owned_resource(
        owner,
        owner.add(0x1b4).cast(),
        owner.add(0xfc),
        owner.add(0xf8).cast(),
        selector,
    );
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::ptr;

    const OWNER_SIZE: usize = 0x1c0;

    fn owner_storage() -> [usize; OWNER_SIZE / core::mem::size_of::<usize>()] {
        [0; OWNER_SIZE / core::mem::size_of::<usize>()]
    }

    #[test]
    fn unchanged_selector_leaves_the_fixed_resource_slot_intact() {
        let _heap = crate::heap::veneers::tests::mock_heap();
        let mut owner = owner_storage();
        let owner = owner.as_mut_ptr().cast::<u8>();
        unsafe {
            let resource_slot = owner.add(0x1b4).cast::<*mut u8>();
            let selector_slot = owner.add(0xf8).cast::<u32>();
            resource_slot.write(crate::heap::veneers::tests::mock_block());
            selector_slot.write(0xfeed_beef);
            resource_owner_replace_slot_1b4(owner, 0xfeed_beef);
            assert_eq!(resource_slot.read(), crate::heap::veneers::tests::mock_block());
            assert_eq!(selector_slot.read(), 0xfeed_beef);
            assert_eq!(crate::heap::veneers::tests::free_log().0, 0);
        }
    }

    #[test]
    fn zero_selector_releases_and_clears_the_fixed_resource_slot() {
        let _heap = crate::heap::veneers::tests::mock_heap();
        let mut owner = owner_storage();
        let owner = owner.as_mut_ptr().cast::<u8>();
        unsafe {
            let resource_slot = owner.add(0x1b4).cast::<*mut u8>();
            let selector_slot = owner.add(0xf8).cast::<u32>();
            resource_slot.write(crate::heap::veneers::tests::mock_block());
            selector_slot.write(7);
            resource_owner_replace_slot_1b4(owner, 0);
            assert_eq!(resource_slot.read(), ptr::null_mut());
            assert_eq!(selector_slot.read(), 0);
            assert_eq!(crate::heap::veneers::tests::free_log(), (1, crate::heap::veneers::tests::mock_block(), 2));
        }
    }
}
