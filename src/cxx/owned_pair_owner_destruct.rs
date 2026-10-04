//! Owned-pair owner destruction — `FUN_081d8764` @ `0x081d8764`.
//!
//! True extent [0x081d8764,0x081d8788): 36 bytes, comprising 32 code
//! bytes and the 0x0898e0a8 vtable literal at 0x081d8784. The next real
//! function begins at 0x081d8788. Raw aligned ARM-word decoding finds two
//! incoming plain BLs (0x081f4e30, 0x081f4e38), one outgoing plain BL
//! (0x081d8778 to 0x081d85e8), and zero predicated BLs in either direction.
//!
//! Install the owner's destruction vtable, destroy/deallocate its owned
//! pair through the existing port, and return the original owner pointer.
//! A null pair preserves the auxiliary word; a non-null pair clears it
//! after resource and pair deletion. The caller destroys two embedded
//! owners at +0x2c and +0x18. Concrete class identity is not established.
//! No behavioral deviations: u32 word fields retain target offsets on hosts.

use crate::heap::owned_pair_destroy_and_deallocate::owned_pair_destroy_and_deallocate;

#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn owned_pair_owner_destruct(owner: *mut u32) -> *mut u32 {
    owner.write(0x0898_e0a8);
    owned_pair_destroy_and_deallocate(owner.cast());
    owner
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::heap::veneers::tests::{free_log, mock_heap};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::LazyLock;

    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::OWNED_PAIR_OWNER_DESTRUCT, 0x1000)
            .map(|pointer| pointer as usize)
    });

    #[test]
    fn empty_owner_preserves_auxiliary_and_neighbors_on_repeated_destruction() {
        let _lock = mock_heap();
        let mut words = [0xaaaa_aaaa, 0x1111_1111, 0xffff_ffff, 0, 0xbbbb_bbbb];
        let owner = unsafe { words.as_mut_ptr().add(1) };
        for _ in 0..2 {
            assert_eq!(unsafe { owned_pair_owner_destruct(owner) }, owner);
            assert_eq!(words, [0xaaaa_aaaa, 0x0898_e0a8, 0xffff_ffff, 0, 0xbbbb_bbbb]);
            assert_eq!(free_log().0, 0);
        }
    }

    #[test]
    fn populated_owner_destroys_real_pair_and_preserves_adjacent_words() {
        let Some(base) = *FIXTURE else {
            assert!(note_missing_u32_fixture("cxx/owned_pair_owner_destruct"));
            return;
        };
        for resource in [0, 0x1234_5000] {
            let _lock = mock_heap();
            let slab = base as *mut u32;
            let owner = unsafe { slab.add(1) };
            let pair = unsafe { slab.add(8) };
            unsafe {
                slab.write(0xaaaa_aaaa);
                owner.write(0x1111_1111);
                owner.add(1).write(0xffff_ffff);
                owner.add(2).write(pair as usize as u32);
                owner.add(3).write(0xbbbb_bbbb);
                pair.write(0xcccc_cccc);
                pair.add(1).write(resource);
                pair.add(2).write(0xdddd_dddd);
                assert_eq!(owned_pair_owner_destruct(owner), owner);
                assert_eq!([owner.read(), owner.add(1).read(), owner.add(2).read()], [0x0898_e0a8, 0, 0]);
                assert_eq!([pair.read(), pair.add(1).read(), pair.add(2).read()], [0, 0, 0xdddd_dddd]);
                assert_eq!(slab.read(), 0xaaaa_aaaa);
                assert_eq!(owner.add(3).read(), 0xbbbb_bbbb);
                assert_eq!(free_log(), (if resource == 0 { 1 } else { 2 }, pair.cast(), 2));
                owned_pair_owner_destruct(owner);
                assert_eq!(free_log(), (if resource == 0 { 1 } else { 2 }, pair.cast(), 2));
            }
        }
    }
}
