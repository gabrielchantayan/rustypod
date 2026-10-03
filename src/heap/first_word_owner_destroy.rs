//! `first_word_owner_destroy` — original `FUN_08242f20` @ 0x08242f20.
//!
//! True extent: 24 bytes, 0x08242f20..0x08242f38; the next function begins
//! with `mov r3,r0`. Raw A32 decoding finds two inbound plain BLs at
//! 0x08256560 and 0x08256568, zero predicated BLs. The body has one plain
//! BL to the already ported `operator_delete_tag3` @ 0x082aad14 and no
//! predicated BLs. Load the owner's first pointer word, delete that allocation,
//! and return the owner without clearing its pointer or freeing the owner.
//! The caller destroys embedded owners at +0x10 and +0x04 and uses the return
//! value to walk back through its enclosing object.
//!
//! Deliberate deviation: the pointer field widens on hosts; `repr(C)` keeps
//! it at offset zero and its target size is four bytes. No new callee seam.
//! Codegen retains the load/call/return sequence; LLVM additionally saves
//! sl/fp and establishes a frame pointer (28 bytes versus the original 24).

use crate::heap::veneers::operator_delete_tag3;

/// The only field inspected by this non-deleting destructor.
#[repr(C)]
pub struct FirstWordOwner {
    pub allocation: *mut u8,
}

/// # Safety
/// `owner` must be non-NULL and point to an aligned, readable owner. Its
/// allocation must be NULL or a live tag-3 allocation. The pointer is left
/// dangling after release, matching retailOS; do not destroy it twice.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn first_word_owner_destroy(owner: *mut FirstWordOwner) -> *mut FirstWordOwner {
    operator_delete_tag3((*owner).allocation);
    owner
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heap::veneers::tests::{free_log, mock_heap};

    #[repr(C)]
    struct Fixture {
        owner: FirstWordOwner,
        following: [u32; 2],
    }

    #[test]
    fn empty_allocation_preserves_owner_and_adjacent_words() {
        let _heap = mock_heap();
        let mut fixture = Fixture {
            owner: FirstWordOwner { allocation: core::ptr::null_mut() },
            following: [0x12345678, 0x87654321],
        };
        let owner = &mut fixture.owner as *mut FirstWordOwner;
        assert_eq!(unsafe { first_word_owner_destroy(owner) }, owner);
        assert!(fixture.owner.allocation.is_null());
        assert_eq!(fixture.following, [0x12345678, 0x87654321]);
        assert_eq!(free_log().0, 0);
    }

    #[test]
    fn embedded_owner_releases_only_allocation_and_retains_dangling_pointer() {
        let _heap = mock_heap();
        let mut payload = [0x5au8; 32];
        let allocation = payload.as_mut_ptr();
        let mut fixture = Fixture {
            owner: FirstWordOwner { allocation },
            following: [0xabcdef01, 0x10203040],
        };
        let owner = &mut fixture.owner as *mut FirstWordOwner;
        assert_eq!(unsafe { first_word_owner_destroy(owner) }, owner);
        assert_eq!(free_log(), (1, allocation, 3));
        assert_eq!(fixture.owner.allocation, allocation);
        assert_eq!(fixture.following, [0xabcdef01, 0x10203040]);
    }
}
