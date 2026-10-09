//! `header_buffer_release` — original `FUN_080f69d4` @ 0x080f69d4.
//!
//! True extent: 36 bytes, 0x080f69d4..0x080f69f8; the next function
//! independently loads the allocation, adds its 12-byte header, and returns.
//! Raw A32 decoding finds two inbound plain BLs (0x080f6920, 0x080f6a48),
//! zero predicated BLs, and one internal plain BL to the already ported
//! `operator_delete_tag3` @ 0x082aad14 (zero internal predicated BLs).
//! Load the allocation at owner +4; if NULL, return without a store. Otherwise
//! release it with tag 3 and clear the allocation, preserving the vtable.
//! The builder @ 0x080f68f4 allocates payload length +12; the non-deleting
//! destructor @ 0x080f6a34 installs its vtable before calling this routine.
//!
//! Deliberate deviation: `repr(C)` pointer fields widen on hosts; on ARM the
//! vtable and allocation remain exactly two four-byte words. No new seam.
//! The routine has no defined return value; r0 is zero on both original paths.
//! Codegen preserves load/NULL guard/delete/clear, with a shared epilogue
//! and LLVM's additional sl/fp saves (40 bytes versus the original 36).

use crate::heap::veneers::operator_delete_tag3;

/// Vtable-bearing owner of a tag-3 allocation with a 12-byte payload header.
#[repr(C)]
pub struct HeaderBuffer {
    pub vtable: *const (),
    pub allocation: *mut u8,
}

/// # Safety
/// `owner` must be aligned, non-NULL, and writable. Its allocation must be NULL
/// or a live tag-3 allocation, with no concurrent access during release.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn header_buffer_release(owner: *mut HeaderBuffer) {
    let allocation = (*owner).allocation;
    if allocation.is_null() {
        return;
    }
    operator_delete_tag3(allocation);
    (*owner).allocation = core::ptr::null_mut();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heap::veneers::tests::{free_log, mock_heap};

    #[repr(C)]
    struct Fixture {
        owner: HeaderBuffer,
        following: [u32; 2],
    }

    #[test]
    fn empty_owner_preserves_vtable_and_neighbors() {
        let _heap = mock_heap();
        let vtable = &0x12345678u32 as *const u32 as *const ();
        let mut fixture = Fixture {
            owner: HeaderBuffer { vtable, allocation: core::ptr::null_mut() },
            following: [0xabcdef01, 0x10203040],
        };
        unsafe { header_buffer_release(&mut fixture.owner); }
        assert_eq!(free_log().0, 0);
        assert!(fixture.owner.allocation.is_null());
        assert_eq!(fixture.owner.vtable, vtable);
        assert_eq!(fixture.following, [0xabcdef01, 0x10203040]);
    }

    #[test]
    fn release_clears_allocation_and_repeated_release_does_not_double_free() {
        let _heap = mock_heap();
        let mut payload = [0x5au8; 44];
        let allocation = payload.as_mut_ptr();
        let vtable = &0x87654321u32 as *const u32 as *const ();
        let mut fixture = Fixture {
            owner: HeaderBuffer { vtable, allocation },
            following: [0xabcdef01, 0x10203040],
        };
        unsafe { header_buffer_release(&mut fixture.owner); }
        assert_eq!(free_log(), (1, allocation, 3));
        assert!(fixture.owner.allocation.is_null());
        assert_eq!(fixture.owner.vtable, vtable);
        assert_eq!(fixture.following, [0xabcdef01, 0x10203040]);
        unsafe { header_buffer_release(&mut fixture.owner); }
        assert_eq!(free_log(), (1, allocation, 3));
    }
}
