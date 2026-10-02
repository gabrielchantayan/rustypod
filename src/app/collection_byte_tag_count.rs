//! Signed element count of the embedded byte-tag collection.
//!
//! Original `FUN_082988e4` @ **0x082988e4**, true size **8 bytes**,
//! ending at the next real function, 0x082988ec. Raw words are
//! `e5900058` (ldr r0,[r0,#0x58]) and `e12fff1e` (bx lr).
//! Whole-image A32 decoding verifies two inbound plain BLs at 0x081b2758
//! and 0x0829d610, no predicated inbound BLs, and no outbound BLs.
//!
//! Return the count word unchanged, interpreted as signed by both callers'
//! indexed iteration bounds. No clamping, dispatch, or NULL check.
//! Deliberate deviation: reuse ByteTagCollectionOwner's repr(C) layout;
//! its vtable pointer widens on hosts, while ARM keeps count at +0x58.

use crate::app::collection_find_byte_tag::ByteTagCollectionOwner;

/// # Safety
/// `owner` must be aligned and readable through its count field.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn collection_byte_tag_count(owner: *const ByteTagCollectionOwner) -> i32 {
    unsafe { core::ptr::addr_of!((*owner).count).read() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_signed_bounds_and_observes_updated_count() {
        let mut owner = ByteTagCollectionOwner {
            opaque_prefix: [0xa5a5a5a5; 21],
            collection_vtable: core::ptr::null(),
            count: 0,
        };
        for count in [0, 1, i32::MAX, i32::MIN, -1, 0x12345678] {
            owner.count = count;
            assert_eq!(unsafe { collection_byte_tag_count(&owner) }, count);
            assert_eq!(owner.count, count);
            assert_eq!(owner.opaque_prefix, [0xa5a5a5a5; 21]);
            assert!(owner.collection_vtable.is_null());
        }
    }
}
