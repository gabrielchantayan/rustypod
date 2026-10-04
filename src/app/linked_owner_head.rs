//! Linked owner head — `FUN_081f1984` @ `0x081f1984`, 8 bytes.
//!
//! Raw words `e5900008 e12fff1e` decode as `ldr r0,[r0,#8]; bx lr`.
//! The next real function, linked_node_prepend, starts at 0x081f198c.
//! Whole-image A32 decoding verifies two plain inbound BLs (0x08235870,
//! 0x082359a0), zero predicated inbound BLs and zero body calls.
//! Return owner word 2, including a zero head, without dereferencing it.
//! The two callers use the returned address for virtual dispatch; its concrete
//! object type is unrecovered. Deliberate deviation: represent the opaque
//! target address as u32 rather than a host pointer, preserving four-byte
//! fields on every host. No null-owner guard or callee seams are added.

/// # Safety
/// `owner` must point to at least three readable, aligned u32 words.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn linked_owner_head(owner: *const u32) -> u32 {
    core::ptr::read(owner.add(2))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_empty_and_opaque_heads_without_touching_neighbor_words() {
        for head in [0, 1, 0x0800_0000, 0x8000_0000, u32::MAX] {
            let owner = [0x1122_3344, 0x5566_7788, head, !head];
            let before = owner;
            assert_eq!(unsafe { linked_owner_head(owner.as_ptr()) }, head);
            assert_eq!(owner, before);
        }
    }

    #[test]
    fn accepts_a_minimal_owner_and_observes_head_replacement() {
        let mut owner = [0xffff_ffff, 0x1234_5678, 0];
        assert_eq!(unsafe { linked_owner_head(owner.as_ptr()) }, 0);
        owner[2] = 0x0812_3450;
        assert_eq!(unsafe { linked_owner_head(owner.as_ptr()) }, 0x0812_3450);
        owner[2] = 0;
        assert_eq!(unsafe { linked_owner_head(owner.as_ptr()) }, 0);
    }
}
