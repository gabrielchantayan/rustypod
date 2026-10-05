//! Timed-gateway optional-child owner initialization.
//!
//! `timed_gateway_child_owner_construct` — `FUN_0818be78` @ 0x0818be78.
//! True size: 40 bytes (36 code + 4-byte literal), next function 0x0818bea0.
//! Raw aligned ARM decoding: two incoming plain BLs at 0x08267bd0 and
//! 0x0827365c, zero predicated BLs; body has zero plain or predicated BLs.
//! Install vtable 0x08989a10, clear only the state byte at +4, clear child
//! at +8, set selection at +12 to 255 and flag at +13 to zero. Return the
//! original pointer (r0 is untouched). Preserve +5..+7 and +14..+15.
//! Class identity and the meanings of the two trailing bytes are unverified.
//!
//! Deliberate deviations: reuse the destructor's repr(C) owner layout;
//! pointers widen on hosts, so trailing fields move with the child field.
//! No allocation, child destruction, or null check occurs in the original.

use super::timed_gateway_child_owner_destruct::{TimedGatewayChildOwner, TIMED_GATEWAY_OWNER_VTABLE};

/// # Safety
/// `owner` must be non-null, aligned, and writable for a complete owner.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn timed_gateway_child_owner_construct(
    owner: *mut TimedGatewayChildOwner,
) -> *mut TimedGatewayChildOwner {
    (*owner).vtable = TIMED_GATEWAY_OWNER_VTABLE;
    core::ptr::addr_of_mut!((*owner).state).cast::<u8>().write(0);
    (*owner).child = core::ptr::null_mut();
    (*owner).selection = 0xff;
    (*owner).flag = 0;
    owner
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::timed_gateway_child_owner_destruct::GatewayOwnedChild;

    #[test]
    fn clears_only_initialized_fields_and_returns_original_owner() {
        for state in [0, u32::MAX, 0x1234_5678, 0xff00_00ff] {
            let mut child = GatewayOwnedChild { vtable: core::ptr::null() };
            let mut owner = TimedGatewayChildOwner {
                vtable: usize::MAX, state, child: &mut child,
                selection: 17, flag: 255, reserved: [0xa5, 0x5a],
            };
            let address = &mut owner as *mut _;
            for _ in 0..2 {
                assert_eq!(unsafe { timed_gateway_child_owner_construct(address) }, address);
                assert_eq!(owner.vtable, TIMED_GATEWAY_OWNER_VTABLE);
                let mut expected = state.to_ne_bytes();
                expected[0] = 0;
                assert_eq!(owner.state.to_ne_bytes(), expected);
                assert!(owner.child.is_null());
                assert_eq!(owner.selection, 255);
                assert_eq!(owner.flag, 0);
                assert_eq!(owner.reserved, [0xa5, 0x5a]);
            }
        }
    }

    #[test]
    fn does_not_write_neighbor_objects() {
        let mut owners = core::array::from_fn::<_, 3, _>(|_| TimedGatewayChildOwner {
            vtable: 7, state: u32::MAX, child: core::ptr::null_mut(),
            selection: 9, flag: 10, reserved: [11, 12],
        });
        unsafe { timed_gateway_child_owner_construct(&mut owners[1]); }
        for index in [0, 2] {
            assert_eq!(owners[index].vtable, 7);
            assert_eq!(owners[index].state, u32::MAX);
            assert_eq!(owners[index].selection, 9);
            assert_eq!(owners[index].flag, 10);
            assert_eq!(owners[index].reserved, [11, 12]);
        }
    }
}
