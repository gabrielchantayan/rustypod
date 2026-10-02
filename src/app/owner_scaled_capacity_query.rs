//! Owner capacity expressed in 1-KiB units.
//!
//! `FUN_08296f18` @ `0x08296f18`: 76 bytes, ending before the real
//! prologue at `0x08296f64`. Raw words verify two plain BL instructions,
//! zero predicated BLs; two external plain BL callers, zero predicated.
//! A nonzero +0x14 count calls owner_capacity_query, reloads the count,
//! then multiplies (count >> 1) by (capacity >> 9), modulo 2^32. A zero
//! count calls facade_registry_walk with selector 1 and tail-dispatches
//! the returned facade's vtable slot +0x0c with that facade as receiver.
//! Deliberate deviations: RegistryNode and vtable pointers widen natively
//! on hosts; firmware offsets remain exact. The existing capacity port's
//! host-only non-NULL interface fallback is inherited, not device behavior.

use crate::app::facade_registry_walk::{facade_registry_walk, RegistryFacade, RegistryNode};
use crate::cxx::transition_addon::owner_capacity_query;

unsafe fn query_with_capacity(
    owner: *mut RegistryNode,
    capacity_query: impl FnOnce(*mut u8) -> u32,
) -> u32 {
    if (*owner).opaque_0c[2] != 0 {
        let capacity = capacity_query(owner.cast());
        // The virtual capacity call may change the count: reload after it.
        return ((*owner).opaque_0c[2] >> 1).wrapping_mul(capacity >> 9);
    }
    let facade = facade_registry_walk(owner, 1);
    let query: unsafe extern "C" fn(*mut RegistryFacade) -> u32 =
        core::mem::transmute(((*facade).vtable as *const usize).add(3).read());
    query(facade)
}

/// Original @ 0x08296f18, 76 bytes; two plain BLs and no predicated BLs.
/// See the module header for the algorithm and host ABI deviations.
///
/// # Safety
/// Owner must be a valid registry node. Its capacity interface and any
/// selected facade must have valid vtables and compatible query methods.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn owner_scaled_capacity_query(owner: *mut RegistryNode) -> u32 {
    query_with_capacity(owner, |this| owner_capacity_query(this))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(count: u32) -> RegistryNode {
        RegistryNode {
            opaque_00: [0; 2], facade: core::ptr::null_mut(),
            opaque_0c: [0, 0, count], opaque_18: 0, state_19: 0, pad_1a: [0; 2],
        }
    }

    #[test]
    fn shifts_truncate_before_wrapping_product() {
        for count in [1, 2, 3, 511, 512, 513, 0x8000_0001, u32::MAX] {
            for capacity in [0, 1, 511, 512, 513, 1023, 1024, u32::MAX] {
                let mut owner = node(count);
                let expected = (((count as u64 / 2) * (capacity as u64 / 512))
                    & 0xffff_ffff) as u32;
                assert_eq!(unsafe { query_with_capacity(&mut owner, |_| capacity) }, expected);
            }
        }
    }

    #[test]
    fn capacity_call_can_replace_count_including_zero() {
        for updated in [0, 1, 7, u32::MAX] {
            let mut owner = node(2);
            let ptr = &mut owner as *mut RegistryNode;
            let result = unsafe { query_with_capacity(ptr, |_| {
                (*ptr).opaque_0c[2] = updated;
                1024
            }) };
            assert_eq!(result, (updated >> 1).wrapping_mul(2));
        }
    }

    #[test]
    fn null_capacity_interface_uses_real_default_capacity() {
        let mut owner = node(17);
        assert_eq!(unsafe { owner_scaled_capacity_query(&mut owner) }, 8);
    }

    unsafe extern "C" fn facade_query(facade: *mut RegistryFacade) -> u32 {
        // Reading receiver data proves the selected facade, not the owner,
        // is passed to the virtual method.
        (*facade).opaque_04
    }

    #[test]
    fn zero_count_dispatches_selected_facade_slot_three() {
        let table = [0usize, 0, 0, facade_query as *const () as usize];
        let mut facade = RegistryFacade {
            vtable: table.as_ptr() as usize, opaque_04: 0xfedc_ba98,
            kind_08: 1, pad_09: [0; 3],
        };
        let mut owner = node(0);
        owner.facade = &mut facade;
        assert_eq!(unsafe { owner_scaled_capacity_query(&mut owner) }, 0xfedc_ba98);
        assert_eq!(unsafe { query_with_capacity(&mut owner, |_| panic!("capacity path")) }, 0xfedc_ba98);
    }
}
