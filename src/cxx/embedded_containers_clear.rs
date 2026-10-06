//! `embedded_containers_clear` — `FUN_08178d64` @ `0x08178d64`.
//!
//! True extent: 52 bytes, [0x08178d64, 0x08178d98). The next function
//! starts with `str r1,[r0,#0x7c]`, followed by `bx lr`. Raw A32 words
//! establish three outbound plain BLs, no predicated BLs, and one tail B.
//! Whole-image decoding finds two inbound plain BLs (0x08179060 and
//! 0x0828a684), no predicated BLs. Ghidra's extent is correct, but its C
//! obscures the last call to observable_array_clear.
//!
//! Release enabled elements of the container at +0x24, then clear it.
//! Release allocations yielded by the container at +0x50, then clear it.
//! These are distinct ownership policies; neither release gate suppresses
//! the corresponding clear. No object/vtable installation or deletion occurs.
//!
//! Deliberate deviations: reuse the three existing ports. Host objects use
//! repr(C) member fields rather than overlapping target byte offsets, because
//! the existing helper models contain native-width pointers. LLVM selects
//! the final call/return versus tail branch; the recovered API returns void.

use super::observable_array::ObservableArray;
use super::templates::{container_release_enabled_elements, ContainerReleaseEnabledElements};
use crate::util::vtable_slot_40_release_each::vtable_slot_40_release_each;

#[cfg(target_arch = "arm")]
unsafe extern "C" {
    fn observable_array_clear(this: *mut ObservableArray);
}
#[cfg(not(target_arch = "arm"))]
use super::observable_array::observable_array_clear;

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostEmbeddedContainers {
    pub first: ContainerReleaseEnabledElements,
    pub second: crate::util::vtable_slot_40_release_each::HostReleaseEachObject,
}

/// Releases and clears both embedded containers in ownership order.
///
/// # Safety
/// On target, `this + 0x24` and `this + 0x50` must satisfy the respective
/// release helper and observable-array clear contracts. On host, `this`
/// must point to HostEmbeddedContainers with valid native vtables.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn embedded_containers_clear(this: *mut u32) {
    #[cfg(target_os = "none")]
    let (first, second) = (this.add(0x24 / 4).cast::<u8>(), this.add(0x50 / 4).cast::<u8>());
    #[cfg(not(target_os = "none"))]
    let (first, second) = {
        let owner = this.cast::<HostEmbeddedContainers>();
        (core::ptr::addr_of_mut!((*owner).first).cast::<u8>(),
         core::ptr::addr_of_mut!((*owner).second).cast::<u8>())
    };
    container_release_enabled_elements(first.cast());
    observable_array_clear(first.cast());
    vtable_slot_40_release_each(second);
    observable_array_clear(second.cast());
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::observable_array::{ObservableArrayClearHost, ObservableArrayClearVtable};
    use crate::util::vtable_slot_40_release_each::HostReleaseEachObject;

    unsafe extern "C" fn remove_tail(array: *mut ObservableArray, delta: i32) {
        let array = array.cast::<ObservableArrayClearHost>();
        // Real state transition: ARM's wrapping negation must remove exactly
        // the current length, including INT_MIN and negative bit patterns.
        (*array).len = (*array).len.wrapping_add(delta as u32);
    }

    #[test]
    fn clears_disabled_containers_even_with_nonzero_or_wrapping_lengths() {
        let vtable = ObservableArrayClearVtable {
            unresolved_00_b8: [0; 47], remove_tail,
        };
        for (first_len, second_len) in [(0, 0u32), (3, 7), (u32::MAX, 0x8000_0000), (0x8000_0000, 1)] {
            let mut owner = HostEmbeddedContainers {
                first: unsafe { core::mem::zeroed() },
                second: HostReleaseEachObject {
                    vtable: (&vtable as *const ObservableArrayClearVtable).cast(),
                    iteration_count: second_len as i32,
                    enabled: 0,
                },
            };
            unsafe {
                let first = core::ptr::addr_of_mut!(owner.first).cast::<ObservableArrayClearHost>();
                (*first).vtable = &vtable;
                (*first).len = first_len;
                embedded_containers_clear(core::ptr::addr_of_mut!(owner).cast());
                assert_eq!((*first).len, 0);
                assert_eq!(owner.second.iteration_count, 0);
                assert_eq!(owner.second.enabled, 0);
                assert_eq!((*first).vtable, &vtable as *const _);
                // Repeated cleanup of empty arrays remains a valid transition.
                embedded_containers_clear(core::ptr::addr_of_mut!(owner).cast());
                assert_eq!((*first).len, 0);
                assert_eq!(owner.second.iteration_count, 0);
            }
        }
    }

    #[test]
    fn enabled_empty_allocation_container_never_dispatches_release_slot() {
        let vtable = ObservableArrayClearVtable { unresolved_00_b8: [0; 47], remove_tail };
        let mut owner = HostEmbeddedContainers {
            first: unsafe { core::mem::zeroed() },
            second: HostReleaseEachObject {
                vtable: (&vtable as *const ObservableArrayClearVtable).cast(),
                iteration_count: 0, enabled: 1,
            },
        };
        unsafe {
            let first = core::ptr::addr_of_mut!(owner.first).cast::<ObservableArrayClearHost>();
            (*first).vtable = &vtable;
            embedded_containers_clear(core::ptr::addr_of_mut!(owner).cast());
            assert_eq!((*first).len, 0);
            assert_eq!(owner.second.iteration_count, 0);
            assert_eq!(owner.second.enabled, 1);
        }
    }
}
