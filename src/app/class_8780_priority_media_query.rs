//! `class_8780_priority_media_query` — `FUN_081a4c28` @ **0x081a4c28**.
//! True size 40 bytes, ending at the independent function at 0x081a4c50.
//! Raw A32 decoding: incoming 2 plain BLs (0x081a4eb0, 0x081a4f00),
//! 0 predicated BLs; outgoing 2 plain BLs, 0 predicated BLs, 1 register BX tail.
//!
//! Query the class-0x8780 dispatch state. Return zero unless it is 3;
//! otherwise obtain the global media-player interface and return its
//! unresolved vtable slot +0x11c result unchanged. The original has no NULL
//! guards and callers distinguish zero from every nonzero return value.
//!
//! Deliberate deviations: recover the object argument and u32 return omitted
//! by Ghidra. Host vtable pointers use native width; repr(C) retains ARM slot
//! offsets. Reuse the existing singleton getter's documented not-hook-ready
//! behavior. No business-level identity is assigned to the dynamic callee.

use super::class_8780_dispatch_state::class_8780_dispatch_state;
use super::media_player_interface_slot_11c::MediaPlayerInterfaceSlot11c;

unsafe fn query(
    object: *const u8,
    get_interface: impl FnOnce() -> *mut MediaPlayerInterfaceSlot11c,
) -> u32 {
    if class_8780_dispatch_state(object) != 3 {
        return 0;
    }
    let interface = get_interface();
    let vtable = core::ptr::read_volatile(core::ptr::addr_of!((*interface).vtable));
    ((*vtable).dispatch)(interface)
}

/// Return media slot +0x11c only when the object's dispatch state is 3.
///
/// # Safety
/// `object` must be readable through +0x8c. In state 3 the global interface
/// must exist, with a readable vtable and callable slot +0x11c returning u32.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn class_8780_priority_media_query(object: *const u8) -> u32 {
    query(object, || super::singletons::media_player_interface_get().cast())
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::media_player_interface_slot_11c::MediaPlayerInterfaceSlot11cVtable;

    #[repr(C)]
    struct Interface {
        base: MediaPlayerInterfaceSlot11c,
        result: u32,
        calls: u32,
    }

    unsafe extern "C" fn state_query(interface: *mut MediaPlayerInterfaceSlot11c) -> u32 {
        let interface = &mut *interface.cast::<Interface>();
        interface.calls += 1;
        interface.result
    }

    #[test]
    fn inactive_states_return_zero_without_acquiring_interface() {
        for (gate, value) in [(0, 0), (0, 255), (1, 0), (255, 0), (1, 1), (255, 255)] {
            let mut object = [0u8; 0x8d];
            object[0x8a] = gate;
            object[0x8c] = value;
            assert_eq!(unsafe { query(object.as_ptr(),
                || panic!("inactive state acquired singleton")) }, 0);
            assert_eq!(unsafe { class_8780_priority_media_query(object.as_ptr()) }, 0);
        }
    }

    #[test]
    fn priority_overrides_secondary_state_and_preserves_full_slot_result() {
        let vtable = MediaPlayerInterfaceSlot11cVtable {
            unresolved_000_118: [0; 71], dispatch: state_query,
        };
        for priority in [1, 128, 255] {
            for (gate, value) in [(0, 0), (1, 0), (255, 255)] {
                for result in [0, 1, 0x8000_0000, u32::MAX] {
                    let mut object = [0u8; 0x8d];
                    object[0x1c] = priority;
                    object[0x8a] = gate;
                    object[0x8c] = value;
                    let before = object;
                    let mut interface = Interface {
                        base: MediaPlayerInterfaceSlot11c { vtable: &vtable },
                        result, calls: 0,
                    };
                    assert_eq!(unsafe { query(object.as_ptr(), || &mut interface.base) }, result);
                    assert_eq!(interface.calls, 1);
                    assert_eq!(object, before);
                }
            }
        }
    }
}
