//! Original: `FUN_081eda94` @ `0x081eda94`, true extent 32 bytes
//! (`0x081eda94..0x081edab4`): six A32 instructions and two literals.
//! Whole-image decoding verifies two inbound plain BLs (0x08212604,
//! 0x08227ef0), zero predicated BLs. The body has no BL and ends in BX r3.
//!
//! Stores the full input word at +0x2c, then reads resource kind 0x2a2a2a2a,
//! id 0x891a through the receiver's virtual slot +0x58. Neither the stored
//! state's domain nor this resource's user-facing identity is established.
//! Deliberate deviations: Rust calls and returns the virtual result instead
//! of tail-branching; existing repr(C) layouts widen pointers on hosts while
//! retaining target offsets on ARM. No added guards or direct callee seam.

use crate::app::class_8900::Class8900;
use crate::app::resource_chain::{ResourceKind, ResourceProvider};

/// # Safety
/// `this` must be a writable Class8900 with a callable resource-read slot.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn class_8900_state_2c_set_and_read(this: *mut Class8900, state: u32) -> u32 {
    (*this).state_below_cache[10] = state;
    let read = (*(*this).vtable).read;
    read(this.cast::<ResourceProvider>(), ResourceKind(0x2a2a_2a2a), 0x891a)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::resource_chain::ResourceProviderVTable;

    unsafe extern "C" fn read(provider: *mut ResourceProvider, kind: ResourceKind, id: u32) -> u32 {
        assert_eq!((kind.0, id), (0x2a2a_2a2a, 0x891a));
        let receiver = &mut *provider.cast::<Class8900>();
        // The callback observes the new state, not the previous one.
        let state = receiver.state_below_cache[10];
        receiver.cached_6031 = state;
        state ^ 0x8765_4321
    }

    unsafe extern "C" fn replacement(_: *mut ResourceProvider, _: *mut ResourceProvider) -> u32 { panic!("unexpected slot") }
    unsafe extern "C" fn find(_: *mut ResourceProvider, _: ResourceKind, _: u32, _: *mut *mut u8) -> u32 { panic!("unexpected slot") }
    unsafe extern "C" fn write(_: *mut ResourceProvider, _: ResourceKind, _: u32, _: u32, _: u32) -> u32 { panic!("unexpected slot") }

    #[test]
    fn stores_full_word_before_dispatch_even_when_unchanged_and_returns_virtual_result() {
        let vtable = ResourceProviderVTable {
            slots_below: [None; 22], read, slot_5c: None,
            replacement_allowed: replacement, find, write,
        };
        let mut receiver = Class8900 {
            vtable: &vtable, state_below_cache: [0xa5a5_a5a5; 11],
            cached_6031: 0, state_below_store: [0x5555_5555; 209],
            store: core::ptr::null_mut(),
        };
        for state in [0, 1, 0x8000_0000, u32::MAX, u32::MAX] {
            receiver.cached_6031 = !state;
            let result = unsafe { class_8900_state_2c_set_and_read(&mut receiver, state) };
            assert_eq!(result, state ^ 0x8765_4321);
            assert_eq!(receiver.state_below_cache[10], state);
            assert_eq!(receiver.cached_6031, state);
            assert_eq!(receiver.state_below_cache[..10], [0xa5a5_a5a5; 10]);
            assert_eq!(receiver.state_below_store, [0x5555_5555; 209]);
            assert!(receiver.store.is_null());
            assert_eq!(receiver.vtable, &vtable as *const _);
        }
    }
}
