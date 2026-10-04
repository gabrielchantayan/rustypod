//! TV-out resource refresh — FUN_081ec45c @ 0x081ec45c.
//! True extent 52 bytes to the next function at 0x081ec490: 44 code
//! bytes and two literals. Raw A32 scan finds two incoming plain BLs
//! (0x081e94d4, 0x08212c94), zero predicated BLs, and one outgoing
//! plain BL to resource_chain_write @ 0x08272230.
//!
//! Read the provider at receiver +0x378 and write a stack word containing
//! 0x60bf by address to ("prID", 0x60ef), flags 4. Ignore the result.
//! Callers handle ToggleSetting_TVOut and HandleTVOutChanged. The receiver
//! layout is shared with the adjacent TV-signal refresh port.
//!
//! Deviations: repr(C) widens host pointers while preserving ARM offsets;
//! an inline helper accepts low-address scratch for host tests. Production
//! uses a stack word as the original does. No ARM behavioral deviations,
//! null guards, or additional receiver dispatches.

use super::resource_chain::{resource_chain_write, ResourceKind};
use super::tv_signal_resource_refresh::TvSignalReceiver;

#[inline(always)]
unsafe fn refresh(receiver: *mut TvSignalReceiver, scratch: *mut u32) {
    scratch.write(0x60bf);
    resource_chain_write((*receiver).provider, ResourceKind(0x7072_4944),
        0x60ef, scratch as usize as u32, 4);
}

/// # Safety
/// Receiver and its non-null provider chain and virtual entries must be
/// valid. Providers must consume the stack word synchronously. The
/// address-valued u32 ABI requires a 32-bit-addressable stack.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn tv_out_resource_refresh(receiver: *mut TvSignalReceiver) {
    let mut scratch = 0;
    refresh(receiver, &mut scratch);
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;
    use super::super::resource_chain::{ResourceProvider, ResourceProviderVTable};

    struct State { accept: u32, writes: usize, reads: usize, readback: u32 }

    unsafe extern "C" fn write(provider: *mut ResourceProvider, kind: ResourceKind,
        id: u32, value: u32, flags: u32) -> u32 {
        let state = &mut *(*provider).state_below_next[0].cast::<State>();
        assert_eq!((kind.0, id, flags), (0x7072_4944, 0x60ef, 4));
        assert_eq!(*(value as usize as *const u32), 0x60bf);
        state.writes += 1;
        state.accept
    }
    unsafe extern "C" fn read(provider: *mut ResourceProvider, kind: ResourceKind, id: u32) -> u32 {
        assert_eq!((kind.0, id), (0x7072_4944, 0x60ef));
        let state = &mut *(*provider).state_below_next[0].cast::<State>();
        state.reads += 1;
        state.readback
    }
    unsafe extern "C" fn find(_: *mut ResourceProvider, _: ResourceKind, _: u32,
        _: *mut *mut u8) -> u32 { panic!("unexpected lookup") }
    unsafe extern "C" fn replacement(_: *mut ResourceProvider, _: *mut ResourceProvider) -> u32 {
        panic!("unexpected replacement")
    }

    #[test]
    fn declines_fall_through_and_any_nonzero_accept_stops_without_receiver_dispatch() {
        let scratch = crate::testing::try_map_u32_slab(
            crate::testing::hints::TV_OUT_RESOURCE_REFRESH, 4096,
        ).expect("low-address scratch").cast::<u32>();
        let vtable = ResourceProviderVTable {
            slots_below: [None; 22], read, slot_5c: None,
            replacement_allowed: replacement, find, write,
        };
        for (first, second, readback) in [(0, 0, 0), (0, 1, 0),
            (0, 0x8000_0000, u32::MAX), (1, 1, 0), (u32::MAX, 1, u32::MAX)] {
            let mut states = [State { accept: first, writes: 0, reads: 0, readback },
                State { accept: second, writes: 0, reads: 0, readback }];
            let mut tail = ResourceProvider { vtable: &vtable,
                state_below_next: [ptr::null_mut(); 4], next: ptr::null_mut() };
            let mut head = ResourceProvider { vtable: &vtable,
                state_below_next: [ptr::null_mut(); 4], next: &mut tail };
            head.state_below_next[0] = ptr::addr_of_mut!(states[0]).cast();
            tail.state_below_next[0] = ptr::addr_of_mut!(states[1]).cast();
            let mut receiver = TvSignalReceiver { vtable: ptr::null(),
                unresolved: [u32::MAX; 221], provider: &mut head };
            unsafe { scratch.write(0xdead_beef); refresh(&mut receiver, scratch); }
            assert_eq!((states[0].writes, states[0].reads), (1, usize::from(first != 0)));
            assert_eq!((states[1].writes, states[1].reads),
                (usize::from(first == 0), usize::from(first == 0 && second != 0)));
            assert_eq!(receiver.unresolved, [u32::MAX; 221]);
            assert!(receiver.vtable.is_null());
            assert_eq!(receiver.provider, &mut head as *mut ResourceProvider);
        }
    }
}
