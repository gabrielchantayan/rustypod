//! TV-signal resource refresh — FUN_081ed5e4 @ 0x081ed5e4.
//! True extent 88 bytes, ending at next function 0x081ed63c: 72 code
//! bytes and four literal words. Raw A32 scan: two inbound plain BLs
//! (0x081e9500, 0x08212cbc), zero predicated BLs; one outbound BL to
//! resource_chain_write and one BLX through receiver vtable +0x58.
//!
//! Write the word 0x60bf by address to ("prID", 0x60f0), flags 4, on
//! the provider at receiver +0x378. Then reload the receiver vtable and
//! dispatch ("Str ", 0x892e), ignoring both results. Callers handle
//! ToggleSetting_TVSignal and HandleTVSignalChanged; the concrete virtual
//! method identity is unresolved, so its name describes the dispatch only.
//!
//! Deviations: repr(C) widens pointers on hosts, retaining target offsets.
//! The inline body accepts scratch storage so host tests can place the
//! address-valued u32 argument below 4 GiB; production uses a stack word.
//! No behavioral deviations on ARM. No null guards are added.
//! Verification: 14069 host tests pass; ARM release builds. An isolated
//! executable runs this export on a low-address pthread stack and observes
//! the write followed by dispatch even when the provider declines. The
//! normal host example cannot build because of unrelated host cfg errors.
//! match.py reports a structural diff: the same +0x378 provider load,
//! stack-address argument, direct BL and reloaded +0x58 BLX; LLVM uses
//! mov/orr for numeric literals and adds frame-pointer setup. The archive
//! disassembly leaves the direct BL relocation unresolved. No device run.

use core::ptr;
use super::resource_chain::{resource_chain_write, ResourceKind, ResourceProvider};

type ResourceDispatch = unsafe extern "C" fn(*mut TvSignalReceiver, ResourceKind, u32) -> u32;

#[repr(C)]
pub struct TvSignalVtable {
    pub unresolved: [usize; 22],
    pub dispatch_resource: ResourceDispatch,
}

#[repr(C)]
pub struct TvSignalReceiver {
    pub vtable: *const TvSignalVtable,
    pub unresolved: [u32; 221],
    pub provider: *mut ResourceProvider,
}

#[cfg(target_pointer_width = "32")]
const _: () = {
    assert!(core::mem::offset_of!(TvSignalReceiver, provider) == 0x378);
    assert!(core::mem::offset_of!(TvSignalVtable, dispatch_resource) == 0x58);
};

#[inline(always)]
unsafe fn refresh(receiver: *mut TvSignalReceiver, scratch: *mut u32) {
    scratch.write(0x60bf);
    resource_chain_write((*receiver).provider, ResourceKind(0x7072_4944),
        0x60f0, scratch as usize as u32, 4);
    let vtable = ptr::read_volatile(ptr::addr_of!((*receiver).vtable));
    let dispatch = ptr::read_volatile(ptr::addr_of!((*vtable).dispatch_resource));
    dispatch(receiver, ResourceKind::STRING, 0x892e);
}

/// # Safety
/// Receiver, provider chain, and virtual entries must be valid. Providers
/// must consume the scratch word synchronously, not retain its address.
/// The address-valued provider ABI requires a 32-bit-addressable stack.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn tv_signal_resource_refresh(receiver: *mut TvSignalReceiver) {
    let mut scratch = 0;
    refresh(receiver, &mut scratch);
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::resource_chain::ResourceProviderVTable;

    #[repr(C)]
    struct Fixture {
        receiver: TvSignalReceiver,
        changed: *const TvSignalVtable,
        writes: usize,
        reads: usize,
        dispatched: u32,
        accept: u32,
    }

    unsafe extern "C" fn write(provider: *mut ResourceProvider, kind: ResourceKind,
        id: u32, value: u32, flags: u32) -> u32 {
        let f = &mut *(*provider).state_below_next[0].cast::<Fixture>();
        assert_eq!((kind.0, id, flags), (0x7072_4944, 0x60f0, 4));
        assert_eq!(*(value as usize as *const u32), 0x60bf);
        f.writes += 1;
        f.receiver.vtable = f.changed;
        f.accept
    }
    unsafe extern "C" fn read(provider: *mut ResourceProvider, _: ResourceKind, _: u32) -> u32 {
        let f = &mut *(*provider).state_below_next[0].cast::<Fixture>();
        f.reads += 1;
        0
    }
    unsafe extern "C" fn find(_: *mut ResourceProvider, _: ResourceKind, _: u32,
        _: *mut *mut u8) -> u32 { panic!("unexpected lookup") }
    unsafe extern "C" fn replacement(_: *mut ResourceProvider, _: *mut ResourceProvider) -> u32 {
        panic!("unexpected replacement")
    }
    unsafe extern "C" fn old(_: *mut TvSignalReceiver, _: ResourceKind, _: u32) -> u32 {
        panic!("stale vtable")
    }
    unsafe extern "C" fn changed(receiver: *mut TvSignalReceiver, kind: ResourceKind, id: u32) -> u32 {
        let f = &mut *receiver.cast::<Fixture>();
        assert_eq!((kind, id), (ResourceKind::STRING, 0x892e));
        assert_eq!(f.writes, 1);
        f.dispatched += 1;
        u32::MAX
    }

    #[test]
    fn dispatch_survives_decline_and_zero_readback_and_reloads_vtable() {
        let scratch = crate::testing::try_map_u32_slab(
            crate::testing::hints::TV_SIGNAL_RESOURCE_REFRESH, 4096,
        ).expect("low-address scratch").cast::<u32>();
        let initial = TvSignalVtable { unresolved: [0; 22], dispatch_resource: old };
        let updated = TvSignalVtable { unresolved: [0; 22], dispatch_resource: changed };
        let provider_vtable = ResourceProviderVTable {
            slots_below: [None; 22], read, slot_5c: None,
            replacement_allowed: replacement, find, write,
        };
        for accept in [0, 0x8000_0000] {
            let mut f = Fixture {
                receiver: TvSignalReceiver { vtable: &initial, unresolved: [0; 221], provider: ptr::null_mut() },
                changed: &updated, writes: 0, reads: 0, dispatched: 0, accept,
            };
            let mut provider = ResourceProvider {
                vtable: &provider_vtable, state_below_next: [ptr::null_mut(); 4], next: ptr::null_mut(),
            };
            provider.state_below_next[0] = ptr::addr_of_mut!(f).cast();
            f.receiver.provider = &mut provider;
            unsafe { refresh(&mut f.receiver, scratch); }
            assert_eq!((f.writes, f.reads, f.dispatched), (1, usize::from(accept != 0), 1));
        }
    }
}
