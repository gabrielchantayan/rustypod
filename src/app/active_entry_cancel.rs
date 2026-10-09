//! Active entry cancellation — FUN_08104f20 @ 0x08104f20.
//!
//! True extent 68 bytes: 64 instruction bytes plus the 0x089d0554 literal
//! at 0x08104f60; the next real function starts at 0x08104f64. Full-image
//! ARM-word decoding verifies two inbound plain BLs (0x08105160,
//! 0x08105308), zero predicated BLs. The body has two plain BLs, zero
//! predicated BLs, and one BLX through listener vtable slot +0x44.
//! If owner byte +1 is nonzero, invoke that slot on the kind-10 listener,
//! clear the byte, reload controller word +4, and cancel entry 0x81.
//! Always return 1, including the inactive path.
//!
//! Deviations: reuse the existing listener getter and cancellation ports;
//! preserve the unknown virtual method's slot rather than invent its identity.
//! Host tests use local word storage and injected call boundaries. The public
//! host export cannot access retail globals. The getter's unported constructor
//! remains an existing dependency, so this port is not independently hook-ready.

use core::ptr;

#[inline(always)]
unsafe fn cancel_active(
    owner: *mut u32,
    stop_listener: impl FnOnce(),
    cancel: impl FnOnce(u32, u32),
) -> u32 {
    let active = owner.cast::<u8>().add(1);
    if ptr::read_volatile(active) != 0 {
        stop_listener();
        ptr::write_volatile(active, 0);
        let controller = ptr::read_volatile(owner.add(1));
        cancel(controller, 0x81);
    }
    1
}

/// Cancel the active controller entry after notifying its kind-10 listener.
///
/// # Safety
/// Retail owner storage, the kind-10 listener and its vtable slot +0x44,
/// and the controller cancellation dependencies must be valid.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn active_entry_cancel() -> u32 {
    #[cfg(target_os = "none")]
    {
        cancel_active(0x089d_0554 as *mut u32,
            || {
                let listener = super::singletons::event_listener_kind_10_get();
                let vtable = ptr::read(listener.cast::<*const u32>());
                let method: unsafe extern "C" fn(*mut u8) =
                    core::mem::transmute(ptr::read(vtable.add(0x44 / 4)) as usize);
                method(listener);
            },
            |controller, entry| {
                super::registered_entry_cancel::registered_entry_cancel(controller as *mut u8, entry);
            })
    }
    #[cfg(not(target_os = "none"))]
    {
        panic!("active_entry_cancel requires retailOS globals on host")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;

    #[test]
    fn inactive_skips_listener_and_controller_cancellation() {
        let mut owner = [0xaabb00cc, 0];
        let original = owner;
        assert_eq!(unsafe { cancel_active(owner.as_mut_ptr(),
            || panic!("inactive listener"), |_, _| panic!("inactive cancellation")) }, 1);
        assert_eq!(owner, original);
    }

    #[test]
    fn every_nonzero_flag_stops_before_clear_and_reloads_controller() {
        for flag in 1..=255u32 {
            let mut owner = [0xaabb00cc | (flag << 8), 0x12345678];
            let state = owner.as_mut_ptr();
            let stopped = Cell::new(false);
            let cancelled = Cell::new(false);
            assert_eq!(unsafe { cancel_active(state,
                || {
                    assert_eq!(ptr::read(state), 0xaabb00cc | (flag << 8));
                    ptr::write(state.add(1), 0x87654321);
                    // Listener may mutate the flag; the caller must still clear it.
                    ptr::write(state.cast::<u8>().add(1), 0xff);
                    stopped.set(true);
                },
                |controller, entry| {
                    assert!(stopped.get());
                    assert_eq!(ptr::read(state), 0xaabb00cc);
                    assert_eq!((controller, entry), (0x87654321, 0x81));
                    cancelled.set(true);
                }) }, 1);
            assert!(cancelled.get());
            assert_eq!(owner, [0xaabb00cc, 0x87654321]);
            assert_eq!(unsafe { cancel_active(state,
                || panic!("repeat stop"), |_, _| panic!("repeat cancel")) }, 1);
        }
    }
}
