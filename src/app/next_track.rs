//! `handle_next_track` — FUN_08217610 @ 0x08217610, 148 bytes exactly
//! (next prologue: 0x082176a4). Raw-word counts: two incoming BL sites,
//! one plain BL and one BLNE; body: five plain BL, three predicated BL,
//! two virtual BLX. The HandleSelect dispatcher identifies the NextTrack event.
//!
//! Refresh the running inactivity timer, stop an active progress transition,
//! conditionally deactivate the auxiliary layout, then query player slot 11c.
//! A nonzero result resets the timer and dispatches player slot b8 before
//! updating volume. Otherwise dispatch player slot c0 with selector 2; on zero,
//! invoke the rental-warning/navigation helper with action 3. Always return 1.
//!
//! Deviations: no behavioral changes. Unported 0x08217004 remains an exact
//! address-backed call, not a guessed implementation. Host fixtures replace
//! dependencies through a private operation table; target calls reuse ports.


#[cfg(target_arch = "arm")]
extern "C" {
    fn media_player_interface_slot_11c() -> u32;
    fn media_player_slot_b8_then_volume_controller_update(volume: *mut u8) -> u32;
}
#[cfg(not(target_arch = "arm"))]
use super::media_player_interface_slot_11c::media_player_interface_slot_11c;
#[cfg(not(target_arch = "arm"))]
use super::media_player_slot_b8_then_volume_controller_update::media_player_slot_b8_then_volume_controller_update;
use core::ptr::addr_of;

#[repr(C)]
struct Controller {
    vtable: *const usize,
    prefix: [u8; 0xb0 - core::mem::size_of::<*const usize>()],
    volume: u32,
    gap: [u8; 0x0d],
    transition_active: u8,
    tail: [u8; 6],
    auxiliary_layout: u32,
}
const _: () = assert!(core::mem::offset_of!(Controller, volume) == 0xb0);
const _: () = assert!(core::mem::offset_of!(Controller, transition_active) == 0xc1);
const _: () = assert!(core::mem::offset_of!(Controller, auxiliary_layout) == 0xc8);

#[derive(Clone, Copy)]
struct Ops {
    refresh: unsafe extern "C" fn(*mut u8),
    stop: unsafe extern "C" fn(*mut u8),
    deactivate: unsafe extern "C" fn(*mut u8),
    query: unsafe extern "C" fn() -> u32,
    reset: unsafe extern "C" fn(*mut u8),
    update: unsafe extern "C" fn(*mut u8) -> u32,
    get_interface: unsafe extern "C" fn() -> *mut u8,
    navigate: unsafe extern "C" fn(*mut u8, u32),
}

unsafe extern "C" fn navigate(this: *mut u8, action: u32) {
    #[cfg(target_os = "none")]
    {
        let callee: unsafe extern "C" fn(*mut u8, u32) =
            unsafe { core::mem::transmute(0x0821_7004usize) };
        unsafe { callee(this, action) };
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = (this, action);
        panic!("handle_next_track requires firmware callee 0x08217004");
    }
}

const OPS: Ops = Ops {
    refresh: super::timer_reset::timer_reset_4000_if_running,
    stop: super::progress_layout_transition::stop_progress_layout_transition,
    deactivate: super::layout_state::deactivate_layout_state,
    query: media_player_interface_slot_11c,
    reset: super::timer_reset::timer_reset_4000,
    update: media_player_slot_b8_then_volume_controller_update,
    get_interface: super::singletons::media_player_interface_get,
    navigate,
};

/// Handle NextTrack. All controller fields and selected virtual entries must
/// be valid; callbacks may mutate fields, which are reloaded as in retailOS.
/// Virtual tables use native pointer-sized slots on host, four-byte slots on ARM.
/// # Safety
/// `this` must point to a live controller through +0xcb and its referenced objects.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn handle_next_track(this: *mut u8) -> u32 {
    unsafe { run(this.cast(), OPS) }
}

unsafe fn run(this: *mut Controller, ops: Ops) -> u32 {
    unsafe {
        (ops.refresh)(this.cast());
        if addr_of!((*this).transition_active).read_volatile() != 0 {
            (ops.stop)(this.cast());
        }
        if addr_of!((*this).auxiliary_layout).read_volatile() != 0 {
            let table = addr_of!((*this).vtable).read_volatile();
            let check: unsafe extern "C" fn(*mut u8) -> u32 =
                core::mem::transmute(table.add(0x13c / 4).read());
            if check(this.cast()) != 0 {
                (ops.deactivate)(addr_of!((*this).auxiliary_layout).read_volatile() as usize as *mut u8);
            }
        }
        if (ops.query)() != 0 {
            (ops.reset)(this.cast());
            (ops.update)(addr_of!((*this).volume).read_volatile() as usize as *mut u8);
        } else {
            let interface = (ops.get_interface)();
            let table = interface.cast::<*const usize>().read();
            let advance: unsafe extern "C" fn(*mut u8, u32) -> u32 =
                core::mem::transmute(table.add(0xc0 / 4).read());
            if advance(interface, 2) == 0 {
                (ops.navigate)(this.cast(), 3);
            }
        }
        1
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::cell::RefCell;
    std::thread_local! {
        static EVENTS: RefCell<std::vec::Vec<u32>> = const { RefCell::new(std::vec::Vec::new()) };
        static QUERY: RefCell<u32> = const { RefCell::new(0) };
        static ADVANCE: RefCell<u32> = const { RefCell::new(0) };
        static CHECK: RefCell<u32> = const { RefCell::new(0) };
    }
    fn event(value: u32) { EVENTS.with(|e| e.borrow_mut().push(value)); }
    unsafe extern "C" fn refresh(_: *mut u8) { event(1); }
    unsafe extern "C" fn stop(this: *mut u8) {
        event(2);
        unsafe { (*this.cast::<Controller>()).transition_active = 0; }
    }
    unsafe extern "C" fn check(this: *mut u8) -> u32 {
        event(3);
        unsafe { (*this.cast::<Controller>()).auxiliary_layout = 0x4560; }
        CHECK.with(|v| *v.borrow())
    }
    unsafe extern "C" fn deactivate(layout: *mut u8) { event(layout as usize as u32); }
    unsafe extern "C" fn query() -> u32 { event(4); QUERY.with(|v| *v.borrow()) }
    unsafe extern "C" fn reset(this: *mut u8) {
        event(5);
        unsafe { (*this.cast::<Controller>()).volume = 0x7890; }
    }
    unsafe extern "C" fn update(volume: *mut u8) -> u32 { event(volume as usize as u32); 0 }
    unsafe extern "C" fn advance(_: *mut u8, selector: u32) -> u32 {
        assert_eq!(selector, 2);
        event(6);
        ADVANCE.with(|v| *v.borrow())
    }
    unsafe extern "C" fn get_interface() -> *mut u8 {
        // Synchronous dispatch: stack fixture cannot escape this getter, so use
        // a thread-local persistent table/object for the native-pointer ABI.
        std::thread_local! {
            static TABLE: [usize; 49] = {
                let mut table = [0; 49]; table[48] = advance as *const () as usize; table
            };
            static OBJECT: *const usize = TABLE.with(|t| t.as_ptr());
        }
        OBJECT.with(|o| (o as *const *const usize).cast_mut().cast())
    }
    unsafe extern "C" fn navigate(_: *mut u8, action: u32) { assert_eq!(action, 3); event(7); }

    #[test]
    fn next_track_branches_and_callback_field_reloads() {
        let ops = Ops { refresh, stop, deactivate, query, reset, update, get_interface, navigate };
        for active in [0, 0xff] {
            for auxiliary in [0, 0x1230] {
                for allowed in [0, 9] {
                    for state in [0, 7] {
                        for advanced in [0, 8] {
                            EVENTS.with(|e| e.borrow_mut().clear());
                            QUERY.with(|v| *v.borrow_mut() = state);
                            ADVANCE.with(|v| *v.borrow_mut() = advanced);
                            CHECK.with(|v| *v.borrow_mut() = allowed);
                            let mut table = [0usize; 80];
                            table[79] = check as *const () as usize;
                            let mut controller: Controller = unsafe { core::mem::zeroed() };
                            controller.vtable = table.as_ptr();
                            controller.transition_active = active;
                            controller.auxiliary_layout = auxiliary;
                            controller.volume = 0x1110;
                            assert_eq!(unsafe { run(&mut controller, ops) }, 1);
                            let mut expected = std::vec![1];
                            if active != 0 { expected.push(2); }
                            if auxiliary != 0 {
                                expected.push(3);
                                if allowed != 0 { expected.push(0x4560); }
                            }
                            expected.push(4);
                            if state != 0 { expected.extend([5, 0x7890]); }
                            else {
                                expected.push(6);
                                if advanced == 0 { expected.push(7); }
                            }
                            EVENTS.with(|e| assert_eq!(*e.borrow(), expected));
                            assert_eq!(controller.transition_active, 0);
                        }
                    }
                }
            }
        }
    }
}
