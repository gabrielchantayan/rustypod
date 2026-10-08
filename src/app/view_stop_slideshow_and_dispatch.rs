//! Stop a view's slideshow and dispatch — `FUN_0810cb34` @ `0x0810cb34`.
//! True size: 44 bytes, through 0x0810cb5f; next function starts at 0x0810cb60.
//! Raw A32: one outbound plain BL, zero predicated BL, one indirect BLX;
//! two inbound plain BL sites (0x08156454, 0x081997d4), zero predicated BL.
//!
//! Set the associated state at view+0x13c to interval zero using the existing
//! slideshow_interval_set port. Reload the view's vtable after notification,
//! call slot +0x158 with the view, ignore its result, and return one.
//! The virtual callee has no established semantic identity.
//!
//! Deliberate deviation: host vtables use native-width pointers at the same
//! word index; all other object fields retain target-width u32 layout.

use crate::app::slideshow_interval_set::slideshow_interval_set;

type ViewDispatch = unsafe extern "C" fn(*mut u8) -> u32;

/// # Safety
/// `view` must be aligned and readable through +0x13f. Its associated state
/// must satisfy slideshow_interval_set's contract. Its first pointer must
/// reference a vtable with a callable slot at target word index 0x158/4.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn view_stop_slideshow_and_dispatch(view: *mut u8) -> u32 {
    let state = view.add(0x13c).cast::<u32>().read() as usize as *mut u8;
    slideshow_interval_set(state, 0);
    let vtable = view.cast::<*const usize>().read();
    let dispatch: ViewDispatch = core::mem::transmute(vtable.add(0x158 / 4).read());
    dispatch(view);
    1
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::drivers::timer::{TimerOps, TIMER_OPS, TIMER_STATE_RUNNING, TIMER_STATE_STOPPED};
    use crate::app::slideshow_delay_set::{SLIDESHOW_MESSAGE_DISPATCH, SlideshowMessageDispatch};
    use crate::testing::{hints, try_map_u32_slab, TIMER_OPS_TEST_LOCK};
    use core::ptr::{addr_of, addr_of_mut};

    struct Restore(TimerOps, SlideshowMessageDispatch);
    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe {
                addr_of_mut!(TIMER_OPS).write_volatile(self.0);
                addr_of_mut!(SLIDESHOW_MESSAGE_DISPATCH).write_volatile(self.1);
            }
        }
    }
    unsafe extern "C" fn trace(_: *mut u8) {}
    unsafe extern "C" fn notify(state: *mut u8, _: u32, _: u32) {
        // Simulate notification replacing the view's virtual method table.
        let view = state.add(0x900).cast::<*mut u8>().read();
        let replacement = state.add(0x908).cast::<*const usize>().read();
        view.cast::<*const usize>().write(replacement);
    }
    unsafe extern "C" fn stale(view: *mut u8) -> u32 {
        view.add(0x100).cast::<u32>().write(0xbad);
        0
    }
    unsafe extern "C" fn updated(view: *mut u8) -> u32 {
        let state = view.add(0x13c).cast::<u32>().read() as usize as *mut u8;
        let timer = state.add(0x8dc).cast::<u32>().read() as usize as *mut u8;
        view.add(0x100).cast::<u32>().write(timer.add(0x20).cast::<u32>().read());
        view.add(0x104).cast::<i32>().write(state.add(0x8cc).cast::<i32>().read());
        view.add(0x108).cast::<u32>().write(state.add(0x8c8).cast::<u32>().read());
        0xffff_ffff
    }

    #[test]
    fn stops_running_or_stopped_timer_before_reloaded_virtual_dispatch() {
        let _lock = TIMER_OPS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _message_lock = crate::app::slideshow_delay_set::TEST_LOCK
            .lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let _restore = Restore(addr_of!(TIMER_OPS).read_volatile(),
                addr_of!(SLIDESHOW_MESSAGE_DISPATCH).read_volatile());
            let mut ops = _restore.0;
            ops.trace_assert = trace;
            addr_of_mut!(TIMER_OPS).write_volatile(ops);
            addr_of_mut!(SLIDESHOW_MESSAGE_DISPATCH).write_volatile(notify);
            let slab = try_map_u32_slab(hints::VIEW_STOP_SLIDESHOW_AND_DISPATCH, 0x3000)
                .expect("view slideshow target-width fixture");
            let view = slab;
            let state = slab.add(0x1000);
            let timer = slab.add(0x2000);
            let mut old_table = [0usize; 0x158 / 4 + 1];
            let mut new_table = old_table;
            old_table[0x158 / 4] = stale as *const () as usize;
            new_table[0x158 / 4] = updated as *const () as usize;
            for initial in [TIMER_STATE_RUNNING, TIMER_STATE_STOPPED] {
                slab.write_bytes(0, 0x3000);
                view.cast::<*const usize>().write(old_table.as_ptr());
                view.add(0x13c).cast::<u32>().write(state as usize as u32);
                state.add(0x8dc).cast::<u32>().write(timer as usize as u32);
                state.add(0x8cc).cast::<i32>().write(1500);
                state.add(0x8c8).cast::<u32>().write(2);
                state.add(0x900).cast::<*mut u8>().write(view);
                state.add(0x908).cast::<*const usize>().write(new_table.as_ptr());
                timer.add(4).cast::<u32>().write(77);
                timer.add(0x20).cast::<u32>().write(initial);
                assert_eq!(view_stop_slideshow_and_dispatch(view), 1);
                assert_eq!(view.add(0x100).cast::<u32>().read(), TIMER_STATE_STOPPED);
                assert_eq!(view.add(0x104).cast::<i32>().read(), 0);
                assert_eq!(view.add(0x108).cast::<u32>().read(), 0);
                assert_eq!(timer.add(4).cast::<u32>().read(), 77);
            }
        }
    }
}
