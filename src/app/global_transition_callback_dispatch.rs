use crate::drivers::pwrcon::{pwrcon_acquire_clock_2, pwrcon_restore_clock_2};
use crate::kernel::kobj::{mailbox_slot_post, Mailbox};
use crate::kernel::sync_mutex::{mutex_lock, mutex_unlock, Mutex};

const TRANSITION_STATE_ADDRESS: usize = 0x089c_a458;
const STATE_ACTIVE: usize = 0;
const STATE_CALLBACK: usize = 1;
const STATE_MUTEX: usize = 2;
const STATE_NOTIFICATION_SLOT: usize = 3;

type TransitionCallback = unsafe extern "C" fn(u32, u32);

#[cfg(not(target_os = "none"))]
static mut HOST_TRANSITION_STATE: *mut u32 = core::ptr::null_mut();


#[cfg(test)]
static TRANSITION_STATE_TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
#[inline(always)]
unsafe fn transition_state() -> *mut u32 {
    #[cfg(target_os = "none")]
    {
        TRANSITION_STATE_ADDRESS as *mut u32
    }
    #[cfg(not(target_os = "none"))]
    {
        HOST_TRANSITION_STATE
    }
}

/// global_transition_callback_dispatch — original: `FUN_0836b240` @
/// `0x0836b240` (212 bytes; `0x0836b314` is its literal pool and the next
/// real function begins at `0x0836b318`).
///
/// Raw ARM decoding establishes one plain inbound `bl` and two predicated
/// inbound `bl` sites. It locks the global transition state, acquires clock 2,
/// and invokes the callback object's vtable slot +8 while transitioning its
/// active flag for event kinds 1/4 (activate) and 2/3 (deactivate). It then
/// restores the clock state, unlocks, and posts the notification mailbox for
/// kinds 1/4. The two early status returns (11 for no callback object; 17 for
/// no mutex) precede every side effect.
///
/// Deliberate deviations: none. The target representation uses four adjacent
/// target-width words rather than host pointer-sized fields, preserving the
/// retailOS offsets on both targets.
///
/// # Safety
///
/// The global state at `0x089c_a458` must contain the retailOS callback,
/// mutex, and mailbox-slot objects described above.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn global_transition_callback_dispatch(kind: u32, argument: u32) -> u32 {
    let state = transition_state();
    if state.add(STATE_CALLBACK).read() == 0 {
        return 11;
    }
    if state.add(STATE_MUTEX).read() == 0 {
        return 17;
    }

    mutex_lock(state.add(STATE_MUTEX).cast::<Mutex>());
    let was_enabled = pwrcon_acquire_clock_2();

    if kind == 1 || kind == 4 {
        if state.add(STATE_ACTIVE).read() == 0 {
            state.add(STATE_ACTIVE).write(1);
            invoke_transition_callback(state, kind, argument);
        }
    } else if (kind == 2 || kind == 3) && state.add(STATE_ACTIVE).read() == 1 {
        invoke_transition_callback(state, kind, argument);
        state.add(STATE_ACTIVE).write(0);
    }

    pwrcon_restore_clock_2(was_enabled);
    mutex_unlock(state.add(STATE_MUTEX).cast::<Mutex>());
    if kind == 1 || kind == 4 {
        mailbox_slot_post(state.add(STATE_NOTIFICATION_SLOT).cast::<*mut Mailbox>());
    }
    0
}

#[inline(always)]
unsafe fn invoke_transition_callback(state: *mut u32, kind: u32, argument: u32) {
    let callback_object = state.add(STATE_CALLBACK).read() as usize as *const u32;
    let vtable = callback_object.read() as usize as *const u32;
    let callback: TransitionCallback = core::mem::transmute(vtable.add(2).read() as usize);
    callback(kind, argument);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, try_map_u32_slab};

    #[test]
    fn absent_callback_returns_11_before_any_side_effect() {
        let _guard = TRANSITION_STATE_TEST_LOCK.lock();
        let Some(state) = try_map_u32_slab(hints::GLOBAL_TRANSITION_CALLBACK_DISPATCH, 16) else {
            return;
        };
        unsafe {
            let state = state.cast::<u32>();
            state.write(0);
            state.add(1).write(0);
            state.add(2).write(0xffff_ffff);
            HOST_TRANSITION_STATE = state;
            assert_eq!(global_transition_callback_dispatch(1, 0x1234), 11);
            assert_eq!(state.read(), 0);
        }
    }

    #[test]
    fn absent_mutex_returns_17_before_any_side_effect() {
        let _guard = TRANSITION_STATE_TEST_LOCK.lock();
        let Some(state) = try_map_u32_slab(hints::GLOBAL_TRANSITION_CALLBACK_DISPATCH_NO_MUTEX, 16) else {
            return;
        };
        unsafe {
            let state = state.cast::<u32>();
            state.write(0);
            state.add(1).write(1);
            state.add(2).write(0);
            HOST_TRANSITION_STATE = state;
            assert_eq!(global_transition_callback_dispatch(4, 0x5678), 17);
            assert_eq!(state.read(), 0);
        }
    }
}
