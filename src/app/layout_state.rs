//! Layout-state activation/deactivation helpers for the unnamed embedded-timer
//! object selected by the media-layout controller.
//!
//! `deactivate_layout_state` — original: `FUN_081a221c` @ **0x081a221c**
//! (**56 bytes exactly**, `0x081a221c..0x081a2254`). The sibling method opens
//! with `push {r4, lr}` at `0x081a2254`; there is no literal pool.
//!
//! Decoding every ARM B/BL immediate in `osos.dec` finds **10 direct `bl`
//! callers**: one unconditional `bl` at `0x0821c668` and nine caller-gated
//! `blne` sites (`0x08216818`, `0x08216878`, `0x08217650`, `0x082176d4`,
//! `0x0821cfd4`, `0x0821db50`, `0x0821deec`, `0x0821fa28`, `0x0821fce0`). A
//! further `bne` tail transfer at `0x0821f494` reaches the entry. No aligned
//! data word in the image holds this address, so it is not virtually
//! dispatched. The caller-side predicates gate the action; the body itself
//! has no flag or NULL guard.
//!
//! ## Algorithm
//!
//! Lock `this + 0x74`, call `FUN_081a2158(this, 0)` to propagate the disabled
//! state, stop the embedded timer at `this + 0x30`, clear `this + 0x70`, then
//! unlock. The stores and both calls are unconditional.
//!
//! ## Deliberate deviations
//!
//! `mutex_lock`, `timer_stop`, and `mutex_unlock` are already ported and are
//! called directly on target. `FUN_081a2158` is not in `names.yaml`, so it is
//! represented by a volatile dispatch seam: target builds call its verified
//! firmware address and host tests install a recorder. Host builds make the
//! outer mutex calls no-ops because this is a 32-bit embedded mutex at offset
//! `0x74`, which is necessarily misaligned for Rust's 64-bit-host `Mutex`;
//! this does not affect target code.

use core::ptr;

use crate::drivers::timer::timer_stop;
use crate::app::singletons::{singleton_class_8900, volume_controller_get};
use crate::app::volume_controller_byte_at_90::volume_controller_byte_at_90;
#[cfg(target_os = "none")]
use crate::kernel::sync_mutex::{mutex_lock, mutex_unlock, Mutex};

const PRIMARY_PROFILE_OFFSET: usize = 0x14;
const ALTERNATE_PROFILE_OFFSET: usize = 0x18;
const TIMER_OFFSET: usize = 0x30;
const TRANSITION_SENTINEL_OFFSET: usize = 0x5c;
const PREPARED_OFFSET: usize = 0x68;
const ACTIVE_OFFSET: usize = 0x70;
const MUTEX_OFFSET: usize = 0x74;

/// Unported direct callee `FUN_081a2158`.
pub const LAYOUT_STATE_SET_ENABLED_ADDRESS: usize = 0x081a_2158;

/// Dispatch slot for the unported layout-state propagation method.
#[derive(Clone, Copy)]
pub struct LayoutStateOps {
    /// Propagates `enabled` through this object's dependent layout objects.
    pub set_enabled: unsafe extern "C" fn(this: *mut u8, enabled: u32),
    /// Returns the class-0x8900 selector byte queried by `FUN_081eda10`.
    pub class_8900_path_selector: unsafe extern "C" fn(class_8900: *mut u8) -> u32,
    /// Calls `FUN_0812af10` for a selected profile and returns its r0 result.
    pub reset_selected_profile: unsafe extern "C" fn(profile: *mut u8) -> *mut u8,
    /// Calls the `FUN_081a1848` branch with the profile-reset return value.
    pub run_primary_layout_path: unsafe extern "C" fn(state: *mut u8),
    /// Calls the `FUN_081a1a90` branch with the layout-state object.
    pub run_fallback_layout_path: unsafe extern "C" fn(this: *mut u8),
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_set_enabled(this: *mut u8, enabled: u32) {
    let f: unsafe extern "C" fn(*mut u8, u32) =
        unsafe { core::mem::transmute(LAYOUT_STATE_SET_ENABLED_ADDRESS) };
    unsafe { f(this, enabled) };
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_class_8900_path_selector(class_8900: *mut u8) -> u32 {
    let f: unsafe extern "C" fn(*mut u8) -> u32 = unsafe { core::mem::transmute(0x081e_da10usize) };
    unsafe { f(class_8900) }
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_reset_selected_profile(profile: *mut u8) -> *mut u8 {
    let f: unsafe extern "C" fn(*mut u8) -> *mut u8 = unsafe { core::mem::transmute(0x0812_af10usize) };
    unsafe { f(profile) }
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_run_primary_layout_path(state: *mut u8) {
    let f: unsafe extern "C" fn(*mut u8) = unsafe { core::mem::transmute(0x081a_1848usize) };
    unsafe { f(state) };
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_run_fallback_layout_path(this: *mut u8) {
    let f: unsafe extern "C" fn(*mut u8) = unsafe { core::mem::transmute(0x081a_1a90usize) };
    unsafe { f(this) };
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_set_enabled(_this: *mut u8, _enabled: u32) {
    panic!("layout_state requires firmware callee 0x081a2158")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_class_8900_path_selector(_class_8900: *mut u8) -> u32 {
    panic!("activate_layout_state requires firmware callee 0x081eda10")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_reset_selected_profile(_profile: *mut u8) -> *mut u8 {
    panic!("activate_layout_state requires firmware callee 0x0812af10")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_run_primary_layout_path(_state: *mut u8) {
    panic!("activate_layout_state requires firmware callee 0x081a1848")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_run_fallback_layout_path(_this: *mut u8) {
    panic!("activate_layout_state requires firmware callee 0x081a1a90")
}

#[cfg(target_os = "none")]
pub static mut LAYOUT_STATE_OPS: LayoutStateOps = LayoutStateOps {
    set_enabled: firmware_set_enabled,
    class_8900_path_selector: firmware_class_8900_path_selector,
    reset_selected_profile: firmware_reset_selected_profile,
    run_primary_layout_path: firmware_run_primary_layout_path,
    run_fallback_layout_path: firmware_run_fallback_layout_path,
};

#[cfg(not(target_os = "none"))]
pub static mut LAYOUT_STATE_OPS: LayoutStateOps = LayoutStateOps {
    set_enabled: missing_set_enabled,
    class_8900_path_selector: missing_class_8900_path_selector,
    reset_selected_profile: missing_reset_selected_profile,
    run_primary_layout_path: missing_run_primary_layout_path,
    run_fallback_layout_path: missing_run_fallback_layout_path,
};

#[inline(always)]
fn layout_state_ops() -> LayoutStateOps {
    unsafe { ptr::addr_of!(LAYOUT_STATE_OPS).read_volatile() }
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn lock_layout_mutex(this: *mut u8) {
    unsafe { mutex_lock(this.add(MUTEX_OFFSET).cast::<Mutex>()) };
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn lock_layout_mutex(_this: *mut u8) {}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn unlock_layout_mutex(this: *mut u8) {
    unsafe { mutex_unlock(this.add(MUTEX_OFFSET).cast::<Mutex>()) };
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn unlock_layout_mutex(_this: *mut u8) {}

#[inline(always)]
unsafe fn profile_at(this: *const u8, offset: usize) -> *mut u8 {
    let profile = unsafe { this.add(offset).cast::<u32>().read_volatile() };
    profile as usize as *mut u8
}

/// `deactivate_layout_state` — original: `FUN_081a221c` @ **0x081a221c**
/// (56 bytes; 10 direct `bl` callers: 1 `bl` and 9 `blne`, plus one `bne`
/// tail transfer).
///
/// Disables this layout state under its embedded mutex: propagates literal
/// zero, stops the embedded timer, then clears the active byte. It has no
/// null or active-state guard, exactly as retailOS.
///
/// # Safety
///
/// `this` must point to a writable, target-layout object through its mutex at
/// `+0x74`; its embedded timer at `+0x30` must be initialized. The installed
/// `LAYOUT_STATE_OPS.set_enabled` slot must be callable.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn deactivate_layout_state(this: *mut u8) {
    unsafe { lock_layout_mutex(this) };
    let set_enabled = layout_state_ops().set_enabled;
    unsafe { set_enabled(this, 0) };
    unsafe { timer_stop(this.add(TIMER_OFFSET)) };
    unsafe { this.add(ACTIVE_OFFSET).write_volatile(0) };
    unsafe { unlock_layout_mutex(this) };
}

/// activate_layout_state — original: `FUN_081a2254` @ **0x081a2254**
/// (132 bytes exactly, `0x081a2254..0x081a22d8`; **9 direct `bl` callers:**
/// 3 plain `bl` and 6 caller-gated `blne`; no direct `b` transfer or aligned
/// data-word reference).
///
/// Stops the embedded timer, propagates enabled, writes transition sentinel
/// `-1`, clears the prepared byte, and sets the active byte. It then initializes
/// class-0x8900, branches only when its selector equals one, chooses the
/// primary or alternate profile from `+0x14`/`+0x18` according to the raw
/// volume-controller byte at `+0x90`, and passes the selected profile's reset
/// result into the primary path. Every other selector takes the fallback path.
/// The mutex is tail-unlocked after either branch; there is no NULL or
/// active-state guard.
///
/// Deliberate deviations: existing mutex, timer, singleton, and
/// volume-controller ports are called directly. The four unported direct
/// callees retain their verified firmware addresses behind volatile
/// `LAYOUT_STATE_OPS` slots; their identities are not inferred. Host mutex
/// calls remain no-ops because the target's 32-bit mutex is misaligned for
/// the host `Mutex` representation.
///
/// # Safety
///
/// `this` must point to a writable target-layout object through `+0x74`.
/// Target pointer words at `+0x14` and `+0x18` must be valid for the installed
/// profile-reset slot, and every installed `LAYOUT_STATE_OPS` slot must be
/// callable.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn activate_layout_state(this: *mut u8) {
    unsafe { lock_layout_mutex(this) };
    unsafe { timer_stop(this.add(TIMER_OFFSET)) };
    let ops = layout_state_ops();
    unsafe { (ops.set_enabled)(this, 1) };
    unsafe { this.add(TRANSITION_SENTINEL_OFFSET).cast::<u32>().write_volatile(u32::MAX) };
    unsafe { this.add(PREPARED_OFFSET).write_volatile(0) };
    unsafe { this.add(ACTIVE_OFFSET).write_volatile(1) };

    let class_8900 = unsafe { singleton_class_8900() };
    if unsafe { (ops.class_8900_path_selector)(class_8900) } == 1 {
        let volume_controller = unsafe { volume_controller_get() };
        let profile_offset = if unsafe { volume_controller_byte_at_90(volume_controller) } == 0 {
            PRIMARY_PROFILE_OFFSET
        } else {
            ALTERNATE_PROFILE_OFFSET
        };
        let state = unsafe { (ops.reset_selected_profile)(profile_at(this, profile_offset)) };
        unsafe { (ops.run_primary_layout_path)(state) };
    } else {
        unsafe { (ops.run_fallback_layout_path)(this) };
    }

    unsafe { unlock_layout_mutex(this) };
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::app::singletons::{
        CLASS_8900_INSTANCE, SINGLETON_LOCK, VOLUME_CONTROLLER_INSTANCE,
    };
    use crate::drivers::timer::{TimerOps, TIMER_OPS, TIMER_STATE_RUNNING, TIMER_STATE_STOPPED};
    use crate::testing::{
        hints, note_missing_u32_fixture, try_map_u32_slab, TIMER_OPS_TEST_LOCK,
    };
    use std::sync::{LazyLock, Mutex, MutexGuard};
    use std::vec::Vec;

    const OBJECT_BYTES: usize = 0x84;
    const TIMER_STATE_OFFSET: usize = 0x20;

    #[repr(align(8))]
    struct LayoutStateObject([u8; OBJECT_BYTES]);

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Call {
        TimerStop(usize),
        SetEnabled(usize, u32),
        Class8900PathSelector(usize),
        ResetSelectedProfile(usize),
        RunPrimaryLayoutPath(usize),
        RunFallbackLayoutPath(usize),
    }

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static CALLS: Mutex<Vec<Call>> = Mutex::new(Vec::new());
    static ACTIVATION_FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::LAYOUT_STATE_ACTIVATE, 0x1000).map(|pointer| pointer as usize)
    });
    static mut CLASS_8900_PATH_SELECTOR: u32 = 0;
    static mut RESET_SELECTED_PROFILE_RESULT: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn recording_trace(timer: *mut u8) {
        CALLS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(Call::TimerStop(timer as usize));
    }

    unsafe extern "C" fn recording_set_enabled(this: *mut u8, enabled: u32) {
        CALLS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(Call::SetEnabled(this as usize, enabled));
    }

    unsafe extern "C" fn recording_class_8900_path_selector(class_8900: *mut u8) -> u32 {
        CALLS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(Call::Class8900PathSelector(class_8900 as usize));
        unsafe { CLASS_8900_PATH_SELECTOR }
    }

    unsafe extern "C" fn recording_reset_selected_profile(profile: *mut u8) -> *mut u8 {
        CALLS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(Call::ResetSelectedProfile(profile as usize));
        unsafe { RESET_SELECTED_PROFILE_RESULT }
    }

    unsafe extern "C" fn recording_run_primary_layout_path(state: *mut u8) {
        CALLS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(Call::RunPrimaryLayoutPath(state as usize));
    }

    unsafe extern "C" fn recording_run_fallback_layout_path(this: *mut u8) {
        CALLS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(Call::RunFallbackLayoutPath(this as usize));
    }

    struct TimerOpsRestore(TimerOps);

    impl Drop for TimerOpsRestore {
        fn drop(&mut self) {
            unsafe { ptr::addr_of_mut!(TIMER_OPS).write_volatile(self.0) };
        }
    }

    struct LayoutStateOpsRestore(LayoutStateOps);

    impl Drop for LayoutStateOpsRestore {
        fn drop(&mut self) {
            unsafe { ptr::addr_of_mut!(LAYOUT_STATE_OPS).write_volatile(self.0) };
        }
    }

    struct SingletonCachesRestore {
        class_8900: *mut u8,
        volume_controller: *mut u8,
    }

    impl Drop for SingletonCachesRestore {
        fn drop(&mut self) {
            unsafe {
                ptr::addr_of_mut!(CLASS_8900_INSTANCE).write_volatile(self.class_8900);
                ptr::addr_of_mut!(VOLUME_CONTROLLER_INSTANCE).write_volatile(self.volume_controller);
            }
        }
    }

    unsafe fn install_recorders() -> (TimerOpsRestore, LayoutStateOpsRestore) {
        let saved_timer_ops = unsafe { ptr::addr_of!(TIMER_OPS).read_volatile() };
        let mut recorded_timer_ops = saved_timer_ops;
        recorded_timer_ops.trace_assert = recording_trace;
        unsafe { ptr::addr_of_mut!(TIMER_OPS).write_volatile(recorded_timer_ops) };

        let saved_layout_ops = unsafe { ptr::addr_of!(LAYOUT_STATE_OPS).read_volatile() };
        unsafe {
            let mut recorded_layout_ops = saved_layout_ops;
            recorded_layout_ops.set_enabled = recording_set_enabled;
            recorded_layout_ops.class_8900_path_selector = recording_class_8900_path_selector;
            recorded_layout_ops.reset_selected_profile = recording_reset_selected_profile;
            recorded_layout_ops.run_primary_layout_path = recording_run_primary_layout_path;
            recorded_layout_ops.run_fallback_layout_path = recording_run_fallback_layout_path;
            ptr::addr_of_mut!(LAYOUT_STATE_OPS).write_volatile(recorded_layout_ops)
        };

        (TimerOpsRestore(saved_timer_ops), LayoutStateOpsRestore(saved_layout_ops))
    }

    fn calls() -> Vec<Call> {
        CALLS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn prepare_object(active: u8, timer_state: u32) -> LayoutStateObject {
        let mut object = LayoutStateObject([0; OBJECT_BYTES]);
        unsafe {
            object.0.as_mut_ptr().add(ACTIVE_OFFSET).write_volatile(active);
            object
                .0
                .as_mut_ptr()
                .add(TIMER_OFFSET + TIMER_STATE_OFFSET)
                .cast::<u32>()
                .write_volatile(timer_state);
        }
        object
    }
    fn lock_ops() -> (MutexGuard<'static, ()>, MutexGuard<'static, ()>) {
        let timer_guard = TIMER_OPS_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let layout_guard = OPS_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        (timer_guard, layout_guard)
    }


    unsafe fn install_singleton_caches(
        class_8900: *mut u8,
        volume_controller: *mut u8,
    ) -> SingletonCachesRestore {
        let saved = SingletonCachesRestore {
            class_8900: unsafe { ptr::addr_of!(CLASS_8900_INSTANCE).read_volatile() },
            volume_controller: unsafe { ptr::addr_of!(VOLUME_CONTROLLER_INSTANCE).read_volatile() },
        };
        unsafe {
            ptr::addr_of_mut!(CLASS_8900_INSTANCE).write_volatile(class_8900);
            ptr::addr_of_mut!(VOLUME_CONTROLLER_INSTANCE).write_volatile(volume_controller);
        }
        saved
    }

    fn activation_fixture() -> Option<*mut u8> {
        (*ACTIVATION_FIXTURE).map(|address| address as *mut u8)
    }

    unsafe fn prepare_activation_fixture(
        this: *mut u8,
        volume_controller: *mut u8,
        primary_profile: *mut u8,
        alternate_profile: *mut u8,
        volume_flag: u8,
    ) {
        unsafe {
            this.write_bytes(0, 0x200);
            this.add(PRIMARY_PROFILE_OFFSET)
                .cast::<u32>()
                .write_volatile(primary_profile as usize as u32);
            this.add(ALTERNATE_PROFILE_OFFSET)
                .cast::<u32>()
                .write_volatile(alternate_profile as usize as u32);
            this.add(ACTIVE_OFFSET).write_volatile(0xff);
            this.add(PREPARED_OFFSET).write_volatile(0xff);
            this.add(TRANSITION_SENTINEL_OFFSET)
                .cast::<u32>()
                .write_volatile(0);
            this.add(TIMER_OFFSET + TIMER_STATE_OFFSET)
                .cast::<u32>()
                .write_volatile(TIMER_STATE_RUNNING);
            volume_controller.add(0x90).write_volatile(volume_flag);
        }
    }

    fn lock_activation_ops() -> (MutexGuard<'static, ()>, MutexGuard<'static, ()>, MutexGuard<'static, ()>) {
        let singleton_guard = SINGLETON_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let timer_guard = TIMER_OPS_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let layout_guard = OPS_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        (singleton_guard, timer_guard, layout_guard)
    }

    #[test]
    fn deactivation_propagates_zero_stops_timer_then_clears_active_flag() {
        let _guards = lock_ops();
        let mut object = prepare_object(0xff, TIMER_STATE_RUNNING);
        CALLS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
        unsafe {
            let _restore = install_recorders();
            let this = object.0.as_mut_ptr();

            deactivate_layout_state(this);

            assert_eq!(
                calls(),
                std::vec![Call::SetEnabled(this as usize, 0), Call::TimerStop(this.add(TIMER_OFFSET) as usize)],
                "retailOS propagates the disabled state before stopping its timer"
            );
            assert_eq!(
                this.add(TIMER_OFFSET + TIMER_STATE_OFFSET).cast::<u32>().read_volatile(),
                TIMER_STATE_STOPPED,
                "the embedded timer reaches timer_stop"
            );
            assert_eq!(this.add(ACTIVE_OFFSET).read_volatile(), 0);
        }
    }

    #[test]
    fn deactivation_is_unconditional_when_already_inactive_and_stopped() {
        let _guards = lock_ops();
        let mut object = prepare_object(0, TIMER_STATE_STOPPED);
        CALLS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
        unsafe {
            let _restore = install_recorders();
            let this = object.0.as_mut_ptr();

            deactivate_layout_state(this);

            assert_eq!(
                calls(),
                std::vec![Call::SetEnabled(this as usize, 0), Call::TimerStop(this.add(TIMER_OFFSET) as usize)],
                "the original has no active-state guard"
            );
            assert_eq!(this.add(ACTIVE_OFFSET).read_volatile(), 0);
            assert_eq!(
                this.add(TIMER_OFFSET + TIMER_STATE_OFFSET).cast::<u32>().read_volatile(),
                TIMER_STATE_STOPPED
            );
        }
    }
    #[test]
    fn activation_selects_volume_profile_and_forwards_reset_result_to_primary_path() {
        let _guards = lock_activation_ops();
        let Some(this) = activation_fixture() else {
            assert!(note_missing_u32_fixture("app/layout_state activation"));
            return;
        };
        let volume_controller = unsafe { this.add(0x200) };
        let primary_profile = unsafe { this.add(0x400) };
        let alternate_profile = unsafe { this.add(0x500) };
        let primary_path_state = unsafe { this.add(0x600) };
        let class_8900 = unsafe { this.add(0x700) };

        for (volume_flag, expected_profile) in [(0u8, primary_profile), (0xff, alternate_profile)] {
            unsafe {
                prepare_activation_fixture(
                    this,
                    volume_controller,
                    primary_profile,
                    alternate_profile,
                    volume_flag,
                );
                CLASS_8900_PATH_SELECTOR = 1;
                RESET_SELECTED_PROFILE_RESULT = primary_path_state;
                CALLS
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .clear();
                let _singleton_restore = install_singleton_caches(class_8900, volume_controller);
                let _ops_restore = install_recorders();

                activate_layout_state(this);

                assert_eq!(
                    calls(),
                    std::vec![
                        Call::TimerStop(this.add(TIMER_OFFSET) as usize),
                        Call::SetEnabled(this as usize, 1),
                        Call::Class8900PathSelector(class_8900 as usize),
                        Call::ResetSelectedProfile(expected_profile as usize),
                        Call::RunPrimaryLayoutPath(primary_path_state as usize),
                    ],
                    "selector=1 uses the raw volume byte to choose a profile and forwards reset r0"
                );
                assert_eq!(this.add(TRANSITION_SENTINEL_OFFSET).cast::<u32>().read_volatile(), u32::MAX);
                assert_eq!(this.add(PREPARED_OFFSET).read_volatile(), 0);
                assert_eq!(this.add(ACTIVE_OFFSET).read_volatile(), 1);
                assert_eq!(
                    this.add(TIMER_OFFSET + TIMER_STATE_OFFSET).cast::<u32>().read_volatile(),
                    TIMER_STATE_STOPPED
                );
            }
        }
    }

    #[test]
    fn activation_uses_fallback_for_every_selector_other_than_one() {
        let _guards = lock_activation_ops();
        let Some(this) = activation_fixture() else {
            assert!(note_missing_u32_fixture("app/layout_state activation"));
            return;
        };
        let volume_controller = unsafe { this.add(0x200) };
        let primary_profile = unsafe { this.add(0x400) };
        let alternate_profile = unsafe { this.add(0x500) };
        let class_8900 = unsafe { this.add(0x700) };

        unsafe {
            prepare_activation_fixture(
                this,
                volume_controller,
                primary_profile,
                alternate_profile,
                0,
            );
            CLASS_8900_PATH_SELECTOR = 2;
            RESET_SELECTED_PROFILE_RESULT = this.add(0x600);
            CALLS
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clear();
            let _singleton_restore = install_singleton_caches(class_8900, volume_controller);
            let _ops_restore = install_recorders();

            activate_layout_state(this);

            assert_eq!(
                calls(),
                std::vec![
                    Call::TimerStop(this.add(TIMER_OFFSET) as usize),
                    Call::SetEnabled(this as usize, 1),
                    Call::Class8900PathSelector(class_8900 as usize),
                    Call::RunFallbackLayoutPath(this as usize),
                ],
                "only an exact selector value of one enters the profile path"
            );
            assert_eq!(this.add(TRANSITION_SENTINEL_OFFSET).cast::<u32>().read_volatile(), u32::MAX);
            assert_eq!(this.add(PREPARED_OFFSET).read_volatile(), 0);
            assert_eq!(this.add(ACTIVE_OFFSET).read_volatile(), 1);
        }
    }
}
