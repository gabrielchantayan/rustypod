//! UI resource lifecycle cleanup.
//!
//! The lazy state provider and the resource-release helper are both outside
//! the ported UI surface. Their narrow contracts are kept as a dispatch table
//! so target integration can wire the retailOS callees while host tests can
//! supply deterministic recorders.

/// Offset of the resource pointer within the lazy UI resource state.
const RESOURCE_OFFSET: usize = 0x04;
/// Offset of the active marker cleared only after a successful release.
const ACTIVE_OFFSET: usize = 0x08;

/// Calls needed by [`ui_resource_release`].
///
/// `state` is retailOS `FUN_081f5034` @ `0x081f5034`: it lazily returns a
/// 0x18-byte singleton. Only its resource word at +0x04 and active byte at
/// +0x08 are observed here. `release` is `FUN_0838f764` @ `0x0838f764`,
/// whose zero result means that the resource was released successfully.
#[derive(Clone, Copy)]
pub struct UiResourceReleaseOps {
    pub state: unsafe extern "C" fn() -> *mut u8,
    pub release: unsafe extern "C" fn(resource: *mut u8) -> i32,
}

unsafe extern "C" fn missing_ui_resource_state() -> *mut u8 {
    static mut EMPTY_STATE: [u32; 3] = [0; 3];
    core::ptr::addr_of_mut!(EMPTY_STATE).cast()
}

unsafe extern "C" fn missing_ui_resource_release(_resource: *mut u8) -> i32 {
    0
}

/// Unwired resource lifecycle operations. The empty default state preserves
/// the original early return until the surrounding UI resource subsystem is
/// ported and installs its retailOS helpers.
pub const DEFAULT_UI_RESOURCE_RELEASE_OPS: UiResourceReleaseOps = UiResourceReleaseOps {
    state: missing_ui_resource_state,
    release: missing_ui_resource_release,
};

/// Active UI resource lifecycle operations. Target integration writes this
/// once with the retailOS helper bridges; host tests temporarily install
/// recorders.
pub static mut UI_RESOURCE_RELEASE_OPS: UiResourceReleaseOps = DEFAULT_UI_RESOURCE_RELEASE_OPS;

/// Volatile dispatch prevents target builds using the defaults from folding
/// away the integration boundary.
#[inline(always)]
fn ui_resource_release_ops() -> UiResourceReleaseOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(UI_RESOURCE_RELEASE_OPS)) }
}

/// ui_resource_release — original: `FUN_0811f76c` @ `0x0811f76c` (72 bytes).
///
/// Obtains the lazy UI resource state, returns 0 immediately when its +0x04
/// resource word is empty, and otherwise releases that resource. A nonzero
/// helper result is returned unchanged. Only a zero result clears the state
/// byte at +0x08 and then its resource word at +0x04, preserving the original
/// success-only cleanup order.
///
/// # Deviations
///
/// `FUN_081f5034` and `FUN_0838f764` are not ported. Their observed contracts
/// are represented by [`UI_RESOURCE_RELEASE_OPS`] instead of guessed
/// implementations; the default state is empty, so an unwired build follows
/// the original early-return path safely.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ui_resource_release() -> i32 {
    let ops = ui_resource_release_ops();
    let state = unsafe { (ops.state)() };
    let resource_word = unsafe {
        (state.add(RESOURCE_OFFSET) as *const u32).read_volatile()
    };
    if resource_word == 0 {
        return 0;
    }

    let result = unsafe { (ops.release)(resource_word as usize as *mut u8) };
    if result != 0 {
        return result;
    }

    unsafe {
        state.add(ACTIVE_OFFSET).write_volatile(0);
        (state.add(RESOURCE_OFFSET) as *mut u32).write_volatile(0);
    }
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};
    #[repr(align(4))]
    struct State([u8; 12]);

    #[derive(Default)]
    struct Mock {
        state: usize,
        release_result: i32,
        release_calls: usize,
        released_resource: usize,
    }

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static MOCK: Mutex<Mock> = Mutex::new(Mock {
        state: 0,
        release_result: 0,
        release_calls: 0,
        released_resource: 0,
    });

    unsafe extern "C" fn mock_state() -> *mut u8 {
        MOCK.lock().unwrap().state as *mut u8
    }

    unsafe extern "C" fn mock_release(resource: *mut u8) -> i32 {
        let mut mock = MOCK.lock().unwrap();
        mock.release_calls += 1;
        mock.released_resource = resource as usize;
        mock.release_result
    }

    fn install_mock(state: &mut State, release_result: i32) -> (MutexGuard<'static, ()>, UiResourceReleaseOps) {
        let lock = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let previous = unsafe { UI_RESOURCE_RELEASE_OPS };
        *MOCK.lock().unwrap() = Mock {
            state: state.0.as_mut_ptr() as usize,
            release_result,
            ..Mock::default()
        };
        unsafe {
            UI_RESOURCE_RELEASE_OPS = UiResourceReleaseOps {
                state: mock_state,
                release: mock_release,
            };
        }
        (lock, previous)
    }

    fn restore_ops(previous: UiResourceReleaseOps) {
        unsafe { UI_RESOURCE_RELEASE_OPS = previous };
    }

    fn resource(state: &State) -> u32 {
        u32::from_le_bytes(state.0[RESOURCE_OFFSET..RESOURCE_OFFSET + 4].try_into().unwrap())
    }

    #[test]
    fn empty_state_returns_without_releasing_or_storing() {
        let mut state = State([0xa5; 12]);
        state.0[RESOURCE_OFFSET..RESOURCE_OFFSET + 4].copy_from_slice(&0u32.to_le_bytes());
        let before = state.0;
        let (_lock, previous) = install_mock(&mut state, 0);

        let result = unsafe { ui_resource_release() };
        restore_ops(previous);

        assert_eq!(result, 0);
        assert_eq!(state.0, before, "the early return does not alter state");
        assert_eq!(MOCK.lock().unwrap().release_calls, 0);
    }

    #[test]
    fn helper_failure_is_preserved_and_leaves_state_intact() {
        const RESOURCE: u32 = 0x0123_4567;
        const FAILURE: i32 = 0x15;
        let mut state = State([0xa5; 12]);
        state.0[RESOURCE_OFFSET..RESOURCE_OFFSET + 4].copy_from_slice(&RESOURCE.to_le_bytes());
        let before = state.0;
        let (_lock, previous) = install_mock(&mut state, FAILURE);

        let result = unsafe { ui_resource_release() };
        restore_ops(previous);

        let mock = MOCK.lock().unwrap();
        assert_eq!(result, FAILURE);
        assert_eq!(mock.release_calls, 1);
        assert_eq!(mock.released_resource, RESOURCE as usize);
        assert_eq!(state.0, before, "a helper failure preserves retry state");
    }

    #[test]
    fn successful_release_clears_active_byte_then_resource_word() {
        const RESOURCE: u32 = 0x0bad_f00d;
        let mut state = State([0xa5; 12]);
        state.0[RESOURCE_OFFSET..RESOURCE_OFFSET + 4].copy_from_slice(&RESOURCE.to_le_bytes());
        let (_lock, previous) = install_mock(&mut state, 0);

        let result = unsafe { ui_resource_release() };
        restore_ops(previous);

        assert_eq!(result, 0);
        assert_eq!(MOCK.lock().unwrap().release_calls, 1);
        assert_eq!(resource(&state), 0, "successful release clears the resource word");
        assert_eq!(state.0[ACTIVE_OFFSET], 0, "successful release clears the active byte");
        for (offset, byte) in state.0.iter().enumerate() {
            if (RESOURCE_OFFSET..=ACTIVE_OFFSET).contains(&offset) {
                assert_eq!(*byte, 0, "cleared state byte +{offset:#x}");
            } else {
                assert_eq!(*byte, 0xa5, "unrelated state byte +{offset:#x}");
            }
        }
    }
}
