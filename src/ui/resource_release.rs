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
/// `release` is `FUN_0838f764` @ `0x0838f764`, whose zero result means that
/// the resource was released successfully. The state getter is now the
/// directly ported [`crate::ui::lazy_resource_state::lazy_ui_resource_state`].
#[derive(Clone, Copy)]
pub struct UiResourceReleaseOps {
    pub release: unsafe extern "C" fn(resource: *mut u8) -> i32,
}

unsafe extern "C" fn missing_ui_resource_release(_resource: *mut u8) -> i32 {
    0
}

/// Unwired resource-release operation. The state getter is ported; the
/// release helper remains an integration boundary.
pub const DEFAULT_UI_RESOURCE_RELEASE_OPS: UiResourceReleaseOps = UiResourceReleaseOps {
    release: missing_ui_resource_release,
};

/// Active UI resource-release operation. Target integration writes this once
/// with the retailOS release bridge; host tests temporarily install a recorder.
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
/// `FUN_0838f764` is not ported and remains represented by
/// [`UI_RESOURCE_RELEASE_OPS`]. The state getter is called directly.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ui_resource_release() -> i32 {
    let ops = ui_resource_release_ops();
    let state = unsafe { crate::ui::lazy_resource_state::lazy_ui_resource_state() };
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
    use parking_lot::{Mutex, MutexGuard};
    #[repr(align(4))]
    struct State([u8; 12]);

    #[derive(Default)]
    struct Mock {
        release_result: i32,
        release_calls: usize,
        released_resource: usize,
    }

    static MOCK: Mutex<Mock> = Mutex::new(Mock {
        release_result: 0,
        release_calls: 0,
        released_resource: 0,
    });

    unsafe extern "C" fn mock_release(resource: *mut u8) -> i32 {
        let mut mock = MOCK.lock();
        mock.release_calls += 1;
        mock.released_resource = resource as usize;
        mock.release_result
    }

    fn install_mock(state: &mut State, release_result: i32) -> (MutexGuard<'static, ()>, UiResourceReleaseOps, *mut u8) {
        let lock = crate::ui::lazy_resource_state::UI_RESOURCE_STATE_TEST_LOCK.lock();
        let previous = unsafe { UI_RESOURCE_RELEASE_OPS };
        let previous_state = unsafe { crate::ui::lazy_resource_state::UI_RESOURCE_STATE_CACHE };
        *MOCK.lock() = Mock {
            release_result,
            ..Mock::default()
        };
        unsafe {
            crate::ui::lazy_resource_state::UI_RESOURCE_STATE_CACHE = state.0.as_mut_ptr();
            UI_RESOURCE_RELEASE_OPS = UiResourceReleaseOps {
                release: mock_release,
            };
        }
        (lock, previous, previous_state)
    }

    fn restore_ops(previous: UiResourceReleaseOps, previous_state: *mut u8) {
        unsafe {
            UI_RESOURCE_RELEASE_OPS = previous;
            crate::ui::lazy_resource_state::UI_RESOURCE_STATE_CACHE = previous_state;
        }
    }


    fn resource(state: &State) -> u32 {
        u32::from_le_bytes(state.0[RESOURCE_OFFSET..RESOURCE_OFFSET + 4].try_into().unwrap())
    }

    #[test]
    fn empty_state_returns_without_releasing_or_storing() {
        let mut state = State([0xa5; 12]);
        state.0[RESOURCE_OFFSET..RESOURCE_OFFSET + 4].copy_from_slice(&0u32.to_le_bytes());
        let before = state.0;
        let (_lock, previous, previous_state) = install_mock(&mut state, 0);

        let result = unsafe { ui_resource_release() };
        restore_ops(previous, previous_state);

        assert_eq!(result, 0);
        assert_eq!(state.0, before, "the early return does not alter state");
        assert_eq!(MOCK.lock().release_calls, 0);
    }

    #[test]
    fn helper_failure_is_preserved_and_leaves_state_intact() {
        const RESOURCE: u32 = 0x0123_4567;
        const FAILURE: i32 = 0x15;
        let mut state = State([0xa5; 12]);
        state.0[RESOURCE_OFFSET..RESOURCE_OFFSET + 4].copy_from_slice(&RESOURCE.to_le_bytes());
        let before = state.0;
        let (_lock, previous, previous_state) = install_mock(&mut state, FAILURE);

        let result = unsafe { ui_resource_release() };
        restore_ops(previous, previous_state);

        let mock = MOCK.lock();
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
        let (_lock, previous, previous_state) = install_mock(&mut state, 0);

        let result = unsafe { ui_resource_release() };
        restore_ops(previous, previous_state);

        assert_eq!(result, 0);
        assert_eq!(MOCK.lock().release_calls, 1);
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
