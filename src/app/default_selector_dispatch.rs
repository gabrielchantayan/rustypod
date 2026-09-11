//! `dispatch_default_selector` — original: `FUN_0821a11c` @ `0x0821a11c`
//! (12 instruction bytes, `0x0821a11c..0x0821a128`; the next separately linked
//! function begins at `0x0821a128`).
//!
//! Raw ARM is a three-instruction tail wrapper: it moves `notify` from `r1` to
//! `r2`, writes the signed selector sentinel `-1` to `r1`, then branches to
//! the unported `FUN_082193d8` at `0x082193d8`. Decoding every ARM `B`/`BL`
//! immediate in `osos.dec` finds **9 direct call sites**, all unconditional
//! `bl` (0x08131368, 0x08225948, 0x082270ec, 0x0822962c, 0x0822a814,
//! 0x0823110c, 0x0823213c, 0x08232ac0, 0x082392b4); there are no predicated
//! calls. The forwarded notification flag is both zero and nonzero at those
//! sites.
//!
//! Deliberate deviation: `FUN_082193d8` is unported. Target builds call its
//! fixed retailOS address; host tests install a volatile dispatch seam.

#[cfg(not(target_os = "none"))]
use core::ptr::addr_of;

const RETAIL_DEFAULT_SELECTOR_DISPATCH: usize = 0x0821_93d8;

/// ABI of the unported general selector dispatcher at `0x082193d8`.
pub type DefaultSelectorDispatch = unsafe extern "C" fn(*mut u8, i32, u32);

/// Host seam for the unported selector dispatcher.
#[derive(Clone, Copy)]
pub struct DefaultSelectorDispatchOps {
    pub dispatch: DefaultSelectorDispatch,
}

#[cfg(target_os = "none")]
unsafe fn retail_default_selector_dispatch(context: *mut u8, selector: i32, notify: u32) {
    let dispatch: DefaultSelectorDispatch = core::mem::transmute(RETAIL_DEFAULT_SELECTOR_DISPATCH);
    dispatch(context, selector, notify)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_default_selector_dispatch(_context: *mut u8, _selector: i32, _notify: u32) {
    panic!("install default-selector dispatch host operations before calling this wrapper")
}

/// Host default before a test installs the retail dispatch equivalent.
#[cfg(not(target_os = "none"))]
pub const DEFAULT_DEFAULT_SELECTOR_DISPATCH_OPS: DefaultSelectorDispatchOps =
    DefaultSelectorDispatchOps { dispatch: missing_default_selector_dispatch };

/// Host-side dispatcher seam. Target builds always call `0x082193d8`.
#[cfg(not(target_os = "none"))]
pub static mut DEFAULT_SELECTOR_DISPATCH_OPS: DefaultSelectorDispatchOps =
    DEFAULT_DEFAULT_SELECTOR_DISPATCH_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn host_default_selector_dispatch(context: *mut u8, selector: i32, notify: u32) {
    let dispatch = core::ptr::read_volatile(addr_of!(DEFAULT_SELECTOR_DISPATCH_OPS.dispatch));
    dispatch(context, selector, notify)
}

/// Dispatches `context` with the general dispatcher's default selector.
///
/// The raw wrapper preserves `notify` verbatim, including values other than
/// zero and one, while fixing selector `-1`.
///
/// # Safety
///
/// `context` and `notify` must meet the unported dispatcher's requirements.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn dispatch_default_selector(context: *mut u8, notify: u32) {
    #[cfg(target_os = "none")]
    retail_default_selector_dispatch(context, -1, notify);
    #[cfg(not(target_os = "none"))]
    host_default_selector_dispatch(context, -1, notify);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut DISPATCH_CALL: Option<(*mut u8, i32, u32)> = None;

    unsafe extern "C" fn record_dispatch(context: *mut u8, selector: i32, notify: u32) {
        DISPATCH_CALL = Some((context, selector, notify));
    }

    fn install_recorder() -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            addr_of_mut!(DISPATCH_CALL).write(None);
            addr_of_mut!(DEFAULT_SELECTOR_DISPATCH_OPS).write(DefaultSelectorDispatchOps {
                dispatch: record_dispatch,
            });
        }
        guard
    }

    fn restore_default(guard: MutexGuard<'static, ()>) {
        unsafe {
            addr_of_mut!(DEFAULT_SELECTOR_DISPATCH_OPS)
                .write(DEFAULT_DEFAULT_SELECTOR_DISPATCH_OPS);
        }
        drop(guard);
    }

    #[test]
    fn forwards_default_selector_and_zero_notification() {
        let guard = install_recorder();
        let mut context = [0u8; 4];

        unsafe { dispatch_default_selector(context.as_mut_ptr(), 0) };

        unsafe {
            assert_eq!(addr_of!(DISPATCH_CALL).read(), Some((context.as_mut_ptr(), -1, 0)));
        }
        restore_default(guard);
    }

    #[test]
    fn preserves_non_boolean_notification_bits() {
        let guard = install_recorder();
        let mut context = [0u8; 4];

        unsafe { dispatch_default_selector(context.as_mut_ptr(), u32::MAX) };

        unsafe {
            assert_eq!(
                addr_of!(DISPATCH_CALL).read(),
                Some((context.as_mut_ptr(), -1, u32::MAX))
            );
        }
        restore_default(guard);
    }
}
