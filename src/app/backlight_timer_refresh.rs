//! Refresh the settings context's backlight-timer value.
//!
//! Original: `FUN_08227ed8` @ **0x08227ed8**, **36 bytes**, ending at the
//! next real function at `0x08227efc`. Raw ARM-word scanning verifies **2 BL
//! callers: 1 plain BL (0x08227f04), 1 BLNE (0x082278cc)**. The body has
//! three unconditional BL instructions and no predicated calls.
//!
//! Resolve the class-0x6000 singleton, read its unsigned byte at +0x34 via
//! `0x08171bdc`, and pass that value and the context's +0xb0 object to
//! `0x081eda94`. That setter stores the value at +0x2c and tail-dispatches
//! vtable +0x58 with (0x2a2a2a2a, 0x891a). Return 1 unconditionally.
//! The caller identifies this path as `ShowSetting_BacklightTimer`.
//!
//! Deliberate deviations: none on target; the getter uses the Rust port and
//! unported external operations retain verified addresses or host injection.
//! The context prefix uses repr(C) fields so its pointer remains native-width
//! on the host while occupying the stock +0xb0 word on ARM.

#[repr(C)]
pub struct BacklightTimerContext {
    pub prefix: [u32; 0xb0 / 4],
    pub settings: *mut u8,
}

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct BacklightTimerOps {
    pub instance: unsafe extern "C" fn() -> *mut u8,
    pub set_timer: unsafe extern "C" fn(*mut u8, u32),
}

#[cfg(not(target_os = "none"))]
pub static mut BACKLIGHT_TIMER_OPS: Option<BacklightTimerOps> = None;

/// # Safety
/// `context` must contain a valid settings object; the class-0x6000 singleton
/// and its timer getter and the settings setter must satisfy the retail ABI.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn backlight_timer_refresh(context: *mut BacklightTimerContext) -> u32 {
    #[cfg(target_os = "none")]
    {
        let store = crate::app::registry::instance_of_class_6000();
        let set_timer: unsafe extern "C" fn(*mut u8, u32) = core::mem::transmute(0x081e_da94usize);
        let timer = crate::app::class_6000_property::class6000_backlight_timer(store);
        set_timer(core::ptr::addr_of!((*context).settings).read(), timer);
    }
    #[cfg(not(target_os = "none"))]
    {
        let ops = core::ptr::addr_of!(BACKLIGHT_TIMER_OPS).read().expect("install backlight timer host operations");
        let store = (ops.instance)();
        let timer = crate::app::class_6000_property::class6000_backlight_timer(store);
        (ops.set_timer)(core::ptr::addr_of!((*context).settings).read(), timer);
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicPtr, Ordering};

    static STORE: AtomicPtr<u8> = AtomicPtr::new(core::ptr::null_mut());
    unsafe extern "C" fn instance() -> *mut u8 { STORE.load(Ordering::Relaxed) }
    // Model the verified setter's state transition and notification. The
    // notification observes the new value, rather than just echoing arguments.
    #[repr(C)]
    struct Settings { words: [u32; 12], observed: u32 }
    unsafe extern "C" fn set_timer(settings: *mut u8, timer: u32) {
        let settings = &mut *settings.cast::<Settings>();
        settings.words[11] = timer;
        settings.observed = settings.words[11];
    }

    #[test]
    fn refresh_replaces_stale_timer_and_zero_extends_all_byte_values() {
        let mut store = [0xffu8; 0x38];
        let mut settings = Settings { words: [0xdead_beef; 12], observed: 0xdead_beef };
        let mut context = BacklightTimerContext { prefix: [0xa5a5_a5a5; 44], settings: (&mut settings as *mut Settings).cast() };
        STORE.store(store.as_mut_ptr(), Ordering::Relaxed);
        unsafe { BACKLIGHT_TIMER_OPS = Some(BacklightTimerOps { instance, set_timer }); }
        for value in 0..=255u32 {
            store[0x34] = value as u8;
            assert_eq!(unsafe { backlight_timer_refresh(&mut context) }, 1);
            assert_eq!(settings.words[11], value);
            assert_eq!(settings.observed, value);
            assert_eq!(&settings.words[..11], &[0xdead_beef; 11]);
            assert_eq!(context.prefix, [0xa5a5_a5a5; 44]);
        }
        unsafe { BACKLIGHT_TIMER_OPS = None; }
        STORE.store(core::ptr::null_mut(), Ordering::Relaxed);
    }
}
