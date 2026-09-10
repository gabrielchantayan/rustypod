//! Access to the shared callback-queue instance.
//!
//! `callback_queue_instance_get` — original: `FUN_081fbb24` @ **0x081fbb24**
//! (**12 instruction bytes**, followed by its 4-byte literal pool; **10 direct
//! `bl` call sites, all unconditional**: 0x081378ac, 0x0814bc70, 0x0814bf6c,
//! 0x0814c000, 0x0814c0dc, 0x08206f50, 0x08206fd0, 0x08207088, 0x08207110,
//! and 0x08207614). Raw ARM is `ldr r0,[pc,#4]; ldr r0,[r0]; bx lr`, whose
//! literal is the runtime-owned global word at 0x089cfcc8. It returns that
//! queue instance as-is: no construction, NULL guard, or validation.
//!
//! The queue is allocated as 0x6c bytes by `FUN_081fb5e0` and receives
//! callbacks through its sibling operations (`FUN_081fb524`, `FUN_081fb52c`,
//! and `FUN_081fb5d8`), which is the basis for its name. Deliberate host
//! deviation: the 32-bit firmware global is represented by a native-width
//! static pointer, so host fixtures remain valid on 64-bit systems.

/// Firmware word containing the callback-queue instance pointer.
#[cfg(target_os = "none")]
const CALLBACK_QUEUE_INSTANCE_GLOBAL: *const *mut u8 = 0x089c_fcc8 as *const *mut u8;

/// Native-width host model of [`CALLBACK_QUEUE_INSTANCE_GLOBAL`].
#[cfg(not(target_os = "none"))]
static mut HOST_CALLBACK_QUEUE_INSTANCE: *mut u8 = core::ptr::null_mut();

/// Returns the shared callback-queue instance pointer without constructing or
/// validating it.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn callback_queue_instance_get() -> *mut u8 {
    #[cfg(target_os = "none")]
    {
        return unsafe { CALLBACK_QUEUE_INSTANCE_GLOBAL.read_volatile() };
    }

    #[cfg(not(target_os = "none"))]
    unsafe {
        core::ptr::addr_of!(HOST_CALLBACK_QUEUE_INSTANCE).read_volatile()
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static ACCESS_TEST_LOCK: Mutex<()> = Mutex::new(());

    struct CallbackQueueInstanceReset;

    impl Drop for CallbackQueueInstanceReset {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(HOST_CALLBACK_QUEUE_INSTANCE)
                    .write(core::ptr::null_mut());
            }
        }
    }

    fn install_empty_instance_slot() -> MutexGuard<'static, ()> {
        let guard = ACCESS_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            core::ptr::addr_of_mut!(HOST_CALLBACK_QUEUE_INSTANCE)
                .write(core::ptr::null_mut());
        }
        guard
    }

    #[test]
    fn returns_null_before_callback_queue_initialization() {
        let _guard = install_empty_instance_slot();
        let _reset = CallbackQueueInstanceReset;

        assert!(unsafe { callback_queue_instance_get() }.is_null());
    }

    #[test]
    fn loads_the_current_callback_queue_global_word() {
        let _guard = install_empty_instance_slot();
        let _reset = CallbackQueueInstanceReset;
        let mut first = [0u32; 1];
        let mut second = [0u32; 1];

        unsafe {
            core::ptr::addr_of_mut!(HOST_CALLBACK_QUEUE_INSTANCE)
                .write(first.as_mut_ptr().cast());
            assert_eq!(callback_queue_instance_get(), first.as_mut_ptr().cast());

            core::ptr::addr_of_mut!(HOST_CALLBACK_QUEUE_INSTANCE)
                .write(second.as_mut_ptr().cast());
            assert_eq!(callback_queue_instance_get(), second.as_mut_ptr().cast());
        }
    }
}
