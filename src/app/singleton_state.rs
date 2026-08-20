//! Access to the state word owned by an opaque application singleton.
//!
//! `singleton_state_get` — original: `FUN_08086df0` @ 0x08086df0 (16 bytes).
//! Raw ARM is `push {r4,lr}; bl 0x08127954; pop {r4,lr}; b 0x0829919c`.
//! The tail helper at 0x0829919c is `ldr r0,[r0,#0x18]; bx lr`, so the
//! source-level operation fetches the singleton object, then returns its word
//! at +0x18. The object accessor is itself an unported global-slot getter
//! (it returns the `+4` word of its globals block), so this wrapper neither
//! constructs nor validates either object. Its two direct callers use the
//! returned word as a vtable-bearing state object, but its concrete class
//! remains unknown.

/// ABI of the unported singleton-object accessor `FUN_08127954`.
pub type SingletonObjectGet = unsafe extern "C" fn() -> *mut u8;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_singleton_object_get() -> *mut u8 {
    let get: SingletonObjectGet = unsafe { core::mem::transmute(0x0812_7954usize) };
    unsafe { get() }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_singleton_object_get() -> *mut u8 {
    panic!("singleton_state_get requires singleton accessor 0x08127954")
}

#[cfg(target_os = "none")]
const DEFAULT_SINGLETON_OBJECT_GET: SingletonObjectGet = firmware_singleton_object_get;
#[cfg(not(target_os = "none"))]
const DEFAULT_SINGLETON_OBJECT_GET: SingletonObjectGet = missing_singleton_object_get;

/// Unported `FUN_08127954` singleton-object accessor. Target builds invoke
/// the retailOS function; host tests install a recording mock through this
/// seam.
pub static mut SINGLETON_OBJECT_GET: SingletonObjectGet = DEFAULT_SINGLETON_OBJECT_GET;

/// singleton_state_get — original: `FUN_08086df0` @ 0x08086df0 (16 bytes).
///
/// Calls the opaque singleton-object accessor before loading and returning
/// that object's raw word at offset +0x18, incorporating the original's
/// tail helper `FUN_0829919c`. No NULL or validity check is introduced for
/// either the returned object or its word.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn singleton_state_get() -> u32 {
    let get = unsafe { core::ptr::addr_of_mut!(SINGLETON_OBJECT_GET).read_volatile() };
    let singleton = unsafe { get() };
    unsafe { (singleton.add(0x18) as *const u32).read() }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static ACCESS_TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut RETURNED_SINGLETON: *mut u8 = core::ptr::null_mut();
    static mut ACCESS_COUNT: u32 = 0;
    static mut WORD_TO_INSTALL: u32 = 0;

    unsafe extern "C" fn recording_singleton_object_get() -> *mut u8 {
        unsafe {
            ACCESS_COUNT += 1;
            (RETURNED_SINGLETON.add(0x18) as *mut u32).write(WORD_TO_INSTALL);
            RETURNED_SINGLETON
        }
    }

    struct SingletonObjectGetReset;

    impl Drop for SingletonObjectGetReset {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(SINGLETON_OBJECT_GET).write(DEFAULT_SINGLETON_OBJECT_GET);
            }
        }
    }

    fn install_recording_singleton_object_get() -> MutexGuard<'static, ()> {
        let guard = ACCESS_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            RETURNED_SINGLETON = core::ptr::null_mut();
            ACCESS_COUNT = 0;
            WORD_TO_INSTALL = 0;
            core::ptr::addr_of_mut!(SINGLETON_OBJECT_GET).write(recording_singleton_object_get);
        }
        guard
    }

    #[test]
    fn calls_the_singleton_accessor_before_loading_its_state_word() {
        let _guard = install_recording_singleton_object_get();
        let _reset = SingletonObjectGetReset;
        let mut singleton = [0u32; 7];
        singleton[6] = 0xdead_beef;
        unsafe {
            RETURNED_SINGLETON = singleton.as_mut_ptr() as *mut u8;
            WORD_TO_INSTALL = 0x7654_3210;
            assert_eq!(singleton_state_get(), WORD_TO_INSTALL);
            assert_eq!(ACCESS_COUNT, 1);
        }
    }

    #[test]
    fn returns_the_full_raw_word_at_offset_0x18() {
        let _guard = install_recording_singleton_object_get();
        let _reset = SingletonObjectGetReset;
        let mut singleton = [0u32; 7];
        unsafe {
            RETURNED_SINGLETON = singleton.as_mut_ptr() as *mut u8;
            WORD_TO_INSTALL = u32::MAX;
            assert_eq!(singleton_state_get(), u32::MAX);
            assert_eq!(ACCESS_COUNT, 1);
        }
    }
}
