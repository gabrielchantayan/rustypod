//! `static_string_lookup` — original: `FUN_08052090` @ 0x08052090.
//!
//! Raw `osos.dec` establishes the exact 56-byte extent
//! `0x08052090..0x080520c8`; `0x080520c8` is the next function entry. A full
//! A32 decode finds three outbound unconditional `bl` instructions and no
//! predicated `bl` instructions. There are three direct inbound unconditional
//! `bl` call sites.
//!
//! Algorithm: clear a 0x104-byte stack key buffer, ask the retail static-key
//! builder to fill it, and return zero on builder failure. On success, pass the
//! key to the retail lookup routine and return its 32-bit result.
//!
//! Deliberate deviation: the retail IRAM memzero veneer at `0x08037db8` is
//! replaced with the existing Rust `memzero_aligned` port. The two unported
//! callees retain their verified addresses on target; host tests install
//! recording seams because their identities and data sources are not yet
//! ported.
#[cfg(target_os = "none")]
use core::mem::transmute;
use core::mem::MaybeUninit;

const RETAIL_STATIC_KEY_BUILD_ADDRESS: usize = 0x0805_205c;
const RETAIL_STATIC_KEY_LOOKUP_ADDRESS: usize = 0x080b_42e4;

type StaticKeyBuild = unsafe extern "C" fn(*mut u8) -> u32;
type StaticKeyLookup = unsafe extern "C" fn(*mut u8) -> u32;

#[cfg(target_os = "none")]
unsafe fn retail_static_key_build(key: *mut u8) -> u32 {
    unsafe { transmute::<usize, StaticKeyBuild>(RETAIL_STATIC_KEY_BUILD_ADDRESS)(key) }
}

#[cfg(target_os = "none")]
unsafe fn retail_static_key_lookup(key: *mut u8) -> u32 {
    unsafe { transmute::<usize, StaticKeyLookup>(RETAIL_STATIC_KEY_LOOKUP_ADDRESS)(key) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_static_key_build(_: *mut u8) -> u32 {
    panic!("static_string_lookup requires a static-key builder fixture")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_static_key_lookup(_: *mut u8) -> u32 {
    panic!("static_string_lookup requires a static-key lookup fixture")
}

#[cfg(not(target_os = "none"))]
static mut STATIC_KEY_BUILD: StaticKeyBuild = missing_static_key_build;
#[cfg(not(target_os = "none"))]
static mut STATIC_KEY_LOOKUP: StaticKeyLookup = missing_static_key_lookup;

#[cfg(not(target_os = "none"))]
#[doc(hidden)]
pub unsafe fn install_static_string_lookup_for_test(build: StaticKeyBuild, lookup: StaticKeyLookup) {
    unsafe {
        STATIC_KEY_BUILD = build;
        STATIC_KEY_LOOKUP = lookup;
    }
}

/// Returns the 32-bit result of looking up the retail static key.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn static_string_lookup() -> u32 {
    let mut key = MaybeUninit::<[u8; 0x104]>::uninit();
    unsafe {
        let zero = core::ptr::read_volatile(
            &(crate::libc::memzero::memzero_aligned as unsafe extern "C" fn(*mut u8, usize) -> *mut u8),
        );
        zero(key.as_mut_ptr().cast(), 0x104);
        let key = key.assume_init_mut();

        #[cfg(target_os = "none")]
        let build_result = retail_static_key_build(key.as_mut_ptr());
        #[cfg(not(target_os = "none"))]
        let build_result = STATIC_KEY_BUILD(key.as_mut_ptr());
        if build_result != 0 {
            return 0;
        }

        #[cfg(target_os = "none")]
        return retail_static_key_lookup(key.as_mut_ptr());
        #[cfg(not(target_os = "none"))]
        return STATIC_KEY_LOOKUP(key.as_mut_ptr());
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static BUILD_RESULT: AtomicU32 = AtomicU32::new(0);
    static LOOKUP_RESULT: AtomicU32 = AtomicU32::new(0);
    static BUILD_CALLS: AtomicU32 = AtomicU32::new(0);
    static LOOKUP_CALLS: AtomicU32 = AtomicU32::new(0);
    static KEY_WAS_ZEROED: AtomicU32 = AtomicU32::new(0);
    static LOOKUP_KEY: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn build_fixture(key: *mut u8) -> u32 {
        BUILD_CALLS.fetch_add(1, Ordering::SeqCst);
        let all_zero = unsafe { core::slice::from_raw_parts(key, 0x104).iter().all(|&byte| byte == 0) };
        KEY_WAS_ZEROED.store(u32::from(all_zero), Ordering::SeqCst);
        unsafe { key.write(b'k'); }
        BUILD_RESULT.load(Ordering::SeqCst)
    }

    unsafe extern "C" fn lookup_fixture(key: *mut u8) -> u32 {
        LOOKUP_CALLS.fetch_add(1, Ordering::SeqCst);
        LOOKUP_KEY.store(key as usize, Ordering::SeqCst);
        assert_eq!(unsafe { key.read() }, b'k');
        LOOKUP_RESULT.load(Ordering::SeqCst)
    }

    fn install(build_result: u32, lookup_result: u32) {
        BUILD_RESULT.store(build_result, Ordering::SeqCst);
        LOOKUP_RESULT.store(lookup_result, Ordering::SeqCst);
        BUILD_CALLS.store(0, Ordering::SeqCst);
        LOOKUP_CALLS.store(0, Ordering::SeqCst);
        KEY_WAS_ZEROED.store(0, Ordering::SeqCst);
        LOOKUP_KEY.store(0, Ordering::SeqCst);
        unsafe { install_static_string_lookup_for_test(build_fixture, lookup_fixture); }
    }

    #[test]
    fn returns_lookup_result_after_building_a_zeroed_key() {
        let _guard = TEST_LOCK.lock();
        install(0, 0x1234_5678);

        assert_eq!(unsafe { static_string_lookup() }, 0x1234_5678);
        assert_eq!(BUILD_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(LOOKUP_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(KEY_WAS_ZEROED.load(Ordering::SeqCst), 1);
        assert_ne!(LOOKUP_KEY.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn builder_failure_returns_zero_without_lookup() {
        let _guard = TEST_LOCK.lock();
        install(1, 0x1234_5678);

        assert_eq!(unsafe { static_string_lookup() }, 0);
        assert_eq!(BUILD_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(LOOKUP_CALLS.load(Ordering::SeqCst), 0);
        assert_eq!(KEY_WAS_ZEROED.load(Ordering::SeqCst), 1);
    }
}
