//! Prepares the class-0x7f80 artwork cache for use.
//!
//! `artwork_cache_prepare` — original: `FUN_081b6cec` @ **0x081b6cec**
//! (**96 bytes**, `0x081b6cec..0x081b6d4c`; `0x081b6d4c` begins the next
//! separately linked function).
//!
//! Raw ARM decoding finds two inbound unconditional `bl` sites
//! (`0x080ff070`, `0x08158f1c`) and no inbound predicated forms. Its body has
//! two unconditional direct `bl` calls and two predicated calls (`bleq` to
//! `heap_panic`, `blne` to the pending-artwork release).
//!
//! # Algorithm
//!
//! Lock the embedded mutex at `+0x18`. A zero state byte at `+0x20` is fatal.
//! Any state other than one clears the Showcase timer slots, clears byte
//! `+0xe8`, optionally releases pending artwork when `+0xea` is nonzero, and
//! stamps state one. It then unlocks on every returning path.
//!
//! # Deliberate deviations
//!
//! The pending-artwork release callee is still unported. Target builds call
//! its verified retail address (`0x081b753c`); host tests inject it. The cache
//! reset directly uses the existing `showcase_clear_timer_slots_and_stop` port.
//! Byte offsets preserve the ARM layout despite the wider host mutex.

use crate::heap::veneers::heap_panic;
use crate::kernel::sync_mutex::{mutex_lock, mutex_unlock, Mutex};

const MUTEX_OFFSET: usize = 0x18;
const STATE_OFFSET: usize = 0x20;
const RESET_BYTE_OFFSET: usize = 0xe8;
const PENDING_ARTWORK_OFFSET: usize = 0xea;

type CacheCall = unsafe extern "C" fn(*mut u8);

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn call_retail_cache(address: usize, cache: *mut u8) {
    let call: CacheCall = core::mem::transmute(address);
    call(cache);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn no_op_cache(_: *mut u8) {}

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct ArtworkCachePrepareOps {
    pub release_pending_artwork: CacheCall,
}

#[cfg(not(target_os = "none"))]
pub const DEFAULT_ARTWORK_CACHE_PREPARE_OPS: ArtworkCachePrepareOps = ArtworkCachePrepareOps {
    release_pending_artwork: no_op_cache,
};

#[cfg(not(target_os = "none"))]
pub static mut ARTWORK_CACHE_PREPARE_OPS: ArtworkCachePrepareOps = DEFAULT_ARTWORK_CACHE_PREPARE_OPS;

/// Prepares a cache that uses its state byte to guard one-time initialization.
///
/// # Safety
///
/// `cache` must point to a writable retail cache layout containing an embedded
/// mutex at `+0x18` and bytes at `+0x20`, `+0xe8`, and `+0xea`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn artwork_cache_prepare(cache: *mut u8) {
    let mutex = cache.add(MUTEX_OFFSET).cast::<Mutex>();
    mutex_lock(mutex);

    let state = cache.add(STATE_OFFSET).read_volatile();
    if state == 0 {
        heap_panic();
    }
    if state != 1 {
        crate::app::showcase_clear_timer_slots::showcase_clear_timer_slots_and_stop(cache);
        cache.add(RESET_BYTE_OFFSET).write_volatile(0);
        if cache.add(PENDING_ARTWORK_OFFSET).read_volatile() != 0 {
            #[cfg(target_os = "none")]
            call_retail_cache(0x081b_753c, cache);
            #[cfg(not(target_os = "none"))]
            (ARTWORK_CACHE_PREPARE_OPS.release_pending_artwork)(cache);
        }
        cache.add(STATE_OFFSET).write_volatile(1);
    }

    mutex_unlock(mutex);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    extern crate std;
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::{LazyLock, Mutex};

    const FIXTURE_LEN: usize = 0x1000;
    const TIMER_SLOT_OFFSET: usize = 0x1c4;
    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static BASE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::ARTWORK_CACHE_PREPARE, FIXTURE_LEN).map(|pointer| pointer as usize)
    });
    static mut RELEASE_CALLS: usize = 0;
    static mut RELEASE_CACHE: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn record_release(cache: *mut u8) {
        RELEASE_CALLS += 1;
        RELEASE_CACHE = cache;
    }

    struct Restore(ArtworkCachePrepareOps);
    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe { addr_of_mut!(ARTWORK_CACHE_PREPARE_OPS).write(self.0) };
        }
    }

    unsafe fn prepare_fixture(cache: *mut u8) -> Restore {
        cache.write_bytes(0, FIXTURE_LEN);
        RELEASE_CALLS = 0;
        RELEASE_CACHE = core::ptr::null_mut();
        let restore = Restore(addr_of!(ARTWORK_CACHE_PREPARE_OPS).read());
        ARTWORK_CACHE_PREPARE_OPS = ArtworkCachePrepareOps { release_pending_artwork: record_release };
        restore
    }

    #[test]
    fn state_one_only_unlocks_without_mutating_cache() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(base) = *BASE else {
            assert!(note_missing_u32_fixture("app::artwork_cache_prepare"));
            return;
        };
        unsafe {
            let cache = base as *mut u8;
            let _restore = prepare_fixture(cache);
            cache.add(STATE_OFFSET).write(1);
            cache.add(RESET_BYTE_OFFSET).write(0xa5);
            cache.add(PENDING_ARTWORK_OFFSET).write(1);
            artwork_cache_prepare(cache);
            assert_eq!(RELEASE_CALLS, 0);
            assert_eq!(cache.add(STATE_OFFSET).read(), 1);
            assert_eq!(cache.add(RESET_BYTE_OFFSET).read(), 0xa5);
        }
    }

    #[test]
    fn nonzero_nonone_state_clears_timer_slots_and_releases_pending_artwork() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(base) = *BASE else {
            assert!(note_missing_u32_fixture("app::artwork_cache_prepare"));
            return;
        };
        unsafe {
            let cache = base as *mut u8;
            let _restore = prepare_fixture(cache);
            cache.add(STATE_OFFSET).write(2);
            cache.add(RESET_BYTE_OFFSET).write(0xff);
            cache.add(PENDING_ARTWORK_OFFSET).write(0x80);
            for slot in 0..4 {
                cache.add(TIMER_SLOT_OFFSET + slot * 4).cast::<u32>().write(0xa5a5_5a5a);
            }
            artwork_cache_prepare(cache);
            assert_eq!(RELEASE_CALLS, 1);
            assert_eq!(RELEASE_CACHE, cache);
            assert_eq!(cache.add(STATE_OFFSET).read(), 1);
            assert_eq!(cache.add(RESET_BYTE_OFFSET).read(), 0);
            for slot in 0..4 {
                assert_eq!(cache.add(TIMER_SLOT_OFFSET + slot * 4).cast::<u32>().read(), 0);
            }
        }
    }

    #[test]
    fn nonone_state_skips_release_when_no_artwork_is_pending() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(base) = *BASE else {
            assert!(note_missing_u32_fixture("app::artwork_cache_prepare"));
            return;
        };
        unsafe {
            let cache = base as *mut u8;
            let _restore = prepare_fixture(cache);
            cache.add(STATE_OFFSET).write(0xff);
            artwork_cache_prepare(cache);
            assert_eq!(RELEASE_CALLS, 0);
            assert_eq!(cache.add(STATE_OFFSET).read(), 1);
            assert_eq!(cache.add(RESET_BYTE_OFFSET).read(), 0);
        }
    }
}
