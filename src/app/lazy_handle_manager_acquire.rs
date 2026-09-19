//! Lazy shared-handle manager acquisition.
//!
//! Port:
//! - [`lazy_handle_manager_acquire`] — original: `FUN_081bbff0` @
//!   `0x081bbff0` (132 bytes: 124 instruction bytes plus its two-word literal
//!   pool; the distinct next function begins at `0x081bc07c`).

use crate::app::lazy_handle_manager::LazyHandleManager;
use crate::drivers::cache_address_translate::cache_address_translate;
use crate::drivers::timer::read_usec_timer_into_2;
use crate::kernel::sync_mutex::{mutex_lock, mutex_unlock, Mutex};
use crate::runtime::random::ansi_rand;

const RANDOM_SEED_SET_ADDRESS: usize = 0x080e_8a64;
const CACHE_RANGE_MAINTENANCE_ADDRESS: usize = 0x0805_97f0;
const CACHE_RANGE_START_ADDRESS: usize = 0x083e_2360;
const CACHE_RANGE_LENGTH_ADDRESS: usize = 0x083e_235c;

type RandomSeedSet = unsafe extern "C" fn(u32);
type CacheRangeMaintenance = unsafe extern "C" fn(u32, u32);
type TimerRead = unsafe extern "C" fn(*mut u32);

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_random_seed_set(seed: u32) {
    let set_seed: RandomSeedSet = core::mem::transmute(RANDOM_SEED_SET_ADDRESS);
    set_seed(seed);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_random_seed_set(_seed: u32) {}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_cache_range_maintenance(address: u32, len: u32) {
    let maintain: CacheRangeMaintenance = core::mem::transmute(CACHE_RANGE_MAINTENANCE_ADDRESS);
    maintain(address, len);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_cache_range_maintenance(_address: u32, _len: u32) {}

static mut RANDOM_SEED_SET: RandomSeedSet = {
    #[cfg(target_os = "none")]
    { firmware_random_seed_set }
    #[cfg(not(target_os = "none"))]
    { host_random_seed_set }
};
static mut CACHE_RANGE_MAINTENANCE: CacheRangeMaintenance = {
    #[cfg(target_os = "none")]
    { firmware_cache_range_maintenance }
    #[cfg(not(target_os = "none"))]
    { host_cache_range_maintenance }
};
static mut TIMER_READ: TimerRead = read_usec_timer_into_2;

#[cfg(not(target_os = "none"))]
static mut HOST_CACHE_RANGE_START: u32 = 0;
#[cfg(not(target_os = "none"))]
static mut HOST_CACHE_RANGE_LENGTH: u32 = 0;

#[inline(always)]
unsafe fn cache_range() -> (u32, u32) {
    #[cfg(target_os = "none")]
    {
        (
            core::ptr::read_volatile(CACHE_RANGE_START_ADDRESS as *const u32),
            core::ptr::read_volatile(CACHE_RANGE_LENGTH_ADDRESS as *const u32),
        )
    }
    #[cfg(not(target_os = "none"))]
    {
        (HOST_CACHE_RANGE_START, HOST_CACHE_RANGE_LENGTH)
    }
}

/// lazy_handle_manager_acquire — original: `FUN_081bbff0` @ `0x081bbff0`
/// (132 bytes: 124 instruction bytes plus the literal pool at
/// `0x081bc074..0x081bc07c`; binary-decoded).
///
/// Verified call count: eight plain unconditional `bl` instructions, at
/// `0x081bc000`, `0x081bc014`, `0x081bc024`, `0x081bc02c`, `0x081bc030`,
/// `0x081bc04c`, `0x081bc060`, and `0x081bc068`; zero predicated `bl`.
///
/// Locks the 16-byte lazy manager. Its initialized byte makes subsequent calls
/// return zero after unlocking. On first acquisition it samples Timer E into a
/// stack word, gives that sample to the unported seed-store entry at
/// `0x080e8a64`, generates and stores an ANSI-C random handle in both `out`
/// and manager+8, marks the manager initialized, translates the dynamic cache
/// range address using the ported mirror rule, performs the unported range
/// maintenance entry at `0x080597f0`, unlocks, and returns the handle.
///
/// Deliberate deviations: the two unported callees retain verified raw-address
/// target dispatch; host builds use replaceable test seams rather than assign
/// identities beyond their observed seed-store and range-maintenance effects.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.lazy_handle_manager_acquire")]
#[inline(never)]
pub unsafe extern "C" fn lazy_handle_manager_acquire(
    manager: *mut LazyHandleManager,
    out: *mut u32,
) -> u32 {
    let mutex = manager.cast::<Mutex>();
    mutex_lock(mutex);
    if core::ptr::read_volatile(core::ptr::addr_of!((*manager).initialized)) != 0 {
        mutex_unlock(mutex);
        return 0;
    }

    let mut timer_sample = 0;
    (TIMER_READ)(&mut timer_sample);
    (RANDOM_SEED_SET)(timer_sample);
    let handle = ansi_rand();
    out.write_volatile(handle);
    core::ptr::write_volatile(core::ptr::addr_of_mut!((*manager).cached_handle), handle as i32);
    core::ptr::write_volatile(core::ptr::addr_of_mut!((*manager).initialized), 1);
    let (cache_start, cache_len) = cache_range();
    let cache_address = cache_address_translate(cache_start);
    (CACHE_RANGE_MAINTENANCE)(cache_address, cache_len);
    mutex_unlock(mutex);
    handle
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr;
    use std::sync::{Mutex as HostMutex, MutexGuard};

    static TEST_LOCK: HostMutex<()> = HostMutex::new(());
    static mut TIMER_SAMPLE: u32 = 0;
    static mut SEEDED_WITH: u32 = 0;
    static mut CACHE_CALL: (u32, u32) = (0, 0);

    unsafe extern "C" fn timer_read(out: *mut u32) { out.write(TIMER_SAMPLE); }
    unsafe extern "C" fn seed_set(seed: u32) {
        SEEDED_WITH = seed;
        crate::runtime::random::ANSI_RAND_STATE.write(seed);
    }
    unsafe extern "C" fn cache_maintenance(address: u32, len: u32) {
        CACHE_CALL = (address, len);
    }

    fn reset() -> MutexGuard<'static, ()> {
        let lock = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            TIMER_READ = timer_read;
            RANDOM_SEED_SET = seed_set;
            CACHE_RANGE_MAINTENANCE = cache_maintenance;
            TIMER_SAMPLE = 0x1234_5678;
            SEEDED_WITH = 0;
            CACHE_CALL = (0, 0);
            HOST_CACHE_RANGE_START = 0x1800_0120;
            HOST_CACHE_RANGE_LENGTH = 0x44;
        }
        lock
    }

    fn restore(lock: MutexGuard<'static, ()>) {
        unsafe {
            TIMER_READ = read_usec_timer_into_2;
            RANDOM_SEED_SET = host_random_seed_set;
            CACHE_RANGE_MAINTENANCE = host_cache_range_maintenance;
        }
        drop(lock);
    }

    #[test]
    fn first_acquisition_seeds_generates_stores_and_maintains_translated_range() {
        let lock = reset();
        unsafe {
            let mut manager = LazyHandleManager { mutex_words: [0; 2], cached_handle: -1, initialized: 0, padding: [0; 3] };
            let mut out = 0;
            let prior_rand_state = crate::runtime::random::ANSI_RAND_STATE;
            crate::runtime::random::ANSI_RAND_STATE = ptr::addr_of_mut!(TIMER_SAMPLE);
            let expected = TIMER_SAMPLE.wrapping_mul(0x41c6_4e6d).wrapping_add(0x3039) >> 16 & 0x7fff;
            assert_eq!(lazy_handle_manager_acquire(&mut manager, &mut out), expected);
            assert_eq!(out, expected);
            assert_eq!(manager.cached_handle, expected as i32);
            assert_eq!(manager.initialized, 1);
            assert_eq!(SEEDED_WITH, 0x1234_5678);
            assert_eq!(CACHE_CALL, (0x2200_0120, 0x44));
            crate::runtime::random::ANSI_RAND_STATE = prior_rand_state;
        }
        restore(lock);
    }

    #[test]
    fn initialized_manager_does_not_touch_output_or_first_acquisition_effects() {
        let lock = reset();
        unsafe {
            let mut manager = LazyHandleManager { mutex_words: [0; 2], cached_handle: 0x7654_3210, initialized: 1, padding: [0; 3] };
            let mut out = 0xa5a5_a5a5;
            assert_eq!(lazy_handle_manager_acquire(&mut manager, &mut out), 0);
            assert_eq!(out, 0xa5a5_a5a5);
            assert_eq!(manager.cached_handle, 0x7654_3210);
            assert_eq!(SEEDED_WITH, 0);
            assert_eq!(CACHE_CALL, (0, 0));
        }
        restore(lock);
    }
}
