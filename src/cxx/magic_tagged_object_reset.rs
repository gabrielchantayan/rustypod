//! `magic_tagged_object_reset` — retailOS `FUN_08049428` at `0x08049428`.
//!
//! Raw `osos.dec` establishes the 60-byte extent 0x08049428..0x08049464; the
//! literal word at 0x08049464 is the global mutex address, and the next
//! separately entered function begins at 0x08049468. The body has two plain
//! `bl` calls (the POSIX mutex-lock veneer and `bzero`) and one predicated
//! `blne` call (`magic_tagged_object_destroy`).
//!
//! # Algorithm
//!
//! A NULL object returns zero. Otherwise the routine locks the global C++
//! mutex, destroys the optional target pointer at object `+0x08`, clears the
//! 28-byte object, then tail-branches to the mutex unlock veneer.
//!
//! Target pointers remain `u32` words, preserving ARM offsets on 64-bit hosts.
//! Deliberate deviations: the existing `REGION_MUTEX_OPS` seam replaces the
//! retail mutex veneers, and Rust calls rather than tail-branches to unlock.

use crate::cxx::magic_tagged_object_destroy::magic_tagged_object_destroy;
use crate::heap::block_region::REGION_MUTEX_OPS;
use crate::libc::bzero::bzero;

const MAGIC_TAGGED_OBJECT_MUTEX_ADDRESS: usize = 0x08a7_74c0;
const TARGET_WORD: usize = 0x08 / 4;
const OBJECT_LEN: i32 = 0x1c;

#[cfg(target_os = "none")]
#[inline(always)]
fn global_mutex() -> *mut u8 {
    MAGIC_TAGGED_OBJECT_MUTEX_ADDRESS as *mut u8
}

#[cfg(not(target_os = "none"))]
static mut HOST_MAGIC_TAGGED_OBJECT_MUTEX: [u8; 16] = [0; 16];

#[cfg(not(target_os = "none"))]
#[inline(always)]
fn global_mutex() -> *mut u8 {
    core::ptr::addr_of_mut!(HOST_MAGIC_TAGGED_OBJECT_MUTEX).cast()
}

/// Destroys the optional target in `object` and clears its seven target words.
///
/// # Safety
///
/// `object` is either NULL or points to a writable 28-byte target-layout
/// object. Its word at `+0x08`, when nonzero, must name an object accepted by
/// [`magic_tagged_object_destroy`].
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn magic_tagged_object_reset(object: *mut u32) -> u32 {
    if object.is_null() {
        return 0;
    }

    let lock = core::ptr::read_volatile(core::ptr::addr_of!(REGION_MUTEX_OPS.lock));
    lock(global_mutex());
    let target = object.add(TARGET_WORD).read() as *mut u32;
    if !target.is_null() {
        magic_tagged_object_destroy(target);
    }
    bzero(object.cast(), OBJECT_LEN);
    let unlock = core::ptr::read_volatile(core::ptr::addr_of!(REGION_MUTEX_OPS.unlock));
    unlock(global_mutex())
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::block_region::RegionMutexOps;
    static mut EVENTS: [(*mut u8, u32); 2] = [(core::ptr::null_mut(), 0); 2];
    use core::ptr::{addr_of, addr_of_mut};
    use parking_lot::{Mutex, MutexGuard};

    static LOCK: Mutex<()> = Mutex::new(());
    static mut EVENT_COUNT: usize = 0;

    unsafe extern "C" fn record_lock(mutex: *mut u8) -> u32 {
        EVENTS[EVENT_COUNT] = (mutex, 0);
        EVENT_COUNT += 1;
        0x11
    }

    unsafe extern "C" fn record_unlock(mutex: *mut u8) -> u32 {
        EVENTS[EVENT_COUNT] = (mutex, 1);
        EVENT_COUNT += 1;
        0x22
    }

    struct Reset {
        _guard: MutexGuard<'static, ()>,
        ops: RegionMutexOps,
    }

    impl Drop for Reset {
        fn drop(&mut self) {
            unsafe { addr_of_mut!(REGION_MUTEX_OPS).write(self.ops); }
        }
    }

    fn install() -> Reset {
        let guard = LOCK.lock();
        unsafe {
            let ops = addr_of!(REGION_MUTEX_OPS).read();
            REGION_MUTEX_OPS = RegionMutexOps { lock: record_lock, unlock: record_unlock };
            EVENTS = [(core::ptr::null_mut(), 0); 2];
            EVENT_COUNT = 0;
            Reset { _guard: guard, ops }
        }
    }

    #[test]
    fn null_object_does_not_touch_the_mutex() {
        let _reset = install();
        assert_eq!(unsafe { magic_tagged_object_reset(core::ptr::null_mut()) }, 0);
        assert_eq!(unsafe { EVENT_COUNT }, 0);
    }

    #[test]
    fn clears_a_null_target_object_between_lock_and_unlock() {
        let _reset = install();
        let mut object = [0xfeed_beefu32; 7];
        object[TARGET_WORD] = 0;

        assert_eq!(unsafe { magic_tagged_object_reset(object.as_mut_ptr()) }, 0x22);
        assert_eq!(object, [0; 7]);
        unsafe {
            assert_eq!(EVENT_COUNT, 2);
            assert_eq!(EVENTS[0], (global_mutex(), 0));
            assert_eq!(EVENTS[1], (global_mutex(), 1));
        }
    }
}
