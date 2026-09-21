//! Flushes a pending cache request.
//!
//! `cache_request_flush` is retailOS `FUN_082b172c` at `0x082b172c`. Raw
//! `osos.dec` words establish the 84-byte body `0x082b172c..0x082b177f`; the
//! next separately entered function begins with `push {r4-r11,lr}` at
//! `0x082b1780`. It has two outbound plain unconditional `bl` instructions
//! (`cache_block_prepare` and `drive_slot_flush`) and no predicated `bl`.
//! Whole-image A32 decoding finds three inbound plain `bl` call sites and no
//! predicated inbound `bl` call sites.
//!
//! If request word five is nonzero, the routine prepares and flushes its cache
//! block with dirty and timestamp flags set. On success it clears word five,
//! loads the halfword at `request[0][0x78]` as a drive index, and flushes the
//! drive slot's pending metadata.
//!
//! Deliberate deviations: the target calls the existing Rust ports directly;
//! host tests use an operation seam because those ports have independent host
//! seams.

#[cfg(not(target_os = "none"))]
use core::ptr;

#[cfg(target_os = "none")]
use super::{cache_block_prepare::cache_block_prepare, drive_slot_flush::drive_slot_flush_pending_writes};

/// Target word index of the request's owning descriptor.
const REQUEST_DESCRIPTOR_WORD: usize = 0;
/// Target word index of the pending-flush flag.
const REQUEST_PENDING_FLUSH_WORD: usize = 5;
/// Byte offset of the drive context halfword in the descriptor.
const DESCRIPTOR_DRIVE_CONTEXT_OFFSET: usize = 0x78;

#[derive(Clone, Copy)]
pub struct CacheRequestFlushOps {
    pub prepare: unsafe extern "C" fn(*mut u8, u32, u32) -> u32,
    pub flush_drive: unsafe extern "C" fn(u32) -> u32,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_prepare(_request: *mut u8, _dirty: u32, _timestamp: u32) -> u32 { 0 }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_flush_drive(_index: u32) -> u32 { 0 }

#[cfg(not(target_os = "none"))]
pub static mut CACHE_REQUEST_FLUSH_OPS: CacheRequestFlushOps = CacheRequestFlushOps {
    prepare: missing_prepare,
    flush_drive: missing_flush_drive,
};

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn cache_request_flush_ops() -> CacheRequestFlushOps {
    CacheRequestFlushOps { prepare: cache_block_prepare, flush_drive: drive_slot_flush_pending_writes }
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn cache_request_flush_ops() -> CacheRequestFlushOps {
    ptr::read_volatile(ptr::addr_of!(CACHE_REQUEST_FLUSH_OPS))
}

/// Flushes a request's pending cache block and its drive metadata.
///
/// # Safety
///
/// `request` must provide target-width words through index five. When word five
/// is nonzero, word zero must be a valid target-width descriptor pointer with a
/// readable halfword at `+0x78`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cache_request_flush(request: *mut u8) -> u32 {
    let words = request.cast::<u32>();
    if words.add(REQUEST_PENDING_FLUSH_WORD).read_volatile() == 0 {
        return 1;
    }

    let ops = cache_request_flush_ops();
    if (ops.prepare)(request, 1, 1) == 0 {
        return 1;
    }

    words.add(REQUEST_PENDING_FLUSH_WORD).write_volatile(0);
    let descriptor = words.add(REQUEST_DESCRIPTOR_WORD).read_volatile() as usize as *mut u8;
    let drive_index = descriptor.add(DESCRIPTOR_DRIVE_CONTEXT_OFFSET).cast::<u16>().read_volatile() as u32;
    if (ops.flush_drive)(drive_index) == 0 { 0 } else { 1 }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use parking_lot::Mutex;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut PREPARE_RESULT: u32 = 1;
    static mut FLUSH_RESULT: u32 = 1;
    static mut PREPARE_CALLS: u32 = 0;
    static mut FLUSH_CALLS: u32 = 0;

    unsafe extern "C" fn prepare(request: *mut u8, dirty: u32, timestamp: u32) -> u32 {
        unsafe { PREPARE_CALLS += 1; }
        assert_eq!((dirty, timestamp), (1, 1));
        assert!(!request.is_null());
        unsafe { PREPARE_RESULT }
    }
    unsafe extern "C" fn flush_drive(index: u32) -> u32 {
        assert_eq!(index, 7);
        unsafe { FLUSH_CALLS += 1; FLUSH_RESULT }
    }

    struct Restore;
    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe { CACHE_REQUEST_FLUSH_OPS = CacheRequestFlushOps { prepare: missing_prepare, flush_drive: missing_flush_drive }; }
        }
    }

    fn install() -> (parking_lot::MutexGuard<'static, ()>, Restore) {
        let guard = OPS_LOCK.lock();
        unsafe {
            PREPARE_RESULT = 1;
            FLUSH_RESULT = 1;
            PREPARE_CALLS = 0;
            FLUSH_CALLS = 0;
            CACHE_REQUEST_FLUSH_OPS = CacheRequestFlushOps { prepare, flush_drive };
        }
        (guard, Restore)
    }

    #[test]
    fn pending_flag_prepare_failure_and_drive_failure_follow_stock_boundaries() {
        let (_guard, _restore) = install();
        let Some(slab) = try_map_u32_slab(hints::CACHE_REQUEST_FLUSH, 0x1000) else {
            assert!(crate::testing::note_missing_u32_fixture("fs/cache_request_flush"));
            return;
        };
        let request = slab.cast::<u32>();
        let descriptor = unsafe { slab.add(0x100) };
        unsafe {
            request.write(descriptor as usize as u32);
            descriptor.add(DESCRIPTOR_DRIVE_CONTEXT_OFFSET).cast::<u16>().write(7);
            request.add(REQUEST_PENDING_FLUSH_WORD).write(0);
            assert_eq!(cache_request_flush(slab), 1);
            assert_eq!((PREPARE_CALLS, FLUSH_CALLS), (0, 0));

            request.add(REQUEST_PENDING_FLUSH_WORD).write(1);
            PREPARE_RESULT = 0;
            assert_eq!(cache_request_flush(slab), 1);
            assert_eq!(request.add(REQUEST_PENDING_FLUSH_WORD).read(), 1);
            assert_eq!((PREPARE_CALLS, FLUSH_CALLS), (1, 0));

            PREPARE_RESULT = 1;
            FLUSH_RESULT = 0;
            assert_eq!(cache_request_flush(slab), 0);
            assert_eq!(request.add(REQUEST_PENDING_FLUSH_WORD).read(), 0);
            assert_eq!((PREPARE_CALLS, FLUSH_CALLS), (2, 1));
        }
    }
}
