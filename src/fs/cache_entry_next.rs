//! Sequential cache-entry allocation.
//!
//! `cache_entry_allocate_next` is retailOS `FUN_082e4320` at `0x082e4320`
//! (52 bytes; the following word at `0x082e4354` is the BSS-address literal
//! `0x08a0a744`, and the next separately entered function starts at
//! `0x082e4358`). The raw body contains three unconditional `bl` instructions
//! and no predicated call forms.
//!
//! Under the cache lock, the function advances the BSS allocation cursor by
//! 508 bytes. It then asks the cache-entry allocator for an entry keyed by the
//! new cursor value, zero block index, and incoming cache key; the allocator's
//! output pointer is returned. Deliberate deviation: Rust preserves
//! `cache_key` across the lock calls explicitly, instead of relying on their
//! observed preservation of ARM `r3`.

#[cfg(target_os = "none")]
use super::cache_lock::{cache_lock_signal, cache_lock_wait};

const CACHE_CURSOR_ADDRESS: usize = 0x08a0_a744;
const CACHE_CURSOR_STRIDE: u32 = 0x1fc;

type CacheEntryAllocate = unsafe extern "C" fn(*mut *mut u8, u32, u32, u32) -> u32;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn cache_cursor() -> *mut u32 {
    CACHE_CURSOR_ADDRESS as *mut u32
}

#[cfg(not(target_os = "none"))]
static mut HOST_CACHE_CURSOR: u32 = 0;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn cache_cursor() -> *mut u32 {
    core::ptr::addr_of_mut!(HOST_CACHE_CURSOR)
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn cache_entry_allocate(entry_out: *mut *mut u8, cursor: u32, cache_key: u32) {
    let function: CacheEntryAllocate = core::mem::transmute(0x082d_fdf0usize);
    function(entry_out, cursor, 0, cache_key);
}

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
struct CacheEntryNextHostOps {
    allocate: CacheEntryAllocate,
    enter: unsafe extern "C" fn(),
    leave: unsafe extern "C" fn(),
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_allocate(
    _entry_out: *mut *mut u8,
    _cursor: u32,
    _block_index: u32,
    _cache_key: u32,
) -> u32 {
    panic!("cache_entry_allocate_next allocator called without a host seam")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_noop() {}

#[cfg(not(target_os = "none"))]
const DEFAULT_CACHE_ENTRY_NEXT_HOST_OPS: CacheEntryNextHostOps = CacheEntryNextHostOps {
    allocate: unavailable_allocate,
    enter: host_noop,
    leave: host_noop,
};

#[cfg(not(target_os = "none"))]
static mut CACHE_ENTRY_NEXT_HOST_OPS: CacheEntryNextHostOps = DEFAULT_CACHE_ENTRY_NEXT_HOST_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn cache_entry_allocate(entry_out: *mut *mut u8, cursor: u32, cache_key: u32) {
    (core::ptr::read_volatile(core::ptr::addr_of!(CACHE_ENTRY_NEXT_HOST_OPS)).allocate)(
        entry_out,
        cursor,
        0,
        cache_key,
    );
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn cache_lock_enter() {
    cache_lock_wait();
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn cache_lock_leave() {
    cache_lock_signal();
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn cache_lock_enter() {
    (core::ptr::read_volatile(core::ptr::addr_of!(CACHE_ENTRY_NEXT_HOST_OPS)).enter)();
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn cache_lock_leave() {
    (core::ptr::read_volatile(core::ptr::addr_of!(CACHE_ENTRY_NEXT_HOST_OPS)).leave)();
}

/// Allocates a cache entry using the next global cache cursor position.
///
/// Original: `FUN_082e4320` at `0x082e4320`, 52 bytes, 3 plain `bl` calls and
/// no predicated forms (binary-verified). The `cache_key` parameter preserves
/// the original incoming `r3` value.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cache_entry_allocate_next(cache_key: u32) -> *mut u8 {
    cache_lock_enter();
    let cursor = cache_cursor().read_volatile().wrapping_add(CACHE_CURSOR_STRIDE);
    cache_cursor().write_volatile(cursor);
    cache_lock_leave();

    let mut entry = core::ptr::null_mut();
    cache_entry_allocate(&mut entry, cursor, cache_key);
    entry
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::{Mutex, MutexGuard};

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut ALLOC_CALLS: [(u32, u32, u32); 2] = [(0, 0, 0); 2];
    static mut ALLOC_CALL_COUNT: usize = 0;
    static mut ALLOC_RESULT: *mut u8 = core::ptr::null_mut();
    static mut LOCK_CALLS: [u8; 4] = [0; 4];
    static mut LOCK_CALL_COUNT: usize = 0;

    unsafe extern "C" fn record_allocate(
        entry_out: *mut *mut u8,
        cursor: u32,
        block_index: u32,
        cache_key: u32,
    ) -> u32 {
        ALLOC_CALLS[ALLOC_CALL_COUNT] = (cursor, block_index, cache_key);
        ALLOC_CALL_COUNT += 1;
        *entry_out = ALLOC_RESULT;
        0
    }

    unsafe extern "C" fn record_enter() {
        LOCK_CALLS[LOCK_CALL_COUNT] = 1;
        LOCK_CALL_COUNT += 1;
    }

    unsafe extern "C" fn record_leave() {
        LOCK_CALLS[LOCK_CALL_COUNT] = 2;
        LOCK_CALL_COUNT += 1;
    }

    struct Fixture(MutexGuard<'static, ()>);

    impl Fixture {
        fn install(cursor: u32, result: *mut u8) -> Self {
            let guard = TEST_LOCK.lock();
            unsafe {
                HOST_CACHE_CURSOR = cursor;
                ALLOC_CALLS = [(0, 0, 0); 2];
                ALLOC_CALL_COUNT = 0;
                ALLOC_RESULT = result;
                LOCK_CALLS = [0; 4];
                LOCK_CALL_COUNT = 0;
                core::ptr::addr_of_mut!(CACHE_ENTRY_NEXT_HOST_OPS).write_volatile(CacheEntryNextHostOps {
                    allocate: record_allocate,
                    enter: record_enter,
                    leave: record_leave,
                });
            }
            Self(guard)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(CACHE_ENTRY_NEXT_HOST_OPS)
                    .write_volatile(DEFAULT_CACHE_ENTRY_NEXT_HOST_OPS);
            }
        }
    }

    #[test]
    fn advances_cursor_before_each_allocation_and_forwards_key() {
        let _fixture = Fixture::install(0x1000, 0x1234usize as *mut u8);

        assert_eq!(unsafe { cache_entry_allocate_next(0xa5a5_5a5a) }, 0x1234usize as *mut u8);
        assert_eq!(unsafe { cache_entry_allocate_next(7) }, 0x1234usize as *mut u8);
        assert_eq!(unsafe { ALLOC_CALLS }, [(0x11fc, 0, 0xa5a5_5a5a), (0x13f8, 0, 7)]);
        assert_eq!(unsafe { &LOCK_CALLS[..LOCK_CALL_COUNT] }, [1, 2, 1, 2]);
    }

    #[test]
    fn cursor_wraps_and_null_allocator_output_passes_through() {
        let _fixture = Fixture::install(u32::MAX - 0x100, core::ptr::null_mut());

        assert!(unsafe { cache_entry_allocate_next(0) }.is_null());
        assert_eq!(unsafe { ALLOC_CALLS[0] }, (0xfb, 0, 0));
        assert_eq!(unsafe { &LOCK_CALLS[..LOCK_CALL_COUNT] }, [1, 2]);
    }
}
