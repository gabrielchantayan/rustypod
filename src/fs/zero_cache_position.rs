//! `find_zero_cache_position` — original: `FUN_082e1098` @ `0x082e1098`
//! (84 bytes, `0x082e1098..0x082e10e8`; the next separately linked function
//! begins at `0x082e10ec`). Every ARM `B`/`BL` word in `osos.dec` was decoded:
//! eight direct call sites, all unconditional plain `bl`; no predicated form
//! reaches this function.
//!
//! # Algorithm
//!
//! Searches the half-open unsigned position range `[start, end)`. At each
//! position it calls `FUN_082e0cac` to read an opaque cache value. A failed
//! read returns zero immediately; a successful zero value returns that
//! position; a nonzero value advances to the next position. Reaching `end`
//! without a zero also returns zero. Thus zero is both the not-found/error
//! sentinel and the valid result when the matching position is zero.
//!
//! # Deliberate deviations
//!
//! `FUN_082e0cac` at `0x082e0cac` is not ported, so target builds call its
//! verified resident address while host builds use a test seam. The retail
//! stack word is uninitialized before each call, but every successful body of
//! that helper writes it; Rust initializes it to make that same successful
//! path defined without exposing an observable difference.

#[cfg(not(target_os = "none"))]
use core::ptr;

/// ABI of unported `FUN_082e0cac` at `0x082e0cac`.
type ReadCachePositionValue = unsafe extern "C" fn(*mut u8, u32, *mut u32) -> u32;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn read_cache_position_value(cache: *mut u8, position: u32, value: *mut u32) -> u32 {
    let read: ReadCachePositionValue = core::mem::transmute(0x082e_0cacusize);
    read(cache, position, value)
}

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
struct ZeroCachePositionHostOps {
    read: ReadCachePositionValue,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_read_cache_position_value(
    _cache: *mut u8,
    _position: u32,
    _value: *mut u32,
) -> u32 {
    panic!("find_zero_cache_position called without a host seam")
}

#[cfg(not(target_os = "none"))]
const DEFAULT_ZERO_CACHE_POSITION_HOST_OPS: ZeroCachePositionHostOps = ZeroCachePositionHostOps {
    read: unavailable_read_cache_position_value,
};

#[cfg(not(target_os = "none"))]
static mut ZERO_CACHE_POSITION_HOST_OPS: ZeroCachePositionHostOps =
    DEFAULT_ZERO_CACHE_POSITION_HOST_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn read_cache_position_value(cache: *mut u8, position: u32, value: *mut u32) -> u32 {
    let ops = ptr::read_volatile(ptr::addr_of!(ZERO_CACHE_POSITION_HOST_OPS));
    (ops.read)(cache, position, value)
}

/// Finds the first cache position whose fetched value is zero.
///
/// Original: `FUN_082e1098` at `0x082e1098`, 84 bytes, with eight verified
/// unconditional direct `bl` callers. `cache` is forwarded without a NULL
/// guard exactly as the original does; the resident reader defines it. The
/// range comparison is unsigned and `end` is exclusive.
///
/// # Safety
///
/// `cache` and its position range must meet unported `FUN_082e0cac`'s
/// requirements. Its output pointer is valid only for the duration of each
/// transfer, as in the original stack-local ABI.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.find_zero_cache_position")]
#[inline(never)]
pub unsafe extern "C" fn find_zero_cache_position(
    cache: *mut u8,
    mut start: u32,
    end: u32,
) -> u32 {
    while start < end {
        let mut value = 0;
        if read_cache_position_value(cache, start, &mut value) == 0 {
            return 0;
        }
        if value == 0 {
            return start;
        }
        start = start.wrapping_add(1);
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    static TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    static mut READ_RESULTS: [(u32, u32); 8] = [(0, 0); 8];
    static mut READ_RESULT_COUNT: usize = 0;
    static mut READ_CALLS: [u32; 8] = [0; 8];
    static mut READ_CALL_COUNT: usize = 0;
    static mut READ_CACHE: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn record_read(cache: *mut u8, position: u32, value: *mut u32) -> u32 {
        READ_CACHE = cache;
        READ_CALLS[READ_CALL_COUNT] = position;
        let (status, result) = READ_RESULTS[READ_CALL_COUNT];
        READ_CALL_COUNT += 1;
        if status != 0 {
            value.write(result);
        }
        status
    }

    struct HostOpsReset(ZeroCachePositionHostOps);

    impl Drop for HostOpsReset {
        fn drop(&mut self) {
            unsafe {
                ZERO_CACHE_POSITION_HOST_OPS = self.0;
            }
        }
    }

    unsafe fn install_recorder(results: &[(u32, u32)]) -> HostOpsReset {
        READ_RESULTS = [(0, 0); 8];
        READ_RESULTS[..results.len()].copy_from_slice(results);
        READ_RESULT_COUNT = results.len();
        READ_CALLS = [0; 8];
        READ_CALL_COUNT = 0;
        READ_CACHE = core::ptr::null_mut();
        let previous = ZERO_CACHE_POSITION_HOST_OPS;
        ZERO_CACHE_POSITION_HOST_OPS = ZeroCachePositionHostOps { read: record_read };
        HostOpsReset(previous)
    }

    #[test]
    fn returns_first_zero_value_and_forwards_cache() {
        let _guard = TEST_LOCK.lock();
        let cache = 0x1234usize as *mut u8;
        let _reset = unsafe { install_recorder(&[(1, 0x44), (1, 0)]) };

        assert_eq!(unsafe { find_zero_cache_position(cache, 9, 13) }, 10);
        unsafe {
            assert_eq!(READ_CACHE, cache);
            assert_eq!(READ_CALL_COUNT, 2);
            assert_eq!(&READ_CALLS[..READ_CALL_COUNT], &[9, 10]);
        }
    }

    #[test]
    fn failure_and_exhaustion_return_zero() {
        let _guard = TEST_LOCK.lock();
        let cache = 0x5678usize as *mut u8;
        let _reset = unsafe { install_recorder(&[(1, 7), (0, 0), (1, 0)]) };

        assert_eq!(unsafe { find_zero_cache_position(cache, 20, 23) }, 0);
        unsafe {
            assert_eq!(READ_CALL_COUNT, 2);
            assert_eq!(&READ_CALLS[..READ_CALL_COUNT], &[20, 21]);
        }

        unsafe {
            READ_RESULTS = [(1, 7); 8];
            READ_CALLS = [0; 8];
            READ_CALL_COUNT = 0;
        }
        assert_eq!(unsafe { find_zero_cache_position(cache, 20, 22) }, 0);
        unsafe {
            assert_eq!(READ_CALL_COUNT, 2);
            assert_eq!(&READ_CALLS[..READ_CALL_COUNT], &[20, 21]);
        }
    }

    #[test]
    fn empty_or_reversed_range_skips_reader() {
        let _guard = TEST_LOCK.lock();
        let _reset = unsafe { install_recorder(&[(1, 0)]) };

        assert_eq!(unsafe { find_zero_cache_position(core::ptr::null_mut(), 5, 5) }, 0);
        assert_eq!(unsafe { find_zero_cache_position(core::ptr::null_mut(), 6, 5) }, 0);
        unsafe {
            assert_eq!(READ_CALL_COUNT, 0);
            assert_eq!(READ_RESULT_COUNT, 1);
        }
    }

    #[test]
    fn zero_position_remains_ambiguous_zero_result() {
        let _guard = TEST_LOCK.lock();
        let _reset = unsafe { install_recorder(&[(1, 0)]) };

        assert_eq!(unsafe { find_zero_cache_position(core::ptr::null_mut(), 0, 1) }, 0);
        unsafe {
            assert_eq!(READ_CALL_COUNT, 1);
            assert_eq!(READ_CALLS[0], 0);
        }
    }
}
