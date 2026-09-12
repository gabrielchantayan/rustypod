//! Shared resident boundary for `FUN_082e0cac` at `0x082e0cac`.
//!
//! The 368-byte helper decodes the raw value at a FAT position. It remains
//! unported; target builds call its verified retailOS entry, while host tests
//! replace only this call boundary. Keeping the seam here prevents individual
//! FAT traversal ports from inventing independent models of its behavior.

#[cfg(not(target_os = "none"))]
use core::ptr;

/// ABI of unported `FUN_082e0cac` at `0x082e0cac`.
pub(crate) type ReadCachePositionValue = unsafe extern "C" fn(*mut u8, u32, *mut u32) -> u32;

#[cfg(target_os = "none")]
#[inline(always)]
pub(crate) unsafe fn read_cache_position_value(
    cache: *mut u8,
    position: u32,
    value: *mut u32,
) -> u32 {
    let read: ReadCachePositionValue = core::mem::transmute(0x082e_0cacusize);
    read(cache, position, value)
}

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
struct CachePositionValueHostOps {
    read: ReadCachePositionValue,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_read_cache_position_value(
    _cache: *mut u8,
    _position: u32,
    _value: *mut u32,
) -> u32 {
    panic!("a FAT cache-position port called without a host reader seam")
}

#[cfg(not(target_os = "none"))]
const DEFAULT_CACHE_POSITION_VALUE_HOST_OPS: CachePositionValueHostOps = CachePositionValueHostOps {
    read: unavailable_read_cache_position_value,
};

#[cfg(not(target_os = "none"))]
static mut CACHE_POSITION_VALUE_HOST_OPS: CachePositionValueHostOps =
    DEFAULT_CACHE_POSITION_VALUE_HOST_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
pub(crate) unsafe fn read_cache_position_value(
    cache: *mut u8,
    position: u32,
    value: *mut u32,
) -> u32 {
    let ops = ptr::read_volatile(ptr::addr_of!(CACHE_POSITION_VALUE_HOST_OPS));
    (ops.read)(cache, position, value)
}

#[cfg(all(test, not(target_os = "none")))]
pub(crate) static CACHE_POSITION_VALUE_TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

#[cfg(all(test, not(target_os = "none")))]
pub(crate) unsafe fn replace_read_cache_position_value(
    read: ReadCachePositionValue,
) -> ReadCachePositionValue {
    let previous = CACHE_POSITION_VALUE_HOST_OPS.read;
    CACHE_POSITION_VALUE_HOST_OPS = CachePositionValueHostOps { read };
    previous
}
