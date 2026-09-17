//! Default-value wrapper for a cache position.
//!
//! `cache_position_write_default_value` is retailOS `FUN_082e3bcc` at
//! `0x082e3bcc` (20 instruction bytes, followed by its literal word at
//! `0x082e3be0`; the next separately linked entry begins at `0x082e3be4`).
//! Every ARM `B`/`BL` word in `osos.dec` was decoded: five direct callers, all
//! unconditional plain `bl` at `0x082e0028`, `0x082e022c`, `0x082e02d8`,
//! `0x082e6140`, and `0x082e67a4`; no predicated forms or tail branches target
//! this entry.
//!
//! It reads the cache format halfword at `cache + 0x6c`, selects `0x0000ffff`
//! unless that format is 8 (then `0x0fffffff`), and tail-branches to the
//! common writer entry at `0x082e39f4`. The incoming `r2` is overwritten;
//! incoming `r3` passes through as the common writer's fourth argument.
//! Deliberate deviation: that common writer is not ported, so target builds
//! dispatch to its verified retailOS address and host tests install a recording
//! seam rather than infer its cache-update behavior.

#[cfg(not(target_os = "none"))]
use core::ptr;

pub(crate) type WriteCachePositionValue = unsafe extern "C" fn(*mut u8, u32, u32, u32) -> u32;

#[cfg(target_os = "none")]
#[inline(always)]
pub(crate) unsafe fn write_cache_position_value(
    cache: *mut u8,
    position: u32,
    value: u32,
    packed_value: u32,
) -> u32 {
    let write: WriteCachePositionValue = core::mem::transmute(0x082e_39f4usize);
    write(cache, position, value, packed_value)
}

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
struct CachePositionValueHostOps {
    write: WriteCachePositionValue,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_write_cache_position_value(
    _cache: *mut u8,
    _position: u32,
    _value: u32,
    _packed_value: u32,
) -> u32 {
    panic!("a FAT port called common cache-position writer without a host seam")
}

#[cfg(not(target_os = "none"))]
const DEFAULT_CACHE_POSITION_VALUE_HOST_OPS: CachePositionValueHostOps =
    CachePositionValueHostOps {
        write: unavailable_write_cache_position_value,
    };

#[cfg(not(target_os = "none"))]
static mut CACHE_POSITION_VALUE_HOST_OPS: CachePositionValueHostOps =
    DEFAULT_CACHE_POSITION_VALUE_HOST_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
pub(crate) unsafe fn write_cache_position_value(
    cache: *mut u8,
    position: u32,
    value: u32,
    packed_value: u32,
) -> u32 {
    let ops = ptr::read_volatile(ptr::addr_of!(CACHE_POSITION_VALUE_HOST_OPS));
    (ops.write)(cache, position, value, packed_value)
}

#[cfg(all(test, not(target_os = "none")))]
pub(crate) static CACHE_POSITION_VALUE_WRITE_TEST_LOCK: parking_lot::Mutex<()> =
    parking_lot::Mutex::new(());

#[cfg(all(test, not(target_os = "none")))]
pub(crate) unsafe fn replace_write_cache_position_value(
    write: WriteCachePositionValue,
) -> WriteCachePositionValue {
    let previous = CACHE_POSITION_VALUE_HOST_OPS.write;
    CACHE_POSITION_VALUE_HOST_OPS = CachePositionValueHostOps { write };
    previous
}

/// Selects the format-specific default and writes it through the common cache writer.
///
/// Original: `FUN_082e3bcc` at `0x082e3bcc`, 20 bytes, five unconditional
/// plain `bl` call sites (binary-verified). `unused` names the incoming `r2`:
/// the original unconditionally replaces it before the tail branch. There is
/// no NULL guard before the aligned halfword load at `cache + 0x6c`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cache_position_write_default_value(
    cache: *mut u8,
    position: u32,
    _unused: u32,
    packed_value: u32,
) -> u32 {
    let value = if cache.add(0x6c).cast::<u16>().read() == 8 {
        0x0fff_ffff
    } else {
        0x0000_ffff
    };
    write_cache_position_value(cache, position, value, packed_value)
}

#[cfg(all(test, not(target_os = "none")))]
mod tests {
    use super::*;

    #[repr(C, align(4))]
    struct CacheFixture {
        before_format: [u8; 0x6c],
        format: u16,
        after_format: u16,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct Call {
        cache: usize,
        position: u32,
        value: u32,
        packed_value: u32,
    }

    static TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    static mut LAST_CALL: Option<Call> = None;

    unsafe extern "C" fn recording_writer(
        cache: *mut u8,
        position: u32,
        value: u32,
        packed_value: u32,
    ) -> u32 {
        LAST_CALL = Some(Call {
            cache: cache as usize,
            position,
            value,
            packed_value,
        });
        0xa5a5_5a5a
    }

    unsafe fn call_with_format(format: u16, unused: u32, packed_value: u32) -> (u32, Call) {
        let mut cache = CacheFixture {
            before_format: [0; 0x6c],
            format,
            after_format: 0,
        };
        LAST_CALL = None;
        let cache_ptr = (&mut cache as *mut CacheFixture).cast::<u8>();
        let result = cache_position_write_default_value(
            cache_ptr,
            0x1234_5678,
            unused,
            packed_value,
        );
        let call = LAST_CALL.unwrap();
        assert_eq!(call.cache, cache_ptr as usize);
        (result, call)
    }

    #[test]
    fn selects_sixteen_bit_default_for_non_eight_formats() {
        let _guard = TEST_LOCK.lock();
        let previous = unsafe { replace_write_cache_position_value(recording_writer) };

        let (result, call) = unsafe { call_with_format(3, 0xdead_beef, 0x7654_3210) };

        unsafe { replace_write_cache_position_value(previous) };
        assert_eq!(result, 0xa5a5_5a5a);
        assert_eq!(call.value, 0x0000_ffff);
        assert_eq!(call.position, 0x1234_5678);
        assert_eq!(call.packed_value, 0x7654_3210);
    }

    #[test]
    fn selects_twenty_eight_bit_default_only_for_format_eight() {
        let _guard = TEST_LOCK.lock();
        let previous = unsafe { replace_write_cache_position_value(recording_writer) };

        let (_, format_eight_call) = unsafe { call_with_format(8, 0, 0x0123_4567) };
        let (_, other_format_call) = unsafe { call_with_format(9, u32::MAX, 0x89ab_cdef) };

        unsafe { replace_write_cache_position_value(previous) };
        assert_eq!(format_eight_call.value, 0x0fff_ffff);
        assert_eq!(format_eight_call.packed_value, 0x0123_4567);
        assert_eq!(other_format_call.value, 0x0000_ffff);
        assert_eq!(other_format_call.packed_value, 0x89ab_cdef);
    }

}
