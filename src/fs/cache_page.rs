//! Cache-page halfword access.
//!
//! `cache_position_halfword_access` is retailOS `FUN_082e1a34` at
//! `0x082e1a34` (68 bytes; the next separately linked function begins at
//! `0x082e1a78`). Every ARM `B`/`BL` word in `osos.dec` was decoded: there
//! are 10 direct call sites, all unconditional plain `bl`; no predicated
//! forms or tail branches reach it.
//!
//! The function resolves the cache page containing `position` through the
//! unported resolver at `0x082e3d78`, passing `write` as its third argument.
//! A NULL page returns zero without touching `value`. Otherwise, the low byte
//! of `position` selects one of 256 aligned halfwords in that page: `write ==
//! 0` copies the selected halfword to `*value`; any nonzero `write` copies
//! `*value` into it. Successful transfers return one.
//!
//! Deliberate deviation: the page resolver is not ported. Target builds call
//! its retailOS load address directly; host tests replace it with a recording
//! seam. The resolver is responsible for caching and dirty-page bookkeeping,
//! so this wrapper intentionally does not infer either behavior.

#[cfg(not(target_os = "none"))]
use core::ptr;

type CachePageResolve = unsafe extern "C" fn(*mut u8, u32, u32) -> *mut u8;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn cache_page_resolve(cache: *mut u8, position: u32, write: u32) -> *mut u8 {
    let resolve: CachePageResolve = core::mem::transmute(0x082e_3d78usize);
    resolve(cache, position, write)
}

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
struct CachePageHostOps {
    resolve: CachePageResolve,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_cache_page_resolve(
    _cache: *mut u8,
    _position: u32,
    _write: u32,
) -> *mut u8 {
    panic!("cache_position_halfword_access resolver called without a host seam")
}

#[cfg(not(target_os = "none"))]
const DEFAULT_CACHE_PAGE_HOST_OPS: CachePageHostOps = CachePageHostOps {
    resolve: unavailable_cache_page_resolve,
};

#[cfg(not(target_os = "none"))]
static mut CACHE_PAGE_HOST_OPS: CachePageHostOps = DEFAULT_CACHE_PAGE_HOST_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn cache_page_resolve(cache: *mut u8, position: u32, write: u32) -> *mut u8 {
    let ops = ptr::read_volatile(ptr::addr_of!(CACHE_PAGE_HOST_OPS));
    (ops.resolve)(cache, position, write)
}

/// Transfers one halfword between a cache page and `value`.
///
/// Original: `FUN_082e1a34` at `0x082e1a34`, 68 bytes, 10 plain `bl` call
/// sites (binary-verified). The page resolver receives the unmodified
/// `cache`, `position`, and `write` ABI arguments. `value` has no NULL guard
/// on the successful path, matching the retail `ldrh`/`strh` operations.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cache_position_halfword_access(
    cache: *mut u8,
    position: u32,
    value: *mut u16,
    write: u32,
) -> u32 {
    let page = cache_page_resolve(cache, position, write);
    if page.is_null() {
        return 0;
    }

    let halfword = page.cast::<u16>().add((position & 0xff) as usize);
    if write == 0 {
        value.write(halfword.read());
    } else {
        halfword.write(value.read());
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr::addr_of_mut;

    static TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    static mut RESOLVER_RESULT: *mut u8 = ptr::null_mut();
    static mut RESOLVER_CALL: Option<(*mut u8, u32, u32)> = None;

    #[repr(align(4))]
    struct CachePage([u16; 256]);

    static mut PAGE: CachePage = CachePage([0; 256]);

    unsafe extern "C" fn record_resolve(cache: *mut u8, position: u32, write: u32) -> *mut u8 {
        RESOLVER_CALL = Some((cache, position, write));
        RESOLVER_RESULT
    }

    struct HostOpsReset(CachePageHostOps);

    impl Drop for HostOpsReset {
        fn drop(&mut self) {
            unsafe {
                CACHE_PAGE_HOST_OPS = self.0;
            }
        }
    }

    unsafe fn install_resolver() -> HostOpsReset {
        let previous = CACHE_PAGE_HOST_OPS;
        CACHE_PAGE_HOST_OPS = CachePageHostOps {
            resolve: record_resolve,
        };
        HostOpsReset(previous)
    }

    #[test]
    fn resolver_failure_preserves_value() {
        let _guard = TEST_LOCK.lock();
        let _reset = unsafe { install_resolver() };
        let cache = 0x1234usize as *mut u8;
        let mut value = 0x6a5cu16;

        unsafe {
            RESOLVER_RESULT = ptr::null_mut();
            RESOLVER_CALL = None;
            assert_eq!(cache_position_halfword_access(cache, 0xfeed_be5a, &mut value, 0), 0);
            assert_eq!(RESOLVER_CALL, Some((cache, 0xfeed_be5a, 0)));
        }
        assert_eq!(value, 0x6a5c);
    }

    #[test]
    fn read_uses_low_position_byte_as_halfword_slot() {
        let _guard = TEST_LOCK.lock();
        let _reset = unsafe { install_resolver() };
        let cache = 0x1234usize as *mut u8;
        let mut value = 0;

        unsafe {
            PAGE.0 = [0; 256];
            PAGE.0[0x5a] = 0xbad1;
            RESOLVER_RESULT = addr_of_mut!(PAGE.0).cast::<u8>();
            RESOLVER_CALL = None;
            assert_eq!(cache_position_halfword_access(cache, 0xdead_be5a, &mut value, 0), 1);
            assert_eq!(RESOLVER_CALL, Some((cache, 0xdead_be5a, 0)));
        }
        assert_eq!(value, 0xbad1);
    }

    #[test]
    fn nonzero_write_updates_selected_slot() {
        let _guard = TEST_LOCK.lock();
        let _reset = unsafe { install_resolver() };
        let cache = 0x9876usize as *mut u8;
        let mut value = 0x4d2eu16;

        unsafe {
            PAGE.0 = [0; 256];
            RESOLVER_RESULT = addr_of_mut!(PAGE.0).cast::<u8>();
            RESOLVER_CALL = None;
            assert_eq!(
                cache_position_halfword_access(cache, 0x0102_0307, &mut value, u32::MAX),
                1
            );
            assert_eq!(PAGE.0[7], 0x4d2e);
            assert_eq!(RESOLVER_CALL, Some((cache, 0x0102_0307, u32::MAX)));
        }
    }
}
