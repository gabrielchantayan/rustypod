//! OpenSSL `RAND_bytes` dispatch wrapper.
//!
//! Original: `FUN_080620f8` @ **0x080620f8** (52 bytes,
//! `0x080620f8..0x0806212c`; the distinct `FUN_0806212c` begins at
//! `0x0806212c`). A complete decode of every aligned ARM `B`/`BL` immediate
//! in `osos.dec` finds **8 direct `bl` call sites**, all unconditional:
//! `0x080600a0`, `0x08062648`, `0x080627b8`, `0x080627e0`, `0x08062878`,
//! `0x080628a0`, `0x080d4b48`, and `0x080e8c30`. No predicated direct call
//! enters this function.
//!
//! # Algorithm
//!
//! Calls the lazy RAND-method getter at `0x0806212c`, checks both the returned
//! method and its `RAND_METHOD.bytes` slot at `+0x04`, and tail-dispatches the
//! supplied buffer and signed byte count. Missing method or slot returns `-1`.
//! The adjacent wrappers use slots `+0x0c`, `+0x10`, and `+0x14` with the
//! OpenSSL `RAND_METHOD` `add`, `pseudorand`, and `status` signatures; this
//! identifies the `+0x04` slot as `RAND_bytes` rather than merely an unnamed
//! two-argument callback.
//!
//! # Deliberate deviations
//!
//! `FUN_0806212c` is not ported. Target builds call it at its verified retailOS
//! entry; host builds use an injectable getter because the target's raw 32-bit
//! method words cannot hold native-width function pointers. The target keeps
//! the exact two-word prefix and dispatches the raw `+0x04` word.

#[cfg(not(target_os = "none"))]
use core::ptr::addr_of;

const RETAIL_RAND_GET_METHOD: usize = 0x0806_212c;

/// Signature of `RAND_METHOD.bytes`.
pub type RandBytesCallback = unsafe extern "C" fn(buffer: *mut u8, count: i32) -> i32;

/// Target prefix of OpenSSL's `RAND_METHOD`; only the `bytes` slot is reached.
#[cfg(target_os = "none")]
#[repr(C)]
pub struct RandMethod {
    _seed: u32,
    bytes: u32,
}

#[cfg(target_os = "none")]
const _: [(); 4] = [(); core::mem::offset_of!(RandMethod, bytes)];

/// Host representation of the same slots.
///
/// Its native-width fields deliberately differ from retailOS's 4-byte words,
/// so tests can invoke an actual host callback instead of truncating it.
#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct RandMethod {
    _seed: usize,
    pub bytes: Option<RandBytesCallback>,
}

/// ABI of the lazy accessor `FUN_0806212c`.
pub type RandMethodGetter = unsafe extern "C" fn() -> *const RandMethod;

/// Host-only replacement for the still-unported RAND-method accessor.
#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct RandBytesOps {
    pub get_rand_method: RandMethodGetter,
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn rand_get_method() -> *const RandMethod {
    let getter: RandMethodGetter = core::mem::transmute(RETAIL_RAND_GET_METHOD);
    getter()
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_rand_method() -> *const RandMethod {
    core::ptr::null()
}

/// Default host operation: no installed RAND method, matching the wrapper's
/// failure path without inventing an implementation for `FUN_0806212c`.
#[cfg(not(target_os = "none"))]
pub const DEFAULT_RAND_BYTES_OPS: RandBytesOps = RandBytesOps {
    get_rand_method: missing_rand_method,
};

/// Host-side seam. Target builds always call `FUN_0806212c` directly.
#[cfg(not(target_os = "none"))]
pub static mut RAND_BYTES_OPS: RandBytesOps = DEFAULT_RAND_BYTES_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn rand_get_method() -> *const RandMethod {
    let ops = addr_of!(RAND_BYTES_OPS).read_volatile();
    (ops.get_rand_method)()
}

/// OpenSSL `RAND_bytes` — original: `FUN_080620f8` @ `0x080620f8` (52 bytes;
/// 8 direct, unconditional `bl` call sites, binary-verified).
///
/// # Safety
///
/// When a RAND method and its `bytes` slot are installed, `buffer` and `count`
/// must satisfy that callback's contract. The retail wrapper has no buffer or
/// count validation; it forwards both unchanged.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.rand_bytes")]
#[inline(never)]
pub unsafe extern "C" fn rand_bytes(buffer: *mut u8, count: i32) -> i32 {
    let method = rand_get_method();
    if method.is_null() {
        return -1;
    }

    #[cfg(target_os = "none")]
    {
        let bytes_word = core::ptr::addr_of!((*method).bytes).read();
        if bytes_word == 0 {
            return -1;
        }
        let bytes: RandBytesCallback = core::mem::transmute(bytes_word as usize);
        return bytes(buffer, count);
    }

    #[cfg(not(target_os = "none"))]
    match (*method).bytes {
        Some(bytes) => bytes(buffer, count),
        None => -1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut CURRENT_METHOD: *const RandMethod = core::ptr::null();
    static mut RECORDED_BUFFER: *mut u8 = core::ptr::null_mut();
    static mut RECORDED_COUNT: i32 = 0;

    unsafe extern "C" fn test_get_rand_method() -> *const RandMethod {
        CURRENT_METHOD
    }

    unsafe extern "C" fn write_test_bytes(buffer: *mut u8, count: i32) -> i32 {
        RECORDED_BUFFER = buffer;
        RECORDED_COUNT = count;
        for index in 0..count.max(0) as usize {
            buffer.add(index).write(0xa0 | index as u8);
        }
        37
    }

    static METHOD_WITH_BYTES: RandMethod = RandMethod {
        _seed: 0,
        bytes: Some(write_test_bytes),
    };
    static METHOD_WITHOUT_BYTES: RandMethod = RandMethod {
        _seed: 0,
        bytes: None,
    };

    unsafe fn install_method(method: *const RandMethod) {
        CURRENT_METHOD = method;
        RAND_BYTES_OPS = RandBytesOps {
            get_rand_method: test_get_rand_method,
        };
    }

    #[test]
    fn missing_method_returns_negative_one_without_touching_buffer() {
        let _guard = TEST_LOCK.lock();
        let mut buffer = [0x5au8; 3];
        unsafe {
            install_method(core::ptr::null());
            assert_eq!(rand_bytes(buffer.as_mut_ptr(), buffer.len() as i32), -1);
            RAND_BYTES_OPS = DEFAULT_RAND_BYTES_OPS;
        }
        assert_eq!(buffer, [0x5a; 3]);
    }

    #[test]
    fn missing_bytes_slot_returns_negative_one_without_touching_buffer() {
        let _guard = TEST_LOCK.lock();
        let mut buffer = [0x5au8; 3];
        unsafe {
            install_method(core::ptr::addr_of!(METHOD_WITHOUT_BYTES));
            assert_eq!(rand_bytes(buffer.as_mut_ptr(), buffer.len() as i32), -1);
            RAND_BYTES_OPS = DEFAULT_RAND_BYTES_OPS;
        }
        assert_eq!(buffer, [0x5a; 3]);
    }

    #[test]
    fn dispatches_buffer_and_signed_count_unchanged() {
        let _guard = TEST_LOCK.lock();
        let mut buffer = [0u8; 5];
        unsafe {
            install_method(core::ptr::addr_of!(METHOD_WITH_BYTES));
            assert_eq!(rand_bytes(buffer.as_mut_ptr(), 5), 37);
            let recorded_buffer = RECORDED_BUFFER;
            let recorded_count = RECORDED_COUNT;
            RAND_BYTES_OPS = DEFAULT_RAND_BYTES_OPS;
            assert_eq!(recorded_buffer, buffer.as_mut_ptr());
            assert_eq!(recorded_count, 5);
        }
        assert_eq!(buffer, [0xa0, 0xa1, 0xa2, 0xa3, 0xa4]);
    }

    #[test]
    fn forwards_zero_count_to_installed_method() {
        let _guard = TEST_LOCK.lock();
        let mut buffer = [0x5au8; 1];
        unsafe {
            install_method(core::ptr::addr_of!(METHOD_WITH_BYTES));
            assert_eq!(rand_bytes(buffer.as_mut_ptr(), 0), 37);
            let recorded_count = RECORDED_COUNT;
            RAND_BYTES_OPS = DEFAULT_RAND_BYTES_OPS;
            assert_eq!(recorded_count, 0);
        }
        assert_eq!(buffer, [0x5a]);
    }
}
