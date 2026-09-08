//! Normalize a string object's path separators, then prepend its volume prefix.
//!
//! `string_object_normalize_volume_path` — original: `FUN_081bd9b8` @
//! `0x081bd9b8` (44 bytes of code, despite Ghidra's incorrect 88-byte
//! extent; the next function begins at `0x081bd9e4`). Eighteen direct call
//! sites, all unconditional `bl`, zero predicated forms, and zero plain `b`
//! branches, verified by decoding every ARM B/BL word in `osos.dec`.
//!
//! Raw ARM calls the separator normalizer @ `0x08279198` as
//! `(path, '/', 0)`, loads the low byte at `volume_record + 0x10`, and
//! tail-calls @ `0x0827916c`. That tail target builds the UTF-16 string
//! `[volume_code, ':', '\\', 0]` and inserts it at character index zero.
//! Thus this wrapper turns a path into a slash-normalized volume-qualified
//! path. Neither helper is ported, so the deliberate deviation is the two
//! explicit dispatch boundaries below: device builds call their verified ROM
//! addresses and host tests install recorders. The wrapper itself has no NULL
//! guards, just like the original.

use super::string_object::StringObject;

const NORMALIZE_PATH_SEPARATORS_ADDRESS: usize = 0x0827_9198;
const PREPEND_VOLUME_PATH_PREFIX_ADDRESS: usize = 0x0827_916c;
const VOLUME_CODE_OFFSET: usize = 0x10;
const PATH_SEPARATOR: u32 = b'/' as u32;

/// ABI of `FUN_08279198`: replace `:`, `/`, and `\\` in `path` with the
/// requested separator. A zero third argument retains its non-escape-aware
/// path-normalization mode.
pub type NormalizePathSeparators = unsafe extern "C" fn(*mut StringObject, u32, u32);

/// ABI of `FUN_0827916c`: prepend `[volume_code, ':', '\\', 0]` as UTF-16
/// code units at character position zero.
pub type PrependVolumePathPrefix = unsafe extern "C" fn(*mut StringObject, u32);

/// Calls retained at the two unported helper boundaries.
#[derive(Clone, Copy)]
pub struct StringObjectPathOps {
    pub normalize_separators: NormalizePathSeparators,
    pub prepend_volume_prefix: PrependVolumePathPrefix,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_normalize_path_separators(
    path: *mut StringObject, separator: u32, escaped_mode: u32,
) {
    let helper: NormalizePathSeparators = core::mem::transmute(NORMALIZE_PATH_SEPARATORS_ADDRESS);
    helper(path, separator, escaped_mode);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_normalize_path_separators(
    _path: *mut StringObject, _separator: u32, _escaped_mode: u32,
) {
    panic!("string_object_normalize_volume_path requires helper 0x08279198");
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_prepend_volume_path_prefix(path: *mut StringObject, volume_code: u32) {
    let helper: PrependVolumePathPrefix = core::mem::transmute(PREPEND_VOLUME_PATH_PREFIX_ADDRESS);
    helper(path, volume_code);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_prepend_volume_path_prefix(
    _path: *mut StringObject, _volume_code: u32,
) {
    panic!("string_object_normalize_volume_path requires helper 0x0827916c");
}

#[cfg(target_os = "none")]
pub const DEFAULT_STRING_OBJECT_PATH_OPS: StringObjectPathOps = StringObjectPathOps {
    normalize_separators: firmware_normalize_path_separators,
    prepend_volume_prefix: firmware_prepend_volume_path_prefix,
};

#[cfg(not(target_os = "none"))]
pub const DEFAULT_STRING_OBJECT_PATH_OPS: StringObjectPathOps = StringObjectPathOps {
    normalize_separators: missing_normalize_path_separators,
    prepend_volume_prefix: missing_prepend_volume_path_prefix,
};

/// Active helper boundary. Target builds use the retailOS helpers; tests swap
/// in recorders until either helper is independently ported.
pub static mut STRING_OBJECT_PATH_OPS: StringObjectPathOps = DEFAULT_STRING_OBJECT_PATH_OPS;

#[inline(always)]
unsafe fn path_ops() -> StringObjectPathOps {
    core::ptr::read_volatile(core::ptr::addr_of!(STRING_OBJECT_PATH_OPS))
}

/// `string_object_normalize_volume_path` — original: `FUN_081bd9b8` @
/// `0x081bd9b8` (44 bytes, all code; 18 unconditional `bl` call sites,
/// binary-scanned).
///
/// Normalize `path`'s `:`, `/`, and `\\` separators to `/`, then prepend the
/// UTF-16 volume prefix selected by the byte at `volume_record + 0x10`. Both
/// pointers must be valid; neither is NULL-checked by the ARM implementation.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn string_object_normalize_volume_path(
    volume_record: *const u8, path: *mut StringObject,
) {
    let ops = path_ops();
    (ops.normalize_separators)(path, PATH_SEPARATOR, 0);
    let volume_code = volume_record.add(VOLUME_CODE_OFFSET).read() as u32;
    (ops.prepend_volume_prefix)(path, volume_code);
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use parking_lot::Mutex;
    use std::ptr;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: [u8; 2] = [0; 2];
    static mut CALL_COUNT: usize = 0;
    static mut NORMALIZE_ARGS: (usize, u32, u32) = (0, 0, 0);
    static mut PREFIX_ARGS: (usize, u32) = (0, 0);

    unsafe extern "C" fn record_normalize(path: *mut StringObject, separator: u32, escaped_mode: u32) {
        CALLS[CALL_COUNT] = 1;
        CALL_COUNT += 1;
        NORMALIZE_ARGS = (path as usize, separator, escaped_mode);
    }

    unsafe extern "C" fn record_prefix(path: *mut StringObject, volume_code: u32) {
        CALLS[CALL_COUNT] = 2;
        CALL_COUNT += 1;
        PREFIX_ARGS = (path as usize, volume_code);
    }

    struct OpsRestore;

    impl Drop for OpsRestore {
        fn drop(&mut self) {
            unsafe { STRING_OBJECT_PATH_OPS = DEFAULT_STRING_OBJECT_PATH_OPS };
        }
    }

    fn with_recorders(run: impl FnOnce()) {
        let _lock = OPS_LOCK.lock();
        unsafe {
            CALLS = [0; 2];
            CALL_COUNT = 0;
            NORMALIZE_ARGS = (0, 0, 0);
            PREFIX_ARGS = (0, 0);
            STRING_OBJECT_PATH_OPS = StringObjectPathOps {
                normalize_separators: record_normalize,
                prepend_volume_prefix: record_prefix,
            };
        }
        run();
    }

    #[test]
    fn normalizes_before_prefixing_the_same_path() {
        with_recorders(|| unsafe {
            let mut volume_record = [0xa5u8; VOLUME_CODE_OFFSET + 1];
            volume_record[VOLUME_CODE_OFFSET] = b'M';
            let mut path = StringObject { vtable: ptr::null(), payload: ptr::null_mut() };

            string_object_normalize_volume_path(volume_record.as_ptr(), &mut path);

            assert_eq!(CALL_COUNT, 2);
            assert_eq!(CALLS, [1, 2]);
            assert_eq!(NORMALIZE_ARGS, (&mut path as *mut StringObject as usize, b'/' as u32, 0));
            assert_eq!(PREFIX_ARGS, (&mut path as *mut StringObject as usize, b'M' as u32));
        });
    }

    #[test]
    fn volume_byte_is_zero_extended_for_every_value() {
        for volume_code in [0u8, b'A', 0xff] {
            with_recorders(|| unsafe {
                let mut volume_record = [0u8; VOLUME_CODE_OFFSET + 1];
                volume_record[VOLUME_CODE_OFFSET] = volume_code;
                let mut path = StringObject { vtable: ptr::null(), payload: ptr::null_mut() };

                string_object_normalize_volume_path(volume_record.as_ptr(), &mut path);

                assert_eq!(PREFIX_ARGS, (&mut path as *mut StringObject as usize, volume_code as u32));
            });
        }
    }
}
