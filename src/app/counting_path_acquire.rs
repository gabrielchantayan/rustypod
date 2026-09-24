//! Counted path assembly and conditional opaque-handle acquisition.
//!
//! `counted_path_acquire` — retailOS `FUN_080aa5c8` at **0x080aa5c8**.
//! Raw `osos.dec` establishes the true 152-byte code extent: 38 ARM words
//! from `stmdb sp!,{r4,r5,r6,lr}` through `ldmia sp!,{r4,r5,r6,pc}` at
//! 0x080aa65c; 0x080aa660 is its `0x64617461` literal and the next distinct
//! function starts at 0x080aa664. Decoding the raw words finds **5 plain
//! `bl` instructions and 1 predicated `bleq`** in the body. Two inbound
//! direct call sites are plain `bl` instructions; one is predicated `bleq`.
//!
//! The wrapper clears a 72-byte facade scratch record, joins `prefix` and
//! `suffix` into the C string after `counted_path`'s u16 prefix, clears that
//! prefix, probes the facade, and dispatches the existing counted-path
//! operation after a successful probe. A probe result other than 0 or -43 is
//! returned unchanged; otherwise it asks the opaque-handle protocol for mode
//! 2 and releases a successful result. Deliberate deviation: stock's scratch
//! record is cleared by the fixed retailOS zeroing routine; Rust initializes
//! the equivalent local array directly.

use core::ptr::write_bytes;

const PATH_JOIN_ADDRESS: usize = 0x0807_9f54;
const FACADE_INITIAL_PROBE_ADDRESS: usize = 0x0805_a8e4;
const SCRATCH_SIZE: usize = 0x48;
const PATH_CAPACITY: u32 = 0xff;
const PROBE_FALLBACK_STATUS: i32 = -0x2b;
const HANDLE_MODE: u32 = 2;
const HANDLE_AUXILIARY_WORD: u32 = 0x6461_7461;

type PathJoin = unsafe extern "C" fn(*const u8, *const u8, *mut u8, u32);
type FacadeInitialProbe = unsafe extern "C" fn(*mut u8, *mut u8, u32) -> i32;

unsafe extern "C" fn firmware_path_join(prefix: *const u8, suffix: *const u8, destination: *mut u8, capacity: u32) {
    #[cfg(target_os = "none")]
    unsafe { core::mem::transmute::<usize, PathJoin>(PATH_JOIN_ADDRESS)(prefix, suffix, destination, capacity) }
    #[cfg(not(target_os = "none"))]
    { let _ = (prefix, suffix, destination, capacity); }
}

unsafe extern "C" fn firmware_facade_initial_probe(counted_path: *mut u8, scratch: *mut u8, selector: u32) -> i32 {
    #[cfg(target_os = "none")]
    unsafe { core::mem::transmute::<usize, FacadeInitialProbe>(FACADE_INITIAL_PROBE_ADDRESS)(counted_path, scratch, selector) }
    #[cfg(not(target_os = "none"))]
    { let _ = (counted_path, scratch, selector); -0x32 }
}

static mut PATH_JOIN: PathJoin = firmware_path_join;
static mut FACADE_INITIAL_PROBE: FacadeInitialProbe = firmware_facade_initial_probe;

#[inline(always)]
unsafe fn path_join_fn() -> PathJoin { unsafe { PATH_JOIN } }
#[inline(always)]
unsafe fn facade_initial_probe_fn() -> FacadeInitialProbe { unsafe { FACADE_INITIAL_PROBE } }

/// `counted_path_acquire` — original: `FUN_080aa5c8` @ **0x080aa5c8**
/// (152 bytes; 2 inbound plain `bl` call sites and 1 predicated `bleq`;
/// body issues 5 plain `bl` and 1 predicated `bleq`).
///
/// Builds the counted path's C string from `prefix` and `suffix`, then probes
/// and dispatches the facade before conditionally acquiring and releasing an
/// opaque mode-2 handle. `counted_path` must provide a writable u16 prefix
/// followed by at least 255 writable bytes.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn counted_path_acquire(
    counted_path: *mut u8,
    _unused: u32,
    prefix: *const u8,
    suffix: *const u8,
) -> i32 {
    let mut scratch = [0u8; SCRATCH_SIZE];
    unsafe {
        write_bytes(scratch.as_mut_ptr(), 0, SCRATCH_SIZE);
        path_join_fn()(prefix, suffix, counted_path.add(2), PATH_CAPACITY);
        (counted_path as *mut u16).write(0);
    }

    let probe = unsafe { facade_initial_probe_fn()(counted_path, scratch.as_mut_ptr(), 0) };
    let status = if probe == 0 {
        unsafe { crate::app::path_facade_probe_dispatch_counted::path_facade_probe_dispatch_counted(counted_path) }
    } else {
        probe
    };
    if status != 0 && status != PROBE_FALLBACK_STATUS {
        return status;
    }

    let mut handle = core::ptr::null_mut();
    let acquire = unsafe {
        crate::cxx::opaque_handle_acquire::opaque_handle_acquire(
            counted_path,
            HANDLE_AUXILIARY_WORD,
            HANDLE_MODE,
            &mut handle,
        )
    };
    if acquire == 0 {
        unsafe { crate::cxx::opaque_handle_release::opaque_handle_release_if_valid(handle.cast()); }
    }
    acquire
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut JOIN_CALL: Option<(usize, usize, usize, u32)> = None;
    static mut PROBE_CALL: Option<(usize, usize, u32)> = None;
    static mut PROBE_RESULT: i32 = 0;
    static mut SCRATCH_WAS_ZEROED: bool = false;

    unsafe extern "C" fn joining(prefix: *const u8, suffix: *const u8, destination: *mut u8, capacity: u32) {
        unsafe {
            JOIN_CALL = Some((prefix as usize, suffix as usize, destination as usize, capacity));
            destination.write(b'x');
            destination.add(1).write(0);
        }
    }
    unsafe extern "C" fn probing(path: *mut u8, scratch: *mut u8, selector: u32) -> i32 {
        unsafe {
            PROBE_CALL = Some((path as usize, scratch as usize, selector));
            SCRATCH_WAS_ZEROED = core::slice::from_raw_parts(scratch, SCRATCH_SIZE).iter().all(|&byte| byte == 0);
            PROBE_RESULT
        }
    }

    struct Seams { join: PathJoin, probe: FacadeInitialProbe }
    impl Seams {
        unsafe fn install() -> Self {
            unsafe { let old = Self { join: PATH_JOIN, probe: FACADE_INITIAL_PROBE }; PATH_JOIN = joining; FACADE_INITIAL_PROBE = probing; old }
        }
    }
    impl Drop for Seams {
        fn drop(&mut self) { unsafe { PATH_JOIN = self.join; FACADE_INITIAL_PROBE = self.probe; } }
    }

    #[test]
    fn preserves_non_fallback_probe_error_after_building_counted_path() {
        let _lock = LOCK.lock();
        unsafe {
            let _seams = Seams::install();
            JOIN_CALL = None;
            PROBE_CALL = None;
            PROBE_RESULT = -7;
            SCRATCH_WAS_ZEROED = false;
            let prefix = b"prefix\0";
            let suffix = b"suffix\0";
            let mut path = [0xa5u8; 258];
            assert_eq!(counted_path_acquire(path.as_mut_ptr(), 123, prefix.as_ptr(), suffix.as_ptr()), -7);
            assert_eq!(&path[..3], &[0, 0, b'x']);
            assert_eq!(JOIN_CALL, Some((prefix.as_ptr() as usize, suffix.as_ptr() as usize, path.as_mut_ptr().add(2) as usize, PATH_CAPACITY)));
            let call = PROBE_CALL.unwrap();
            assert_eq!((call.0, call.2), (path.as_mut_ptr() as usize, 0));
            assert!(SCRATCH_WAS_ZEROED);
        }
    }

    #[test]
    fn preserves_positive_probe_error_without_acquiring_a_handle() {
        let _lock = LOCK.lock();
        unsafe {
            let _seams = Seams::install(); PROBE_RESULT = 19;
            let mut path = [0u8; 258];
            assert_eq!(counted_path_acquire(path.as_mut_ptr(), 0, b"a\0".as_ptr(), b"b\0".as_ptr()), 19);
        }
    }
}
