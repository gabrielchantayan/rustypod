//! `stream_ensure_available` — original: `FUN_082de8f4` @ 0x082de8f4.
//!
//! Raw `osos.dec` establishes the true 96-byte extent 0x082de8f4..0x082de954;
//! the distinct next function begins with `push {r2-r9,lr}` at 0x082de954.
//! There are four direct inbound plain `bl` call sites and no inbound
//! predicated `bl` calls. The body has two unconditional plain `bl` calls and
//! no predicated calls.
//!
//! # Algorithm
//!
//! If the available-byte count at `+0x0e` is below the requested count, clear
//! word `+8` of the optional callback record at `+0x78`, then request that
//! count through the reader at `+0x6c`. A zero result records the requested
//! low byte as available; nonzero results propagate except status 5, which
//! releases the optional callback record and retries while that release returns
//! nonzero.
//!
//! Deliberate deviation: the reader vtable dispatch at `FUN_0837db74` and the
//! callback-record helper `FUN_0837cafc` are not ported. The target defaults
//! preserve their recovered ARM ABIs; host tests install target-width-safe
//! seams because firmware function pointers occupy one 32-bit word.

/// Host/test bridge for the two unported call boundaries.
#[derive(Clone, Copy)]
pub struct StreamEnsureAvailableOps {
    pub request: unsafe extern "C" fn(*mut u8, u32) -> u32,
    pub release_callback: unsafe extern "C" fn(*mut u8) -> u32,
}

type ReaderRequest = unsafe extern "C" fn(*mut u8, u32) -> u32;
type ReleaseCallback = unsafe extern "C" fn(*mut u8) -> u32;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_request(reader: *mut u8, requested: u32) -> u32 {
    let vtable = unsafe { reader.cast::<u32>().read() as *const u32 };
    let request: ReaderRequest = unsafe { core::mem::transmute(vtable.add(7).read() as usize) };
    unsafe { request(reader, requested) }
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_release_callback(callback: *mut u8) -> u32 {
    let release: ReleaseCallback = unsafe { core::mem::transmute(0x0837_cafcusize) };
    unsafe { release(callback) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_request(_reader: *mut u8, _requested: u32) -> u32 {
    panic!("stream_ensure_available requires reader vtable slot +0x1c")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_release_callback(_callback: *mut u8) -> u32 {
    panic!("stream_ensure_available requires FUN_0837cafc")
}

#[cfg(target_os = "none")]
const DEFAULT_STREAM_ENSURE_AVAILABLE_OPS: StreamEnsureAvailableOps = StreamEnsureAvailableOps {
    request: firmware_request,
    release_callback: firmware_release_callback,
};

#[cfg(not(target_os = "none"))]
const DEFAULT_STREAM_ENSURE_AVAILABLE_OPS: StreamEnsureAvailableOps = StreamEnsureAvailableOps {
    request: missing_request,
    release_callback: missing_release_callback,
};

/// Active operations. Host tests replace these target-width call boundaries.
pub static mut STREAM_ENSURE_AVAILABLE_OPS: StreamEnsureAvailableOps =
    DEFAULT_STREAM_ENSURE_AVAILABLE_OPS;

#[inline(always)]
fn stream_ensure_available_ops() -> StreamEnsureAvailableOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(STREAM_ENSURE_AVAILABLE_OPS)) }
}

/// Ensures a stream has at least `requested` bytes available.
///
/// Original: `FUN_082de8f4` @ 0x082de8f4 (96 bytes; two plain outbound `bl`
/// calls and no predicated calls). The raw body trusts every target-width
/// pointer and performs no range validation.
///
/// # Safety
///
/// `stream` must address a readable object through `+0x78`; its reader at
/// `+0x6c` and optional callback record at `+0x78` must satisfy their retail
/// ABIs.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn stream_ensure_available(stream: *mut u8, requested: u32) -> u32 {
    if unsafe { stream.add(0x0e).read() as u32 } >= requested {
        return 0;
    }

    let callback = unsafe { stream.add(0x78).cast::<u32>().read() as usize as *mut u8 };
    if !callback.is_null() {
        unsafe { callback.add(8).cast::<u32>().write(0) };
    }

    let ops = stream_ensure_available_ops();
    loop {
        let reader = unsafe { stream.add(0x6c).cast::<u32>().read() as usize as *mut u8 };
        let status = unsafe { (ops.request)(reader, requested) };
        if status != 5 {
            if status == 0 {
                unsafe { stream.add(0x0e).write(requested as u8) };
            }
            return status;
        }
        let callback = unsafe { stream.add(0x78).cast::<u32>().read() as usize as *mut u8 };
        if unsafe { (ops.release_callback)(callback) } == 0 {
            return 5;
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::{LazyLock, Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::STREAM_ENSURE_AVAILABLE, 0x1000).map(|pointer| pointer as usize)
    });
    static mut REQUEST_RESULTS: [u32; 4] = [0; 4];
    static mut RELEASE_RESULTS: [u32; 4] = [0; 4];
    static mut REQUEST_CALLS: usize = 0;
    static mut RELEASE_CALLS: usize = 0;
    static mut SEEN_READER: *mut u8 = core::ptr::null_mut();
    static mut SEEN_REQUESTED: u32 = 0;
    static mut SEEN_CALLBACK: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn record_request(reader: *mut u8, requested: u32) -> u32 {
        let call = REQUEST_CALLS;
        REQUEST_CALLS += 1;
        SEEN_READER = reader;
        SEEN_REQUESTED = requested;
        REQUEST_RESULTS[call]
    }

    unsafe extern "C" fn record_release(callback: *mut u8) -> u32 {
        let call = RELEASE_CALLS;
        RELEASE_CALLS += 1;
        SEEN_CALLBACK = callback;
        RELEASE_RESULTS[call]
    }

    fn install_recorder() -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            addr_of_mut!(REQUEST_RESULTS).write([0; 4]);
            addr_of_mut!(RELEASE_RESULTS).write([0; 4]);
            addr_of_mut!(REQUEST_CALLS).write(0);
            addr_of_mut!(RELEASE_CALLS).write(0);
            addr_of_mut!(SEEN_READER).write(core::ptr::null_mut());
            addr_of_mut!(SEEN_REQUESTED).write(0);
            addr_of_mut!(SEEN_CALLBACK).write(core::ptr::null_mut());
            addr_of_mut!(STREAM_ENSURE_AVAILABLE_OPS).write(StreamEnsureAvailableOps {
                request: record_request,
                release_callback: record_release,
            });
        }
        guard
    }

    fn restore_default(guard: MutexGuard<'static, ()>) {
        unsafe { addr_of_mut!(STREAM_ENSURE_AVAILABLE_OPS).write(DEFAULT_STREAM_ENSURE_AVAILABLE_OPS) };
        drop(guard);
    }

    fn fixture() -> Option<*mut u8> {
        (*FIXTURE).map(|pointer| pointer as *mut u8)
    }

    #[test]
    fn does_nothing_when_available_count_meets_requested_count() {
        let guard = install_recorder();
        let Some(stream) = fixture() else {
            assert!(note_missing_u32_fixture("stream_ensure_available"));
            restore_default(guard);
            return;
        };
        unsafe {
            stream.write_bytes(0, 0x1000);
            stream.add(0x0e).write(4);
            stream.add(0x80).cast::<u32>().write(0x1234_5678);
            assert_eq!(stream_ensure_available(stream, 4), 0);
            assert_eq!(addr_of!(REQUEST_CALLS).read(), 0);
            assert_eq!(addr_of!(RELEASE_CALLS).read(), 0);
            assert_eq!(stream.add(0x80).cast::<u32>().read(), 0x1234_5678);
        }
        restore_default(guard);
    }

    #[test]
    fn records_requested_low_byte_after_a_successful_request() {
        let guard = install_recorder();
        let Some(stream) = fixture() else {
            assert!(note_missing_u32_fixture("stream_ensure_available"));
            restore_default(guard);
            return;
        };
        unsafe {
            stream.write_bytes(0, 0x1000);
            let callback = stream.add(0x200);
            stream.add(0x6c).cast::<u32>().write(stream.add(0x300) as usize as u32);
            stream.add(0x78).cast::<u32>().write(callback as usize as u32);
            callback.add(8).cast::<u32>().write(0xfeed_beef);
            assert_eq!(stream_ensure_available(stream, 0x103), 0);
            assert_eq!(stream.add(0x0e).read(), 3);
            assert_eq!(callback.add(8).cast::<u32>().read(), 0);
            assert_eq!(addr_of!(REQUEST_CALLS).read(), 1);
            assert_eq!(addr_of!(SEEN_READER).read(), stream.add(0x300));
            assert_eq!(addr_of!(SEEN_REQUESTED).read(), 0x103);
        }
        restore_default(guard);
    }

    #[test]
    fn retries_status_five_until_callback_release_stops_it() {
        let guard = install_recorder();
        let Some(stream) = fixture() else {
            assert!(note_missing_u32_fixture("stream_ensure_available"));
            restore_default(guard);
            return;
        };
        unsafe {
            stream.write_bytes(0, 0x1000);
            let callback = stream.add(0x200);
            stream.add(0x78).cast::<u32>().write(callback as usize as u32);
            REQUEST_RESULTS = [5, 5, 0, 0];
            RELEASE_RESULTS = [1, 0, 0, 0];
            assert_eq!(stream_ensure_available(stream, 4), 5);
            assert_eq!(addr_of!(REQUEST_CALLS).read(), 2);
            assert_eq!(addr_of!(RELEASE_CALLS).read(), 2);
            assert_eq!(addr_of!(SEEN_CALLBACK).read(), callback);
            assert_eq!(stream.add(0x0e).read(), 0);
        }
        restore_default(guard);
    }

    #[test]
    fn propagates_non_retry_errors_without_changing_available_count() {
        let guard = install_recorder();
        let Some(stream) = fixture() else {
            assert!(note_missing_u32_fixture("stream_ensure_available"));
            restore_default(guard);
            return;
        };
        unsafe {
            stream.write_bytes(0, 0x1000);
            REQUEST_RESULTS = [0x0d, 0, 0, 0];
            assert_eq!(stream_ensure_available(stream, 1), 0x0d);
            assert_eq!(stream.add(0x0e).read(), 0);
            assert_eq!(addr_of!(RELEASE_CALLS).read(), 0);
        }
        restore_default(guard);
    }
}
