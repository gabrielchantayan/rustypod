//! Lazy initialization of the shared RAM stream buffer.
//!
//! Port: [`initialize_stream_buffer`] — original: `FUN_08006e88` @
//! `0x08006e88` (**136 bytes: 112 bytes of code plus its 24-byte literal
//! pool; 16 direct `bl` call sites, all unconditional and zero predicated**).
//!
//! Raw ARM returns at `0x08006ef4`; its six literal words occupy
//! `0x08006ef8..0x08006f0c`. The independently linked leaf beginning at
//! `0x08006f10` confirms that the pool belongs to this function, rather than
//! to Ghidra's next function at `0x08006f40`.
//!
//! ## Algorithm
//!
//! Test bit 0 of the C++ guard at `0x22008c90`. If clear and
//! `cxa_guard_acquire` accepts the whole word, construct the fixed buffer at
//! `0x22010398`, register its constructor result with `cxa_atexit`, and
//! release the guard. Independently, if the byte at `0x2200aed5` is clear,
//! initialize the buffer's pages with `(buffer, 1, 0)` and set that byte. The
//! function always returns the fixed buffer address, not the constructor's
//! return value.
//!
//! ## Deliberate deviations
//!
//! The constructor at `0x080073f0` and page initializer at `0x080072cc` are
//! still retailOS, so target builds cross those two ROM seams. The destructor
//! literal is `0x22007454`, the verified IRAM mirror of the real entry at
//! `0x08007454`; it is registered unchanged. Host builds model the three
//! fixed state locations with private storage and replace the two unported
//! calls with inert defaults for deterministic tests.

use core::ffi::c_void;

use crate::runtime::cxa_guard::{cxa_guard_acquire, cxa_guard_release};
use crate::runtime::shutdown_chain::{cxa_atexit, ShutdownHandlerFn};

const STREAM_BUFFER_ADDRESS: usize = 0x2201_0398;
const STREAM_BUFFER_GUARD_ADDRESS: usize = 0x2200_8c90;
const STREAM_BUFFER_READY_ADDRESS: usize = 0x2200_aed5;
const STREAM_BUFFER_DESTRUCTOR_ADDRESS: usize = 0x2200_7454;
const DSO_HANDLE: i32 = 0x089c_a09c;
const STREAM_BUFFER_SIZE: usize = 0x150;

/// ADS C++ stream-buffer constructor at `0x080073f0`.
pub type StreamBufferCtor = unsafe extern "C" fn(this: *mut u8) -> *mut u8;

/// RetailOS page allocation and initialization at `0x080072cc`.
pub type StreamBufferPageInitialize = unsafe extern "C" fn(
    stream_buffer: *mut u8,
    allocate_if_needed: u32,
    page_context: u32,
) -> u32;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_stream_buffer_ctor(this: *mut u8) -> *mut u8 {
    let constructor: StreamBufferCtor = core::mem::transmute(0x0800_73f0usize);
    constructor(this)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_stream_buffer_ctor(this: *mut u8) -> *mut u8 {
    this
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_stream_buffer_page_initialize(
    stream_buffer: *mut u8,
    allocate_if_needed: u32,
    page_context: u32,
) -> u32 {
    let initialize: StreamBufferPageInitialize = core::mem::transmute(0x0800_72ccusize);
    initialize(stream_buffer, allocate_if_needed, page_context)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_stream_buffer_page_initialize(
    _stream_buffer: *mut u8,
    _allocate_if_needed: u32,
    _page_context: u32,
) -> u32 {
    0
}

static mut STREAM_BUFFER_CTOR: StreamBufferCtor = {
    #[cfg(target_os = "none")]
    {
        firmware_stream_buffer_ctor
    }
    #[cfg(not(target_os = "none"))]
    {
        host_stream_buffer_ctor
    }
};

static mut STREAM_BUFFER_PAGE_INITIALIZE: StreamBufferPageInitialize = {
    #[cfg(target_os = "none")]
    {
        firmware_stream_buffer_page_initialize
    }
    #[cfg(not(target_os = "none"))]
    {
        host_stream_buffer_page_initialize
    }
};

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_stream_buffer_destructor(_object: *mut c_void) {}

#[cfg(target_os = "none")]
fn stream_buffer_destructor() -> ShutdownHandlerFn {
    unsafe { core::mem::transmute(STREAM_BUFFER_DESTRUCTOR_ADDRESS) }
}

#[cfg(not(target_os = "none"))]
fn stream_buffer_destructor() -> ShutdownHandlerFn {
    host_stream_buffer_destructor
}

#[cfg(not(target_os = "none"))]
#[repr(C)]
struct HostStreamBufferState {
    guard: u32,
    ready: u8,
    stream_buffer: [u8; STREAM_BUFFER_SIZE],
}

#[cfg(not(target_os = "none"))]
static mut HOST_STREAM_BUFFER_STATE: HostStreamBufferState = HostStreamBufferState {
    guard: 0,
    ready: 0,
    stream_buffer: [0; STREAM_BUFFER_SIZE],
};

unsafe fn stream_buffer_state() -> (*mut u32, *mut u8, *mut u8) {
    #[cfg(target_os = "none")]
    {
        (
            STREAM_BUFFER_GUARD_ADDRESS as *mut u32,
            STREAM_BUFFER_ADDRESS as *mut u8,
            STREAM_BUFFER_READY_ADDRESS as *mut u8,
        )
    }

    #[cfg(not(target_os = "none"))]
    {
        let state = core::ptr::addr_of_mut!(HOST_STREAM_BUFFER_STATE);
        (
            core::ptr::addr_of_mut!((*state).guard),
            core::ptr::addr_of_mut!((*state).stream_buffer) as *mut u8,
            core::ptr::addr_of_mut!((*state).ready),
        )
    }
}

#[inline(always)]
fn stream_buffer_ctor() -> StreamBufferCtor {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(STREAM_BUFFER_CTOR)) }
}

#[inline(always)]
fn stream_buffer_page_initialize() -> StreamBufferPageInitialize {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(STREAM_BUFFER_PAGE_INITIALIZE)) }
}

/// initialize_stream_buffer — original: `FUN_08006e88` @ `0x08006e88`
/// (136 bytes: 112 bytes of code plus a 24-byte literal pool; 16 direct,
/// unconditional `bl` call sites, binary-verified by decoding every ARM B/BL
/// word in `osos.dec`).
///
/// Lazily constructs the fixed RAM stream buffer and independently initializes
/// its pages on the first call. A nonzero guard with bit 0 clear enters
/// `cxa_guard_acquire`, which refuses it; the page-initialization byte remains
/// independently eligible. Every path returns the fixed buffer address.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.initialize_stream_buffer")]
#[inline(never)]
pub unsafe extern "C" fn initialize_stream_buffer() -> *mut u8 {
    let (guard, stream_buffer, ready) = stream_buffer_state();
    if (core::ptr::read_volatile(guard) & 1) == 0 && cxa_guard_acquire(guard) != 0 {
        let this = stream_buffer_ctor()(stream_buffer);
        cxa_atexit(this.cast::<c_void>(), stream_buffer_destructor(), DSO_HANDLE);
        cxa_guard_release(guard);
    }
    if core::ptr::read_volatile(ready) == 0 {
        stream_buffer_page_initialize()(stream_buffer, 1, 0);
        core::ptr::write_volatile(ready, 1);
    }
    stream_buffer
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::runtime::shutdown_chain::{shutdown_chain_head, AllocFn, FreeFn, ShutdownNode, SHUTDOWN_ALLOC, SHUTDOWN_FREE};
    use core::ptr;
    use std::boxed::Box;
    use std::sync::{Mutex, MutexGuard};

    #[derive(Clone, Copy)]
    struct Mock {
        ctor_calls: usize,
        page_initialize_calls: usize,
        ctor_argument: usize,
        page_initialize_argument: (usize, u32, u32),
        ctor_result: usize,
    }

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static MOCK: Mutex<Mock> = Mutex::new(Mock {
        ctor_calls: 0,
        page_initialize_calls: 0,
        ctor_argument: 0,
        page_initialize_argument: (0, 0, 0),
        ctor_result: 0,
    });

    unsafe extern "C" fn recording_ctor(this: *mut u8) -> *mut u8 {
        let mut mock = MOCK.lock().unwrap_or_else(|error| error.into_inner());
        mock.ctor_calls += 1;
        mock.ctor_argument = this as usize;
        mock.ctor_result as *mut u8
    }

    unsafe extern "C" fn recording_page_initialize(
        stream_buffer: *mut u8,
        allocate_if_needed: u32,
        page_context: u32,
    ) -> u32 {
        let mut mock = MOCK.lock().unwrap_or_else(|error| error.into_inner());
        mock.page_initialize_calls += 1;
        mock.page_initialize_argument = (stream_buffer as usize, allocate_if_needed, page_context);
        0
    }

    unsafe extern "C" fn box_alloc(size: usize) -> *mut u8 {
        assert_eq!(size, core::mem::size_of::<ShutdownNode>());
        Box::into_raw(Box::new(ShutdownNode {
            next: ptr::null_mut(), arg: ptr::null_mut(), handler: host_stream_buffer_destructor, key: 0,
        })) as *mut u8
    }

    unsafe extern "C" fn box_free(block: *mut u8) {
        drop(Box::from_raw(block as *mut ShutdownNode));
    }

    struct Fixture {
        _lock: MutexGuard<'static, ()>,
        previous_ctor: StreamBufferCtor,
        previous_page_initialize: StreamBufferPageInitialize,
        previous_alloc: AllocFn,
        previous_free: FreeFn,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            unsafe {
                let head = shutdown_chain_head();
                let mut node = head.read();
                while !node.is_null() {
                    let next = (*node).next;
                    drop(Box::from_raw(node));
                    node = next;
                }
                head.write(ptr::null_mut());
                STREAM_BUFFER_CTOR = self.previous_ctor;
                STREAM_BUFFER_PAGE_INITIALIZE = self.previous_page_initialize;
                SHUTDOWN_ALLOC = self.previous_alloc;
                SHUTDOWN_FREE = self.previous_free;
            }
        }
    }

    fn fixture(guard: u32, ready: u8, ctor_result: usize) -> Fixture {
        let lock = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            let previous_ctor = STREAM_BUFFER_CTOR;
            let previous_page_initialize = STREAM_BUFFER_PAGE_INITIALIZE;
            let previous_alloc = SHUTDOWN_ALLOC;
            let previous_free = SHUTDOWN_FREE;
            let (guard_cell, stream_buffer, ready_cell) = stream_buffer_state();
            guard_cell.write(guard);
            ready_cell.write(ready);
            stream_buffer.write_bytes(0, STREAM_BUFFER_SIZE);
            *MOCK.lock().unwrap_or_else(|error| error.into_inner()) = Mock {
                ctor_calls: 0,
                page_initialize_calls: 0,
                ctor_argument: 0,
                page_initialize_argument: (0, 0, 0),
                ctor_result,
            };
            shutdown_chain_head().write(ptr::null_mut());
            STREAM_BUFFER_CTOR = recording_ctor;
            STREAM_BUFFER_PAGE_INITIALIZE = recording_page_initialize;
            SHUTDOWN_ALLOC = box_alloc;
            SHUTDOWN_FREE = box_free;
            Fixture { _lock: lock, previous_ctor, previous_page_initialize, previous_alloc, previous_free }
        }
    }

    fn stream_buffer() -> *mut u8 {
        unsafe { stream_buffer_state().1 }
    }

    #[test]
    fn cold_start_constructs_registers_initializes_and_returns_fixed_buffer() {
        let constructor_result = 0x1357_9bdfusize;
        let _fixture = fixture(0, 0, constructor_result);

        let returned = unsafe { initialize_stream_buffer() };

        assert_eq!(returned, stream_buffer(), "returns the fixed stream buffer, not ctor output");
        let mock = MOCK.lock().unwrap_or_else(|error| error.into_inner());
        assert_eq!(mock.ctor_calls, 1);
        assert_eq!(mock.ctor_argument, stream_buffer() as usize);
        assert_eq!(mock.page_initialize_calls, 1);
        assert_eq!(mock.page_initialize_argument, (stream_buffer() as usize, 1, 0));
        drop(mock);
        unsafe {
            let (guard, _, ready) = stream_buffer_state();
            assert_eq!(guard.read(), 1, "cxa guard publishes before returning");
            assert_eq!(ready.read(), 1, "page initialization records its separate once flag");
            let node = shutdown_chain_head().read();
            assert!(!node.is_null(), "constructor result is registered for shutdown");
            assert_eq!((*node).arg, constructor_result as *mut c_void);
            assert_eq!((*node).handler as usize, stream_buffer_destructor() as usize);
            assert_eq!((*node).key, DSO_HANDLE);
        }
    }

    #[test]
    fn bit_clear_nonzero_guard_refuses_construction_but_still_initializes_pages() {
        let _fixture = fixture(2, 0, 0);

        assert_eq!(unsafe { initialize_stream_buffer() }, stream_buffer());

        let mock = MOCK.lock().unwrap_or_else(|error| error.into_inner());
        assert_eq!(mock.ctor_calls, 0, "the whole nonzero guard is rejected by cxa acquire");
        assert_eq!(mock.page_initialize_calls, 1, "page setup has an independent flag");
        unsafe {
            let (guard, _, ready) = stream_buffer_state();
            assert_eq!(guard.read(), 2, "a refused guard acquire preserves the unusual input");
            assert_eq!(ready.read(), 1);
            assert!(shutdown_chain_head().read().is_null(), "refused construction is not registered");
        }
    }

    #[test]
    fn ready_initialized_buffer_has_no_repeat_side_effects() {
        let _fixture = fixture(1, 1, 0);

        assert_eq!(unsafe { initialize_stream_buffer() }, stream_buffer());
        assert_eq!(unsafe { initialize_stream_buffer() }, stream_buffer());

        let mock = MOCK.lock().unwrap_or_else(|error| error.into_inner());
        assert_eq!(mock.ctor_calls, 0);
        assert_eq!(mock.page_initialize_calls, 0);
        unsafe { assert!(shutdown_chain_head().read().is_null()) };
    }
}
