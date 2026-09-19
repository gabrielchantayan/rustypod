//! Full-page buffered writer handoff — `FUN_08064fb8` @ **0x08064fb8**.
//!
//! Raw `osos.dec` establishes the exact 152-byte extent
//! `0x08064fb8..0x0806504f`; the literal at `0x08065050` is followed by the
//! separately linked function at `0x08065054`. It has eight direct plain
//! `bl` instructions (two allocation/creation calls on the cold path, lock,
//! one of each setup pair, transform, and unlock), and no predicated `bl`.
//!
//! # Algorithm
//!
//! Lazily creates the shared eight-byte mutex, locks it, selects one of two
//! hardware-transform setup helpers from state word `+0x50` bit 0, processes
//! `(page, len)`, selects one of two completion helpers from bit 1, unlocks,
//! and returns zero. The state counter words at `+0x40` and `+0x44` are owned
//! by the transform helper.
//!
//! # Deliberate deviations
//!
//! The four hardware helpers have no established Rust identities. Target
//! builds invoke their verified retailOS addresses; host tests install a
//! replaceable operation table. The mutex global is read from its original
//! RAM address on target and is a host fixture slot otherwise.

#[cfg(not(target_os = "none"))]
use core::ptr::{addr_of, read_volatile};

use crate::crypto::buffered_writer_write::BufferedWriterState;
use crate::heap::veneers::operator_new;
use crate::kernel::sync_mutex::{mutex_create, mutex_lock, mutex_unlock, Mutex};

const TRANSFORM_MUTEX_ADDRESS: usize = 0x089c_d91c;
const TRANSFORM_SETUP_ADDRESS: usize = 0x0809_ca98;
const TRANSFORM_RESET_ADDRESS: usize = 0x0807_d7d0;
const TRANSFORM_UPDATE_ADDRESS: usize = 0x0808_c558;
const TRANSFORM_FINISH_ADDRESS: usize = 0x0809_2364;
const TRANSFORM_COMPLETE_RESET_ADDRESS: usize = 0x0808_6178;

type TransformSetup = unsafe extern "C" fn(*mut BufferedWriterState);
type TransformUpdate = unsafe extern "C" fn(*mut BufferedWriterState, *mut u8, u32);
type TransformFinish = unsafe extern "C" fn(*mut BufferedWriterState, *mut u8);

/// The unported hardware-transform operations selected by the two flag bits.
#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct BufferedWriterFlushOps {
    pub setup: TransformSetup,
    pub reset: TransformSetup,
    pub complete_reset: TransformSetup,
    pub update: TransformUpdate,
    pub finish: TransformFinish,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_setup(_state: *mut BufferedWriterState) {
    panic!("install buffered-writer flush host operations")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_complete_reset(_state: *mut BufferedWriterState) {
    panic!("install buffered-writer flush host operations")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_update(_state: *mut BufferedWriterState, _page: *mut u8, _len: u32) {
    panic!("install buffered-writer flush host operations")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_finish(_state: *mut BufferedWriterState, _storage: *mut u8) {
    panic!("install buffered-writer flush host operations")
}

#[cfg(not(target_os = "none"))]
pub static mut BUFFERED_WRITER_FLUSH_OPS: BufferedWriterFlushOps = BufferedWriterFlushOps {
    setup: missing_setup,
    reset: missing_setup,
    complete_reset: missing_complete_reset,
    update: missing_update,
    finish: missing_finish,
};
#[cfg(not(target_os = "none"))]
pub static mut BUFFERED_WRITER_TRANSFORM_MUTEX: *mut Mutex = core::ptr::null_mut();

#[inline(always)]
unsafe fn transform_mutex_slot() -> *mut *mut Mutex {
    #[cfg(target_os = "none")]
    { TRANSFORM_MUTEX_ADDRESS as *mut *mut Mutex }
    #[cfg(not(target_os = "none"))]
    { core::ptr::addr_of_mut!(BUFFERED_WRITER_TRANSFORM_MUTEX) }
}

#[inline(always)]
unsafe fn setup(state: *mut BufferedWriterState) {
    #[cfg(target_os = "none")]
    unsafe { core::mem::transmute::<usize, TransformSetup>(TRANSFORM_SETUP_ADDRESS)(state) }
    #[cfg(not(target_os = "none"))]
    unsafe { read_volatile(addr_of!(BUFFERED_WRITER_FLUSH_OPS.setup))(state) }
}
#[inline(always)]
unsafe fn reset(state: *mut BufferedWriterState) {
    #[cfg(target_os = "none")]
    unsafe { core::mem::transmute::<usize, TransformSetup>(TRANSFORM_RESET_ADDRESS)(state) }
    #[cfg(not(target_os = "none"))]
    unsafe { read_volatile(addr_of!(BUFFERED_WRITER_FLUSH_OPS.reset))(state) }
}
#[inline(always)]
unsafe fn complete_reset(state: *mut BufferedWriterState) {
    #[cfg(target_os = "none")]
    unsafe { core::mem::transmute::<usize, TransformSetup>(TRANSFORM_COMPLETE_RESET_ADDRESS)(state) }
    #[cfg(not(target_os = "none"))]
    unsafe { read_volatile(addr_of!(BUFFERED_WRITER_FLUSH_OPS.complete_reset))(state) }
}
#[inline(always)]
unsafe fn update(state: *mut BufferedWriterState, page: *mut u8, len: u32) {
    #[cfg(target_os = "none")]
    unsafe { core::mem::transmute::<usize, TransformUpdate>(TRANSFORM_UPDATE_ADDRESS)(state, page, len) }
    #[cfg(not(target_os = "none"))]
    unsafe { read_volatile(addr_of!(BUFFERED_WRITER_FLUSH_OPS.update))(state, page, len) }
}
#[inline(always)]
unsafe fn finish(state: *mut BufferedWriterState, storage: *mut u8) {
    #[cfg(target_os = "none")]
    unsafe { core::mem::transmute::<usize, TransformFinish>(TRANSFORM_FINISH_ADDRESS)(state, storage) }
    #[cfg(not(target_os = "none"))]
    unsafe { read_volatile(addr_of!(BUFFERED_WRITER_FLUSH_OPS.finish))(state, storage) }
}

/// Processes one complete buffered-writer page through the selected transform.
///
/// # Safety
/// `state` must name the target-layout writer state; `page` must be readable
/// for `len` bytes. The `+0x4c` word must name writable 20-byte transform
/// storage when flag bit 1 is clear. The installed host operations or retailOS
/// helpers must accept this exact ABI.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn buffered_writer_flush(
    state: *mut BufferedWriterState,
    page: *mut u8,
    len: u32,
) -> u32 {
    let slot = unsafe { transform_mutex_slot() };
    let mut mutex = unsafe { slot.read() };
    if mutex.is_null() {
        mutex = unsafe { operator_new(8).cast::<Mutex>() };
        unsafe { mutex_create(mutex) };
        unsafe { slot.write(mutex) };
    }
    unsafe { mutex_lock(mutex) };
    let flags = unsafe { state.cast::<u32>().add(20).read() };
    if flags & 1 == 0 {
        unsafe { setup(state) };
    } else {
        unsafe { reset(state) };
    }
    unsafe { update(state, page, len) };
    if flags & 2 == 0 {
        let storage = unsafe { state.cast::<u32>().add(19).read() };
        unsafe { finish(state, (storage as usize) as *mut u8) };
    } else {
        unsafe { complete_reset(state) };
    }
    unsafe { mutex_unlock(mutex) };
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::Mutex as TestMutex;
    use std::sync::LazyLock;

    static LOCK: TestMutex<()> = TestMutex::new(());
    static CALLS: LazyLock<TestMutex<std::vec::Vec<&'static str>>> = LazyLock::new(|| TestMutex::new(std::vec::Vec::new()));
    static mut UPDATE_ARGS: (*mut u8, u32) = (core::ptr::null_mut(), 0);

    unsafe extern "C" fn record_setup(_state: *mut BufferedWriterState) { CALLS.lock().push("setup") }
    unsafe extern "C" fn record_reset(_state: *mut BufferedWriterState) { CALLS.lock().push("reset") }
    unsafe extern "C" fn record_complete_reset(_state: *mut BufferedWriterState) { CALLS.lock().push("complete_reset") }
    unsafe extern "C" fn record_update(_state: *mut BufferedWriterState, page: *mut u8, len: u32) {
        CALLS.lock().push("update");
        unsafe { UPDATE_ARGS = (page, len) };
    }
    unsafe extern "C" fn record_finish(_state: *mut BufferedWriterState, _storage: *mut u8) { CALLS.lock().push("finish") }

    #[test]
    fn selects_each_flag_controlled_helper_and_forwards_page() {
        let _guard = LOCK.lock();
        let mut mutex = Mutex { sem_cell: core::ptr::null_mut(), unused: 0 };
        let mut state: BufferedWriterState = unsafe { core::mem::zeroed() };
        let mut page = [0u8; 16];
        unsafe {
            BUFFERED_WRITER_TRANSFORM_MUTEX = &mut mutex;
            BUFFERED_WRITER_FLUSH_OPS = BufferedWriterFlushOps { setup: record_setup, reset: record_reset, complete_reset: record_complete_reset, update: record_update, finish: record_finish };
            for (flags, expected) in [(0, ["setup", "update", "finish"]), (1, ["reset", "update", "finish"]), (2, ["setup", "update", "complete_reset"]), (3, ["reset", "update", "complete_reset"])] {
                CALLS.lock().clear();
                state.page_flags = flags;
                assert_eq!(buffered_writer_flush(&mut state, page.as_mut_ptr(), 7), 0);
                assert_eq!(*CALLS.lock(), expected);
                assert_eq!(UPDATE_ARGS, (page.as_mut_ptr(), 7));
            }
            BUFFERED_WRITER_TRANSFORM_MUTEX = core::ptr::null_mut();
            BUFFERED_WRITER_FLUSH_OPS = BufferedWriterFlushOps { setup: missing_setup, reset: missing_setup, complete_reset: missing_complete_reset, update: missing_update, finish: missing_finish };
        }
    }
}
