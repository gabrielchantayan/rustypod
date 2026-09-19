//! Fixed-page buffered writer append.
//!
//! Port: [`buffered_writer_write`] — `FUN_080569a8` @ **0x080569a8**
//! (**188-byte instruction body**, `0x080569a8..0x08056a64`; its literal pool
//! is the following word and the separately linked successor starts at
//! `0x08056a68`). Raw decoding of every ARM B/BL immediate in `osos.dec`
//! found **six direct `bl` call sites**: five unconditional sites at
//! `0x080436f4`, `0x0804370c`, `0x08392e10`, `0x08392e28`, and `0x08396b0c`,
//! plus the predicated `blne` at `0x0806e3cc`. The same decode finds one
//! distinct `bne` tail caller at `0x083181dc`.
//!
//! # Algorithm
//!
//! Validates a handle, source, and the recovered buffered-state invariant:
//! `pending_len < 0x1000` and the word at `+0x4c` equals the embedded storage
//! address at `+0x54`. It appends source bytes to the page at `+0x6c`. Every
//! full-page handoff is [`buffered_writer_flush`], which selects the retail
//! hardware-transform helpers from the state flags. The port directly uses the
//! already ported `__rt_memcpy` rather than reproducing the ROM thunk at
//! `0x08037db0`.

use core::ptr;

use crate::crypto::buffered_writer_flush::buffered_writer_flush;
use crate::libc::rt_memcpy::__rt_memcpy;

/// Number of bytes in one recovered output page.
pub const BUFFERED_WRITER_PAGE_SIZE: u32 = 0x1000;
/// Raw error returned when the handle, source, or state invariant is invalid.
pub const BUFFERED_WRITER_INVALID_STATE: u32 = 0xffff_5bd9;

/// The two-word outer object accepted by [`buffered_writer_write`].
#[repr(C)]
pub struct BufferedWriterHandle {
    pub _opaque_00: u32,
    /// +0x04: target-width pointer to the state below.
    pub state: u32,
}

/// Recovered state fields touched by [`buffered_writer_write`].
///
/// The word at `+0x4c` is only known to be valid when it names the embedded
/// storage member at `+0x54`; its broader role remains unknown.
#[repr(C)]
pub struct BufferedWriterState {
    pub _opaque_00_48: [u32; 19],
    /// +0x4c: must equal this object's `+0x54` address.
    pub embedded_storage_address: u32,
    /// +0x50: cleared after each completed page handoff.
    pub page_flags: u32,
    pub _embedded_storage_54_64: [u32; 5],
    /// +0x68: bytes currently buffered in [`Self::page`].
    pub pending_len: u32,
    /// +0x6c: 4096-byte page being accumulated.
    pub page: [u8; BUFFERED_WRITER_PAGE_SIZE as usize],
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x4c] = [0; core::mem::offset_of!(BufferedWriterState, embedded_storage_address)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x50] = [0; core::mem::offset_of!(BufferedWriterState, page_flags)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x68] = [0; core::mem::offset_of!(BufferedWriterState, pending_len)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x6c] = [0; core::mem::offset_of!(BufferedWriterState, page)];

#[inline(always)]
unsafe fn flush_page(state: *mut BufferedWriterState) {
    unsafe { buffered_writer_flush(state, ptr::addr_of_mut!((*state).page).cast(), BUFFERED_WRITER_PAGE_SIZE) };
}

/// buffered_writer_write — original: `FUN_080569a8` @ 0x080569a8 (188 bytes;
/// six direct `bl` call sites, five unconditional and one `blne`,
/// binary-verified from `osos.dec`).
///
/// Appends `len` bytes from `source` to the recovered fixed-page writer. A
/// completed page is copied first, handed off while its prior state is still
/// visible, then its flags and pending count are cleared. Returns zero on a
/// valid append or [`BUFFERED_WRITER_INVALID_STATE`] without writes otherwise.
///
/// # Safety
///
/// `handle` and `source` must both be non-null. `handle->state` must be a
/// valid writable [`BufferedWriterState`] whose embedded-address invariant
/// holds; `source` must be readable for `len` bytes. The state handoff must be
/// valid whenever an append fills a page.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn buffered_writer_write(
    handle: *mut BufferedWriterHandle,
    source: *const u8,
    len: u32,
) -> u32 {
    if handle.is_null() || source.is_null() {
        return BUFFERED_WRITER_INVALID_STATE;
    }

    let state = unsafe { (*handle).state as usize as *mut BufferedWriterState };
    let pending_len = unsafe { (*state).pending_len };
    let embedded_storage = unsafe { ptr::addr_of!((*state)._embedded_storage_54_64).cast::<u8>() };
    if pending_len >= BUFFERED_WRITER_PAGE_SIZE
        || unsafe { (*state).embedded_storage_address } != embedded_storage as usize as u32
    {
        return BUFFERED_WRITER_INVALID_STATE;
    }

    let mut source = source;
    let mut remaining = len;
    while unsafe { (*state).pending_len }.wrapping_add(remaining) >= BUFFERED_WRITER_PAGE_SIZE {
        let current_pending = unsafe { (*state).pending_len };
        let page_space = BUFFERED_WRITER_PAGE_SIZE - current_pending;
        let destination = unsafe { ptr::addr_of_mut!((*state).page).cast::<u8>().add(current_pending as usize) };
        unsafe { __rt_memcpy(destination, source, page_space as usize) };
        unsafe { flush_page(state) };
        unsafe { ptr::write_volatile(ptr::addr_of_mut!((*state).page_flags), 0) };
        let pending_after_handoff =
            unsafe { ptr::read_volatile(ptr::addr_of!((*state).pending_len)) };
        unsafe { ptr::write_volatile(ptr::addr_of_mut!((*state).pending_len), 0) };
        let consumed = BUFFERED_WRITER_PAGE_SIZE.wrapping_sub(pending_after_handoff);
        source = unsafe { source.add(consumed as usize) };
        remaining = remaining.wrapping_sub(consumed);
    }

    let destination = unsafe {
        ptr::addr_of_mut!((*state).page)
            .cast::<u8>()
            .add((*state).pending_len as usize)
    };
    unsafe { __rt_memcpy(destination, source, remaining as usize) };
    unsafe { (*state).pending_len = (*state).pending_len.wrapping_add(remaining) };
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::crypto::buffered_writer_flush::{
        BufferedWriterFlushOps, BUFFERED_WRITER_FLUSH_OPS, BUFFERED_WRITER_TRANSFORM_MUTEX,
    };
    use crate::kernel::sync_mutex::Mutex as KernelMutex;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::sync::LazyLock;
    use std::vec::Vec;

    const FIXTURE_LEN: usize = 0x2000;
    const STATE_OFFSET: usize = 0x100;

    static BUFFERED_WRITER_WRITE_TEST_LOCK: Mutex<()> = Mutex::new(());
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::BUFFERED_WRITER_WRITE, FIXTURE_LEN).map(|pointer| pointer as usize)
    });
    static mut TEST_TRANSFORM_MUTEX: KernelMutex = KernelMutex { sem_cell: core::ptr::null_mut(), unused: 0 };

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct FlushCalls {
        count: usize,
        pending: [u32; 3],
        flags: [u32; 3],
        first: [u8; 3],
        penultimate: [u8; 3],
        last: [u8; 3],
        page_matches: [bool; 3],
    }

    impl FlushCalls {
        const fn new() -> Self {
            Self {
                count: 0,
                pending: [0; 3],
                flags: [0; 3],
                first: [0; 3],
                penultimate: [0; 3],
                last: [0; 3],
                page_matches: [false; 3],
            }
        }
    }

    static FLUSH_CALLS: Mutex<FlushCalls> = Mutex::new(FlushCalls::new());
    static FLUSH_PENDING_MUTATION: Mutex<Option<u32>> = Mutex::new(None);

    unsafe extern "C" fn recording_flush(
        state: *mut BufferedWriterState,
        page: *mut u8,
        len: u32,
    ) {
        let mut calls = FLUSH_CALLS.lock();
        let index = calls.count;
        calls.count += 1;
        calls.pending[index] = unsafe { (*state).pending_len };
        calls.flags[index] = unsafe { (*state).page_flags };
        calls.first[index] = unsafe { *page };
        calls.penultimate[index] = unsafe { *page.add(BUFFERED_WRITER_PAGE_SIZE as usize - 2) };
        calls.last[index] = unsafe { *page.add(BUFFERED_WRITER_PAGE_SIZE as usize - 1) };
        calls.page_matches[index] = page == unsafe { ptr::addr_of_mut!((*state).page).cast() } && len == BUFFERED_WRITER_PAGE_SIZE;
        if let Some(pending) = *FLUSH_PENDING_MUTATION.lock() {
            unsafe { (*state).pending_len = pending };
        }
    }
    unsafe extern "C" fn no_op_setup(_state: *mut BufferedWriterState) {}
    unsafe extern "C" fn no_op_finish(_state: *mut BufferedWriterState, _storage: *mut u8) {}

    struct FlushGuard {
        old_ops: BufferedWriterFlushOps,
        old_mutex: *mut KernelMutex,
    }

    impl FlushGuard {
        unsafe fn install() -> Self {
            let old_ops = unsafe { ptr::read_volatile(ptr::addr_of!(BUFFERED_WRITER_FLUSH_OPS)) };
            let old_mutex = unsafe { BUFFERED_WRITER_TRANSFORM_MUTEX };
            unsafe {
                BUFFERED_WRITER_TRANSFORM_MUTEX = core::ptr::addr_of_mut!(TEST_TRANSFORM_MUTEX);
                BUFFERED_WRITER_FLUSH_OPS = BufferedWriterFlushOps {
                    setup: no_op_setup,
                    reset: no_op_setup,
                    complete_reset: no_op_setup,
                    update: recording_flush,
                    finish: no_op_finish,
                };
            }
            *FLUSH_CALLS.lock() = FlushCalls::new();
            *FLUSH_PENDING_MUTATION.lock() = None;
            Self { old_ops, old_mutex }
        }
    }

    impl Drop for FlushGuard {
        fn drop(&mut self) {
            unsafe {
                BUFFERED_WRITER_FLUSH_OPS = self.old_ops;
                BUFFERED_WRITER_TRANSFORM_MUTEX = self.old_mutex;
            }
        }
    }

    fn fixture() -> Option<(*mut BufferedWriterHandle, *mut BufferedWriterState)> {
        let base = *SLAB.as_ref()? as *mut u8;
        unsafe {
            ptr::write_bytes(base, 0, FIXTURE_LEN);
            let handle = base.cast::<BufferedWriterHandle>();
            let state = base.add(STATE_OFFSET).cast::<BufferedWriterState>();
            (*handle).state = state as usize as u32;
            (*state).embedded_storage_address = ptr::addr_of!((*state)._embedded_storage_54_64) as usize as u32;
            Some((handle, state))
        }
    }

    #[test]
    fn rejects_nulls_and_invalid_state_without_touching_the_page() {
        let _lock = BUFFERED_WRITER_WRITE_TEST_LOCK.lock();
        assert_eq!(unsafe { buffered_writer_write(ptr::null_mut(), ptr::null(), 0) }, BUFFERED_WRITER_INVALID_STATE);

        let Some((handle, state)) = fixture() else {
            note_missing_u32_fixture("crypto::buffered_writer_write");
            return;
        };
        unsafe {
            (*state).page[0] = 0xa5;
            assert_eq!(buffered_writer_write(handle, ptr::null(), 0), BUFFERED_WRITER_INVALID_STATE);
            assert_eq!((*state).page[0], 0xa5);

            let source = [1u8];
            (*state).pending_len = BUFFERED_WRITER_PAGE_SIZE;
            assert_eq!(buffered_writer_write(handle, source.as_ptr(), 1), BUFFERED_WRITER_INVALID_STATE);
            assert_eq!((*state).page[0], 0xa5);

            (*state).pending_len = 0;
            (*state).embedded_storage_address = 0;
            assert_eq!(buffered_writer_write(handle, source.as_ptr(), 1), BUFFERED_WRITER_INVALID_STATE);
            assert_eq!((*state).page[0], 0xa5);
        }
    }

    #[test]
    fn retains_a_partial_page_without_handoff() {
        let _lock = BUFFERED_WRITER_WRITE_TEST_LOCK.lock();
        let Some((handle, state)) = fixture() else {
            note_missing_u32_fixture("crypto::buffered_writer_write");
            return;
        };
        let _flush = unsafe { FlushGuard::install() };
        let source = [0x11u8, 0x22, 0x33, 0x44];
        unsafe {
            (*state).pending_len = 3;
            (*state).page_flags = 0x5a;
            (*state).page[0] = 0xa0;
            (*state).page[1] = 0xa1;
            (*state).page[2] = 0xa2;
            assert_eq!(buffered_writer_write(handle, source.as_ptr(), source.len() as u32), 0);
            assert_eq!((*state).pending_len, 7);
            assert_eq!((*state).page_flags, 0x5a);
            assert_eq!((*state).page[0], 0xa0);
            assert_eq!((*state).page[1], 0xa1);
            assert_eq!((*state).page[2], 0xa2);
            assert_eq!((*state).page[3], 0x11);
            assert_eq!((*state).page[4], 0x22);
            assert_eq!((*state).page[5], 0x33);
            assert_eq!((*state).page[6], 0x44);
        }
        assert_eq!(FLUSH_CALLS.lock().count, 0);
    }

    #[test]
    fn flushes_each_completed_page_before_retaining_the_tail() {
        let _lock = BUFFERED_WRITER_WRITE_TEST_LOCK.lock();
        let Some((handle, state)) = fixture() else {
            note_missing_u32_fixture("crypto::buffered_writer_write");
            return;
        };
        let _flush = unsafe { FlushGuard::install() };
        let source: Vec<u8> = (0..8195).map(|index| (index % 251) as u8).collect();
        unsafe {
            (*state).pending_len = 4094;
            (*state).page_flags = 0xdead_beef;
            (*state).page[0] = 0x7a;
            assert_eq!(buffered_writer_write(handle, source.as_ptr(), source.len() as u32), 0);
            assert_eq!((*state).pending_len, 1);
            assert_eq!((*state).page_flags, 0);
            assert_eq!((*state).page[0], source[8194]);
        }

        let calls = *FLUSH_CALLS.lock();
        assert_eq!(calls.count, 3);
        assert_eq!(calls.pending, [4094, 0, 0]);
        assert_eq!(calls.flags, [0xdead_beef, 0, 0]);
        assert_eq!(calls.first, [0x7a, source[2], source[4098]]);
        assert_eq!(calls.penultimate, [source[0], source[4096], source[8192]]);
        assert_eq!(calls.last, [source[1], source[4097], source[8193]]);
        assert_eq!(calls.page_matches, [true; 3]);
    }

    #[test]
    fn reloads_pending_count_after_page_handoff() {
        let _lock = BUFFERED_WRITER_WRITE_TEST_LOCK.lock();
        let Some((handle, state)) = fixture() else {
            note_missing_u32_fixture("crypto::buffered_writer_write");
            return;
        };
        let _flush = unsafe { FlushGuard::install() };
        *FLUSH_PENDING_MUTATION.lock() = Some(4095);
        let source = [0x44u8, 0x55];
        unsafe {
            (*state).pending_len = 4094;
            assert_eq!(buffered_writer_write(handle, source.as_ptr(), source.len() as u32), 0);
            assert_eq!((*state).pending_len, 1);
            assert_eq!((*state).page[0], 0x55);
        }
        assert_eq!(FLUSH_CALLS.lock().pending[0], 4094);
    }
}
