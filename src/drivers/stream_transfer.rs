//! Stream transfer-record copy and cursor advance.
//!
//! `stream_transfer_record_to_cursor` — original: `FUN_08088ed0` @
//! `0x08088ed0` (56 bytes). Reference:
//! `/home/gabe/Programming/ipod-decomp/decomp/c/005/08088ed0_FUN_08088ed0.c`;
//! raw ARM is `0x08088ed0..0x08088f08`.
//!
//! The record holds a byte count at `+0x00` and source pointer at `+0x08`.
//! When the cursor slot is non-null, the ARM code loads its current destination,
//! calls veneer `0x08037db0` (`0x22000020`, `__rt_memcpy`) with
//! `(destination, source, byte_count)`, then reloads and advances the cursor
//! by the same count with wrapping address arithmetic. It always returns the
//! record's byte count. A raw decode of every ARM B/BL instruction found no
//! direct branch to this untracked leaf; the call boundary is identified by
//! the veneer and its recovered `__rt_memcpy` ABI.

use crate::libc::rt_memcpy::__rt_memcpy;

/// Record consumed by [`stream_transfer_record_to_cursor`]. The copied byte
/// count is at `+0x00`; its source starts at `+0x08` on both ARM and hosts.
#[repr(C)]
pub struct StreamTransferRecord {
    pub byte_count: u32,
    pub opaque: u32,
    pub source: *const u8,
}

/// Exact three-register ABI of IRAM `__rt_memcpy` at `0x22000020`, reached by
/// retailOS through veneer `0x08037db0`.
pub type StreamTransferCopyFn = unsafe extern "C" fn(*mut u8, *const u8, u32) -> *mut u8;

/// Calls outside this one-function port.
///
/// The IRAM runtime copy has an already-ported mirror,
/// [`__rt_memcpy`]. The default uses that direct port; host tests replace the
/// boundary with a recorder, following the crate's runtime-call seam pattern.
#[derive(Clone, Copy)]
pub struct StreamTransferOps {
    pub copy: StreamTransferCopyFn,
}

unsafe extern "C" fn runtime_rt_memcpy(dst: *mut u8, src: *const u8, byte_count: u32) -> *mut u8 {
    __rt_memcpy(dst, src, byte_count as usize)
}

/// Default target/host runtime-copy boundary.
pub const DEFAULT_STREAM_TRANSFER_OPS: StreamTransferOps = StreamTransferOps {
    copy: runtime_rt_memcpy,
};

/// Active runtime-copy boundary. The target default calls the existing
/// `__rt_memcpy` port; host tests install a recorder to prove the exact ARM
/// argument order and the post-call cursor update.
pub static mut STREAM_TRANSFER_OPS: StreamTransferOps = DEFAULT_STREAM_TRANSFER_OPS;

#[inline(always)]
fn stream_transfer_ops() -> StreamTransferOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(STREAM_TRANSFER_OPS)) }
}

/// stream_transfer_record_to_cursor — original: `FUN_08088ed0` @
/// `0x08088ed0` (56 bytes).
///
/// Optionally copies `record.byte_count` bytes from `record.source` to the
/// pointer stored in `cursor`, then advances that pointer by the count using
/// wrapping arithmetic. A null cursor skips both operations. The count is
/// returned in every case.
///
/// # Safety
///
/// `record` must be valid. If `cursor` is non-null, it must name a writable
/// cursor slot and its pointed-to destination and `record.source` must satisfy
/// the non-overlapping `__rt_memcpy` contract for `record.byte_count` bytes.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn stream_transfer_record_to_cursor(
    record: *const StreamTransferRecord,
    cursor: *mut *mut u8,
) -> u32 {
    if cursor.is_null() {
        return (*record).byte_count;
    }
    let source = (*record).source;
    let byte_count = (*record).byte_count;
    let destination = *cursor;
    (stream_transfer_ops().copy)(destination, source, byte_count);
    *cursor = destination.wrapping_add((*record).byte_count as usize);
    (*record).byte_count
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr::{addr_of, addr_of_mut, null_mut};
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut COPY_CALLS: Vec<CopyCall> = Vec::new();
    static mut OBSERVED_CURSOR_SLOT: *mut *mut u8 = null_mut();
    static mut POST_CALL_COUNT_MUTATION: *mut u32 = null_mut();

    #[derive(Debug, PartialEq, Eq)]
    struct CopyCall {
        destination: usize,
        source: usize,
        byte_count: u32,
        cursor_during_copy: usize,
    }

    unsafe extern "C" fn recording_copy(
        destination: *mut u8,
        source: *const u8,
        byte_count: u32,
    ) -> *mut u8 {
        let cursor_during_copy = if (*addr_of!(OBSERVED_CURSOR_SLOT)).is_null() {
            0
        } else {
            *(*addr_of!(OBSERVED_CURSOR_SLOT)) as usize
        };
        (*addr_of_mut!(COPY_CALLS)).push(CopyCall {
            destination: destination as usize,
            source: source as usize,
            byte_count,
            cursor_during_copy,
        });
        if !(*addr_of!(POST_CALL_COUNT_MUTATION)).is_null() {
            (*addr_of!(POST_CALL_COUNT_MUTATION)).write(1);
        }
        destination
    }

    fn install_recorder() -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            (*addr_of_mut!(COPY_CALLS)).clear();
            addr_of_mut!(POST_CALL_COUNT_MUTATION).write(null_mut());
            addr_of_mut!(STREAM_TRANSFER_OPS).write(StreamTransferOps { copy: recording_copy });
        }
        guard
    }

    fn restore_default(guard: MutexGuard<'static, ()>) {
        unsafe {
            addr_of_mut!(STREAM_TRANSFER_OPS).write(DEFAULT_STREAM_TRANSFER_OPS);
            addr_of_mut!(OBSERVED_CURSOR_SLOT).write(null_mut());
            addr_of_mut!(POST_CALL_COUNT_MUTATION).write(null_mut());
        }
        drop(guard);
    }

    #[test]
    fn null_cursor_returns_length_without_calling_runtime_copy() {
        let guard = install_recorder();
        let source = [0x11u8, 0x22, 0x33];
        let record = StreamTransferRecord {
            byte_count: source.len() as u32,
            opaque: 0xa5a5_a5a5,
            source: source.as_ptr(),
        };

        assert_eq!(unsafe { stream_transfer_record_to_cursor(&record, null_mut()) }, 3);
        assert!(unsafe { (*addr_of!(COPY_CALLS)).is_empty() });
        restore_default(guard);
    }

    #[test]
    fn runtime_copy_gets_cursor_source_and_length_before_cursor_advances() {
        let guard = install_recorder();
        let source = [0x01u8, 0x02, 0x03, 0x04, 0x05];
        let record = StreamTransferRecord {
            byte_count: source.len() as u32,
            opaque: 0,
            source: source.as_ptr(),
        };
        let mut destination = [0u8; 8];
        let start = destination.as_mut_ptr();
        let mut cursor = start;
        unsafe { addr_of_mut!(OBSERVED_CURSOR_SLOT).write(&mut cursor) };

        assert_eq!(unsafe { stream_transfer_record_to_cursor(&record, &mut cursor) }, 5);
        assert_eq!(
            unsafe { &*addr_of!(COPY_CALLS) },
            &[CopyCall {
                destination: start as usize,
                source: source.as_ptr() as usize,
                byte_count: 5,
                cursor_during_copy: start as usize,
            }],
            "the copy sees the old cursor, so advance is post-call"
        );
        assert_eq!(cursor, unsafe { start.add(5) });
        restore_default(guard);
    }

    #[test]
    fn post_call_record_count_controls_the_advanced_cursor_and_return() {
        let guard = install_recorder();
        let source = [0x11u8, 0x22, 0x33, 0x44, 0x55];
        let mut record = StreamTransferRecord {
            byte_count: source.len() as u32,
            opaque: 0,
            source: source.as_ptr(),
        };
        let mut destination = [0u8; 8];
        let start = destination.as_mut_ptr();
        let mut cursor = start;
        unsafe { addr_of_mut!(POST_CALL_COUNT_MUTATION).write(addr_of_mut!(record.byte_count)) };

        assert_eq!(unsafe { stream_transfer_record_to_cursor(&record, &mut cursor) }, 1);
        assert_eq!(cursor, unsafe { start.add(1) });
        restore_default(guard);
    }

    #[test]
    fn default_runtime_copy_transfers_the_record_span_and_advances_cursor() {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe { addr_of_mut!(STREAM_TRANSFER_OPS).write(DEFAULT_STREAM_TRANSFER_OPS) };
        let source = [0x91u8, 0x82, 0x73, 0x64];
        let record = StreamTransferRecord {
            byte_count: source.len() as u32,
            opaque: u32::MAX,
            source: source.as_ptr(),
        };
        let mut destination = [0xa5u8; 9];
        let start = destination.as_mut_ptr();
        let mut cursor = unsafe { start.add(2) };

        assert_eq!(unsafe { stream_transfer_record_to_cursor(&record, &mut cursor) }, 4);
        assert_eq!(&destination[..2], &[0xa5; 2]);
        assert_eq!(&destination[2..6], &source);
        assert_eq!(&destination[6..], &[0xa5; 3]);
        assert_eq!(cursor, unsafe { start.add(6) });
        drop(guard);
    }
}
