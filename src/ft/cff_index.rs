//! FreeType CFF index lifetime management (`cffload.c`).
//!
//! A [`CffIndex`] holds an optional frame borrowed from its source
//! [`FtStream`] and a separately allocated offset table.  The CFF font
//! loader constructs five of these records and calls [`cff_index_done`] while
//! unwinding a face.

use crate::ft::memory::ft_mem_free;
use crate::ft::stream::{ft_stream_release_frame, FtStream};
use crate::libc::memzero::memzero_aligned;

/// `CFF_IndexRec` as used by this retailOS build.  The index reader at
/// `0x08083338` zeroes 24 bytes, then stores `stream`, `count`, `off_size`,
/// `data_offset`, `offsets`, and (for an extracted frame) `bytes` at these
/// offsets.
#[repr(C)]
pub struct CffIndex {
    pub stream: *mut FtStream,
    pub count: u32,
    pub off_size: u8,
    pub _padding: [u8; 3],
    pub data_offset: u32,
    pub offsets: *mut u32,
    pub bytes: *mut u8,
}

#[cfg(target_pointer_width = "32")]
const _: () = assert!(core::mem::offset_of!(CffIndex, count) == 4);
#[cfg(target_pointer_width = "32")]
const _: () = assert!(core::mem::offset_of!(CffIndex, off_size) == 8);
#[cfg(target_pointer_width = "32")]
const _: () = assert!(core::mem::offset_of!(CffIndex, data_offset) == 12);
#[cfg(target_pointer_width = "32")]
const _: () = assert!(core::mem::offset_of!(CffIndex, offsets) == 16);
#[cfg(target_pointer_width = "32")]
const _: () = assert!(core::mem::offset_of!(CffIndex, bytes) == 20);
#[cfg(target_pointer_width = "32")]
const _: () = assert!(core::mem::size_of::<CffIndex>() == 24);

/// cff_index_done (FreeType `CFF_Index_Done`) — original: `FUN_08087bac` @
/// 0x08087bac (76 bytes, `0x08087bac..0x08087bf8`; the sibling function
/// opens with `push {r4-r9, sl, lr}` at `0x08087bf8`).  Seven direct BL call
/// sites verified by decoding every ARM B/BL word in `osos.dec`: all are
/// unconditional (`0x08082d28`, `0x08082d30`, `0x08082d3c`, `0x08082d44`,
/// `0x08082d50`, `0x0808318c`, and `0x0809a2b8`).
///
/// If `index->stream` is non-null, releases its optional extracted frame,
/// frees the offset table through `stream->memory`, then zeroes all six words
/// of the record.  A null `stream` returns without touching the record; this
/// is the raw ARM `ldreq`/`popeq` path, not a null guard for `index`.
///
/// Deliberate deviation: retail calls the two existing FreeType ports
/// directly, then tail-branches through the IRAM `memzero_aligned` veneer at
/// `0x08037db8`. This port loads all three callees through volatile
/// function-pointer reads: the first two prevent LLVM from inlining their
/// null guards and the third prevents lowering the fixed fill to an AEABI
/// builtin. The resulting indirect calls preserve the same observable order.
///
/// # Safety
/// `index` must point to a valid [`CffIndex`].  When `index->stream` is
/// non-null, its `memory`, `offsets`, and (when its `read` callback is set)
/// `bytes` must satisfy the corresponding FreeType release contracts.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cff_index_done(index: *mut CffIndex) {
    let stream = (*index).stream;
    if stream.is_null() {
        return;
    }

    if !(*index).bytes.is_null() {
        let release = core::ptr::read_volatile(
            &(ft_stream_release_frame as unsafe extern "C" fn(*mut FtStream, *mut *mut u8)),
        );
        release(stream, &mut (*index).bytes);
    }
    let free = core::ptr::read_volatile(
        &(ft_mem_free as unsafe extern "C" fn(*mut crate::ft::memory::FtMemory, *mut u8)),
    );
    free((*stream).memory, (*index).offsets.cast());
    (*index).offsets = core::ptr::null_mut();

    let zero = core::ptr::read_volatile(
        &(memzero_aligned as unsafe extern "C" fn(*mut u8, usize) -> *mut u8),
    );
    zero(index.cast(), core::mem::size_of::<CffIndex>());
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ft::memory::{FtMemory, FtReallocFunc};
    use crate::ft::stream::{FtStreamCloseFunc, FtStreamIoFunc};
    use core::ffi::c_void;
    use core::ptr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static FREE_COUNT: AtomicUsize = AtomicUsize::new(0);
    static FIRST_FREE: AtomicUsize = AtomicUsize::new(0);
    static SECOND_FREE: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn unused_alloc(_memory: *mut FtMemory, _size: i32) -> *mut u8 {
        ptr::null_mut()
    }

    unsafe extern "C" fn record_free(_memory: *mut FtMemory, block: *mut u8) {
        match FREE_COUNT.fetch_add(1, Ordering::SeqCst) {
            0 => FIRST_FREE.store(block as usize, Ordering::SeqCst),
            1 => SECOND_FREE.store(block as usize, Ordering::SeqCst),
            _ => panic!("unexpected extra free"),
        }
    }

    unsafe extern "C" fn unused_realloc(
        _memory: *mut FtMemory,
        _cur_size: i32,
        _new_size: i32,
        _block: *mut u8,
    ) -> *mut u8 {
        ptr::null_mut()
    }

    fn test_memory() -> FtMemory {
        FtMemory {
            user: ptr::null_mut::<c_void>(),
            alloc: unused_alloc,
            free: record_free,
            realloc: unused_realloc as FtReallocFunc,
        }
    }

    fn test_stream(memory: *mut FtMemory, read: Option<FtStreamIoFunc>) -> FtStream {
        FtStream {
            base: ptr::null_mut(),
            size: 0,
            pos: 0,
            descriptor: ptr::null_mut(),
            pathname: ptr::null_mut(),
            read,
            close: None::<FtStreamCloseFunc>,
            memory,
            cursor: ptr::null_mut(),
            limit: ptr::null_mut(),
        }
    }

    #[test]
    fn index_done_releases_frame_before_offsets_and_clears_record() {
        let _guard = TEST_LOCK.lock();
        FREE_COUNT.store(0, Ordering::SeqCst);
        FIRST_FREE.store(0, Ordering::SeqCst);
        SECOND_FREE.store(0, Ordering::SeqCst);

        unsafe extern "C" fn read_stub(
            _stream: *mut FtStream,
            _offset: u32,
            _buffer: *mut u8,
            _count: u32,
        ) -> u32 {
            0
        }

        let mut memory = test_memory();
        let mut stream = test_stream(&mut memory, Some(read_stub));
        let offsets = 0x1111usize as *mut u32;
        let bytes = 0x2222usize as *mut u8;
        let mut index = CffIndex {
            stream: &mut stream,
            count: 7,
            off_size: 3,
            _padding: [0xa5; 3],
            data_offset: 0x4455_6677,
            offsets,
            bytes,
        };

        unsafe { cff_index_done(&mut index) };

        assert_eq!(FREE_COUNT.load(Ordering::SeqCst), 2);
        assert_eq!(FIRST_FREE.load(Ordering::SeqCst), bytes as usize);
        assert_eq!(SECOND_FREE.load(Ordering::SeqCst), offsets as usize);
        assert!(index.stream.is_null());
        assert_eq!(index.count, 0);
        assert_eq!(index.off_size, 0);
        assert_eq!(index._padding, [0; 3]);
        assert_eq!(index.data_offset, 0);
        assert!(index.offsets.is_null());
        assert!(index.bytes.is_null());
    }

    #[test]
    fn index_done_for_memory_stream_forgets_frame_without_freeing_it() {
        let _guard = TEST_LOCK.lock();
        FREE_COUNT.store(0, Ordering::SeqCst);
        FIRST_FREE.store(0, Ordering::SeqCst);

        let mut memory = test_memory();
        let mut stream = test_stream(&mut memory, None);
        let offsets = 0x1111usize as *mut u32;
        let bytes = 0x2222usize as *mut u8;
        let mut index = CffIndex {
            stream: &mut stream,
            count: 1,
            off_size: 1,
            _padding: [0; 3],
            data_offset: 2,
            offsets,
            bytes,
        };

        unsafe { cff_index_done(&mut index) };

        assert_eq!(FREE_COUNT.load(Ordering::SeqCst), 1);
        assert_eq!(FIRST_FREE.load(Ordering::SeqCst), offsets as usize);
        assert!(index.stream.is_null());
        assert!(index.offsets.is_null());
        assert!(index.bytes.is_null());
    }

    #[test]
    fn index_done_with_null_stream_leaves_record_untouched() {
        let _guard = TEST_LOCK.lock();
        FREE_COUNT.store(0, Ordering::SeqCst);

        let offsets = 0x1111usize as *mut u32;
        let bytes = 0x2222usize as *mut u8;
        let mut index = CffIndex {
            stream: ptr::null_mut(),
            count: 7,
            off_size: 3,
            _padding: [0xa5; 3],
            data_offset: 0x4455_6677,
            offsets,
            bytes,
        };

        unsafe { cff_index_done(&mut index) };

        assert_eq!(FREE_COUNT.load(Ordering::SeqCst), 0);
        assert_eq!(index.count, 7);
        assert_eq!(index.off_size, 3);
        assert_eq!(index._padding, [0xa5; 3]);
        assert_eq!(index.data_offset, 0x4455_6677);
        assert_eq!(index.offsets, offsets);
        assert_eq!(index.bytes, bytes);
    }
}
