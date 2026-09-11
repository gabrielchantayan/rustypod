//! Cache-block slot preparation and flush.
//!
//! `cache_block_prepare` is retailOS `FUN_082e48bc` at `0x082e48bc` (180
//! bytes; the separately entered next function begins at `0x082e4970`). Its
//! nine direct call sites were verified by decoding every ARM B/BL word in
//! `osos.dec`: all nine are unconditional `bl`, with no predicated forms.
//!
//! The routine rejects slot indices at or above 16. Under the cache lock, it
//! optionally marks the request header dirty and stamps its two halfword time
//! fields. It then acquires the requested cache block, saves the returned entry
//! in request word 6, copies the request header to that entry's selected
//! 32-byte slot, flushes the entry, and releases its reference. A failed flush
//! detaches the entry owner during that release.
//!
//! Deliberate deviations: the timestamp and cache-header-copy helpers at
//! `0x082e2264` and `0x082e26e8` remain unported, so device builds invoke their
//! verified retailOS addresses. The original enters `cache_block_acquire` with
//! caller-clobbered r2/r3 after the lock boundary; this port passes zero for
//! those unspecified ABI slots. Host builds use recording seams for the two
//! unported helpers and the acquire/flush boundaries, while the target uses
//! the existing cache-lock, cache-block, cache-entry-flush, and
//! cache-entry-release ports.

use super::{
    cache_block::cache_block_acquire,
    cache_entry::cache_entry_release,
    cache_entry_flush::cache_entry_flush,
    cache_lock::{cache_lock_signal, cache_lock_wait},
};

/// Target word index of the cache context pointer in a preparation request.
const REQUEST_CONTEXT_WORD: usize = 0;
/// Target word index of the 32-byte cache-header source in a request.
const REQUEST_HEADER_WORD: usize = 1;
/// Target word index of the storage block to acquire.
const REQUEST_BLOCK_INDEX_WORD: usize = 3;
/// Target word index of the destination slot in the acquired entry.
const REQUEST_SLOT_WORD: usize = 4;
/// Target word index receiving the acquired cache entry.
const REQUEST_ENTRY_WORD: usize = 6;
/// Number of 32-byte cache-header slots in one acquired entry.
const CACHE_ENTRY_SLOT_COUNT: u32 = 16;
/// Byte offset of the first cache-header slot in an acquired entry.
const CACHE_ENTRY_SLOT_OFFSET: usize = 0x18;
/// Byte size of one cache-header slot.
const CACHE_ENTRY_SLOT_SIZE: usize = 0x20;
/// Byte offset of the dirty flag in a cache-header source.
const CACHE_HEADER_FLAGS_OFFSET: usize = 0x0b;
/// Halfword index of the first timestamp destination (`+0x16`).
const CACHE_HEADER_TIMESTAMP_LOW_HALFWORD: usize = 11;
/// Halfword index of the second timestamp destination (`+0x18`).
const CACHE_HEADER_TIMESTAMP_HIGH_HALFWORD: usize = 12;

type TimestampHalves = unsafe extern "C" fn(*mut u16) -> *mut u16;
type CacheHeaderCopy = unsafe extern "C" fn(*mut u8, *mut u8);

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn timestamp_halves(output: *mut u16) {
    let function: TimestampHalves = core::mem::transmute(0x082e2264usize);
    function(output);
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn copy_cache_header(destination: *mut u8, source: *mut u8) {
    let function: CacheHeaderCopy = core::mem::transmute(0x082e26e8usize);
    function(destination, source);
}

#[cfg(not(target_os = "none"))]
type HostBoundary = unsafe extern "C" fn();
#[cfg(not(target_os = "none"))]
type HostCacheBlockAcquire = unsafe extern "C" fn(*mut u8, u32) -> *mut u8;
#[cfg(not(target_os = "none"))]
type HostCacheEntryFlush = unsafe extern "C" fn(*mut u8) -> u32;

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
struct CacheBlockPrepareHostOps {
    enter: HostBoundary,
    timestamp: TimestampHalves,
    leave: HostBoundary,
    acquire: HostCacheBlockAcquire,
    copy: CacheHeaderCopy,
    flush: HostCacheEntryFlush,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_boundary() {
    panic!("cache_block_prepare called without a host seam")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_timestamp(_output: *mut u16) -> *mut u16 {
    panic!("cache_block_prepare timestamp called without a host seam")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_acquire(_context: *mut u8, _block: u32) -> *mut u8 {
    panic!("cache_block_prepare acquire called without a host seam")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_copy(_destination: *mut u8, _source: *mut u8) {
    panic!("cache_block_prepare copy called without a host seam")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_flush(_entry: *mut u8) -> u32 {
    panic!("cache_block_prepare flush called without a host seam")
}

#[cfg(not(target_os = "none"))]
const DEFAULT_CACHE_BLOCK_PREPARE_HOST_OPS: CacheBlockPrepareHostOps = CacheBlockPrepareHostOps {
    enter: unavailable_boundary,
    timestamp: unavailable_timestamp,
    leave: unavailable_boundary,
    acquire: unavailable_acquire,
    copy: unavailable_copy,
    flush: unavailable_flush,
};

#[cfg(not(target_os = "none"))]
static mut CACHE_BLOCK_PREPARE_HOST_OPS: CacheBlockPrepareHostOps = DEFAULT_CACHE_BLOCK_PREPARE_HOST_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn host_ops() -> CacheBlockPrepareHostOps {
    core::ptr::read_volatile(core::ptr::addr_of!(CACHE_BLOCK_PREPARE_HOST_OPS))
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn timestamp_halves(output: *mut u16) {
    (host_ops().timestamp)(output);
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn copy_cache_header(destination: *mut u8, source: *mut u8) {
    (host_ops().copy)(destination, source)
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn cache_lock_enter() {
    (host_ops().enter)();
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn cache_lock_enter() {
    cache_lock_wait();
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn cache_lock_leave() {
    (host_ops().leave)();
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn cache_lock_leave() {
    cache_lock_signal();
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn acquire_cache_block(context: *mut u8, block_index: u32) -> *mut u8 {
    (host_ops().acquire)(context, block_index)
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn acquire_cache_block(context: *mut u8, block_index: u32) -> *mut u8 {
    cache_block_acquire(context, block_index, 0, 0)
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn flush_cache_entry(entry: *mut u8) -> u32 {
    (host_ops().flush)(entry)
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn flush_cache_entry(entry: *mut u8) -> u32 {
    cache_entry_flush(entry)
}

/// Prepares the selected header slot in an acquired cache block and flushes it.
///
/// Original: `FUN_082e48bc` at `0x082e48bc`, 180 bytes, nine unconditional
/// `bl` call sites (binary-verified). `set_dirty` sets bit 5 in header byte
/// `+0x0b`; `set_timestamp` calls the retail timestamp helper and places its
/// low and high halves at header offsets `+0x16` and `+0x18` respectively.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cache_block_prepare(
    request: *mut u8,
    set_dirty: u32,
    set_timestamp: u32,
) -> u32 {
    let request_words = request.cast::<u32>();
    let slot = request_words.add(REQUEST_SLOT_WORD).read();
    if slot >= CACHE_ENTRY_SLOT_COUNT {
        return 0;
    }

    let header = request_words.add(REQUEST_HEADER_WORD).read() as usize as *mut u8;
    cache_lock_enter();
    if set_dirty != 0 {
        let flags = header.add(CACHE_HEADER_FLAGS_OFFSET).read();
        header.add(CACHE_HEADER_FLAGS_OFFSET).write(flags | 0x20);
    }
    if set_timestamp != 0 {
        let mut timestamp = [0u16; 2];
        timestamp_halves(timestamp.as_mut_ptr());
        header
            .cast::<u16>()
            .add(CACHE_HEADER_TIMESTAMP_LOW_HALFWORD)
            .write(timestamp[1]);
        header
            .cast::<u16>()
            .add(CACHE_HEADER_TIMESTAMP_HIGH_HALFWORD)
            .write(timestamp[0]);
    }
    cache_lock_leave();

    let context = request_words.add(REQUEST_CONTEXT_WORD).read() as usize as *mut u8;
    let block_index = request_words.add(REQUEST_BLOCK_INDEX_WORD).read();
    let entry = acquire_cache_block(context, block_index);
    request_words.add(REQUEST_ENTRY_WORD).write(entry as usize as u32);
    if entry.is_null() {
        return 0;
    }

    let destination = entry.add(CACHE_ENTRY_SLOT_OFFSET + slot as usize * CACHE_ENTRY_SLOT_SIZE);
    copy_cache_header(destination, header);
    let flush_result = flush_cache_entry(entry);
    cache_entry_release(entry, (flush_result == 0) as u32);
    flush_result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, try_map_u32_slab};

    static mut ENTERS: u32 = 0;
    static mut LEAVES: u32 = 0;
    static mut TIMESTAMP_CALLS: u32 = 0;
    static mut ACQUIRE_CALL: Option<(*mut u8, u32)> = None;
    static mut COPY_CALL: Option<(*mut u8, *mut u8)> = None;
    static mut FLUSH_CALL: Option<*mut u8> = None;
    static mut ACQUIRED_ENTRY: *mut u8 = core::ptr::null_mut();
    static mut FLUSH_RESULT: u32 = 0;

    unsafe extern "C" fn record_enter() {
        ENTERS += 1;
    }
    unsafe extern "C" fn record_timestamp(output: *mut u16) -> *mut u16 {
        TIMESTAMP_CALLS += 1;
        output.write(0x1122);
        output.add(1).write(0x3344);
        output
    }
    unsafe extern "C" fn record_leave() {
        LEAVES += 1;
    }
    unsafe extern "C" fn record_acquire(context: *mut u8, block_index: u32) -> *mut u8 {
        ACQUIRE_CALL = Some((context, block_index));
        ACQUIRED_ENTRY
    }
    unsafe extern "C" fn record_copy(destination: *mut u8, source: *mut u8) {
        COPY_CALL = Some((destination, source));
    }
    unsafe extern "C" fn record_flush(entry: *mut u8) -> u32 {
        FLUSH_CALL = Some(entry);
        FLUSH_RESULT
    }

    struct HostOpsReset(CacheBlockPrepareHostOps);

    impl Drop for HostOpsReset {
        fn drop(&mut self) {
            unsafe {
                CACHE_BLOCK_PREPARE_HOST_OPS = self.0;
            }
        }
    }

    #[test]
    fn bounds_null_acquisition_and_success_follow_the_retail_order() {
        let Some(slab) = try_map_u32_slab(hints::CACHE_BLOCK_PREPARE, 0x1000) else {
            return;
        };
        let request = slab.cast::<u32>();
        let context = unsafe { slab.add(0x100) };
        let header = unsafe { slab.add(0x200) };
        let entry = unsafe { slab.add(0x300) };
        let reset = unsafe {
            let prior = host_ops();
            CACHE_BLOCK_PREPARE_HOST_OPS = CacheBlockPrepareHostOps {
                enter: record_enter,
                timestamp: record_timestamp,
                leave: record_leave,
                acquire: record_acquire,
                copy: record_copy,
                flush: record_flush,
            };
            HostOpsReset(prior)
        };

        unsafe {
            request.add(REQUEST_CONTEXT_WORD).write(context as usize as u32);
            request.add(REQUEST_HEADER_WORD).write(header as usize as u32);
            request.add(REQUEST_BLOCK_INDEX_WORD).write(0x1234_5678);
            request.add(REQUEST_ENTRY_WORD).write(0xfeed_face);
            request.add(REQUEST_SLOT_WORD).write(CACHE_ENTRY_SLOT_COUNT);
            ENTERS = 0;
            LEAVES = 0;
            TIMESTAMP_CALLS = 0;
            ACQUIRE_CALL = None;
            COPY_CALL = None;
            FLUSH_CALL = None;
            assert_eq!(cache_block_prepare(request.cast(), 1, 1), 0);
            assert_eq!(request.add(REQUEST_ENTRY_WORD).read(), 0xfeed_face);
            assert_eq!(ENTERS, 0);
            assert_eq!(LEAVES, 0);
            assert_eq!(TIMESTAMP_CALLS, 0);
            assert!(ACQUIRE_CALL.is_none());

            request.add(REQUEST_SLOT_WORD).write(2);
            header.add(CACHE_HEADER_FLAGS_OFFSET).write(0x81);
            header.cast::<u16>().add(CACHE_HEADER_TIMESTAMP_LOW_HALFWORD).write(0);
            header.cast::<u16>().add(CACHE_HEADER_TIMESTAMP_HIGH_HALFWORD).write(0);
            ACQUIRED_ENTRY = core::ptr::null_mut();
            assert_eq!(cache_block_prepare(request.cast(), 1, 1), 0);
            assert_eq!(header.add(CACHE_HEADER_FLAGS_OFFSET).read(), 0xa1);
            assert_eq!(header.cast::<u16>().add(CACHE_HEADER_TIMESTAMP_LOW_HALFWORD).read(), 0x3344);
            assert_eq!(header.cast::<u16>().add(CACHE_HEADER_TIMESTAMP_HIGH_HALFWORD).read(), 0x1122);
            assert_eq!(ACQUIRE_CALL, Some((context, 0x1234_5678)));
            assert!(COPY_CALL.is_none());
            assert!(FLUSH_CALL.is_none());

            let entry_words = entry.cast::<u32>();
            entry_words.add(2).write(0xcafe_babe);
            entry_words.add(4).write(2);
            ACQUIRED_ENTRY = entry;
            FLUSH_RESULT = 1;
            COPY_CALL = None;
            FLUSH_CALL = None;
            assert_eq!(cache_block_prepare(request.cast(), 0, 0), 1);
            assert_eq!(request.add(REQUEST_ENTRY_WORD).read(), entry as usize as u32);
            assert_eq!(COPY_CALL, Some((entry.add(CACHE_ENTRY_SLOT_OFFSET + 2 * CACHE_ENTRY_SLOT_SIZE), header)));
            assert_eq!(FLUSH_CALL, Some(entry));
            assert_eq!(entry_words.add(2).read(), 0xcafe_babe);
            assert_eq!(entry_words.add(4).read(), 1);
            entry_words.add(2).write(0x0bad_f00d);
            entry_words.add(4).write(2);
            FLUSH_RESULT = 0;
            assert_eq!(cache_block_prepare(request.cast(), 0, 0), 0);
            assert_eq!(entry_words.add(2).read(), 0);
            assert_eq!(entry_words.add(4).read(), 1);
            assert_eq!(ENTERS, 3);
            assert_eq!(LEAVES, 3);
            assert_eq!(TIMESTAMP_CALLS, 1);
        }

        drop(reset);
    }
}
