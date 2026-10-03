//! Locked platform-file buffer flush and facade status aggregation.
//!
//! `FUN_08278938` @ 0x08278938: 100 bytes, next function 0x0827899c.
//! Raw-word census: two incoming BLs (one AL at 0x081f53d0, one NE at
//! 0x0805ae60); body has five plain BLs, no predicated BLs, one BLX r2.
//! Acquire the owner's counted mutex; if the directory index is -1, return
//! cached status at +0x1c. Otherwise flush the +0x40 buffer collection, select
//! facade 1, call its vtable slot +0x2c with the index, and OR both results.
//! Always release the acquired mutex before returning, including errors.
//!
//! Deviation: the verified but unported collection helper @ 0x082780cc is
//! called at its retail address on-device; host execution of that boundary
//! panics rather than pretending to flush. The facade slot's identity remains
//! unknown. Native-width vtable indexing preserves target four-byte slots.

use crate::app::facade_for_selector::facade_for_selector;
use crate::codegen::file_directory_entry::file_has_directory_entry;
use crate::kernel::sync_mutex::{counted_mutex_guard_acquire, mutex_unlock_counted};

#[inline(always)]
pub(super) unsafe fn flush_buffer_collection(collection: *mut u8) -> u32 {
    #[cfg(target_os = "none")]
    {
        let flush: unsafe extern "C" fn(*mut u8) -> u32 =
            core::mem::transmute(0x0827_80ccusize);
        flush(collection)
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = collection;
        panic!("retail buffer collection flush requires the device")
    }
}

#[inline(always)]
unsafe fn flush_locked<L>(
    file: *mut u8,
    acquire: impl FnOnce(*mut u8) -> L,
    flush: impl FnOnce(*mut u8) -> u32,
    dispatch: impl FnOnce(*mut u8) -> u32,
    release: impl FnOnce(L),
) -> u32 {
    let lock = acquire(file);
    let result = if file_has_directory_entry(file) == 0 {
        file.add(0x1c).cast::<u32>().read()
    } else {
        let buffered = flush(file.add(0x40));
        let facade = dispatch(file);
        buffered | facade
    };
    release(lock);
    result
}

/// Flush the file under its owner's mutex; see module header for binary evidence.
///
/// # Safety
/// `file` must be a live target-layout platform file (at least 0x54 bytes),
/// with a valid owner, buffer collection, facade and vtable callback.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn platform_file_flush(file: *mut u8) -> u32 {
    flush_locked(
        file,
        |file| {
            let mut lock = core::ptr::null_mut();
            counted_mutex_guard_acquire(&mut lock, file.cast());
            lock
        },
        |collection| flush_buffer_collection(collection),
        |file| {
            let facade = facade_for_selector(file.cast(), 1);
            let vtable = facade.cast::<*const usize>().read();
            let index = file.add(0x18).cast::<u32>().read();
            let callback: unsafe extern "C" fn(*mut u8, u32) -> u32 =
                core::mem::transmute(vtable.add(11).read());
            callback(facade.cast(), index)
        },
        |lock| mutex_unlock_counted(lock),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;

    #[test]
    fn closed_returns_cached_status_after_lock_without_flushing() {
        let mut file = [0u32; 0x54 / 4];
        file[6] = 123;
        file[7] = 0x8000_0008;
        let released = Cell::new(false);
        let result = unsafe {
            flush_locked(file.as_mut_ptr().cast(), |file| {
                // The predicate must run after acquisition, not before it.
                file.add(0x18).cast::<u32>().write(u32::MAX);
                17
            }, |_| panic!("closed file flushed"), |_| panic!("closed file dispatched"),
            |lock| { assert_eq!(lock, 17); released.set(true); })
        };
        assert_eq!(result, 0x8000_0008);
        assert!(released.get());
    }

    #[test]
    fn open_combines_all_error_bits_and_reloads_index_after_flush() {
        for (buffered, facade_status) in [(0, 0), (0, 8), (4, 0), (4, 8),
                                         (0x8000_0000, 1), (u32::MAX, 8)] {
            let mut file = [0u32; 0x54 / 4];
            file[6] = 0;
            file[7] = 0xdead_beef;
            let phase = Cell::new(0);
            let result = unsafe {
                flush_locked(file.as_mut_ptr().cast(), |_| { phase.set(1); () },
                    |collection| {
                        assert_eq!(phase.get(), 1);
                        collection.sub(0x28).cast::<u32>().write(37);
                        phase.set(2);
                        buffered
                    }, |file| {
                        let index = file.add(0x18).cast::<u32>().read();
                        assert_eq!(phase.get(), 2);
                        assert_eq!(index, 37);
                        phase.set(3);
                        facade_status
                    }, |_| { assert_eq!(phase.get(), 3); phase.set(4); })
            };
            assert_eq!(result, buffered | facade_status);
            assert_eq!(phase.get(), 4);
            assert_eq!(file[7], 0xdead_beef);
        }
    }
}
