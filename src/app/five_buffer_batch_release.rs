//! Five-buffer batch release — FUN_08105024 @ 0x08105024.
//!
//! True extent 96 bytes, 0x08105024..0x08105084: 88 instruction bytes
//! and literals 0x089d0554 and 0x089caf61. Raw words verify three outbound
//! plain BLs, zero predicated BLs; two inbound plain BLs at 0x08104ee0 and
//! 0x08104f04, zero predicated BLs. Signal controller entry 0x81, then read
//! the enabled byte. If nonzero, reload the batch table for each of five
//! 12-byte records, capture its buffer key, initialize the static pool,
//! and release that key. Ignore all callee results; do not clear the batch.
//!
//! Deviations: existing signal/pool ports replace their stock calls; the
//! unported release remains at verified ARM address 0x08205e5c. Native
//! repr(C) pointers widen only host fixtures. Host export cannot access
//! retail globals; tests exercise the shared algorithm with local storage.

use core::ptr;

#[repr(C)]
pub struct BufferBatchEntry {
    pub buffer_key: u32,
    pub remaining: [u32; 2],
}

#[repr(C)]
pub struct FiveBufferBatch {
    pub unresolved: u32,
    pub entries: *const BufferBatchEntry,
}

#[cfg(target_os = "none")]
const _: () = {
    assert!(core::mem::offset_of!(FiveBufferBatch, entries) == 4);
    assert!(core::mem::size_of::<BufferBatchEntry>() == 12);
};

#[inline(always)]
unsafe fn release_batch(
    batch: *const FiveBufferBatch,
    enabled: *const u8,
    signal: impl FnOnce(),
    mut initialize: impl FnMut(),
    mut release: impl FnMut(u32),
) {
    signal();
    if ptr::read_volatile(enabled) != 0 {
        for index in 0..5 {
            let entries = ptr::read_volatile(ptr::addr_of!((*batch).entries));
            let key = ptr::read(ptr::addr_of!((*entries.add(index)).buffer_key));
            initialize();
            release(key);
        }
    }
}

/// Signal entry 0x81 and return the batch's five buffers to the static pool.
///
/// # Safety
/// Retail globals and stock pool release must be available. When enabled,
/// `batch` must reference five valid records and remain valid across calls.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn five_buffer_batch_release(batch: *const FiveBufferBatch) {
    #[cfg(target_os = "none")]
    {
        use super::registered_entry_signal::registered_entry_signal;
        use super::static_buffer_pool::static_buffer_pool_get;
        let controller = ptr::read((0x089d_0554 as *const u32).add(1)) as *mut u8;
        let stock_release: unsafe extern "C" fn(u32) -> u32 =
            core::mem::transmute(0x0820_5e5cusize);
        release_batch(batch, 0x089c_af61 as *const u8,
            || { registered_entry_signal(controller, 0x81); },
            || { static_buffer_pool_get(); },
            |key| { stock_release(key); });
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = batch;
        panic!("five_buffer_batch_release requires retailOS globals on host")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;

    fn entries(keys: [u32; 5]) -> [BufferBatchEntry; 5] {
        keys.map(|buffer_key| BufferBatchEntry { buffer_key, remaining: [0xaaaaaaaa, 0xbbbbbbbb] })
    }

    #[test]
    fn disabled_after_signal_never_dereferences_batch() {
        let enabled = Cell::new(0xffu8);
        unsafe {
            release_batch(ptr::null(), enabled.as_ptr(), || enabled.set(0),
                || panic!("disabled initialization"), |_| panic!("disabled release"));
        }
        assert_eq!(enabled.get(), 0);
    }

    #[test]
    fn signal_enables_release_and_each_iteration_reloads_table_before_initialization() {
        let first = entries([10, 11, 12, 13, 14]);
        let second = entries([20, 21, 22, 23, 24]);
        let mut batch = FiveBufferBatch { unresolved: 0x12345678, entries: first.as_ptr() };
        let batch_ptr = &mut batch as *mut FiveBufferBatch;
        let enabled = Cell::new(0u8);
        let initialized = Cell::new(false);
        // An occupied-key model: releasing unknown keys has no effect, as in stock.
        let mut occupied = [10, 11, 20, 21, 22, 23, 24, 14];
        unsafe {
            release_batch(batch_ptr, enabled.as_ptr(), || enabled.set(0x80),
                || {
                    initialized.set(true);
                    // Must not change the key already captured for this iteration.
                    (*batch_ptr).entries = second.as_ptr();
                },
                |key| {
                    assert!(initialized.replace(false));
                    if let Some(slot) = occupied.iter_mut().find(|slot| **slot == key) { *slot = 0; }
                });
        }
        assert_eq!(occupied, [0, 11, 20, 0, 0, 0, 0, 14]);
        assert_eq!(batch.unresolved, 0x12345678);
        assert_eq!(first[0].buffer_key, 10);
        assert_eq!(second[4].buffer_key, 24);
        for entry in first.iter().chain(second.iter()) {
            assert_eq!(entry.remaining, [0xaaaaaaaa, 0xbbbbbbbb]);
        }
    }
}
