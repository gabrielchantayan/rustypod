//! Cache-entry flush to storage.
//!
//! `cache_entry_flush` is retailOS `FUN_082e4b4c` at `0x082e4b4c` (56 bytes;
//! the next independently entered function starts at `0x082e4b84`). Its nine
//! call sites were verified by decoding every ARM B/BL word in `osos.dec`: all
//! are plain `bl`, with no predicated calls or tail branches.
//!
//! The routine returns zero without touching storage when the entry or its
//! cache-context link is NULL. Otherwise it reads the low-halfword device id
//! from context `+0x78`, takes the entry block index from `+0x0c`, and writes
//! the one-block payload at `+0x18` through `FUN_082c62f0`. The callee's result
//! remains in r0 and is therefore this routine's result; Ghidra incorrectly
//! reports a void signature.
//!
//! Deliberate deviation: `FUN_082c62f0` is not ported (and has no ledger entry),
//! so target builds call its verified retailOS address while host tests install
//! a recording seam.

/// Target word index of the cache-entry context pointer (`+0x08`).
const CACHE_ENTRY_CONTEXT_WORD: usize = 2;
/// Target word index of the cache-entry storage block index (`+0x0c`).
const CACHE_ENTRY_BLOCK_INDEX_WORD: usize = 3;
/// Target byte offset of the cache-entry block payload.
const CACHE_ENTRY_PAYLOAD_OFFSET: usize = 0x18;
/// Target word index of the device selector in a cache context (`+0x78`).
const CACHE_CONTEXT_DEVICE_WORD: usize = 30;

type DiskBlockWrite = unsafe extern "C" fn(u32, u32, *mut u8, u32, u32) -> u32;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn disk_block_write(
    device: u32,
    block_index: u32,
    source: *mut u8,
    block_count: u32,
    flags: u32,
) -> u32 {
    let function: DiskBlockWrite = core::mem::transmute(0x082c62f0usize);
    function(device, block_index, source, block_count, flags)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_write(
    _device: u32,
    _block_index: u32,
    _source: *mut u8,
    _block_count: u32,
    _flags: u32,
) -> u32 {
    panic!("cache_entry_flush disk writer called without a host seam")
}

#[cfg(not(target_os = "none"))]
static mut DISK_BLOCK_WRITE: DiskBlockWrite = unavailable_write;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn disk_block_write(
    device: u32,
    block_index: u32,
    source: *mut u8,
    block_count: u32,
    flags: u32,
) -> u32 {
    let function = core::ptr::read_volatile(core::ptr::addr_of!(DISK_BLOCK_WRITE));
    function(device, block_index, source, block_count, flags)
}

/// Flushes one cache-entry payload to its storage device.
///
/// Original: `FUN_082e4b4c` at `0x082e4b4c`, 56 bytes, nine plain `bl` call
/// sites (binary-verified). Returns zero if `entry` or its cache-context link
/// is NULL; otherwise forwards the device's low halfword, entry block index,
/// entry payload, one block, and zero flags to the unported disk-write wrapper.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cache_entry_flush(entry: *mut u8) -> u32 {
    if entry.is_null() {
        return 0;
    }

    let entry_words = entry.cast::<u32>();
    let context = (*entry_words.add(CACHE_ENTRY_CONTEXT_WORD) as usize) as *mut u8;
    if context.is_null() {
        return 0;
    }

    let device = *context.cast::<u32>().add(CACHE_CONTEXT_DEVICE_WORD) & 0xffff;
    let block_index = *entry_words.add(CACHE_ENTRY_BLOCK_INDEX_WORD);
    disk_block_write(device, block_index, entry.add(CACHE_ENTRY_PAYLOAD_OFFSET), 1, 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    static mut WRITE_CALL: Option<(u32, u32, *mut u8, u32, u32)> = None;
    static mut WRITE_RESULT: u32 = 0;

    unsafe extern "C" fn record_write(
        device: u32,
        block_index: u32,
        source: *mut u8,
        block_count: u32,
        flags: u32,
    ) -> u32 {
        WRITE_CALL = Some((device, block_index, source, block_count, flags));
        WRITE_RESULT
    }

    struct WriteReset(DiskBlockWrite);

    impl Drop for WriteReset {
        fn drop(&mut self) {
            unsafe {
                DISK_BLOCK_WRITE = self.0;
            }
        }
    }

    #[test]
    fn rejects_null_links_and_forwards_one_block_write() {
        let reset = unsafe {
            let prior = core::ptr::read_volatile(core::ptr::addr_of!(DISK_BLOCK_WRITE));
            DISK_BLOCK_WRITE = record_write;
            WriteReset(prior)
        };
        let Some(slab) = try_map_u32_slab(hints::CACHE_ENTRY_FLUSH, 0x1000) else {
            assert!(note_missing_u32_fixture("fs::cache_entry_flush"));
            return;
        };
        let context = slab.cast::<u32>();
        let entry = unsafe { slab.add(0x100) };
        let entry_words = entry.cast::<u32>();

        unsafe {
            WRITE_CALL = None;
            WRITE_RESULT = 0xfeed_face;

            assert_eq!(cache_entry_flush(core::ptr::null_mut()), 0);
            assert!(WRITE_CALL.is_none());

            entry_words.add(CACHE_ENTRY_CONTEXT_WORD).write(0);
            assert_eq!(cache_entry_flush(entry), 0);
            assert!(WRITE_CALL.is_none());

            context.add(CACHE_CONTEXT_DEVICE_WORD).write(0xface_babe);
            entry_words.add(CACHE_ENTRY_CONTEXT_WORD).write(context as usize as u32);
            entry_words.add(CACHE_ENTRY_BLOCK_INDEX_WORD).write(0x1234_5678);

            assert_eq!(cache_entry_flush(entry), 0xfeed_face);
            assert_eq!(
                WRITE_CALL,
                Some((0xbabe, 0x1234_5678, entry.add(CACHE_ENTRY_PAYLOAD_OFFSET), 1, 0))
            );
        }

        drop(reset);
    }
}
