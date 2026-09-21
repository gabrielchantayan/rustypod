//! Cleared cache-entry allocation.
//!
//! `cache_entry_allocate_cleared` is retailOS `FUN_082e254c` at load address
//! `0x082e254c` (72 bytes; the next independently entered function begins at
//! `0x082e2594`). Raw ARM decoding finds three incoming direct calls, all plain
//! unconditional `bl` (`0x082e0474`, `0x082e29bc`, and `0x082e3320`), with no
//! predicated call sites. Its body has one plain `bl` to `cache_entry_allocate`
//! and one predicated `blne` to `byte_fill`.
//!
//! A non-NULL context replaces the incoming fallback block limit with its word
//! at `+0x1d8`. A block index at or above that exclusive limit returns NULL.
//! Otherwise the allocator receives the output slot, context, index, and cache
//! key; any returned entry has its 512-byte payload at `+0x18` cleared.
//!
//! Deliberate deviation: the port calls the existing Rust `byte_fill` port
//! rather than the retailOS address `0x082e2ef0`; the unported allocator still
//! uses its verified retailOS address on target builds and a host seam in tests.

use crate::libc::byte_fill::byte_fill;

const CACHE_BLOCK_LIMIT_WORD: usize = 118;
const CACHE_ENTRY_PAYLOAD_OFFSET: usize = 0x18;
const CACHE_ENTRY_PAYLOAD_LEN: u32 = 0x200;

type CacheEntryAllocate = unsafe extern "C" fn(*mut *mut u8, *mut u8, u32, u32) -> u32;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn cache_entry_allocate(
    entry_out: *mut *mut u8,
    context: *mut u8,
    block_index: u32,
    cache_key: u32,
) -> u32 {
    let function: CacheEntryAllocate = core::mem::transmute(0x082dfdf0usize);
    function(entry_out, context, block_index, cache_key)
}

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
struct HostOps {
    allocate: CacheEntryAllocate,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_allocate(
    _entry_out: *mut *mut u8,
    _context: *mut u8,
    _block_index: u32,
    _cache_key: u32,
) -> u32 {
    panic!("cache_entry_allocate_cleared allocator called without a host seam")
}

#[cfg(not(target_os = "none"))]
static mut HOST_OPS: HostOps = HostOps { allocate: unavailable_allocate };

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn cache_entry_allocate(
    entry_out: *mut *mut u8,
    context: *mut u8,
    block_index: u32,
    cache_key: u32,
) -> u32 {
    (core::ptr::addr_of!(HOST_OPS).read_volatile().allocate)(entry_out, context, block_index, cache_key)
}

/// Allocates a cache entry then clears its block payload.
///
/// Original: `FUN_082e254c` at `0x082e254c`, 72 bytes, three plain `bl` call
/// sites (binary-verified). `fallback_block_limit` preserves the original r2
/// value for the NULL-context path; a non-NULL context overwrites it from +0x1d8.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cache_entry_allocate_cleared(
    context: *mut u8,
    block_index: u32,
    fallback_block_limit: u32,
    cache_key: u32,
) -> *mut u8 {
    let block_limit = if context.is_null() {
        fallback_block_limit
    } else {
        *context.cast::<u32>().add(CACHE_BLOCK_LIMIT_WORD)
    };
    if block_limit <= block_index {
        return core::ptr::null_mut();
    }

    let mut entry = core::ptr::null_mut();
    cache_entry_allocate(&mut entry, context, block_index, cache_key);
    if !entry.is_null() {
        byte_fill(entry.add(CACHE_ENTRY_PAYLOAD_OFFSET), CACHE_ENTRY_PAYLOAD_LEN, 0);
    }
    entry
}

#[cfg(test)]
mod tests {
    use super::*;

    static mut ALLOCATOR_CALL: Option<(*mut u8, u32, u32)> = None;
    static mut ALLOCATOR_ENTRY: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn record_allocate(
        entry_out: *mut *mut u8,
        context: *mut u8,
        block_index: u32,
        cache_key: u32,
    ) -> u32 {
        ALLOCATOR_CALL = Some((context, block_index, cache_key));
        entry_out.write(ALLOCATOR_ENTRY);
        0
    }

    struct HostOpsReset(HostOps);

    impl Drop for HostOpsReset {
        fn drop(&mut self) {
            unsafe { core::ptr::addr_of_mut!(HOST_OPS).write_volatile(self.0) };
        }
    }

    #[test]
    fn rejects_invalid_limits_and_clears_the_returned_payload() {
        let reset = unsafe {
            let prior = core::ptr::addr_of!(HOST_OPS).read_volatile();
            core::ptr::addr_of_mut!(HOST_OPS).write_volatile(HostOps { allocate: record_allocate });
            HostOpsReset(prior)
        };
        let mut context = [0u32; CACHE_BLOCK_LIMIT_WORD + 1];
        context[CACHE_BLOCK_LIMIT_WORD] = 5;
        let mut entry = [0xa5u8; CACHE_ENTRY_PAYLOAD_OFFSET + CACHE_ENTRY_PAYLOAD_LEN as usize];

        unsafe {
            ALLOCATOR_CALL = None;
            ALLOCATOR_ENTRY = entry.as_mut_ptr();
            assert!(cache_entry_allocate_cleared(core::ptr::null_mut(), 7, 7, 1).is_null());
            assert!(cache_entry_allocate_cleared(context.as_mut_ptr().cast(), 5, 99, 2).is_null());
            assert!(ALLOCATOR_CALL.is_none());

            let result = cache_entry_allocate_cleared(context.as_mut_ptr().cast(), 4, 0, 0x1234_5678);
            assert_eq!(result, entry.as_mut_ptr());
            assert_eq!(ALLOCATOR_CALL, Some((context.as_mut_ptr().cast(), 4, 0x1234_5678)));
            assert!(entry[..CACHE_ENTRY_PAYLOAD_OFFSET].iter().all(|&byte| byte == 0xa5));
            assert!(entry[CACHE_ENTRY_PAYLOAD_OFFSET..].iter().all(|&byte| byte == 0));

            ALLOCATOR_ENTRY = core::ptr::null_mut();
            assert!(cache_entry_allocate_cleared(context.as_mut_ptr().cast(), 0, 0, 3).is_null());
        }

        drop(reset);
    }
}
