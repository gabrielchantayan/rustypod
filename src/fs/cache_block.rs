//! Cache-backed disk-block acquisition.
//!
//! `cache_block_acquire` is retailOS `FUN_082e3f98` at `0x082e3f98` (128
//! bytes; the next independently entered function starts at `0x082e4018`).
//! Its 13 call sites were verified by decoding every ARM B/BL word in
//! `osos.dec`: all are plain `bl`, with no predicated calls or tail branches.
//!
//! The function rejects a NULL cache context and block indices outside its
//! word-118 exclusive limit. It then asks the cache allocator for a descriptor
//! keyed by the context, block index, and incoming `r3` cache key. Cache hits
//! return the retained descriptor directly; cache misses read one block into
//! the descriptor payload at `+0x18`. A failed read releases the new descriptor
//! with owner detachment and returns NULL.
//!
//! Raw body:
//!
//! ```text
//! 082e3f98:  push {r2, r3, r4, r5, r6, lr}
//! 082e3f9c:  subs r4, r0, #0
//! 082e3fa0:  ldrne r0, [r4, #472]
//! 082e3fa4:  mov r5, r1
//! 082e3fa8:  cmpne r0, r5
//! 082e3fac:  movls r0, #0
//! 082e3fb0:  bls 0x082e4014
//! 082e3fb4:  mov r2, r5
//! 082e3fb8:  mov r1, r4
//! 082e3fbc:  add r0, sp, #4
//! 082e3fc0:  bl  0x082dfdf0
//! 082e3fc4:  ldr r1, [sp, #4]
//! 082e3fc8:  cmp r1, #0
//! 082e3fcc:  beq 0x082e4010
//! 082e3fd0:  cmp r0, #0
//! 082e3fd4:  bne 0x082e4010
//! 082e3fd8:  mov r3, #0
//! 082e3fdc:  str r3, [sp]
//! 082e3fe0:  add r2, r1, #24
//! 082e3fe4:  ldrh r0, [r4, #120]
//! 082e3fe8:  mov r1, r5
//! 082e3fec:  mov r3, #1
//! 082e3ff0:  bl  0x082c6244
//! 082e3ff4:  cmp r0, #0
//! 082e3ff8:  bne 0x082e4010
//! 082e3ffc:  ldr r0, [sp, #4]
//! 082e4000:  mov r1, #1
//! 082e4004:  bl  0x082e18bc
//! 082e4008:  mov r0, #0
//! 082e400c:  str r0, [sp, #4]
//! 082e4010:  ldr r0, [sp, #4]
//! 082e4014:  pop {r2, r3, r4, r5, r6, pc}
//! ```
//!
//! Deliberate deviation: the port calls the already ported
//! `cache_entry_release` instead of its original load address. The allocator
//! and disk-transfer callees remain unported, so target builds invoke their
//! retailOS addresses while host tests install recording seams.

use super::cache_entry::cache_entry_release;

/// Target word index of the cache context's block-index limit (`+0x1d8`).
const CACHE_BLOCK_LIMIT_WORD: usize = 118;
/// Target word index of the storage-device selector (`+0x78`).
const CACHE_DEVICE_WORD: usize = 30;
/// Target byte offset of the cache descriptor's block payload.
const CACHE_ENTRY_PAYLOAD_OFFSET: usize = 0x18;

type CacheEntryAllocate = unsafe extern "C" fn(*mut *mut u8, *mut u8, u32, u32) -> u32;
type DiskBlockRead = unsafe extern "C" fn(u32, u32, *mut u8, u32, u32) -> u32;

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

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn disk_block_read(
    device: u32,
    block_index: u32,
    destination: *mut u8,
    block_count: u32,
    flags: u32,
) -> u32 {
    let function: DiskBlockRead = core::mem::transmute(0x082c6244usize);
    function(device, block_index, destination, block_count, flags)
}

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
struct CacheBlockHostOps {
    allocate: CacheEntryAllocate,
    read: DiskBlockRead,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_allocate(
    _entry_out: *mut *mut u8,
    _context: *mut u8,
    _block_index: u32,
    _cache_key: u32,
) -> u32 {
    panic!("cache_block_acquire allocator called without a host seam")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_read(
    _device: u32,
    _block_index: u32,
    _destination: *mut u8,
    _block_count: u32,
    _flags: u32,
) -> u32 {
    panic!("cache_block_acquire disk reader called without a host seam")
}

#[cfg(not(target_os = "none"))]
const DEFAULT_CACHE_BLOCK_HOST_OPS: CacheBlockHostOps = CacheBlockHostOps {
    allocate: unavailable_allocate,
    read: unavailable_read,
};

#[cfg(not(target_os = "none"))]
static mut CACHE_BLOCK_HOST_OPS: CacheBlockHostOps = DEFAULT_CACHE_BLOCK_HOST_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn host_ops() -> CacheBlockHostOps {
    core::ptr::read_volatile(core::ptr::addr_of!(CACHE_BLOCK_HOST_OPS))
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn cache_entry_allocate(
    entry_out: *mut *mut u8,
    context: *mut u8,
    block_index: u32,
    cache_key: u32,
) -> u32 {
    (host_ops().allocate)(entry_out, context, block_index, cache_key)
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn disk_block_read(
    device: u32,
    block_index: u32,
    destination: *mut u8,
    block_count: u32,
    flags: u32,
) -> u32 {
    (host_ops().read)(device, block_index, destination, block_count, flags)
}

/// Acquires the cache descriptor for one storage block.
///
/// Original: `FUN_082e3f98` at `0x082e3f98`, 128 bytes, 13 plain `bl` call
/// sites (binary-verified). `ignored` preserves the original `r2` ABI slot;
/// the body overwrites it with `block_index` before calling the allocator.
/// `cache_key` is forwarded in `r3` to identify a cache entry within `context`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cache_block_acquire(
    context: *mut u8,
    block_index: u32,
    _ignored: u32,
    cache_key: u32,
) -> *mut u8 {
    if context.is_null() || (*context.cast::<u32>().add(CACHE_BLOCK_LIMIT_WORD)) <= block_index {
        return core::ptr::null_mut();
    }

    let mut entry = core::ptr::null_mut();
    let was_cache_hit = cache_entry_allocate(&mut entry, context, block_index, cache_key);
    if !entry.is_null() && was_cache_hit == 0 {
        let device = (*context.cast::<u32>().add(CACHE_DEVICE_WORD) & 0xffff) as u32;
        let payload = entry.add(CACHE_ENTRY_PAYLOAD_OFFSET);
        if disk_block_read(device, block_index, payload, 1, 0) == 0 {
            cache_entry_release(entry, 1);
            entry = core::ptr::null_mut();
        }
    }

    entry
}

#[cfg(test)]
mod tests {
    use super::*;

    static mut ALLOCATOR_CALL: Option<(*mut u8, u32, u32)> = None;
    static mut READER_CALL: Option<(u32, u32, *mut u8, u32, u32)> = None;
    static mut ALLOCATOR_RESULT: u32 = 0;
    static mut ALLOCATOR_ENTRY: *mut u8 = core::ptr::null_mut();
    static mut READER_RESULT: u32 = 0;

    unsafe extern "C" fn record_allocate(
        entry_out: *mut *mut u8,
        context: *mut u8,
        block_index: u32,
        cache_key: u32,
    ) -> u32 {
        ALLOCATOR_CALL = Some((context, block_index, cache_key));
        entry_out.write(ALLOCATOR_ENTRY);
        ALLOCATOR_RESULT
    }

    unsafe extern "C" fn record_read(
        device: u32,
        block_index: u32,
        destination: *mut u8,
        block_count: u32,
        flags: u32,
    ) -> u32 {
        READER_CALL = Some((device, block_index, destination, block_count, flags));
        READER_RESULT
    }

    struct HostOpsReset(CacheBlockHostOps);

    impl Drop for HostOpsReset {
        fn drop(&mut self) {
            unsafe {
                CACHE_BLOCK_HOST_OPS = self.0;
            }
        }
    }

    #[test]
    fn enforces_bounds_distinguishes_hits_and_releases_failed_misses() {
        let reset = unsafe {
            let prior = host_ops();
            CACHE_BLOCK_HOST_OPS = CacheBlockHostOps {
                allocate: record_allocate,
                read: record_read,
            };
            HostOpsReset(prior)
        };
        let mut context = [0u32; CACHE_BLOCK_LIMIT_WORD + 1];
        context[CACHE_BLOCK_LIMIT_WORD] = 9;
        context[CACHE_DEVICE_WORD] = 0xface_babe;
        let mut entry = [0u32; 6 + 128];
        entry[2] = 0x1111_1111;
        entry[4] = 1;

        unsafe {
            ALLOCATOR_CALL = None;
            READER_CALL = None;
            ALLOCATOR_ENTRY = entry.as_mut_ptr().cast();
            ALLOCATOR_RESULT = 1;
            READER_RESULT = 1;

            assert!(cache_block_acquire(core::ptr::null_mut(), 0, 0, 0).is_null());
            assert!(cache_block_acquire(context.as_mut_ptr().cast(), 9, 0, 0).is_null());
            assert!(ALLOCATOR_CALL.is_none());
            assert!(READER_CALL.is_none());

            let hit = cache_block_acquire(context.as_mut_ptr().cast(), 8, 0xdead_beef, 0x1234_5678);
            assert_eq!(hit, entry.as_mut_ptr().cast());
            assert_eq!(ALLOCATOR_CALL, Some((context.as_mut_ptr().cast(), 8, 0x1234_5678)));
            assert!(READER_CALL.is_none());

            ALLOCATOR_RESULT = 0;
            let miss = cache_block_acquire(context.as_mut_ptr().cast(), 3, 0, 0x55aa_aa55);
            assert_eq!(miss, entry.as_mut_ptr().cast());
            assert_eq!(READER_CALL, Some((0xbabe, 3, entry.as_mut_ptr().cast::<u8>().add(CACHE_ENTRY_PAYLOAD_OFFSET), 1, 0)));

            READER_RESULT = 0;
            entry[2] = 0xcafe_babe;
            entry[4] = 1;
            let failed_miss = cache_block_acquire(context.as_mut_ptr().cast(), 2, 0, 0xface_cafe);
            assert!(failed_miss.is_null());
            assert_eq!(entry[2], 0);
            assert_eq!(entry[4], 0);
        }

        drop(reset);
    }
}
