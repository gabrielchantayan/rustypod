//! Cache-block flush validation.
//!
//! `cache_blocks_flush` is retailOS `FUN_082e044c` at load address
//! `0x082e044c` (132 bytes, `0x082e044c..0x082e04cf`; `mov r12,#0x20` at
//! `0x082e04d0` begins the next independent function). Whole-image ARM
//! decoding finds two inbound plain `bl` calls and no inbound predicated `bl`
//! calls. The body has four plain outbound `bl` calls.
//!
//! The routine converts the incoming first FAT cluster to a cache-block index,
//! then acquires and flushes each cache entry through the volume's `+0x1cc`
//! entry-count limit. It releases successfully flushed entries without
//! detaching their owner; a failed allocation or flush releases the current
//! entry with its owner detached and returns false. A completed range returns
//! true. Deliberate deviation: target builds call already ported Rust callees
//! rather than their retailOS addresses; host builds use a recording seam.

use super::{
    cache_entry::cache_entry_release,
    cache_entry_allocate_cleared::cache_entry_allocate_cleared,
    cache_entry_flush::cache_entry_flush,
    fat_cluster_to_block::fat_cluster_to_block_index,
};
use super::fat_dirent::FatVolume;

const CACHE_ENTRY_COUNT_OFFSET: usize = 0x1cc;

type ClusterToBlock = unsafe extern "C" fn(*const u8, u32) -> u32;
type AllocateCleared = unsafe extern "C" fn(*mut u8, u32, u32, u32) -> *mut u8;
type Flush = unsafe extern "C" fn(*mut u8) -> u32;
type Release = unsafe extern "C" fn(*mut u8, u32);

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn cluster_to_block(volume: *const u8, cluster: u32) -> u32 {
    fat_cluster_to_block_index(volume.cast::<FatVolume>(), cluster)
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn allocate_cleared(volume: *mut u8, block: u32, limit: u32, cache_key: u32) -> *mut u8 {
    cache_entry_allocate_cleared(volume, block, limit, cache_key)
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn flush(entry: *mut u8) -> u32 {
    cache_entry_flush(entry)
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn release(entry: *mut u8, detach_owner: u32) {
    cache_entry_release(entry, detach_owner)
}

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
struct HostOps {
    cluster_to_block: ClusterToBlock,
    allocate_cleared: AllocateCleared,
    flush: Flush,
    release: Release,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_cluster_to_block(_volume: *const u8, _cluster: u32) -> u32 {
    panic!("cache_blocks_flush cluster conversion called without a host seam")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_allocate_cleared(
    _volume: *mut u8,
    _block: u32,
    _limit: u32,
    _cache_key: u32,
) -> *mut u8 {
    panic!("cache_blocks_flush allocation called without a host seam")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_flush(_entry: *mut u8) -> u32 {
    panic!("cache_blocks_flush flush called without a host seam")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_release(_entry: *mut u8, _detach_owner: u32) {
    panic!("cache_blocks_flush release called without a host seam")
}

#[cfg(not(target_os = "none"))]
const DEFAULT_HOST_OPS: HostOps = HostOps {
    cluster_to_block: unavailable_cluster_to_block,
    allocate_cleared: unavailable_allocate_cleared,
    flush: unavailable_flush,
    release: unavailable_release,
};

#[cfg(not(target_os = "none"))]
static mut HOST_OPS: HostOps = DEFAULT_HOST_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn host_ops() -> HostOps {
    core::ptr::addr_of!(HOST_OPS).read_volatile()
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn cluster_to_block(volume: *const u8, cluster: u32) -> u32 {
    (host_ops().cluster_to_block)(volume, cluster)
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn allocate_cleared(volume: *mut u8, block: u32, limit: u32, cache_key: u32) -> *mut u8 {
    (host_ops().allocate_cleared)(volume, block, limit, cache_key)
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn flush(entry: *mut u8) -> u32 {
    (host_ops().flush)(entry)
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn release(entry: *mut u8, detach_owner: u32) {
    (host_ops().release)(entry, detach_owner)
}

/// Flushes cache blocks beginning with a FAT cluster.
///
/// Original: `FUN_082e044c` at `0x082e044c`, 132 bytes, two inbound plain
/// `bl` calls and no predicated inbound calls (binary-verified). `limit` and
/// `cache_key` preserve the original incoming `r2` and `r3` values for the
/// allocation call.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cache_blocks_flush(
    volume: *mut u8,
    first_cluster: u32,
    limit: u32,
    cache_key: u32,
) -> u32 {
    let mut block = cluster_to_block(volume, first_cluster);
    if block == 0 {
        return 0;
    }

    let mut index = 0;
    while index < volume.add(CACHE_ENTRY_COUNT_OFFSET).cast::<u16>().read() as u32 {
        let entry = allocate_cleared(volume, block, limit, cache_key);
        if entry.is_null() {
            return 0;
        }
        if flush(entry) == 0 {
            release(entry, 1);
            return 0;
        }
        release(entry, 0);
        index = index.wrapping_add(1);
        block = block.wrapping_add(1);
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::{Mutex, MutexGuard};

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut INITIAL_BLOCK: u32 = 0;
    static mut ALLOCATIONS: [(u32, u32, u32); 4] = [(0, 0, 0); 4];
    static mut ALLOCATION_COUNT: usize = 0;
    static mut ENTRIES: [*mut u8; 4] = [core::ptr::null_mut(); 4];
    static mut FLUSH_RESULTS: [u32; 4] = [0; 4];
    static mut RELEASES: [(*mut u8, u32); 4] = [(core::ptr::null_mut(), 0); 4];
    static mut RELEASE_COUNT: usize = 0;

    unsafe extern "C" fn record_cluster_to_block(_volume: *const u8, _cluster: u32) -> u32 {
        INITIAL_BLOCK
    }

    unsafe extern "C" fn record_allocate(
        _volume: *mut u8,
        block: u32,
        limit: u32,
        cache_key: u32,
    ) -> *mut u8 {
        ALLOCATIONS[ALLOCATION_COUNT] = (block, limit, cache_key);
        let entry = ENTRIES[ALLOCATION_COUNT];
        ALLOCATION_COUNT += 1;
        entry
    }

    unsafe extern "C" fn record_flush(entry: *mut u8) -> u32 {
        let index = ENTRIES.iter().position(|&candidate| candidate == entry).unwrap();
        FLUSH_RESULTS[index]
    }

    unsafe extern "C" fn record_release(entry: *mut u8, detach_owner: u32) {
        RELEASES[RELEASE_COUNT] = (entry, detach_owner);
        RELEASE_COUNT += 1;
    }

    struct Fixture(MutexGuard<'static, ()>, HostOps);

    impl Fixture {
        fn install(block: u32, entries: [*mut u8; 4], flush_results: [u32; 4]) -> Self {
            let guard = TEST_LOCK.lock();
            unsafe {
                let prior = core::ptr::addr_of!(HOST_OPS).read_volatile();
                INITIAL_BLOCK = block;
                ALLOCATIONS = [(0, 0, 0); 4];
                ALLOCATION_COUNT = 0;
                ENTRIES = entries;
                FLUSH_RESULTS = flush_results;
                RELEASES = [(core::ptr::null_mut(), 0); 4];
                RELEASE_COUNT = 0;
                core::ptr::addr_of_mut!(HOST_OPS).write_volatile(HostOps {
                    cluster_to_block: record_cluster_to_block,
                    allocate_cleared: record_allocate,
                    flush: record_flush,
                    release: record_release,
                });
                Self(guard, prior)
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            unsafe { core::ptr::addr_of_mut!(HOST_OPS).write_volatile(self.1) };
        }
    }

    fn volume(entry_count: u16) -> [u8; CACHE_ENTRY_COUNT_OFFSET + 2] {
        let mut volume = [0; CACHE_ENTRY_COUNT_OFFSET + 2];
        volume[CACHE_ENTRY_COUNT_OFFSET..].copy_from_slice(&entry_count.to_le_bytes());
        volume
    }

    #[test]
    fn returns_false_without_allocation_when_cluster_conversion_fails() {
        let _fixture = Fixture::install(0, [core::ptr::null_mut(); 4], [0; 4]);
        let mut volume = volume(3);

        assert_eq!(unsafe { cache_blocks_flush(volume.as_mut_ptr(), 1, 9, 10) }, 0);
        assert_eq!(unsafe { ALLOCATION_COUNT }, 0);
    }

    #[test]
    fn flushes_each_entry_and_retains_owners_on_success() {
        let mut first = 0u8;
        let mut second = 0u8;
        let _fixture = Fixture::install(40, [&mut first, &mut second, core::ptr::null_mut(), core::ptr::null_mut()], [1, 7, 0, 0]);
        let mut volume = volume(2);

        assert_eq!(unsafe { cache_blocks_flush(volume.as_mut_ptr(), 2, 0xaa, 0xbb) }, 1);
        assert_eq!(unsafe { &ALLOCATIONS[..ALLOCATION_COUNT] }, [(40, 0xaa, 0xbb), (41, 0xaa, 0xbb)]);
        assert_eq!(unsafe { &RELEASES[..RELEASE_COUNT] }, [(&mut first as *mut u8, 0), (&mut second as *mut u8, 0)]);
    }

    #[test]
    fn detaches_the_entry_and_stops_at_the_first_flush_failure() {
        let mut first = 0u8;
        let mut second = 0u8;
        let _fixture = Fixture::install(7, [&mut first, &mut second, core::ptr::null_mut(), core::ptr::null_mut()], [1, 0, 0, 0]);
        let mut volume = volume(3);

        assert_eq!(unsafe { cache_blocks_flush(volume.as_mut_ptr(), 2, 1, 2) }, 0);
        assert_eq!(unsafe { ALLOCATION_COUNT }, 2);
        assert_eq!(unsafe { &RELEASES[..RELEASE_COUNT] }, [(&mut first as *mut u8, 0), (&mut second as *mut u8, 1)]);
    }
}
