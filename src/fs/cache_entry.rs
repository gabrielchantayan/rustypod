//! Cache-entry reference release.
//!
//! `cache_entry_release` is retailOS `FUN_082e18bc` at `0x082e18bc` (60
//! bytes — the next independently entered function starts at `0x082e18f8`).
//! Call sites: 29, verified by decoding every ARM B/BL word in `osos.dec`;
//! all 29 are plain `bl`, with no predicated call sites.
//!
//! The entry is a five-word cache descriptor: word 2 is its source/owner
//! pointer, and word 4 is a reference count. Under the retailOS synchronization
//! boundary, this function decrements a nonzero count and, when requested,
//! clears the owner pointer. The entry may be NULL; that still enters and
//! leaves the synchronization boundary without accessing it.
//!
//! Raw body:
//!
//! ```text
//! 082e18bc:  push {r4, r5, r6, lr}
//! 082e18c0:  mov  r5, r1
//! 082e18c4:  mov  r4, r0
//! 082e18c8:  bl   0x082d7924
//! 082e18cc:  cmp  r4, #0
//! 082e18d0:  beq  0x082e18f0
//! 082e18d4:  ldr  r0, [r4, #16]
//! 082e18d8:  cmp  r0, #0
//! 082e18dc:  subne r0, r0, #1
//! 082e18e0:  strne r0, [r4, #16]
//! 082e18e4:  cmp  r5, #0
//! 082e18e8:  movne r0, #0
//! 082e18ec:  strne r0, [r4, #8]
//! 082e18f0:  pop  {r4, r5, r6, lr}
//! 082e18f4:  b    0x082d7944
//! ```
//!
//! Deliberate deviation: the two synchronization callees are unported and
//! have no verified semantic identity, so target builds invoke their retailOS
//! load addresses directly. Host builds use recording boundaries solely to
//! test call ordering; they do not replace the cache-entry mutation.

/// Target word index of the cache entry's source/owner pointer.
const ENTRY_OWNER_WORD: usize = 2;

/// Target word index of the cache entry's reference count.
const ENTRY_REFS_WORD: usize = 4;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn retail_call_082d7924() {
    let function: unsafe extern "C" fn() = core::mem::transmute(0x082d7924usize);
    function();
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn retail_call_082d7944() {
    let function: unsafe extern "C" fn() = core::mem::transmute(0x082d7944usize);
    function();
}

#[cfg(not(target_os = "none"))]
type HostBoundary = unsafe extern "C" fn();

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
struct CacheEntryHostOps {
    enter: HostBoundary,
    leave: HostBoundary,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_noop() {}

#[cfg(not(target_os = "none"))]
const DEFAULT_CACHE_ENTRY_HOST_OPS: CacheEntryHostOps = CacheEntryHostOps {
    enter: host_noop,
    leave: host_noop,
};

#[cfg(not(target_os = "none"))]
static mut CACHE_ENTRY_HOST_OPS: CacheEntryHostOps = DEFAULT_CACHE_ENTRY_HOST_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn host_ops() -> CacheEntryHostOps {
    core::ptr::read_volatile(core::ptr::addr_of!(CACHE_ENTRY_HOST_OPS))
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn retail_call_082d7924() {
    (host_ops().enter)();
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn retail_call_082d7944() {
    (host_ops().leave)();
}

/// cache_entry_release — original: `FUN_082e18bc` @ `0x082e18bc` (60 bytes;
/// 29 plain `bl` call sites, binary-verified).
///
/// Decrements a nonzero cache-entry reference count at target word 4 and, if
/// `detach_owner` is nonzero, clears the target owner-pointer word 2. Both
/// mutations occur between the two retailOS synchronization calls; NULL still
/// makes both calls and performs no entry access.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cache_entry_release(entry: *mut u8, detach_owner: u32) {
    retail_call_082d7924();

    if !entry.is_null() {
        let words = entry.cast::<u32>();
        let references = words.add(ENTRY_REFS_WORD);
        let count = references.read();
        if count != 0 {
            references.write(count - 1);
        }
        if detach_owner != 0 {
            words.add(ENTRY_OWNER_WORD).write(0);
        }
    }

    retail_call_082d7944();
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};

    static ENTERS: AtomicUsize = AtomicUsize::new(0);
    static LEAVES: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn record_enter() {
        ENTERS.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn record_leave() {
        LEAVES.fetch_add(1, Ordering::SeqCst);
    }

    struct HostOpsReset(CacheEntryHostOps);

    impl Drop for HostOpsReset {
        fn drop(&mut self) {
            unsafe {
                CACHE_ENTRY_HOST_OPS = self.0;
            }
        }
    }

    #[test]
    fn releases_counts_optionally_detaches_and_brackets_every_path() {
        let reset = unsafe {
            let prior = host_ops();
            CACHE_ENTRY_HOST_OPS = CacheEntryHostOps {
                enter: record_enter,
                leave: record_leave,
            };
            HostOpsReset(prior)
        };
        ENTERS.store(0, Ordering::SeqCst);
        LEAVES.store(0, Ordering::SeqCst);

        unsafe {
            cache_entry_release(core::ptr::null_mut(), 1);
        }

        let mut zero_references = [0x1111_1111, 0x2222_2222, 0x3333_3333, 0x4444_4444, 0];
        unsafe {
            cache_entry_release(zero_references.as_mut_ptr().cast(), 0);
        }
        assert_eq!(zero_references, [0x1111_1111, 0x2222_2222, 0x3333_3333, 0x4444_4444, 0]);

        let mut shared_entry = [0xaaaa_aaaau32, 0xbbbb_bbbb, 0xdead_beef, 0xcccc_cccc, 7];
        unsafe {
            cache_entry_release(shared_entry.as_mut_ptr().cast(), 2);
        }
        assert_eq!(shared_entry, [0xaaaa_aaaa, 0xbbbb_bbbb, 0, 0xcccc_cccc, 6]);
        assert_eq!(ENTERS.load(Ordering::SeqCst), 3);
        assert_eq!(LEAVES.load(Ordering::SeqCst), 3);

        drop(reset);
    }
}
