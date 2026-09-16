//! Resource-index record lookup dispatcher.
//!
//! `resource_index_lookup` — original: `FUN_080506bc` @ `0x080506bc`
//! (76 bytes).
//!
//! Raw ARM body, decoded from `osos.dec`:
//!
//! ```text
//! 080506bc  push {r3,r4,r5,lr}
//! 080506c0  mov  r5,r0            @ index
//! 080506c4  mov  r0,r1
//! 080506c8  mov  r4,r1            @ entry
//! 080506cc  bl   0x0806b410       @ scoped_context_owner_validity(entry)
//! 080506d0  cmp  r0,#0
//! 080506d4  beq  0x08050704       @ return NULL
//! 080506d8  ldr  r1,[r4,#0xf0]    @ direct key
//! 080506dc  cmp  r1,#0
//! 080506e0  movne r0,r5
//! 080506e4  ldmiane sp!,{r3,r4,r5,lr}
//! 080506e8  bne  0x08050418       @ tail: direct-key lookup(index, key)
//! 080506ec  mov  r3,#0
//! 080506f0  str  r3,[sp]          @ fifth argument = 0
//! 080506f4  ldr  r2,[r4,#0x110]   @ indirect key low word
//! 080506f8  ldr  r3,[r4,#0x114]   @ indirect key high word
//! 080506fc  mov  r0,r5
//! 08050700  bl   0x0805054c       @ indirect-key lookup(index, 0, lo, hi, 0)
//! 08050704  ldmia sp!,{r3,r4,r5,pc}
//! ```
//!
//! The next separately linked function starts at `0x08050708`, establishing
//! the exact 76-byte extent with no literal pool. A complete decode of every
//! ARM immediate B/BL word in `osos.dec` finds four inbound unconditional
//! plain `bl` calls (`0x080513a4`, `0x0809dd18`, `0x0809e098`,
//! `0x082a4500`), zero predicated `bl` forms, and two inbound direct tail
//! branches (unconditional `b` at `0x08051354`, predicated `bne` at
//! `0x08051388`). The body itself contains two `bl` calls plus the
//! predicated `bne` tail branch.
//!
//! Algorithm: validate `entry`'s owner element through the ported
//! `scoped_context_owner_validity` (`0x0806b410`) and return NULL when it
//! rejects. A nonzero direct key at entry `+0xf0` tail-branches to the
//! 32-bit-key record search at `0x08050418`. Otherwise the 64-bit indirect
//! key at entry `+0x110`/`+0x114` is searched through `0x0805054c`, passing
//! a zero second argument and an explicit zero fifth (stack) argument, which
//! that callee reads at `[sp,#0x30]`.
//!
//! Deliberate deviations: both record searches remain retailOS-owned;
//! target builds call their verified fixed addresses while host tests
//! substitute native callbacks through a private ops table. The entry
//! layout keeps the owner element as a target-width typed pointer (it is
//! consumed by the owner predicate as `*const *const u8`), so host pointer
//! fields widen; the ARM offsets are asserted on 32-bit targets only. LLVM
//! keeps the direct-key path a true tail call (`bx` to a literal-pool
//! `0x08050418` word) and reaches the indirect search through `blx` on a
//! computed address instead of the original direct `bl`; it also builds a
//! frame pointer the original lacks. The observable behavior is identical.

use super::resource_reference_value::{ResourceIndex, ResourceIndexRecord};
use super::scoped_context::scoped_context_owner_validity;

/// Index entry consumed by this routine.
///
/// `owner_element` at target `+0x00` is dereferenced by
/// `scoped_context_owner_validity`. The direct key sits at target `+0xf0`;
/// the indirect 64-bit key at target `+0x110` (low) and `+0x114` (high).
/// Host builds widen the pointer field, so the named fields replace literal
/// offsets there.
#[repr(C)]
pub struct ResourceIndexEntry {
    pub owner_element: *const u8,
    _words_004_0ef: [u32; (0xf0 - 4) / 4],
    pub direct_key: u32,
    _words_0f4_10f: [u32; (0x110 - 0xf4) / 4],
    pub indirect_key_lo: u32,
    pub indirect_key_hi: u32,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0xf0] = [0; core::mem::offset_of!(ResourceIndexEntry, direct_key)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x110] = [0; core::mem::offset_of!(ResourceIndexEntry, indirect_key_lo)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x114] = [0; core::mem::offset_of!(ResourceIndexEntry, indirect_key_hi)];

/// ABI of the retailOS 32-bit direct-key record search at `0x08050418`.
type LookupDirectKey = unsafe extern "C" fn(*mut ResourceIndex, u32) -> *mut ResourceIndexRecord;

/// ABI of the retailOS 64-bit indirect-key record search at `0x0805054c`;
/// its fifth argument travels on the stack.
type LookupIndirectKey =
    unsafe extern "C" fn(*mut ResourceIndex, u32, u32, u32, u32) -> *mut ResourceIndexRecord;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn lookup_direct_key(index: *mut ResourceIndex, key: u32) -> *mut ResourceIndexRecord {
    let lookup: LookupDirectKey = core::mem::transmute(0x0805_0418usize);
    lookup(index, key)
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn lookup_indirect_key(
    index: *mut ResourceIndex,
    key_lo: u32,
    key_hi: u32,
) -> *mut ResourceIndexRecord {
    let lookup: LookupIndirectKey = core::mem::transmute(0x0805_054cusize);
    lookup(index, 0, key_lo, key_hi, 0)
}

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
struct ResourceIndexHostOps {
    lookup_direct: LookupDirectKey,
    lookup_indirect: LookupIndirectKey,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_direct_lookup(
    _index: *mut ResourceIndex,
    _key: u32,
) -> *mut ResourceIndexRecord {
    core::ptr::null_mut()
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_indirect_lookup(
    _index: *mut ResourceIndex,
    _zero: u32,
    _key_lo: u32,
    _key_hi: u32,
    _flag: u32,
) -> *mut ResourceIndexRecord {
    core::ptr::null_mut()
}

#[cfg(not(target_os = "none"))]
const DEFAULT_RESOURCE_INDEX_HOST_OPS: ResourceIndexHostOps = ResourceIndexHostOps {
    lookup_direct: unavailable_direct_lookup,
    lookup_indirect: unavailable_indirect_lookup,
};

#[cfg(not(target_os = "none"))]
static mut RESOURCE_INDEX_HOST_OPS: ResourceIndexHostOps = DEFAULT_RESOURCE_INDEX_HOST_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn lookup_direct_key(index: *mut ResourceIndex, key: u32) -> *mut ResourceIndexRecord {
    let ops = core::ptr::read_volatile(core::ptr::addr_of!(RESOURCE_INDEX_HOST_OPS));
    (ops.lookup_direct)(index, key)
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn lookup_indirect_key(
    index: *mut ResourceIndex,
    key_lo: u32,
    key_hi: u32,
) -> *mut ResourceIndexRecord {
    let ops = core::ptr::read_volatile(core::ptr::addr_of!(RESOURCE_INDEX_HOST_OPS));
    (ops.lookup_indirect)(index, 0, key_lo, key_hi, 0)
}

/// Returns the resource-index record selected by `entry`, or NULL.
///
/// # Safety
///
/// `index` must be readable by the retailOS record searches and `entry`
/// must be readable through target offset `+0x114`; `entry`'s first word
/// must satisfy the owner contract of
/// [`scoped_context_owner_validity`]. The record searches retain the
/// retailOS contracts at `0x08050418` and `0x0805054c`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.resource_index_lookup")]
pub unsafe extern "C" fn resource_index_lookup(
    index: *mut ResourceIndex,
    entry: *mut ResourceIndexEntry,
) -> *mut ResourceIndexRecord {
    if scoped_context_owner_validity(entry.cast::<*const u8>()) == 0 {
        return core::ptr::null_mut();
    }

    let direct_key = core::ptr::addr_of!((*entry).direct_key).read_volatile();
    if direct_key != 0 {
        return lookup_direct_key(index, direct_key);
    }

    let key_lo = core::ptr::addr_of!((*entry).indirect_key_lo).read_volatile();
    let key_hi = core::ptr::addr_of!((*entry).indirect_key_hi).read_volatile();
    lookup_indirect_key(index, key_lo, key_hi)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::sync::atomic::{AtomicBool, Ordering};

    static OPS_LOCK: AtomicBool = AtomicBool::new(false);
    static mut DIRECT_RECORD: *mut ResourceIndexRecord = core::ptr::null_mut();
    static mut DIRECT_CALL: Option<(*mut ResourceIndex, u32)> = None;
    static mut INDIRECT_RECORD: *mut ResourceIndexRecord = core::ptr::null_mut();
    static mut INDIRECT_CALL: Option<(*mut ResourceIndex, u32, u32, u32, u32)> = None;

    unsafe extern "C" fn recording_direct(
        index: *mut ResourceIndex,
        key: u32,
    ) -> *mut ResourceIndexRecord {
        DIRECT_CALL = Some((index, key));
        DIRECT_RECORD
    }

    unsafe extern "C" fn recording_indirect(
        index: *mut ResourceIndex,
        zero: u32,
        key_lo: u32,
        key_hi: u32,
        flag: u32,
    ) -> *mut ResourceIndexRecord {
        INDIRECT_CALL = Some((index, zero, key_lo, key_hi, flag));
        INDIRECT_RECORD
    }

    struct TestLock;

    fn lock_ops() -> TestLock {
        while OPS_LOCK
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            while OPS_LOCK.load(Ordering::Relaxed) {
                core::hint::spin_loop();
            }
        }
        TestLock
    }

    impl Drop for TestLock {
        fn drop(&mut self) {
            OPS_LOCK.store(false, Ordering::Release);
        }
    }

    struct Bench {
        _lock: TestLock,
        // 'tdat'-class element accepted by the owner predicate: class tag
        // word "tdat" at element +0x04.
        tdat: [u32; 2],
        entry: ResourceIndexEntry,
    }

    /// The entry's owner element is left null; each test points it at
    /// `bench.tdat` after the bench has reached its final address.
    fn bench() -> Bench {
        let lock = lock_ops();
        unsafe {
            DIRECT_RECORD = core::ptr::null_mut();
            DIRECT_CALL = None;
            INDIRECT_RECORD = core::ptr::null_mut();
            INDIRECT_CALL = None;
            core::ptr::addr_of_mut!(RESOURCE_INDEX_HOST_OPS).write_volatile(
                ResourceIndexHostOps {
                    lookup_direct: recording_direct,
                    lookup_indirect: recording_indirect,
                },
            );
        }
        let mut bench = Bench {
            _lock: lock,
            tdat: [0, 0x7464_6174],
            entry: ResourceIndexEntry {
                owner_element: core::ptr::null(),
                _words_004_0ef: [0; (0xf0 - 4) / 4],
                direct_key: 0,
                _words_0f4_10f: [0; (0x110 - 0xf4) / 4],
                indirect_key_lo: 0,
                indirect_key_hi: 0,
            },
        };
        bench
    }

    impl Drop for Bench {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(RESOURCE_INDEX_HOST_OPS)
                    .write_volatile(DEFAULT_RESOURCE_INDEX_HOST_OPS);
            }
        }
    }

    #[test]
    fn null_entry_is_rejected_by_owner_predicate() {
        let bench = bench();
        // NULL entry: the owner predicate rejects before any field read.
        let mut index: ResourceIndex = unsafe { core::mem::zeroed() };
        let record = unsafe {
            resource_index_lookup(&mut index, core::ptr::null_mut())
        };
        assert!(record.is_null());
        unsafe {
            assert!(DIRECT_CALL.is_none());
            assert!(INDIRECT_CALL.is_none());
        }
        drop(bench);
    }

    #[test]
    fn foreign_owner_element_is_rejected() {
        let mut bench = bench();
        // Non-'tdat' class tag at element +0x04.
        bench.tdat[1] = 0xdead_beef;
        bench.entry.owner_element = bench.tdat.as_ptr().cast();
        let mut index: ResourceIndex = unsafe { core::mem::zeroed() };
        let record = unsafe {
            resource_index_lookup(&mut index, &mut bench.entry)
        };
        assert!(record.is_null());
        unsafe {
            assert!(DIRECT_CALL.is_none());
            assert!(INDIRECT_CALL.is_none());
        }
    }

    #[test]
    fn nonzero_direct_key_dispatches_direct_search() {
        let mut bench = bench();
        bench.entry.owner_element = bench.tdat.as_ptr().cast();
        let mut index: ResourceIndex = unsafe { core::mem::zeroed() };
        let mut wanted: ResourceIndexRecord = unsafe { core::mem::zeroed() };
        wanted.value = 0x1234_5678;
        bench.entry.direct_key = 0x0000_0042;
        bench.entry.indirect_key_lo = 0xaaaa_aaaa;
        bench.entry.indirect_key_hi = 0xbbbb_bbbb;
        unsafe {
            DIRECT_RECORD = &mut wanted;
        }
        let index_ptr = &mut index as *mut ResourceIndex;
        let record = unsafe { resource_index_lookup(index_ptr, &mut bench.entry) };
        assert_eq!(record, &mut wanted as *mut ResourceIndexRecord);
        unsafe {
            assert_eq!(DIRECT_CALL, Some((index_ptr, 0x0000_0042)));
            assert!(INDIRECT_CALL.is_none());
        }
    }

    #[test]
    fn zero_direct_key_dispatches_indirect_search_with_wide_key() {
        let mut bench = bench();
        bench.entry.owner_element = bench.tdat.as_ptr().cast();
        let mut index: ResourceIndex = unsafe { core::mem::zeroed() };
        let mut wanted: ResourceIndexRecord = unsafe { core::mem::zeroed() };
        wanted.value = 0xfeed_face;
        bench.entry.indirect_key_lo = 0x1122_3344;
        bench.entry.indirect_key_hi = 0x5566_7788;
        unsafe {
            INDIRECT_RECORD = &mut wanted;
        }
        let index_ptr = &mut index as *mut ResourceIndex;
        let record = unsafe { resource_index_lookup(index_ptr, &mut bench.entry) };
        assert_eq!(record, &mut wanted as *mut ResourceIndexRecord);
        unsafe {
            assert_eq!(
                INDIRECT_CALL,
                Some((index_ptr, 0, 0x1122_3344, 0x5566_7788, 0))
            );
            assert!(DIRECT_CALL.is_none());
        }
    }

    #[test]
    fn failed_search_returns_null() {
        let mut bench = bench();
        bench.entry.owner_element = bench.tdat.as_ptr().cast();
        let mut index: ResourceIndex = unsafe { core::mem::zeroed() };
        bench.entry.direct_key = 7;
        let record = unsafe {
            resource_index_lookup(&mut index, &mut bench.entry)
        };
        assert!(record.is_null());
        unsafe {
            assert_eq!(DIRECT_CALL.map(|call| call.1), Some(7));
        }
    }
}
