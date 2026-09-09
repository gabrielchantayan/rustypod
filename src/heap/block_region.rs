//! Ports of the block-deque element -> region accessors used by
//! `pool_seed_regions` (heap/pool.rs) to place each seeded block:
//!
//! - `region_ref_lock` — original: `FUN_082801f8` @ 0x082801f8
//!   (20 bytes; 14 `bl` call sites): loads the element's region object
//!   (elem + 0x4); a NULL region returns immediately (r0 = 0), otherwise
//!   tail-branches to the C++ mutex lock @ 0x082e8390 (via the alias
//!   thunk `b` @ 0x082621a8) on the region's mutex (region + 0x8),
//!   returning the lock result.
//! - `region_ref_unlock` — original: `FUN_082802cc` @ 0x082802cc
//!   (20 bytes; 10 `bl` + 1 tail `b` call sites): identical shape,
//!   tail-branching to the mutex unlock @ 0x082e83d8 (thunk @
//!   0x082621ac).
//! - `region_elem_copy_construct` — original: `FUN_08280464` @
//!   0x08280464 (80 bytes including one vtable literal; 15 `bl` call
//!   sites: 11 unconditional and 4 `blne`): initializes the embedded
//!   recursive mutex, then locks the source region while copying and
//!   retaining its two reference fields.
//! - `block_to_region_start` — original: `FUN_08280430` @ 0x08280430
//!   (48 bytes; 9 `bl` call sites, binary-verified — osos.asm drops
//!   one): locks the element's region, reads the region start address
//!   (region + 0x4), substitutes the fallback address (the literal
//!   0x089cb1b8 — see below) when the region or its start is NULL,
//!   unlocks, and returns the start. This is the POOL_OPS `region_start`
//!   hook of pool.rs: the address the seeded heap block begins at.
//! - `region_elem_destroy` — original: `FUN_082804fc` @ 0x082804fc
//!   (48 bytes + one literal-pool word @ 0x0828052c; 23 `bl` + 1 tail
//!   `b` call sites, binary-verified by decoding every B/BL word in
//!   osos.dec): the 0x28-byte element's C++ destructor. Plants the
//!   class vtable (the literal 0x089a6444 — see below) at elem + 0x0,
//!   locks the element's region (`region_ref_lock`), releases the
//!   region reference @ 0x082803c0 (which decrements the region's
//!   refcount, on zero frees the region's word-1 buffer with tag 43
//!   and `operator delete`s the region, and in every live path
//!   unlocks the mutex `region_ref_lock` took and NULLs elem + 0x4 /
//!   + 0x8), destroys the recursive-mutex member at elem + 0xc
//!   through the dtor thunk @ 0x082621dc (-> mutex destroy @
//!   0x082e82a4; returns its argument), and returns `this` as
//!   `member_result - 0xc` — the deleting destructor @ 0x082804e4
//!   relies on the NULL check it does itself, every other caller
//!   discards the return.
//!
//! Layouts (element stride 0x28, all fields 32-bit on target):
//! `elem + 0x0` = vtable (0x089a6444); `elem + 0x4` = region object
//! pointer; `elem + 0x8` = one more region-ref word (copied by the
//! copy ctor, NULLed by the release); `elem + 0xc..+0x28` = the C++
//! recursive-mutex member (ctor 0x082621b0, dtor thunk 0x082621dc).
//! Pointer-bearing element fields use word indices so their host layout
//! stays disjoint; the mutex member follows those three words (index 3,
//! or +0xc on ARM) for the same reason.
//! `region + 0x0` = refcount; `region + 0x4` = region start address
//! (freed with tag 43 on final release); `region + 0x8` = mutex
//! object pointer.
//!
//! The vtable literal: the four words at 0x089a6444 in osos.dec are
//! `0, 0x082900b8, 0x0828cfa4, 0` and neither code pointer decodes as
//! a function entry (both land mid-instruction-stream — 0x082900b8:
//! `mov r1, #0; mov r0, r9`; 0x0828cfa4: a predicated branch). The
//! port stores the raw ROM address (the ui/view_base.rs precedent:
//! it never dispatches through the table, so the address suffices)
//! and records the anomaly rather than inventing slot identities.
//!
//! The fallback: the original returns the *address* 0x089cb1b8 — the
//! word right after the block-manager global @ 0x089cb1b4 (block_mgr.rs)
//! in the runtime-initialized 0x089cb1xx page — when the element has no
//! live region. Modeled as the address of [`REGION_START_FALLBACK`]
//! (only its address identity is ever used; nothing dereferences it in
//! this cluster).
//!
//! Deviations:
//! - The mutex pair @ 0x082e8390 / 0x082e83d8 is the [`REGION_MUTEX_OPS`]
//!   dispatch boundary — the one seam every heap module in this cluster
//!   brackets its critical sections through. Both slots now default to
//!   the REAL ports (kernel/posix_mutex.rs), whose own mask-ROM callees
//!   carry the "no mutual exclusion before the kernel" contract the old
//!   no-op stubs used to fake wholesale. Host tests install recording
//!   mocks and prove the lock -> read -> unlock protocol, not exclusion.
//! - Pointer fields and the embedded mutex are addressed by WORD INDEX,
//!   not literal target byte offsets: on the 32-bit target `index * WORD`
//!   reproduces the original offsets exactly (0x4, 0x8, 0xc), while on a
//!   64-bit host all element members stay disjoint. A literal +0xc mutex
//!   offset would overlap the host-sized region reference field.
//! - The destructor's two unported callees dispatch through
//!   [`REGION_ELEM_OPS`] (house ops-slot pattern, indirect `blx` in
//!   place of `bl`; client_populate.rs's `region_destroy` slot now
//!   defaults to the real port through an adapter):
//!   - `region_release` @ 0x082803c0 — documented no-op stub. The
//!     stub matches the original exactly for a NULL region (both do
//!     nothing — the early `popeq` even skips the field NULLing),
//!     which is the only element the wired configuration can hold
//!     (no block manager, and client_populate's ctor slots are
//!     stubs). For a live region the original decrements the
//!     refcount, unlocks the mutex `region_ref_lock` took, frees on
//!     zero and NULLs elem + 0x4/+0x8; the stub leaves all of that
//!     to the real 0x082803c0 port when it lands — until then a
//!     hooked destructor on a live-region element would leak the
//!     region and leave its mutex held.
//!   - `member_destroy` @ 0x082621dc — identity stub returning its
//!     argument (the original's own closing `mov r0, r4`; the
//!     recursive-mutex member is opaque to this cluster, the
//!     pool_client.rs `stub_mutex_init` precedent), so the
//!     destructor's `member - 0xc` return is `this` exactly as in
//!     the original.

use crate::kernel::posix_mutex::{posix_mutex_lock, posix_mutex_unlock};
#[cfg(not(target_os = "none"))]
use crate::cxx::mutex::CXX_MUTEX_STATUS_OFFSET;
#[cfg(not(target_os = "none"))]
use crate::cxx::mutex_attr_init::{cxx_mutexattr_init, MUTEXATTR_MAGIC};
#[cfg(not(target_os = "none"))]
use crate::cxx::mutex_settype_init::{
    CXX_MUTEX_SETTYPE_INIT_OPS, MUTEX_KIND_MAX,
};

/// Width of a pointer field: 4 on the ARMv5TE target (matching the
/// original layout), 8 on a 64-bit test host.
const WORD: usize = core::mem::size_of::<*mut u8>();

/// Word index of the region object pointer in a deque element
/// (byte offset 0x4 on the 32-bit target).
pub const ELEM_REGION_INDEX: usize = 1;

/// Word index of the region start address in a region object
/// (byte offset 0x4 on the 32-bit target).
pub const REGION_START_INDEX: usize = 1;

/// Word index of the mutex object pointer in a region object
/// (byte offset 0x8 on the 32-bit target).
pub const REGION_MUTEX_INDEX: usize = 2;

/// The word @ 0x089cb1b8 whose *address* is the fallback "region start"
/// (see the module header). Lives here next to its on-device neighbor
/// `block_mgr::BLOCK_MANAGER` (0x089cb1b4) in spirit; the two are
/// separate statics, which is harmless because only this one's address
/// and only that one's value are ever used.
pub static mut REGION_START_FALLBACK: u32 = 0;

/// The ROM address of the element class's vtable — the destructor's
/// literal-pool word @ 0x0828052c, binary-verified (also the literal of
/// the sibling ctors @ 0x08280464 / 0x082804b8).
///
/// Stored as the `u32` the original stores. The words at this address
/// do not decode as function entries (see the module header), and the
/// port never dispatches through the table, so the raw address
/// suffices — the ui/view_base.rs `VIEW_BASE_VTABLE_ADDRESS`
/// precedent.
pub const REGION_ELEM_VTABLE_ADDRESS: u32 = 0x089a_6444;

/// Word index of the recursive-mutex member inside the element (byte
/// offset 0xc on the 32-bit target). It is an index rather than a literal
/// byte offset so the host representation cannot overlap the preceding
/// pointer fields.
pub const ELEM_MUTEX_INDEX: usize = 3;

/// Offset of the recursive-mutex member inside the element: +0xc on target,
/// and after all three pointer-width element words on the host.
pub const ELEM_MUTEX_OFFSET: usize = ELEM_MUTEX_INDEX * WORD;

/// Indirect dispatch table for the element destructor's unported
/// callees (see the module header for each default's contract).
#[derive(Clone, Copy)]
pub struct RegionElemOps {
    /// Region release @ 0x082803c0 `(elem)`: decrements the region's
    /// refcount under the mutex `region_ref_lock` took; on zero frees
    /// the region's word-1 buffer (tag 43) and `operator delete`s the
    /// region; every live path unlocks and NULLs elem + 0x4/+0x8. A
    /// NULL region does nothing at all (early `popeq`). The default
    /// is the documented no-op stub.
    pub region_release: unsafe extern "C" fn(elem: *mut u8),
    /// Recursive-mutex dtor thunk @ 0x082621dc `(elem + 0xc)`: runs
    /// the mutex destroy @ 0x082e82a4 on the member and returns its
    /// argument. The default is the identity stub (the member is
    /// opaque to this cluster).
    pub member_destroy: unsafe extern "C" fn(member: *mut u8) -> *mut u8,
}

/// Default release: no-op (see the module header — exact for the
/// NULL-region elements the wired configuration can hold; the live
/// region path awaits the real 0x082803c0 port).
unsafe extern "C" fn stub_region_release(_elem: *mut u8) {}

/// Default member dtor: identity, mirroring the original thunk's own
/// `mov r0, r4` return (the pool_client.rs `stub_mutex_init`
/// precedent).
unsafe extern "C" fn stub_member_destroy(member: *mut u8) -> *mut u8 {
    member
}

/// Wired defaults (documented stubs).
pub(crate) const DEFAULT_REGION_ELEM_OPS: RegionElemOps = RegionElemOps {
    region_release: stub_region_release,
    member_destroy: stub_member_destroy,
};

/// The active implementation table. Written once at init on target;
/// host tests swap in recorders and restore the defaults.
pub static mut REGION_ELEM_OPS: RegionElemOps = DEFAULT_REGION_ELEM_OPS;

/// Reads one element op (volatile — same rationale as every dispatch
/// table: a build in which nothing swaps it must not constant-fold the
/// default in).
macro_rules! elem_op {
    ($field:ident) => {
        unsafe { core::ptr::read_volatile(core::ptr::addr_of!(REGION_ELEM_OPS.$field)) }
    };
}

/// Indirect dispatch pair for the C++ mutex @ 0x082e8390 / 0x082e83d8
/// (see the module header; the defaults are the real ports).
#[derive(Clone, Copy)]
pub struct RegionMutexOps {
    /// Mutex lock @ 0x082e8390 (thunk @ 0x082621a8). Returns the lock
    /// status word (0x1a on NULL mutex).
    pub lock: unsafe extern "C" fn(mutex: *mut u8) -> u32,
    /// Mutex unlock @ 0x082e83d8 (thunk @ 0x082621ac).
    pub unlock: unsafe extern "C" fn(mutex: *mut u8) -> u32,
}

/// Adapters onto the real pair. The seam is addressed in bytes because
/// that is what every caller has — a fixed offset into a larger object
/// (region + 0x8, client + 0x24, manager + 0x148, base + 0x8) — and
/// every one of those offsets is word-aligned inside a word-aligned
/// object, so the cast to the typed mutex is sound.
unsafe extern "C" fn region_mutex_lock(mutex: *mut u8) -> u32 {
    posix_mutex_lock(mutex.cast())
}

/// See [`region_mutex_lock`].
unsafe extern "C" fn region_mutex_unlock(mutex: *mut u8) -> u32 {
    posix_mutex_unlock(mutex.cast())
}

/// Wired defaults: the real ports (kernel/posix_mutex.rs).
pub(crate) const DEFAULT_REGION_MUTEX_OPS: RegionMutexOps = RegionMutexOps {
    lock: region_mutex_lock,
    unlock: region_mutex_unlock,
};

/// The active mutex implementation. Host tests install recording mocks;
/// the real ports replace the defaults when they exist.
pub static mut REGION_MUTEX_OPS: RegionMutexOps = DEFAULT_REGION_MUTEX_OPS;

/// Reads one mutex op (volatile — same rationale as every dispatch
/// table: the slot is meant to be swapped at runtime).
macro_rules! mutex_op {
    ($field:ident) => {
        unsafe { core::ptr::read_volatile(core::ptr::addr_of!(REGION_MUTEX_OPS.$field)) }
    };
}

/// Reads a pointer field addressed by word index. The C++ elements are
/// word-aligned on target; host tests deliberately permit byte fixtures.
#[inline(always)]
unsafe fn ptr_field(base: *const u8, index: usize) -> *mut u8 {
    #[cfg(target_os = "none")]
    {
        base.add(index * WORD).cast::<*mut u8>().read()
    }
    #[cfg(not(target_os = "none"))]
    {
        (base.add(index * WORD) as *const *mut u8).read_unaligned()
    }
}

/// Reads a target-width scalar field addressed by word index. Element
/// instances are naturally word-aligned C++ objects, as required by the
/// original `ldr`/`str` instructions.
#[inline(always)]
unsafe fn u32_field(base: *mut u8, index: usize) -> *mut u32 {
    base.add(index * WORD).cast()
}

/// Runs the unported recursive-mutex constructor @ 0x082621b0 on device.
/// On hosts, composes the already ported attribute initializer with the
/// decoded kind-2 settype/PosixMutex initialization sequence so tests can
/// observe the copied element's resulting mutex.
#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn construct_recursive_mutex(member: *mut u8) {
    let construct: unsafe extern "C" fn(*mut u8) -> *mut u8 =
        core::mem::transmute(0x0826_21b0usize);
    construct(member);
}

/// Host model of the unported recursive-mutex constructor @ 0x082621b0.
#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn construct_recursive_mutex(member: *mut u8) {
    let mut attr = [0usize; 2];
    cxx_mutexattr_init(attr.as_mut_ptr());
    let status = core::ptr::read_volatile(core::ptr::addr_of!(
        CXX_MUTEX_SETTYPE_INIT_OPS.pthread_mutexattr_settype
    ))(attr.as_mut_ptr(), MUTEX_KIND_MAX);
    member.add(CXX_MUTEX_STATUS_OFFSET).cast::<u32>().write(status);
    if status == 0 {
        let status = core::ptr::read_volatile(core::ptr::addr_of!(
            CXX_MUTEX_SETTYPE_INIT_OPS.posix_mutex_init
        ))(member, attr.as_mut_ptr());
        member.add(CXX_MUTEX_STATUS_OFFSET).cast::<u32>().write(status);
    }
    // pthread_mutexattr_destroy @ 0x082e8474 clears a valid attr's magic;
    // this transient stack object is otherwise unobservable.
    if attr[0] as u32 == MUTEXATTR_MAGIC {
        attr[0] = 0;
    }
}

/// region_ref_lock — original: `FUN_082801f8` @ 0x082801f8 (20 bytes).
///
/// Locks the region of a deque element. NULL region: returns 0 without
/// touching the mutex (exactly the original's early `bx lr` with the
/// NULL load in r0); otherwise returns the mutex lock result.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn region_ref_lock(elem: *const u8) -> u32 {
    let region = ptr_field(elem, ELEM_REGION_INDEX);
    if region.is_null() {
        return 0;
    }
    (mutex_op!(lock))(ptr_field(region, REGION_MUTEX_INDEX))
}

/// region_ref_unlock — original: `FUN_082802cc` @ 0x082802cc (20 bytes).
///
/// Unlock twin of [`region_ref_lock`].
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn region_ref_unlock(elem: *const u8) -> u32 {
    let region = ptr_field(elem, ELEM_REGION_INDEX);
    if region.is_null() {
        return 0;
    }
    (mutex_op!(unlock))(ptr_field(region, REGION_MUTEX_INDEX))
}

/// region_elem_copy_construct — original: `FUN_08280464` @ 0x08280464
/// (80 bytes: 76 bytes of code and its vtable literal at 0x082804b4).
///
/// Binary-scanned call count: 15 `bl` sites — 11 unconditional and four
/// `blne` (0x0814b988, 0x081a85a8, 0x081fc39c, 0x083e9f14); no tail `b`
/// sites. The predicated callers provide the NULL guard, so this function
/// deliberately dereferences both arguments unconditionally. It plants the
/// element vtable, constructs its embedded recursive mutex, then locks the
/// source's region while copying its region pointer and companion word,
/// increments a non-NULL region's u32 refcount, unlocks the source, and
/// returns `dst`.
///
/// Deliberate host-only deviation: recursive-mutex construction is modeled
/// from the raw 0x082621b0 body by composing its already ported dependencies;
/// device builds call that unported body directly. The modeled
/// pthread_mutexattr_destroy only clears a transient stack attribute's magic,
/// exactly its observable effect here.
///
/// Original listing:
/// ```text
/// 08280464  push {r4,r5,r6,lr}
/// 0828046c  ldr  r1,[pc,#64]       ; 0x089a6444
/// 08280470  str  r1,[r0],#12
/// 08280474  bl   0x082621b0        ; recursive mutex ctor
/// 08280480  bl   0x082801f8        ; source region lock
/// 08280484  ldr  r0,[r5,#4]
/// 08280488  str  r0,[r4,#4]
/// 0828048c  ldr  r1,[r5,#8]
/// 08280494  str  r1,[r4,#8]
/// 08280498  ldrne/addne/strne [r0] ; retain non-NULL region
/// 082804a8  bl   0x082802cc        ; source region unlock
/// ```
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn region_elem_copy_construct(dst: *mut u8, src: *const u8) -> *mut u8 {
    (dst as *mut usize).write(REGION_ELEM_VTABLE_ADDRESS as usize);
    construct_recursive_mutex(dst.add(ELEM_MUTEX_OFFSET));

    region_ref_lock(src);
    let region = ptr_field(src, ELEM_REGION_INDEX);
    #[cfg(target_os = "none")]
    dst.add(ELEM_REGION_INDEX * WORD).cast::<*mut u8>().write(region);
    #[cfg(not(target_os = "none"))]
    (dst.add(ELEM_REGION_INDEX * WORD) as *mut *mut u8).write_unaligned(region);
    u32_field(dst, 2).write((src.add(2 * WORD).cast::<u32>()).read());
    if !region.is_null() {
        let refs = region.cast::<u32>().read();
        region.cast::<u32>().write(refs.wrapping_add(1));
    }
    region_ref_unlock(src);
    dst
}

/// block_to_region_start — original: `FUN_08280430` @ 0x08280430
/// (48 bytes).
///
/// Maps a block-deque element to the start address of its region, under
/// the region's mutex. Elements without a live region (or with a NULL
/// start) map to the fallback address (see the module header).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn block_to_region_start(elem: *const u8) -> *mut u8 {
    region_ref_lock(elem);
    let region = ptr_field(elem, ELEM_REGION_INDEX);
    let mut start = core::ptr::null_mut();
    if !region.is_null() {
        start = ptr_field(region, REGION_START_INDEX);
    }
    if region.is_null() || start.is_null() {
        start = core::ptr::addr_of_mut!(REGION_START_FALLBACK) as *mut u8;
    }
    region_ref_unlock(elem);
    start
}

/// region_elem_destroy — original: `FUN_082804fc` @ 0x082804fc (48
/// bytes + one literal-pool word; 23 `bl` + 1 tail `b` call sites,
/// binary-verified).
///
/// The 0x28-byte deque element's C++ destructor (see the module
/// header): plants the class vtable, releases the region reference
/// under its mutex, destroys the recursive-mutex member, and returns
/// `this` (as `member_result - 0xc`, exactly the original's closing
/// `sub r0, r0, #12`).
///
/// Original listing:
/// ```text
/// 082804fc  push {r4, lr}
/// 08280500  mov  r4, r0
/// 08280504  ldr  r0, [pc, #32]   ; 0x089a6444 (vtable)
/// 08280508  str  r0, [r4]
/// 0828050c  mov  r0, r4
/// 08280510  bl   0x082801f8      ; region_ref_lock
/// 08280514  mov  r0, r4
/// 08280518  bl   0x082803c0      ; region release (REGION_ELEM_OPS)
/// 0828051c  add  r0, r4, #12
/// 08280520  bl   0x082621dc      ; member mutex dtor (REGION_ELEM_OPS)
/// 08280524  sub  r0, r0, #12
/// 08280528  pop  {r4, pc}
/// ```
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn region_elem_destroy(elem: *mut u8) -> *mut u8 {
    (elem as *mut usize).write(REGION_ELEM_VTABLE_ADDRESS as usize);
    region_ref_lock(elem);
    (elem_op!(region_release))(elem);
    let member = (elem_op!(member_destroy))(elem.add(ELEM_MUTEX_OFFSET));
    member.sub(ELEM_MUTEX_OFFSET)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes tests that swap the global mutex ops.
    static OPS_LOCK: Mutex<()> = Mutex::new(());

    /// Mutex-op event log: (is_lock, mutex address).
    static mut EVENTS: Vec<(bool, usize)> = Vec::new();

    unsafe extern "C" fn recording_lock(mutex: *mut u8) -> u32 {
        (*core::ptr::addr_of_mut!(EVENTS)).push((true, mutex as usize));
        0
    }

    unsafe extern "C" fn recording_unlock(mutex: *mut u8) -> u32 {
        (*core::ptr::addr_of_mut!(EVENTS)).push((false, mutex as usize));
        0
    }

    fn mock_mutex() -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            REGION_MUTEX_OPS = RegionMutexOps {
                lock: recording_lock,
                unlock: recording_unlock,
            };
            (*core::ptr::addr_of_mut!(EVENTS)).clear();
        }
        guard
    }

    fn restore_mutex() {
        unsafe { REGION_MUTEX_OPS = DEFAULT_REGION_MUTEX_OPS };
    }

    fn events() -> Vec<(bool, usize)> {
        unsafe { (*core::ptr::addr_of!(EVENTS)).clone() }
    }

    /// Builds a deque element (0x28 raw bytes) pointing at a region
    /// object (0x10 raw bytes) with the given start/mutex fields.
    /// Writes a pointer field by word index, matching [`ptr_field`].
    unsafe fn write_ptr_field(base: *mut u8, index: usize, value: *mut u8) {
        (base.add(index * WORD) as *mut *mut u8).write_unaligned(value);
    }

    unsafe fn write_elem(elem: *mut u8, region: *mut u8) {
        write_ptr_field(elem, ELEM_REGION_INDEX, region);
    }

    unsafe fn write_region(region: *mut u8, start: *mut u8, mutex: *mut u8) {
        write_ptr_field(region, REGION_START_INDEX, start);
        write_ptr_field(region, REGION_MUTEX_INDEX, mutex);
    }

    fn fallback() -> *mut u8 {
        unsafe { core::ptr::addr_of_mut!(REGION_START_FALLBACK) as *mut u8 }
    }

    #[test]
    fn live_region_maps_to_its_start_under_the_lock() {
        let _guard = mock_mutex();
        let mut elem = [0u8; 0x28];
        let mut region = [0u8; 0x18];
        let mutex = 0x5000usize as *mut u8;
        unsafe {
            write_region(region.as_mut_ptr(), 0x2_0000 as *mut u8, mutex);
            write_elem(elem.as_mut_ptr(), region.as_mut_ptr());
            let start = block_to_region_start(elem.as_ptr());
            assert_eq!(start, 0x2_0000 as *mut u8);
        }
        // Lock on the region's mutex, then unlock — in that order.
        assert_eq!(
            events(),
            std::vec![(true, 0x5000), (false, 0x5000)],
            "lock -> read -> unlock protocol"
        );
        restore_mutex();
    }

    #[test]
    fn null_region_returns_fallback_without_mutex_traffic() {
        let _guard = mock_mutex();
        let mut elem = [0u8; 0x28];
        unsafe {
            write_elem(elem.as_mut_ptr(), core::ptr::null_mut());
            assert_eq!(block_to_region_start(elem.as_ptr()), fallback());
        }
        assert!(
            events().is_empty(),
            "NULL region: neither helper reaches the mutex"
        );
        restore_mutex();
    }

    #[test]
    fn null_start_returns_fallback_but_still_locks() {
        let _guard = mock_mutex();
        let mut elem = [0u8; 0x28];
        let mut region = [0u8; 0x18];
        unsafe {
            write_region(region.as_mut_ptr(), core::ptr::null_mut(), 0x6000 as *mut u8);
            write_elem(elem.as_mut_ptr(), region.as_mut_ptr());
            assert_eq!(block_to_region_start(elem.as_ptr()), fallback());
        }
        assert_eq!(events(), std::vec![(true, 0x6000), (false, 0x6000)]);
        restore_mutex();
    }

    #[test]
    fn lock_helper_returns_zero_on_null_region_else_lock_result() {
        let _guard = mock_mutex();
        let mut elem = [0u8; 0x28];
        let mut region = [0u8; 0x18];
        unsafe {
            write_elem(elem.as_mut_ptr(), core::ptr::null_mut());
            assert_eq!(region_ref_lock(elem.as_ptr()), 0);
            assert!(events().is_empty());

            write_region(region.as_mut_ptr(), 0x1000 as *mut u8, 0x7000 as *mut u8);
            write_elem(elem.as_mut_ptr(), region.as_mut_ptr());
            assert_eq!(region_ref_lock(elem.as_ptr()), 0);
            assert_eq!(events(), std::vec![(true, 0x7000)]);
            assert_eq!(region_ref_unlock(elem.as_ptr()), 0);
            assert_eq!(events(), std::vec![(true, 0x7000), (false, 0x7000)]);
        }
        restore_mutex();
    }


    // ---- region_elem_copy_construct -------------------------------

    /// The copy constructor preserves both reference fields while holding
    /// the source's lock, initializes a recursive destination mutex, and
    /// increments the region refcount with the original's u32 wrapping.
    #[test]
    fn copy_construct_retains_live_region_and_initializes_recursive_mutex() {
        use crate::kernel::posix_mutex::PosixMutex;

        let _guard = mock_mutex();
        let mut src = [0usize; 5];
        let mut dst = [0usize; 8];
        let mut region = [0usize; 3];
        let src_ptr = src.as_mut_ptr().cast::<u8>();
        let dst_ptr = dst.as_mut_ptr().cast::<u8>();
        let region_ptr = region.as_mut_ptr().cast::<u8>();
        unsafe {
            write_ptr_field(region_ptr, REGION_MUTEX_INDEX, 0x5000usize as *mut u8);
            region_ptr.cast::<u32>().write(u32::MAX);
            write_ptr_field(src_ptr, ELEM_REGION_INDEX, region_ptr);
            u32_field(src_ptr, 2).write(0xa5a5_5a5a);

            assert_eq!(region_elem_copy_construct(dst_ptr, src_ptr), dst_ptr);
            assert_eq!(dst[0], REGION_ELEM_VTABLE_ADDRESS as usize);
            assert_eq!(ptr_field(dst_ptr, ELEM_REGION_INDEX), region_ptr);
            assert_eq!(u32_field(dst_ptr, 2).read(), 0xa5a5_5a5a);
            assert_eq!(region_ptr.cast::<u32>().read(), 0, "u32 refcount wraps");

            let mutex = &*dst_ptr.add(ELEM_MUTEX_OFFSET).cast::<PosixMutex>();
            assert_eq!(mutex.magic, crate::cxx::mutex_settype_init::MUTEX_LIVE_MAGIC);
            assert_eq!(
                mutex.attr_flags & 0x0030_0000,
                0x0020_0000,
                "kind 2 (recursive) occupies attr bits 4..5"
            );
            assert_eq!(
                dst_ptr
                    .add(ELEM_MUTEX_OFFSET + crate::cxx::mutex::CXX_MUTEX_STATUS_OFFSET)
                    .cast::<u32>()
                    .read(),
                0,
                "the initializer status replaces the successful settype status"
            );
        }
        assert_eq!(
            events(),
            std::vec![(true, 0x5000), (false, 0x5000)],
            "source region remains locked across copy and retain"
        );
        restore_mutex();
    }

    /// A NULL source region is still copied and unlocked through the
    /// helper's early return, but no mutex operation or refcount access runs.
    #[test]
    fn copy_construct_preserves_null_region_without_mutex_traffic() {
        let _guard = mock_mutex();
        let mut src = [0usize; 5];
        let mut dst = [0usize; 8];
        let src_ptr = src.as_mut_ptr().cast::<u8>();
        let dst_ptr = dst.as_mut_ptr().cast::<u8>();
        unsafe {
            write_ptr_field(src_ptr, ELEM_REGION_INDEX, core::ptr::null_mut());
            u32_field(src_ptr, 2).write(0x1020_3040);

            assert_eq!(region_elem_copy_construct(dst_ptr, src_ptr), dst_ptr);
            assert_eq!(dst[0], REGION_ELEM_VTABLE_ADDRESS as usize);
            assert!(ptr_field(dst_ptr, ELEM_REGION_INDEX).is_null());
            assert_eq!(u32_field(dst_ptr, 2).read(), 0x1020_3040);
        }
        assert!(events().is_empty(), "NULL region short-circuits both helpers");
        restore_mutex();
    }
    /// The shipped defaults are the real mutex pair: the seed walk runs
    /// a genuine acquire/release on the region's mutex object and the
    /// mapping comes out unchanged.
    #[test]
    fn the_wired_defaults_map_through_the_real_mutex_pair() {
        use crate::kernel::posix_mutex::{PosixMutex, PRE_KERNEL_THREAD};
        let _guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        restore_mutex();
        let mut elem = [0u8; 0x28];
        let mut region = [0u8; 0x18];
        let mut mutex: PosixMutex = unsafe { core::mem::zeroed() };
        unsafe {
            write_region(
                region.as_mut_ptr(),
                0x3_0000 as *mut u8,
                &mut mutex as *mut PosixMutex as *mut u8,
            );
            write_elem(elem.as_mut_ptr(), region.as_mut_ptr());
            assert_eq!(
                block_to_region_start(elem.as_ptr()),
                0x3_0000 as *mut u8,
                "the real pair must not disturb the mapping"
            );
        }
        assert_eq!(mutex.owner, 0, "acquired and released again");
        assert_eq!(mutex.recursion, 0);

        // ...and the bracket really is a bracket: an unlock-free lock
        // leaves the object held by the (pre-kernel) running thread.
        unsafe { assert_eq!(region_ref_lock(elem.as_ptr()), 0) };
        assert_eq!(mutex.owner, PRE_KERNEL_THREAD, "held");
        assert_eq!(mutex.recursion, 1);
        unsafe { assert_eq!(region_ref_unlock(elem.as_ptr()), 0) };
        assert_eq!(mutex.owner, 0, "released");
    }

    /// A NULL region mutex — the state every zeroed fixture in this
    /// cluster carries — is refused by the real pair without a
    /// dereference, and the mapping still comes through.
    #[test]
    fn the_wired_defaults_tolerate_a_null_mutex() {
        let _guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        restore_mutex();
        let mut elem = [0u8; 0x28];
        let mut region = [0u8; 0x18];
        unsafe {
            write_region(
                region.as_mut_ptr(),
                0x3_0000 as *mut u8,
                core::ptr::null_mut(),
            );
            write_elem(elem.as_mut_ptr(), region.as_mut_ptr());
            assert_eq!(block_to_region_start(elem.as_ptr()), 0x3_0000 as *mut u8);
            assert_eq!(
                region_ref_lock(elem.as_ptr()),
                crate::kernel::posix_mutex::ERR_INVALID_OBJECT
            );
        }
    }

    // ---- region_elem_destroy --------------------------------------

    /// Ordered step log across all three seams (mutex lock/unlock,
    /// region release, member dtor): (step, argument address).
    static mut STEPS: Vec<(&'static str, usize)> = Vec::new();

    unsafe extern "C" fn step_lock(mutex: *mut u8) -> u32 {
        (*core::ptr::addr_of_mut!(STEPS)).push(("lock", mutex as usize));
        0
    }

    unsafe extern "C" fn step_unlock(mutex: *mut u8) -> u32 {
        (*core::ptr::addr_of_mut!(STEPS)).push(("unlock", mutex as usize));
        0
    }

    unsafe extern "C" fn step_release(elem: *mut u8) {
        (*core::ptr::addr_of_mut!(STEPS)).push(("release", elem as usize));
    }

    unsafe extern "C" fn step_member(member: *mut u8) -> *mut u8 {
        (*core::ptr::addr_of_mut!(STEPS)).push(("member", member as usize));
        member
    }

    /// Member recorder with a fabricated return: proves the
    /// destructor's return is `member_result - 0xc`, not `elem`
    /// recomputed (the original's `sub r0, r0, #12`).
    unsafe extern "C" fn step_member_sentinel(member: *mut u8) -> *mut u8 {
        (*core::ptr::addr_of_mut!(STEPS)).push(("member", member as usize));
        0x9000 as *mut u8
    }

    /// Installs step recorders over both ops tables. Returns the
    /// serialization guard.
    fn mock_all() -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            REGION_MUTEX_OPS = RegionMutexOps {
                lock: step_lock,
                unlock: step_unlock,
            };
            REGION_ELEM_OPS = RegionElemOps {
                region_release: step_release,
                member_destroy: step_member,
            };
            (*core::ptr::addr_of_mut!(STEPS)).clear();
        }
        guard
    }

    fn restore_all() {
        unsafe {
            REGION_MUTEX_OPS = DEFAULT_REGION_MUTEX_OPS;
            REGION_ELEM_OPS = DEFAULT_REGION_ELEM_OPS;
        }
    }

    fn steps() -> Vec<(&'static str, usize)> {
        unsafe { (*core::ptr::addr_of!(STEPS)).clone() }
    }

    /// NULL region: no mutex traffic (region_ref_lock's early return),
    /// but the vtable is planted, both slots fire in order, and the
    /// return is `this`.
    #[test]
    fn destroy_null_region_plants_vtable_and_returns_this() {
        let _guard = mock_all();
        let mut elem = [0usize; 5];
        let elem_ptr = elem.as_mut_ptr() as *mut u8;
        unsafe {
            write_elem(elem_ptr, core::ptr::null_mut());
            let back = region_elem_destroy(elem_ptr);
            assert_eq!(back, elem_ptr, "member stub returns its arg; -0xc lands on this");
            assert_eq!(
                elem[0], REGION_ELEM_VTABLE_ADDRESS as usize,
                "the vtable literal is planted first"
            );
        }
        assert_eq!(
            steps(),
            std::vec![
                ("release", elem_ptr as usize),
                ("member", elem_ptr.wrapping_add(ELEM_MUTEX_OFFSET) as usize),
            ],
            "NULL region: no lock, release then member in order"
        );
        restore_all();
    }

    /// Live region: the region's mutex is locked BEFORE the release
    /// slot runs (the original brackets the refcount update), then
    /// the member dtor runs on elem + 0xc.
    #[test]
    fn destroy_live_region_locks_before_release() {
        let _guard = mock_all();
        let mut elem = [0usize; 5];
        let mut region = [0usize; 3];
        let elem_ptr = elem.as_mut_ptr() as *mut u8;
        let region_ptr = region.as_mut_ptr() as *mut u8;
        unsafe {
            write_ptr_field(region_ptr, REGION_MUTEX_INDEX, 0x5000 as *mut u8);
            write_elem(elem_ptr, region_ptr);
            let back = region_elem_destroy(elem_ptr);
            assert_eq!(back, elem_ptr);
            assert_eq!(elem[0], REGION_ELEM_VTABLE_ADDRESS as usize);
        }
        assert_eq!(
            steps(),
            std::vec![
                ("lock", 0x5000),
                ("release", elem_ptr as usize),
                ("member", elem_ptr.wrapping_add(ELEM_MUTEX_OFFSET) as usize),
            ],
            "lock(region->mutex) -> release(elem) -> member(elem + 0xc)"
        );
        restore_all();
    }

    /// The return value is the member slot's result minus 0xc — the
    /// original's closing `sub r0, r0, #12` — not `elem` recomputed.
    #[test]
    fn destroy_returns_member_result_minus_offset() {
        let _guard = mock_all();
        let mut elem = [0usize; 5];
        let elem_ptr = elem.as_mut_ptr() as *mut u8;
        unsafe {
            REGION_ELEM_OPS.member_destroy = step_member_sentinel;
            write_elem(elem_ptr, core::ptr::null_mut());
            let back = region_elem_destroy(elem_ptr);
            assert_eq!(
                back,
                (0x9000usize - ELEM_MUTEX_OFFSET) as *mut u8,
                "r0 = member_result - 0xc"
            );
        }
        restore_all();
    }

    /// The wired defaults on the only element they can meet — a
    /// NULL-region one, exactly what client_populate's ctor stubs
    /// leave behind: vtable planted, no mutex traffic beyond the
    /// real pair's NULL-region short-circuit (none at all), and the
    /// identity member stub makes the return `this`.
    #[test]
    fn destroy_with_wired_defaults_on_null_region() {
        let _guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        restore_all();
        let mut elem = [0usize; 5];
        let elem_ptr = elem.as_mut_ptr() as *mut u8;
        unsafe {
            write_elem(elem_ptr, core::ptr::null_mut());
            assert_eq!(region_elem_destroy(elem_ptr), elem_ptr);
            assert_eq!(elem[0], REGION_ELEM_VTABLE_ADDRESS as usize);
        }
    }
}
