//! Tagged-word buffer pool nesting and slot allocation.
//!
//! The sibling push/pop helpers preserve the slot cursor across nested work;
//! `tagged_word_buffer_pool_take` allocates the embedded slots.
//! The owner object is 0x2c0 bytes:
//! - +0x00 `slot_count` — the live allocation cursor.
//! - +0x04..+0x283 32 embedded [`TaggedWordBuffer`] slots.
//! - +0x284 `flags` — used by the sibling destructor.
//! - +0x288 `nesting_depth` — maintained by the nesting helpers.
//! - +0x28c..+0x2b8 12 saved `slot_count` words.
//! - +0x2bc `overflow_reported` — latch for the one-shot diagnostic.

use crate::heap::tagged_word_buffer::{tagged_word_buffer_destroy, TaggedWordBuffer};
use crate::kernel::diag_ring_record::diag_ring_record;
use crate::drivers::ata_cmd::traced_alloc;
use crate::libc::memzero::memzero_aligned;

static MEMZERO_ALIGNED_CALL: unsafe extern "C" fn(*mut u8, usize) -> *mut u8 = memzero_aligned;

/// Embedded slot count in the 0x2c0-byte pool object.
pub const TAGGED_WORD_BUFFER_POOL_CAPACITY: usize = 32;
/// Depth threshold at which the current nesting depth becomes the selected
/// slot index instead of the mutable slot cursor.
pub const TAGGED_WORD_BUFFER_POOL_DEPTH_LIMIT: u32 = 13;

const TAGGED_WORD_BUFFER_POOL_SIZE: usize = 0x2c0;

/// Target-layout pool object that owns 32 embedded tagged word buffers.
#[repr(C)]
pub struct TaggedWordBufferPool {
    /// +0x00: mutable slot cursor.
    pub slot_count: u32,
    /// +0x04..+0x283: 32 embedded 20-byte tagged word buffers.
    pub slots: [TaggedWordBuffer; TAGGED_WORD_BUFFER_POOL_CAPACITY],
    /// +0x284: control flags used by the sibling destructor.
    pub flags: u32,
    /// +0x288: nesting depth maintained by the sibling push/pop helpers.
    pub nesting_depth: u32,
    /// +0x28c..+0x2b8: saved slot cursors for the first 12 nesting levels.
    pub saved_slot_counts: [u32; 12],
    /// +0x2bc: one-shot overflow diagnostic latch.
    pub overflow_reported: u32,
}

/// `flags` bit 0: release the complete pool after destroying its slots.
pub const TAGGED_WORD_BUFFER_POOL_FLAG_DELETE_THIS: u32 = 1;
/// tagged_word_buffer_pool_push — original: `FUN_0803dec8` @ 0x0803dec8
/// (36 bytes; 11 direct `bl` call sites).
///
/// Raw bytes span 0x0803dec8..0x0803deec; the independent
/// `three_buffer_owner_release` starts at 0x0803deec. Decoding every ARM
/// B/BL immediate in `osos.dec` found ten unconditional `bl` callers and
/// one `bleq` at 0x0803dd9c. The predicated caller invokes this only when
/// its current nesting depth is zero; this body itself has no NULL guard.
///
/// Saves the current slot cursor at nesting depths 0 through 11, then
/// increments the depth. The signed ARM `lt` condition deliberately also
/// admits values with bit 31 set, preserving the firmware's unchecked raw
/// pointer arithmetic. Deliberate deviations: none.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn tagged_word_buffer_pool_push(pool: *mut TaggedWordBufferPool) {
    let nesting_depth = (*pool).nesting_depth;

    if (nesting_depth as i32) < 12 {
        let saved_slot_count = core::ptr::addr_of_mut!((*pool).saved_slot_counts)
            .cast::<u32>()
            .wrapping_add(nesting_depth as usize);
        saved_slot_count.write((*pool).slot_count);
    }

    (*pool).nesting_depth = nesting_depth.wrapping_add(1);
}

/// tagged_word_buffer_pool_pop — original: `FUN_0803dd84` @ 0x0803dd84
/// (68 bytes; 11 direct `bl` call sites).
///
/// Raw bytes span exactly 0x0803dd84..0x0803ddc8; the separately linked
/// `three_buffer_owner_release` starts at 0x0803ddc8. Decoding every ARM
/// B/BL immediate in `osos.dec` found 11 unconditional `bl` callers and no
/// predicated calls. The body returns immediately for NULL; only its
/// conditional call to `tagged_word_buffer_pool_push` occurs after that
/// guard.
///
/// When depth is zero, save the current slot cursor and enter depth one with
/// `tagged_word_buffer_pool_push`. Clear the one-shot overflow latch,
/// decrement depth, then restore the saved cursor when the decremented depth
/// is signed less than 12. The signed condition deliberately preserves the
/// firmware's unchecked raw-pointer arithmetic for bit-31-set depths.
/// Deliberate deviations: none.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn tagged_word_buffer_pool_pop(pool: *mut TaggedWordBufferPool) {
    if pool.is_null() {
        return;
    }

    if (*pool).nesting_depth == 0 {
        tagged_word_buffer_pool_push(pool);
    }

    (*pool).overflow_reported = 0;
    let nesting_depth = (*pool).nesting_depth.wrapping_sub(1);
    (*pool).nesting_depth = nesting_depth;

    if (nesting_depth as i32) < 12 {
        let saved_slot_count = core::ptr::addr_of!((*pool).saved_slot_counts)
            .cast::<u32>()
            .wrapping_add(nesting_depth as usize);
        (*pool).slot_count = saved_slot_count.read();
    }
}

/// tagged_word_buffer_pool_destroy — original: `FUN_0803ddc8` @
/// 0x0803ddc8 (68 bytes; **6 direct `bl` call sites**, binary-verified:
/// 0x08062360 is `blne`; 0x0808e9d0, 0x080c6f90, 0x080c7264, 0x080cbac4,
/// and 0x080cbe08 are unconditional `bl`).
///
/// Raw bytes span exactly 0x0803ddc8..0x0803de0c; the separately linked
/// `tagged_word_buffer_pool_take` starts at 0x0803de0c. NULL returns without
/// touching anything. Otherwise destroys all 32 embedded tagged-word buffers
/// in ascending address order, then reloads `flags` at +0x284 and releases
/// the complete pool through `traced_free` when bit 0 is set.
///
/// Deliberate deviations: none. Release compilation retains the final
/// conditional tail branch to `traced_free`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn tagged_word_buffer_pool_destroy(pool: *mut TaggedWordBufferPool) {
    if pool.is_null() {
        return;
    }

    let slots = core::ptr::addr_of_mut!((*pool).slots).cast::<TaggedWordBuffer>();
    for slot_index in 0..TAGGED_WORD_BUFFER_POOL_CAPACITY {
        unsafe { tagged_word_buffer_destroy(slots.add(slot_index)) };
    }

    let flags = unsafe { core::ptr::addr_of!((*pool).flags).read_volatile() };
    if flags & TAGGED_WORD_BUFFER_POOL_FLAG_DELETE_THIS != 0 {
        unsafe { crate::drivers::ata_cmd::traced_free(pool.cast::<u8>()) };
    }
}

/// tagged_word_buffer_pool_take — original: `FUN_0803de0c` @ 0x0803de0c
/// (100 bytes; 22 `bl` call sites).
///
/// Returns the next embedded [`TaggedWordBuffer`] slot or NULL on overflow.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn tagged_word_buffer_pool_take(
    this: *mut TaggedWordBufferPool,
) -> *mut TaggedWordBuffer {
    let depth = (*this).nesting_depth;
    let slot_index = if depth <= 12 {
        (*this).slot_count
    } else {
        depth
    };

    if slot_index < TAGGED_WORD_BUFFER_POOL_CAPACITY as u32 {
        (*this).slot_count = slot_index + 1;
        core::ptr::addr_of_mut!((*this).slots[slot_index as usize])
    } else {
        if (*this).overflow_reported == 0 {
            diag_ring_record(3, 0x74, 0x6d, 0, 0);
            (*this).overflow_reported = 1;
        }
        core::ptr::null_mut()
    }
}

/// tagged_word_buffer_pool_create — original: `FUN_0803de70` @
/// 0x0803de70 (88 bytes; **6 direct `bl` call sites**, binary-verified:
/// 0x08062230, 0x0808e620, 0x080c6dc8, 0x080c701c, 0x080cb870, and
/// 0x080cbb94 — all unconditional).
///
/// Allocates a 0x2c0-byte [`TaggedWordBufferPool`] through
/// [`traced_alloc`], records diagnostic `(3, 0x6a, 0x41, 0, 0)` and returns
/// NULL when that allocation fails, otherwise clears the complete object and
/// marks `flags` (+0x284) as one. The embedded slots, nesting cursor, saved
/// cursors, and overflow latch therefore start at zero.
///
/// Deliberate deviation: the stock body reaches the IRAM
/// `memzero_aligned` mirror through veneer 0x08037db8. The port invokes the
/// already-ported `memzero_aligned` through a volatile function-pointer load,
/// preserving a real call without allowing LLVM to substitute a builtin.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn tagged_word_buffer_pool_create() -> *mut TaggedWordBufferPool {
    let pool = traced_alloc(TAGGED_WORD_BUFFER_POOL_SIZE as i32, 0, 0).cast::<TaggedWordBufferPool>();
    if pool.is_null() {
        diag_ring_record(3, 0x6a, 0x41, 0, 0);
        return core::ptr::null_mut();
    }

    let zero = core::ptr::read_volatile(core::ptr::addr_of!(MEMZERO_ALIGNED_CALL));
    zero(pool.cast(), TAGGED_WORD_BUFFER_POOL_SIZE);
    (*pool).flags = 1;
    pool
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::mem::{size_of, zeroed};
    use crate::drivers::ata_cmd::{
        TracedAllocHooks, TracedFreeHooks, LARGE_ALLOC_TAG, TRACED_ALLOC_HOOKS,
        TRACED_FREE_HOOKS, TRACED_FREE_TEST_LOCK,
    };
    use crate::kernel::diag_ring_record::{
        BlockGetter, DiagEventRing, DIAG_RING_BLOCK_GETTER,
    };
    use crate::testing::{DIAG_RING_TEST_LOCK, TRACED_ALLOC_TEST_LOCK};
    use core::mem::MaybeUninit;
    use std::sync::Mutex;
    use std::slice;
    use std::vec::Vec;

    #[repr(align(4))]
    struct FactoryStorage([u8; TAGGED_WORD_BUFFER_POOL_SIZE]);

    static mut FACTORY_STORAGE: FactoryStorage =
        FactoryStorage([0; TAGGED_WORD_BUFFER_POOL_SIZE]);
    static mut FACTORY_RING: MaybeUninit<DiagEventRing> = MaybeUninit::uninit();

    static DESTROYED: Mutex<Vec<usize>> = Mutex::new(Vec::new());

    unsafe extern "C" fn record_destroyed(block: *mut u8) {
        DESTROYED.lock().unwrap_or_else(|poison| poison.into_inner()).push(block as usize);
    }

    unsafe extern "C" fn factory_alloc(
        _size: i32,
        _tag1: u32,
        _tag2: u32,
    ) -> *mut u8 {
        core::ptr::addr_of_mut!(FACTORY_STORAGE).cast()
    }

    unsafe extern "C" fn factory_alloc_fail(
        _size: i32,
        _tag1: u32,
        _tag2: u32,
    ) -> *mut u8 {
        core::ptr::null_mut()
    }

    unsafe extern "C" fn factory_ring_getter() -> *mut DiagEventRing {
        core::ptr::addr_of_mut!(FACTORY_RING).cast()
    }

    struct FactoryHookReset {
        allocator: TracedAllocHooks,
        ring_getter: Option<BlockGetter>,
    }

    impl FactoryHookReset {
        unsafe fn save() -> Self {
            Self {
                allocator: core::ptr::read_volatile(core::ptr::addr_of!(TRACED_ALLOC_HOOKS)),
                ring_getter: core::ptr::read_volatile(core::ptr::addr_of!(DIAG_RING_BLOCK_GETTER)),
            }
        }
    }

    impl Drop for FactoryHookReset {
        fn drop(&mut self) {
            unsafe {
                core::ptr::write_volatile(
                    core::ptr::addr_of_mut!(TRACED_ALLOC_HOOKS),
                    self.allocator,
                );
                core::ptr::write_volatile(
                    core::ptr::addr_of_mut!(DIAG_RING_BLOCK_GETTER),
                    self.ring_getter,
                );
            }
        }
    }

    #[test]
    fn pool_layout_matches_the_recovered_extent() {
        assert_eq!(size_of::<TaggedWordBufferPool>(), 0x2c0);
    }

    #[test]
    fn push_saves_slot_cursor_at_first_nesting_depth() {
        let mut pool = unsafe { zeroed::<TaggedWordBufferPool>() };
        pool.slot_count = 0x1234_5678;

        unsafe { tagged_word_buffer_pool_push(&mut pool) };

        assert_eq!(pool.saved_slot_counts[0], 0x1234_5678);
        assert_eq!(pool.nesting_depth, 1);
    }

    #[test]
    fn push_saves_last_slot_then_stops_at_depth_twelve() {
        let mut pool = unsafe { zeroed::<TaggedWordBufferPool>() };
        pool.slot_count = 9;
        pool.nesting_depth = 11;

        unsafe { tagged_word_buffer_pool_push(&mut pool) };

        assert_eq!(pool.saved_slot_counts[11], 9);
        assert_eq!(pool.nesting_depth, 12);

        pool.slot_count = 13;
        unsafe { tagged_word_buffer_pool_push(&mut pool) };

        assert_eq!(pool.saved_slot_counts[11], 9);
        assert_eq!(pool.nesting_depth, 13);
    }

    #[test]
    fn pop_ignores_a_null_pool() {
        unsafe { tagged_word_buffer_pool_pop(core::ptr::null_mut()) };
    }

    #[test]
    fn pop_bootstraps_zero_depth_and_restores_its_saved_slot_cursor() {
        let mut pool = unsafe { zeroed::<TaggedWordBufferPool>() };
        pool.slot_count = 0x1234_5678;

        unsafe { tagged_word_buffer_pool_pop(&mut pool) };

        assert_eq!(pool.slot_count, 0x1234_5678);
        assert_eq!(pool.nesting_depth, 0);
        assert_eq!(pool.saved_slot_counts[0], 0x1234_5678);
    }

    #[test]
    fn destroy_ignores_a_null_pool() {
        unsafe { tagged_word_buffer_pool_destroy(core::ptr::null_mut()) };
    }

    #[test]
    fn destroy_releases_each_embedded_slot_before_owned_pool() {
        let _alloc_guard = TRACED_ALLOC_TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let _free_guard = TRACED_FREE_TEST_LOCK.lock();
        let old_free_hooks = unsafe {
            core::ptr::read_volatile(core::ptr::addr_of!(TRACED_FREE_HOOKS))
        };
        let old_tag = unsafe { core::ptr::addr_of!(LARGE_ALLOC_TAG).read_volatile() };
        unsafe {
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(TRACED_FREE_HOOKS),
                TracedFreeHooks { free: record_destroyed, trace: None },
            );
            core::ptr::addr_of_mut!(LARGE_ALLOC_TAG).write_volatile(0x61);
        }
        DESTROYED.lock().unwrap_or_else(|poison| poison.into_inner()).clear();

        let mut pool = unsafe { zeroed::<TaggedWordBufferPool>() };
        pool.flags = TAGGED_WORD_BUFFER_POOL_FLAG_DELETE_THIS;
        for slot in &mut pool.slots {
            slot.flags = crate::heap::tagged_word_buffer::FLAG_DELETE_THIS;
        }
        let pool_ptr = core::ptr::addr_of_mut!(pool);
        let first_slot = core::ptr::addr_of_mut!(pool.slots).cast::<TaggedWordBuffer>();

        unsafe { tagged_word_buffer_pool_destroy(pool_ptr) };

        let mut expected: Vec<usize> = (0..TAGGED_WORD_BUFFER_POOL_CAPACITY)
            .map(|slot_index| unsafe { first_slot.add(slot_index) as usize })
            .collect();
        expected.push(pool_ptr as usize);
        assert_eq!(
            *DESTROYED.lock().unwrap_or_else(|poison| poison.into_inner()),
            expected,
            "all 32 embedded scalar-deleting destructors precede the owner release",
        );

        unsafe {
            core::ptr::write_volatile(core::ptr::addr_of_mut!(TRACED_FREE_HOOKS), old_free_hooks);
            core::ptr::addr_of_mut!(LARGE_ALLOC_TAG).write_volatile(old_tag);
        }
    }

    #[test]
    fn pop_restores_saved_cursor_below_threshold_and_resets_overflow_latch() {
        let mut pool = unsafe { zeroed::<TaggedWordBufferPool>() };
        pool.slot_count = 3;
        pool.nesting_depth = 12;
        pool.saved_slot_counts[11] = 0xfeed_face;
        pool.overflow_reported = 1;

        unsafe { tagged_word_buffer_pool_pop(&mut pool) };

        assert_eq!(pool.slot_count, 0xfeed_face);
        assert_eq!(pool.nesting_depth, 11);
        assert_eq!(pool.overflow_reported, 0);

        pool.slot_count = 9;
        pool.nesting_depth = TAGGED_WORD_BUFFER_POOL_DEPTH_LIMIT;
        pool.overflow_reported = 1;
        unsafe { tagged_word_buffer_pool_pop(&mut pool) };

        assert_eq!(pool.slot_count, 9);
        assert_eq!(pool.nesting_depth, 12);
        assert_eq!(pool.overflow_reported, 0);
    }

    #[test]
    fn take_uses_slot_cursor_when_depth_is_below_thirteen() {
        let mut pool = unsafe { zeroed::<TaggedWordBufferPool>() };
        pool.slot_count = 5;
        pool.nesting_depth = 12;

        let slot = unsafe { tagged_word_buffer_pool_take(&mut pool) };

        assert_eq!(slot, core::ptr::addr_of_mut!(pool.slots[5]));
        assert_eq!(pool.slot_count, 6);
        assert_eq!(pool.nesting_depth, 12);
    }

    #[test]
    fn take_uses_nesting_depth_at_the_threshold() {
        let mut pool = unsafe { zeroed::<TaggedWordBufferPool>() };
        pool.slot_count = 5;
        pool.nesting_depth = TAGGED_WORD_BUFFER_POOL_DEPTH_LIMIT;

        let slot = unsafe { tagged_word_buffer_pool_take(&mut pool) };

        assert_eq!(slot, core::ptr::addr_of_mut!(pool.slots[13]));
        assert_eq!(pool.slot_count, 14);
        assert_eq!(pool.nesting_depth, TAGGED_WORD_BUFFER_POOL_DEPTH_LIMIT);
    }

    #[test]
    fn take_overflow_returns_null_and_latches_once() {
        let mut pool = unsafe { zeroed::<TaggedWordBufferPool>() };
        pool.slot_count = TAGGED_WORD_BUFFER_POOL_CAPACITY as u32;
        pool.nesting_depth = 0;

        let first = unsafe { tagged_word_buffer_pool_take(&mut pool) };
        assert!(first.is_null());
        assert_eq!(pool.slot_count, TAGGED_WORD_BUFFER_POOL_CAPACITY as u32);
        assert_eq!(pool.overflow_reported, 1);

        let second = unsafe { tagged_word_buffer_pool_take(&mut pool) };
        assert!(second.is_null());
        assert_eq!(pool.overflow_reported, 1);
    }
    #[test]
    fn create_clears_every_field_then_marks_pool_owned() {
        let _ring_guard = DIAG_RING_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _alloc_guard = TRACED_ALLOC_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _reset = unsafe { FactoryHookReset::save() };
        unsafe {
            core::ptr::addr_of_mut!(FACTORY_STORAGE)
                .cast::<u8>()
                .write_bytes(0xa5, TAGGED_WORD_BUFFER_POOL_SIZE);
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(TRACED_ALLOC_HOOKS),
                TracedAllocHooks {
                    alloc: factory_alloc,
                    trace: None,
                },
            );
            core::ptr::write_volatile(core::ptr::addr_of_mut!(DIAG_RING_BLOCK_GETTER), None);
        }

        let pool = unsafe { tagged_word_buffer_pool_create() };

        assert_eq!(pool.cast::<u8>(), core::ptr::addr_of_mut!(FACTORY_STORAGE).cast());
        let bytes = unsafe { slice::from_raw_parts(pool.cast::<u8>(), TAGGED_WORD_BUFFER_POOL_SIZE) };
        assert!(bytes[..0x284].iter().all(|&byte| byte == 0));
        assert_eq!(unsafe { (*pool).flags }, 1);
        assert!(bytes[0x288..].iter().all(|&byte| byte == 0));
    }

    #[test]
    fn create_reports_the_retail_allocation_failure_triple() {
        let _ring_guard = DIAG_RING_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _alloc_guard = TRACED_ALLOC_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _reset = unsafe { FactoryHookReset::save() };
        unsafe {
            core::ptr::addr_of_mut!(FACTORY_RING)
                .cast::<DiagEventRing>()
                .write_bytes(0, 1);
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(TRACED_ALLOC_HOOKS),
                TracedAllocHooks {
                    alloc: factory_alloc_fail,
                    trace: None,
                },
            );
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(DIAG_RING_BLOCK_GETTER),
                Some(factory_ring_getter),
            );
        }

        assert!(unsafe { tagged_word_buffer_pool_create() }.is_null());
        let ring = unsafe { core::ptr::addr_of!(FACTORY_RING).cast::<DiagEventRing>().read() };
        assert_eq!(ring.head, 1);
        assert_eq!(ring.tags[1], 0x0306_a041);
        assert_eq!(ring.data0[1], 0);
        assert_eq!(ring.data1[1], 0);
    }
}
