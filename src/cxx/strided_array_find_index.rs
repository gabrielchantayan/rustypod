//! Strided-array key lookup dispatch — retailOS `FUN_082a47b8` @
//! `0x082a47b8` (88 bytes, `0x082a47b8..0x082a480f`; the next separately
//! linked function begins at `0x082a4810`).
//!
//! Raw decoding establishes four incoming plain `bl` call sites and no
//! predicated `bl` callers. The body has one indirect `blx` through vtable
//! slot +0x64, then tail-dispatches through +0x8c when that predicate returns
//! zero or +0x94 otherwise. It first returns -1 when the signed count at +4
//! is not positive. The slot targets have no verified concrete identities, so
//! this port dispatches the object's vtable directly. Deliberate host
//! deviation: the vtable is widened to hold host function pointers; target
//! assertions retain the physical ARM word offsets.

use super::array_element_at::StridedArray;

/// Vtable portion used by [`strided_array_find_index`].
#[repr(C)]
pub struct StridedArrayFindIndexVtable {
    /// Target words +0x00..+0x60, not decoded by this port.
    pub slots_before_predicate: [usize; 25],
    /// +0x64: selects the key lookup implementation.
    pub select_lookup: unsafe extern "C" fn(*const StridedArray) -> i32,
    /// Target words +0x68..+0x88, not decoded by this port.
    pub slots_before_zero_lookup: [usize; 9],
    /// +0x8c: lookup used when [`select_lookup`](Self::select_lookup) is zero.
    pub zero_lookup: unsafe extern "C" fn(*const StridedArray, *const u32) -> i32,
    /// Target word +0x90, not decoded by this port.
    pub slot_90: usize,
    /// +0x94: lookup used when [`select_lookup`](Self::select_lookup) is nonzero.
    pub nonzero_lookup: unsafe extern "C" fn(*const StridedArray, *const u32) -> i32,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x64] = [0; core::mem::offset_of!(StridedArrayFindIndexVtable, select_lookup)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x8c] = [0; core::mem::offset_of!(StridedArrayFindIndexVtable, zero_lookup)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x94] = [0; core::mem::offset_of!(StridedArrayFindIndexVtable, nonzero_lookup)];

/// strided_array_find_index — original: `FUN_082a47b8` @ `0x082a47b8`
/// (88 bytes; four incoming plain `bl` call sites, no predicated `bl` callers).
///
/// Returns -1 for an empty array. Otherwise it calls vtable slot +0x64 and
/// tail-selects the +0x8c or +0x94 key-lookup slot, forwarding `this` and
/// `key` unchanged.
///
/// # Safety
///
/// `this` must address a readable [`StridedArray`] with a vtable whose +0x64,
/// +0x8c, and +0x94 slots have the signatures represented above. `key` is
/// forwarded without being read by this function. RetailOS performs no NULL
/// checks for either pointer on the non-empty path.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn strided_array_find_index(this: *const StridedArray, key: *const u32) -> i32 {
    let count = core::ptr::addr_of!((*this).count).read_volatile();
    if count <= 0 {
        return -1;
    }

    let vtable = core::ptr::addr_of!((*this).vtable).read_volatile()
        as *const StridedArrayFindIndexVtable;
    let select_lookup = core::ptr::addr_of!((*vtable).select_lookup).read_volatile();
    if select_lookup(this) == 0 {
        let zero_lookup = core::ptr::addr_of!((*vtable).zero_lookup).read_volatile();
        zero_lookup(this, key)
    } else {
        let nonzero_lookup = core::ptr::addr_of!((*vtable).nonzero_lookup).read_volatile();
        nonzero_lookup(this, key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicI32, AtomicUsize, Ordering};

    static SELECT_CALLS: AtomicUsize = AtomicUsize::new(0);
    static ZERO_CALLS: AtomicUsize = AtomicUsize::new(0);
    static NONZERO_CALLS: AtomicUsize = AtomicUsize::new(0);
    static SELECT_RESULT: AtomicI32 = AtomicI32::new(0);
    static FORWARDED_KEY: AtomicUsize = AtomicUsize::new(0);
    static TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());


    unsafe extern "C" fn select_lookup(_: *const StridedArray) -> i32 {
        SELECT_CALLS.fetch_add(1, Ordering::SeqCst);
        SELECT_RESULT.load(Ordering::SeqCst)
    }

    unsafe extern "C" fn zero_lookup(_: *const StridedArray, key: *const u32) -> i32 {
        ZERO_CALLS.fetch_add(1, Ordering::SeqCst);
        FORWARDED_KEY.store(key as usize, Ordering::SeqCst);
        17
    }

    unsafe extern "C" fn nonzero_lookup(_: *const StridedArray, key: *const u32) -> i32 {
        NONZERO_CALLS.fetch_add(1, Ordering::SeqCst);
        FORWARDED_KEY.store(key as usize, Ordering::SeqCst);
        23
    }

    static VTABLE: StridedArrayFindIndexVtable = StridedArrayFindIndexVtable {
        slots_before_predicate: [0; 25],
        select_lookup,
        slots_before_zero_lookup: [0; 9],
        zero_lookup,
        slot_90: 0,
        nonzero_lookup,
    };

    fn reset(select_result: i32) {
        SELECT_CALLS.store(0, Ordering::SeqCst);
        ZERO_CALLS.store(0, Ordering::SeqCst);
        NONZERO_CALLS.store(0, Ordering::SeqCst);
        SELECT_RESULT.store(select_result, Ordering::SeqCst);
        FORWARDED_KEY.store(0, Ordering::SeqCst);
    }

    #[test]
    fn empty_array_returns_sentinel_without_virtual_dispatch() {
        let _guard = TEST_LOCK.lock();
        reset(0);
        let array = StridedArray { vtable: &VTABLE as *const _ as *const _, count: 0, storage: 0 };
        assert_eq!(unsafe { strided_array_find_index(&array, core::ptr::null()) }, -1);
        assert_eq!(SELECT_CALLS.load(Ordering::SeqCst), 0);
        assert_eq!(ZERO_CALLS.load(Ordering::SeqCst), 0);
        assert_eq!(NONZERO_CALLS.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn zero_selector_uses_zero_lookup_and_forwards_key() {
        let _guard = TEST_LOCK.lock();
        reset(0);
        let key = 0x1234_5678;
        let array = StridedArray { vtable: &VTABLE as *const _ as *const _, count: 1, storage: 0 };
        assert_eq!(unsafe { strided_array_find_index(&array, &key) }, 17);
        assert_eq!(SELECT_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(ZERO_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(NONZERO_CALLS.load(Ordering::SeqCst), 0);
        assert_eq!(FORWARDED_KEY.load(Ordering::SeqCst), &key as *const u32 as usize);
    }

    #[test]
    fn nonzero_selector_uses_nonzero_lookup_for_negative_status() {
        let _guard = TEST_LOCK.lock();
        reset(-9);
        let key = 0;
        let array = StridedArray { vtable: &VTABLE as *const _ as *const _, count: -1, storage: 0 };
        assert_eq!(unsafe { strided_array_find_index(&array, &key) }, -1);
        assert_eq!(SELECT_CALLS.load(Ordering::SeqCst), 0);

        let array = StridedArray { vtable: &VTABLE as *const _ as *const _, count: 2, storage: 0 };
        assert_eq!(unsafe { strided_array_find_index(&array, &key) }, 23);
        assert_eq!(SELECT_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(ZERO_CALLS.load(Ordering::SeqCst), 0);
        assert_eq!(NONZERO_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(FORWARDED_KEY.load(Ordering::SeqCst), &key as *const u32 as usize);
    }
}
