//! `item_collection_dispatch` — original: `FUN_08283f74` @ `0x08283f74`.
//!
//! Raw `osos.dec` establishes the true 120-byte extent
//! `0x08283f74..0x08283feb`; `0x08283fec` begins the next function's distinct
//! prologue. Decoding every A32 BL word finds four direct caller sites: four
//! unconditional plain BLs and no predicated BLs. The body itself has two
//! unconditional BLs, to the unported retail dispatchers at `0x08046e50` and
//! `0x08046180`.
//!
//! # Algorithm
//!
//! A null collection returns zero without dispatching. Otherwise index `-1`
//! dispatches the whole collection, forwarding the collection flag at `+0x18c`;
//! every other index dispatches the indexed item. Both paths return one.
//!
//! # Deliberate deviations
//!
//! The two large retail dispatchers are not yet named or ported. Target builds
//! call their verified addresses directly; host builds expose typed seams so
//! tests can observe the exact ABI without executing firmware.

/// ABI of the retail whole-collection dispatcher at `0x08046e50`.
pub type WholeCollectionDispatch = unsafe extern "C" fn(
    *mut u8, *mut u8, u32, u32, *mut u8, u32, u32, *mut u32,
);
/// ABI of the retail indexed-item dispatcher at `0x08046180`.
pub type IndexedItemDispatch = unsafe extern "C" fn(
    *mut u8, *mut u8, u32, u32, i32, *mut u8, i32, *mut u8,
);

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_whole_collection_dispatch(
    _controller: *mut u8, _collection: *mut u8, _action: u32, _enabled: u32,
    _owner: *mut u8, _collection_flag: u32, _index: u32, _result: *mut u32,
) {}
#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_indexed_item_dispatch(
    _controller: *mut u8, _collection: *mut u8, _action: u32, _enabled: u32,
    _index: i32, _owner: *mut u8, _requested_index: i32, _requested_collection: *mut u8,
) {}

#[cfg(not(target_arch = "arm"))]
pub static mut WHOLE_COLLECTION_DISPATCH: WholeCollectionDispatch = missing_whole_collection_dispatch;
#[cfg(not(target_arch = "arm"))]
pub static mut INDEXED_ITEM_DISPATCH: IndexedItemDispatch = missing_indexed_item_dispatch;

#[inline(always)]
unsafe fn whole_collection_dispatch() -> WholeCollectionDispatch {
    #[cfg(target_arch = "arm")]
    { core::mem::transmute(0x0804_6e50usize) }
    #[cfg(not(target_arch = "arm"))]
    { WHOLE_COLLECTION_DISPATCH }
}

#[inline(always)]
unsafe fn indexed_item_dispatch() -> IndexedItemDispatch {
    #[cfg(target_arch = "arm")]
    { core::mem::transmute(0x0804_6180usize) }
    #[cfg(not(target_arch = "arm"))]
    { INDEXED_ITEM_DISPATCH }
}

/// Dispatches a whole collection or one of its indexed items.
///
/// `dispatch_context` is the retail two-word target layout; word one is the
/// owner pointer. It remains `u32` so its `+4` target offset is valid on hosts.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn item_collection_dispatch(
    dispatch_context: *const u32,
    controller: *mut u8,
    index: i32,
    collection: *mut u8,
    action: u32,
    enabled: u32,
) -> u32 {
    if collection.is_null() {
        return 0;
    }

    let owner = dispatch_context.add(1).read() as usize as *mut u8;
    if index == -1 {
        whole_collection_dispatch()(
            controller, collection, action, enabled, owner,
            (collection.add(0x18c).read() & 1) as u32, u32::MAX, core::ptr::null_mut(),
        );
    } else {
        indexed_item_dispatch()(
            controller, collection, action, enabled, index, owner, index, collection,
        );
    }
    1
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    const SLAB_LEN: usize = 0x1000;
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::ITEM_COLLECTION_DISPATCH, SLAB_LEN).map(|p| p as usize)
    });
    static LOCK: Mutex<()> = Mutex::new(());
    static mut WHOLE_CALLS: u32 = 0;
    static mut INDEXED_CALLS: u32 = 0;
    static mut ARGS: [usize; 8] = [0; 8];

    unsafe extern "C" fn record_whole(
        controller: *mut u8, collection: *mut u8, action: u32, enabled: u32,
        owner: *mut u8, flag: u32, index: u32, result: *mut u32,
    ) {
        WHOLE_CALLS += 1;
        ARGS = [controller as usize, collection as usize, action as usize, enabled as usize,
            owner as usize, flag as usize, index as usize, result as usize];
    }
    unsafe extern "C" fn record_indexed(
        controller: *mut u8, collection: *mut u8, action: u32, enabled: u32,
        index: i32, owner: *mut u8, requested_index: i32, requested_collection: *mut u8,
    ) {
        INDEXED_CALLS += 1;
        ARGS = [controller as usize, collection as usize, action as usize, enabled as usize,
            index as usize, owner as usize, requested_index as usize, requested_collection as usize];
    }

    unsafe fn reset() {
        WHOLE_CALLS = 0;
        INDEXED_CALLS = 0;
        ARGS = [0; 8];
        WHOLE_COLLECTION_DISPATCH = record_whole;
        INDEXED_ITEM_DISPATCH = record_indexed;
    }

    #[test]
    fn null_collection_returns_zero_without_a_dispatch() {
        let _guard = LOCK.lock();
        unsafe {
            reset();
            assert_eq!(item_collection_dispatch(core::ptr::null(), core::ptr::null_mut(), -1,
                core::ptr::null_mut(), 3, 4), 0);
            assert_eq!((WHOLE_CALLS, INDEXED_CALLS), (0, 0));
        }
    }

    #[test]
    fn negative_one_dispatches_the_whole_collection_with_its_low_flag() {
        let _guard = LOCK.lock();
        let Some(base) = *SLAB else {
            assert!(note_missing_u32_fixture("app/item_collection_dispatch"));
            return;
        };
        unsafe {
            reset();
            let context = base as *mut u32;
            let collection = (base + 0x100) as *mut u8;
            context.write(0);
            context.add(1).write(collection as usize as u32);
            collection.add(0x18c).write(3);
            assert_eq!(item_collection_dispatch(context, (base + 0x300) as *mut u8, -1,
                collection, 7, 9), 1);
            assert_eq!((WHOLE_CALLS, INDEXED_CALLS), (1, 0));
            assert_eq!(ARGS, [base + 0x300, base + 0x100, 7, 9, base + 0x100, 1, u32::MAX as usize, 0]);
        }
    }

    #[test]
    fn other_indices_use_the_indexed_dispatcher_even_when_negative() {
        let _guard = LOCK.lock();
        let Some(base) = *SLAB else {
            assert!(note_missing_u32_fixture("app/item_collection_dispatch"));
            return;
        };
        unsafe {
            reset();
            let context = base as *mut u32;
            let collection = (base + 0x100) as *mut u8;
            context.add(1).write((base + 0x280) as u32);
            assert_eq!(item_collection_dispatch(context, (base + 0x300) as *mut u8, -2,
                collection, 7, 9), 1);
            assert_eq!((WHOLE_CALLS, INDEXED_CALLS), (0, 1));
            assert_eq!(ARGS, [base + 0x300, base + 0x100, 7, 9, usize::MAX - 1,
                base + 0x280, usize::MAX - 1, base + 0x100]);
        }
    }
}
