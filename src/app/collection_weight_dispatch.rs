//! collection_weight_dispatch — original: `FUN_081ba060` @ 0x081ba060.
//!
//! Raw `osos.dec` words establish the exact 164-byte extent
//! `0x081ba060..0x081ba104`: `0x081ba104` starts the next separately entered
//! function. The body has seven unconditional plain `bl` instructions (two
//! each to `cursor_init`, `cursor_advance`, and `cursor_invalidate`, and one
//! to unported `0x081f7390`) and no predicated `bl` instructions; its four
//! distinct direct callees are those cursor operations plus `0x081f7390`.
//!
//! Algorithm: walk the owner's collection once, accumulating each item's
//! word at `+4`; submit that total to the scheduler handle at `+0x48`; walk
//! again and call each item's vtable slot `+0x10`; then set owner byte `+0x64`.
//! Deliberate deviation: `0x081f7390` has no recovered semantic identity, so
//! target builds call its fixed address while host tests install an ABI seam.

use crate::util::cursor::{cursor_advance, cursor_init, cursor_invalidate, Collection, Cursor};

const RETAIL_SCHEDULER_SUBMIT: usize = 0x081f_7390;

/// Target-width owner layout used by [`collection_weight_dispatch`].
#[repr(C)]
pub struct CollectionDispatchOwner {
    pub unresolved_00_to_44: [u32; 18],
    pub scheduler: u32,
    pub collection: Collection,
    pub unresolved_50_to_63: [u8; 20],
    pub dispatched: u8,
}

/// Item layout observed by the two collection walks.
#[repr(C)]
pub struct WeightedDispatchItem {
    pub vtable: *const WeightedDispatchItemVtable,
    pub weight: u32,
}

/// The item virtual table's callback slot.
#[repr(C)]
pub struct WeightedDispatchItemVtable {
    pub unresolved_00_to_0c: [usize; 4],
    pub dispatch: unsafe extern "C" fn(),
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x48] = [0; core::mem::offset_of!(CollectionDispatchOwner, scheduler)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x4c] = [0; core::mem::offset_of!(CollectionDispatchOwner, collection)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x64] = [0; core::mem::offset_of!(CollectionDispatchOwner, dispatched)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x10] = [0; core::mem::offset_of!(WeightedDispatchItemVtable, dispatch)];

/// ABI of unported scheduler submitter `0x081f7390`.
pub type SchedulerSubmit = unsafe extern "C" fn(*mut u8, u32);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_scheduler_submit(_scheduler: *mut u8, _total: u32) {
    panic!("install collection-weight dispatch host operations before calling this port")
}

#[cfg(not(target_os = "none"))]
pub static mut COLLECTION_WEIGHT_DISPATCH_SUBMIT: SchedulerSubmit = missing_scheduler_submit;

#[inline(always)]
unsafe fn scheduler_submit(scheduler: *mut u8, total: u32) {
    #[cfg(target_os = "none")]
    {
        let submit: SchedulerSubmit = unsafe { core::mem::transmute(RETAIL_SCHEDULER_SUBMIT) };
        unsafe { submit(scheduler, total) };
    }
    #[cfg(not(target_os = "none"))]
    {
        let submit = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(COLLECTION_WEIGHT_DISPATCH_SUBMIT)) };
        unsafe { submit(scheduler, total) };
    }
}

/// Sums collection item weights, submits the total, then dispatches every item.
///
/// # Safety
/// `owner` and its collection must be valid. Each collection entry must be a
/// readable [`WeightedDispatchItem`] whose vtable has a callable `+0x10` slot.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn collection_weight_dispatch(owner: *mut CollectionDispatchOwner) {
    let mut cursor = Cursor { collection: core::ptr::null_mut(), index: 0 };
    unsafe { cursor_init(&mut cursor, core::ptr::addr_of_mut!((*owner).collection)) };
    let invalidate = unsafe {
        core::ptr::read_volatile(&(cursor_invalidate as unsafe extern "C" fn(*mut Cursor)))
    };

    let mut item = core::ptr::null_mut::<WeightedDispatchItem>();
    let mut total = 0u32;
    while unsafe { cursor_advance(&mut cursor, core::ptr::addr_of_mut!(item).cast()) } != 0 {
        total = total.wrapping_add(unsafe { (*item).weight });
    }
    unsafe { invalidate(&mut cursor) };
    unsafe { scheduler_submit((*owner).scheduler as usize as *mut u8, total) };

    unsafe { cursor_init(&mut cursor, core::ptr::addr_of_mut!((*owner).collection)) };
    while unsafe { cursor_advance(&mut cursor, core::ptr::addr_of_mut!(item).cast()) } != 0 {
        let dispatch = unsafe { (*(*item).vtable).dispatch };
        unsafe { dispatch() };
    }
    unsafe { invalidate(&mut cursor) };
    unsafe { (*owner).dispatched = 1 };
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::util::cursor::CollectionVtable;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut ITEMS: [*mut WeightedDispatchItem; 3] = [core::ptr::null_mut(); 3];
    static mut ITEM_COUNT: usize = 0;
    static mut CALLBACKS: u32 = 0;
    static mut SUBMISSION: Option<(usize, u32)> = None;

    unsafe extern "C" fn item_at(_collection: *mut Collection, index: i32, out: *mut u8) -> u32 {
        if index < 0 || index as usize >= unsafe { ITEM_COUNT } { return 0; }
        unsafe { out.cast::<*mut WeightedDispatchItem>().write(ITEMS[index as usize]) };
        1
    }

    unsafe extern "C" fn dispatch() { unsafe { CALLBACKS += 1 } }
    unsafe extern "C" fn record_submit(scheduler: *mut u8, total: u32) {
        unsafe { SUBMISSION = Some((scheduler as usize, total)) };
    }

    static COLLECTION_VTABLE: CollectionVtable = CollectionVtable { unresolved: [0; 15], item_at };
    static ITEM_VTABLE: WeightedDispatchItemVtable = WeightedDispatchItemVtable { unresolved_00_to_0c: [0; 4], dispatch };

    fn owner() -> CollectionDispatchOwner {
        CollectionDispatchOwner { unresolved_00_to_44: [0; 18], scheduler: 0x1234_5678, collection: Collection { vtable: &COLLECTION_VTABLE }, unresolved_50_to_63: [0; 20], dispatched: 0 }
    }

    #[test]
    fn sums_wrapping_weights_then_dispatches_every_item() {
        let _guard = LOCK.lock();
        let mut items = [
            WeightedDispatchItem { vtable: &ITEM_VTABLE, weight: u32::MAX },
            WeightedDispatchItem { vtable: &ITEM_VTABLE, weight: 2 },
            WeightedDispatchItem { vtable: &ITEM_VTABLE, weight: 9 },
        ];
        unsafe { ITEMS = [items.as_mut_ptr(), items.as_mut_ptr().wrapping_add(1), items.as_mut_ptr().wrapping_add(2)]; ITEM_COUNT = 3; CALLBACKS = 0; SUBMISSION = None; COLLECTION_WEIGHT_DISPATCH_SUBMIT = record_submit; }
        let mut owner = owner();
        unsafe { collection_weight_dispatch(&mut owner) };
        assert_eq!(unsafe { SUBMISSION }, Some((0x1234_5678, 10)));
        assert_eq!(unsafe { CALLBACKS }, 3);
        assert_eq!(owner.dispatched, 1);
    }

    #[test]
    fn empty_collection_submits_zero_and_sets_the_completion_byte() {
        let _guard = LOCK.lock();
        unsafe { ITEM_COUNT = 0; CALLBACKS = 0; SUBMISSION = None; COLLECTION_WEIGHT_DISPATCH_SUBMIT = record_submit; }
        let mut owner = owner();
        unsafe { collection_weight_dispatch(&mut owner) };
        assert_eq!(unsafe { SUBMISSION }, Some((0x1234_5678, 0)));
        assert_eq!(unsafe { CALLBACKS }, 0);
        assert_eq!(owner.dispatched, 1);
    }
}
