//! `observable_array_assert_empty_destruct` — retailOS `FUN_083d1a04` at
//! `0x083d1a04`.
//!
//! Raw `osos.dec` establishes 56 bytes: thirteen A32 words from
//! `0x083d1a04` through the tail branch at `0x083d1a38`, followed by vtable
//! literal `0x089a52e0` at `0x083d1a3c`; `0x083d1a40` begins the next real
//! function. There are two inbound plain `bl` sites (`0x081ba804`,
//! `0x0826b6d0`) and no predicated inbound `bl` sites. The body has one plain
//! `bl` to `0x083d1954` and one predicated indirect `blxne` through the
//! attached object's vtable slot `+0x1c`.
//!
//! # Algorithm
//!
//! Re-plants its derived vtable, conditionally invokes the attached object's
//! virtual release at `this+0x14`, verifies all items are null through
//! `0x083d1954`, then tail-chains into `observable_array_destruct`.
//!
//! Deliberate deviations: host builds use an explicit seam only for the dynamic
//! call. The ported item cleanup is called directly; target builds dispatch the
//! recovered virtual slot directly. Rust does not preserve the predicated `blx`
//! or tail branch.

const VTABLE_WORD: u32 = 0x089a_52e0;
const ATTACHED_OBJECT_WORD: usize = 0x14 / 4;

type ReleaseAttachedObject = unsafe extern "C" fn(*mut u8);

#[cfg(target_os = "none")]
unsafe fn release_attached_object(object: *mut u8) {
    let vtable = unsafe { object.cast::<u32>().read_volatile() as usize as *const u32 };
    let release: ReleaseAttachedObject = unsafe { core::mem::transmute(vtable.add(0x1c / 4).read_volatile() as usize) };
    unsafe { release(object) };
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_release_attached_object(_object: *mut u8) {
    panic!("install observable-array assert-empty destructor host release seam before calling this port")
}

#[cfg(not(target_os = "none"))]
pub static mut OBSERVABLE_ARRAY_ASSERT_EMPTY_DESTRUCT_RELEASE: ReleaseAttachedObject = missing_release_attached_object;


#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn observable_array_assert_empty_destruct(this: *mut u32) -> *mut u32 {
    unsafe {
        this.write_volatile(VTABLE_WORD);
        let attached = this.add(ATTACHED_OBJECT_WORD).read_volatile() as usize as *mut u8;
        #[cfg(target_os = "none")]
        if !attached.is_null() {
            release_attached_object(attached);
        }
        #[cfg(not(target_os = "none"))]
        {
            let release = core::ptr::read_volatile(core::ptr::addr_of!(OBSERVABLE_ARRAY_ASSERT_EMPTY_DESTRUCT_RELEASE));
            if !attached.is_null() {
                release(attached);
            }
            crate::cxx::observable_array_assert_items_null::observable_array_assert_items_null(this.cast());
        }
        #[cfg(target_os = "none")]
        crate::cxx::observable_array_assert_items_null::observable_array_assert_items_null(this.cast());
        crate::cxx::observable_array::observable_array_destruct(this.cast()).cast()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::observable_array_assert_items_null::{
        ObservableArrayAssertItemsNull, OBSERVABLE_ARRAY_ASSERT_ITEMS_NULL_OPS,
    };
    use core::sync::atomic::{AtomicUsize, Ordering};
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static RELEASED: AtomicUsize = AtomicUsize::new(0);
    static EVENT: AtomicUsize = AtomicUsize::new(0);
    static mut EMPTY_CELL: u32 = 0;

    unsafe extern "C" fn record_cell_at(_: *mut ObservableArrayAssertItemsNull, index: i32) -> *mut u32 {
        assert_eq!(index, 0);
        assert_eq!(EVENT.fetch_add(1, Ordering::SeqCst), 1);
        core::ptr::addr_of_mut!(EMPTY_CELL)
    }

    unsafe extern "C" fn record_release(object: *mut u8) {
        RELEASED.store(object as usize, Ordering::SeqCst);
        assert_eq!(EVENT.fetch_add(1, Ordering::SeqCst), 0);
    }

    #[test]
    fn releases_attachment_before_asserting_items_and_base_destruction() {
        let _lock = LOCK.lock();
        unsafe {
            let old_release = OBSERVABLE_ARRAY_ASSERT_EMPTY_DESTRUCT_RELEASE;
            let old_items = OBSERVABLE_ARRAY_ASSERT_ITEMS_NULL_OPS;
            OBSERVABLE_ARRAY_ASSERT_EMPTY_DESTRUCT_RELEASE = record_release;
            OBSERVABLE_ARRAY_ASSERT_ITEMS_NULL_OPS = (record_cell_at, old_items.1);
            let mut object = [0; 6];
            object[ATTACHED_OBJECT_WORD] = 0x1234_5000;
            object[1] = 1;
            object[4] = 1;
            RELEASED.store(0, Ordering::SeqCst);
            EVENT.store(0, Ordering::SeqCst);
            let result = observable_array_assert_empty_destruct(object.as_mut_ptr());
            assert_eq!(result, object.as_mut_ptr());
            assert_eq!(object[0], crate::cxx::observable_array::OBSERVABLE_ARRAY_VTABLE);
            assert_eq!(object[1], 0);
            assert_eq!(object[2], 0);
            assert_eq!(RELEASED.load(Ordering::SeqCst), 0x1234_5000);
            OBSERVABLE_ARRAY_ASSERT_ITEMS_NULL_OPS = old_items;
            OBSERVABLE_ARRAY_ASSERT_EMPTY_DESTRUCT_RELEASE = old_release;
        }
    }

    #[test]
    fn null_attachment_skips_virtual_release_but_still_asserts_items() {
        let _lock = LOCK.lock();
        unsafe {
            let old_release = OBSERVABLE_ARRAY_ASSERT_EMPTY_DESTRUCT_RELEASE;
            let old_items = OBSERVABLE_ARRAY_ASSERT_ITEMS_NULL_OPS;
            OBSERVABLE_ARRAY_ASSERT_EMPTY_DESTRUCT_RELEASE = record_release;
            OBSERVABLE_ARRAY_ASSERT_ITEMS_NULL_OPS = (record_cell_at, old_items.1);
            let mut object = [0; 6];
            object[1] = 1;
            object[4] = 1;
            RELEASED.store(0, Ordering::SeqCst);
            EVENT.store(1, Ordering::SeqCst);
            observable_array_assert_empty_destruct(object.as_mut_ptr());
            assert_eq!(RELEASED.load(Ordering::SeqCst), 0);
            OBSERVABLE_ARRAY_ASSERT_ITEMS_NULL_OPS = old_items;
            OBSERVABLE_ARRAY_ASSERT_EMPTY_DESTRUCT_RELEASE = old_release;
        }
    }
}
