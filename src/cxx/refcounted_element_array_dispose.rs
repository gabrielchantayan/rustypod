//! `refcounted_element_array_dispose` — retailOS `FUN_083d1e30` @
//! `0x083d1e30`.
//!
//! ## Verified extent and calls
//!
//! Raw `osos.dec` words establish the 96-byte body `0x083d1e30..0x083d1e8f`:
//! the next independently entered function starts at `0x083d1e90`. It has two
//! plain direct `bl` calls — [`refcounted_body_release_retain_count`] at
//! `0x0839d498` and [`operator_delete`] at `0x082aad24` — no predicated direct
//! `bl` calls, and one indirect `blx` through vtable slot `+0x40`. Raw A32
//! branch decoding finds two incoming plain `bl` calls and no predicated direct
//! callers.
//!
//! ## Algorithm
//!
//! If byte `+0x10` is nonzero, visit signed indices `[0, count)`. The vtable
//! accessor at `+0x40` returns a cell whose first target word is an element.
//! Each non-NULL element releases its embedded refcounted-body slot at `+0x04`,
//! then is tag-2 deleted.
//!
//! ## Deliberate deviations
//!
//! Target pointers and vtables remain 32-bit words. Host fixtures use typed
//! seams and a widened embedded body pointer because native function and data
//! pointers cannot inhabit retailOS u32 fields.

use crate::cxx::handle::refcounted_body_release_retain_count;
#[cfg(not(target_os = "none"))]
use crate::cxx::handle::RefcountedBody;
use crate::heap::veneers::operator_delete;

/// Indexed accessor at the target vtable's `+0x40` slot.
pub type RefcountedElementArrayAt = unsafe extern "C" fn(*mut RefcountedElementArrayDispose, i32) -> *mut u32;

/// Target-layout collection prefix read by the disposal walk.
#[repr(C)]
pub struct RefcountedElementArrayDispose {
    pub vtable: u32,
    pub count: i32,
    pub unresolved_08_0f: [u8; 8],
    pub enabled: u8,
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn dispose_element(element: *mut u8) {
    refcounted_body_release_retain_count(element.add(4).cast());
    operator_delete(element);
}

#[cfg(not(target_os = "none"))]
pub type RefcountedElementRelease = unsafe extern "C" fn(*mut *mut RefcountedBody);
#[cfg(not(target_os = "none"))]
pub type RefcountedElementDelete = unsafe extern "C" fn(*mut u8);

#[cfg(not(target_os = "none"))]
pub static mut REFCOUNTED_ELEMENT_ARRAY_AT: RefcountedElementArrayAt = missing_element_at;
#[cfg(not(target_os = "none"))]
pub static mut REFCOUNTED_ELEMENT_RELEASE: RefcountedElementRelease = refcounted_body_release_retain_count;
#[cfg(not(target_os = "none"))]
pub static mut REFCOUNTED_ELEMENT_DELETE: RefcountedElementDelete = operator_delete;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_element_at(
    _this: *mut RefcountedElementArrayDispose,
    _index: i32,
) -> *mut u32 {
    panic!("refcounted_element_array_dispose requires its vtable accessor")
}

/// Host element representation: only the observed target fields are modeled.
#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostRefcountedElement {
    pub target_prefix: u32,
    pub body: *mut RefcountedBody,
}

/// Host collection representation preserving all observed target offsets.
#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostRefcountedElementArrayDispose {
    pub target_vtable: u32,
    pub count: i32,
    pub unresolved_08_0f: [u8; 8],
    pub enabled: u8,
}

/// Releases and deletes every occupied element while enabled.
///
/// # Safety
///
/// `this` must identify the observed collection layout. Its enabled vtable
/// accessor must return readable cells, and every non-NULL element must own a
/// valid embedded refcounted-body slot and heap allocation.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn refcounted_element_array_dispose(
    this: *mut RefcountedElementArrayDispose,
) {
    #[cfg(target_os = "none")]
    {
        let base = this.cast::<u8>();
        if base.add(0x10).read_volatile() == 0 {
            return;
        }
        let count = base.add(4).cast::<i32>().read_volatile();
        let vtable = base.cast::<u32>().read_volatile() as usize;
        let at: RefcountedElementArrayAt = core::mem::transmute((vtable + 0x40) as *const ());
        let mut index = 0;
        while index < count {
            let element = at(this, index).read_volatile() as usize as *mut u8;
            if !element.is_null() {
                dispose_element(element);
            }
            index += 1;
        }
    }

    #[cfg(not(target_os = "none"))]
    {
        let host = this.cast::<HostRefcountedElementArrayDispose>();
        if (*host).enabled == 0 {
            return;
        }
        let count = (*host).count;
        let mut index = 0;
        while index < count {
            let at = core::ptr::read_volatile(core::ptr::addr_of!(REFCOUNTED_ELEMENT_ARRAY_AT));
            let element = at(this, index).read_volatile() as usize as *mut HostRefcountedElement;
            if !element.is_null() {
                let release = core::ptr::read_volatile(core::ptr::addr_of!(REFCOUNTED_ELEMENT_RELEASE));
                release(core::ptr::addr_of_mut!((*element).body));
                let delete = core::ptr::read_volatile(core::ptr::addr_of!(REFCOUNTED_ELEMENT_DELETE));
                delete(element.cast());
            }
            index += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut INDEXES: [i32; 4] = [0; 4];
    static mut INDEX_COUNT: usize = 0;
    static mut CELLS: [u32; 4] = [0; 4];
    static mut RELEASED: [usize; 4] = [0; 4];
    static mut RELEASE_COUNT: usize = 0;
    static mut DELETED: [usize; 4] = [0; 4];
    static mut DELETE_COUNT: usize = 0;

    unsafe extern "C" fn element_at(_: *mut RefcountedElementArrayDispose, index: i32) -> *mut u32 {
        INDEXES[INDEX_COUNT] = index;
        INDEX_COUNT += 1;
        CELLS.as_mut_ptr().add(index as usize)
    }

    unsafe extern "C" fn record_release(slot: *mut *mut RefcountedBody) {
        RELEASED[RELEASE_COUNT] = slot as usize;
        RELEASE_COUNT += 1;
    }

    unsafe extern "C" fn record_delete(element: *mut u8) {
        DELETED[DELETE_COUNT] = element as usize;
        DELETE_COUNT += 1;
    }

    fn fixture(enabled: u8, count: i32) -> HostRefcountedElementArrayDispose {
        HostRefcountedElementArrayDispose { target_vtable: 0, count, unresolved_08_0f: [0; 8], enabled }
    }

    #[test]
    fn skips_disabled_nonpositive_and_empty_cells() {
        let _lock = LOCK.lock();
        unsafe {
            REFCOUNTED_ELEMENT_ARRAY_AT = element_at;
            REFCOUNTED_ELEMENT_RELEASE = record_release;
            REFCOUNTED_ELEMENT_DELETE = record_delete;
            INDEX_COUNT = 0; RELEASE_COUNT = 0; DELETE_COUNT = 0; CELLS = [0; 4];
            refcounted_element_array_dispose((&mut fixture(0, 2) as *mut HostRefcountedElementArrayDispose).cast());
            refcounted_element_array_dispose((&mut fixture(1, 0) as *mut HostRefcountedElementArrayDispose).cast());
            refcounted_element_array_dispose((&mut fixture(1, -1) as *mut HostRefcountedElementArrayDispose).cast());
            refcounted_element_array_dispose((&mut fixture(1, 1) as *mut HostRefcountedElementArrayDispose).cast());
            assert_eq!(INDEX_COUNT, 1);
            assert_eq!(RELEASE_COUNT, 0);
            assert_eq!(DELETE_COUNT, 0);
        }
    }

    #[test]
    fn releases_embedded_slots_then_deletes_in_index_order() {
        let _lock = LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::CXX_REFCOUNTED_ELEMENT_ARRAY_DISPOSE, 0x1000) else {
            return;
        };
        unsafe {
            let first = slab.cast::<HostRefcountedElement>();
            let second = first.add(1);
            first.write(HostRefcountedElement { target_prefix: 0, body: core::ptr::null_mut() });
            second.write(HostRefcountedElement { target_prefix: 0, body: core::ptr::null_mut() });
            REFCOUNTED_ELEMENT_ARRAY_AT = element_at;
            REFCOUNTED_ELEMENT_RELEASE = record_release;
            REFCOUNTED_ELEMENT_DELETE = record_delete;
            CELLS = [first as usize as u32, 0, second as usize as u32, 0];
            INDEX_COUNT = 0; RELEASE_COUNT = 0; DELETE_COUNT = 0;
            refcounted_element_array_dispose((&mut fixture(1, 3) as *mut HostRefcountedElementArrayDispose).cast());
            assert_eq!(&INDEXES[..INDEX_COUNT], &[0, 1, 2]);
            assert_eq!(&RELEASED[..RELEASE_COUNT], &[core::ptr::addr_of_mut!((*first).body) as usize, core::ptr::addr_of_mut!((*second).body) as usize]);
            assert_eq!(&DELETED[..DELETE_COUNT], &[first as usize, second as usize]);
        }
    }
}
