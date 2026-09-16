//! `refcounted_vtable_release` — original: `FUN_0838d878` @ `0x0838d878`
//! (40 bytes; four verified inbound direct `bl` sites: four plain and zero
//! predicated).
//!
//! Raw ARM establishes the exact body at `0x0838d878..0x0838d89f`; the next
//! real function begins at `0x0838d8a4` with `push {r4-r11,lr}`. It decrements
//! the target-layout object's word at `+0x04`. A nonzero result tail-returns;
//! zero first performs the otherwise-unused load from `owner + 0x40`, then
//! tail-dispatches vtable slot `+0x10` with the object as its only argument.
//! The four inbound direct branches are at `0x082beb10`, `0x083752d8`,
//! `0x0838ad84`, and `0x0838ae40`.
//!
//! Deliberate host deviation: the host vtable holds a native-width function
//! pointer, so its slot does not share ARM's four-byte physical offset. Target
//! dispatch reads the raw 32-bit vtable and slot words. The owner load is
//! volatile in both builds because it is architecturally observable despite
//! its discarded value.

const REFCOUNT_WORD: usize = 1;
const OWNER_OBSERVED_WORD: usize = 0x40 / 4;
const DESTROY_SLOT_WORD: usize = 0x10 / 4;

/// Releases one reference and tail-dispatches the object's slot `+0x10` when
/// its count reaches zero.
///
/// # Safety
/// `owner` must be readable at target offset `+0x40`; `object` must address a
/// target-layout vtable word and reference count, and a zero count after the
/// decrement requires a callable vtable slot `+0x10`.
#[cfg(target_os = "none")]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn refcounted_vtable_release(owner: *mut u32, object: *mut u32) {
    let reference_count = unsafe { object.add(REFCOUNT_WORD).read_volatile() };
    let remaining = reference_count.wrapping_sub(1);
    unsafe { object.add(REFCOUNT_WORD).write_volatile(remaining) };
    if remaining != 0 {
        return;
    }

    let _ = unsafe { owner.add(OWNER_OBSERVED_WORD).read_volatile() };
    let vtable = unsafe { object.read_volatile() } as *const u32;
    let destroy_address = unsafe { vtable.add(DESTROY_SLOT_WORD).read_volatile() };
    let destroy: unsafe extern "C" fn(*mut u32) = unsafe { core::mem::transmute(destroy_address as usize) };
    unsafe { destroy(object) };
}

/// Host model of the only two object fields decoded by this routine.
#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct RefcountedVtableObject {
    pub vtable: *const RefcountedVtable,
    pub reference_count: u32,
}

/// Host model of the vtable's destruction slot.
#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct RefcountedVtable {
    pub slots_before_destroy: [Option<unsafe extern "C" fn()>; DESTROY_SLOT_WORD],
    pub destroy: unsafe extern "C" fn(*mut RefcountedVtableObject),
}

#[cfg(not(target_os = "none"))]
#[inline(never)]
pub unsafe extern "C" fn refcounted_vtable_release(
    owner: *mut u32,
    object: *mut RefcountedVtableObject,
) {
    let reference_count = unsafe { (*object).reference_count };
    let remaining = reference_count.wrapping_sub(1);
    unsafe { (*object).reference_count = remaining };
    if remaining != 0 {
        return;
    }

    let _ = unsafe { owner.add(OWNER_OBSERVED_WORD).read_volatile() };
    let destroy = unsafe { (*(*object).vtable).destroy };
    unsafe { destroy(object) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;
    use core::sync::atomic::{AtomicUsize, Ordering};

    static DESTROY_CALLS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn record_destroy(_object: *mut RefcountedVtableObject) {
        DESTROY_CALLS.fetch_add(1, Ordering::SeqCst);
    }

    const VTABLE: RefcountedVtable = RefcountedVtable {
        slots_before_destroy: [None; DESTROY_SLOT_WORD],
        destroy: record_destroy,
    };

    fn owner_words() -> [u32; OWNER_OBSERVED_WORD + 1] {
        [0; OWNER_OBSERVED_WORD + 1]
    }

    #[test]
    fn keeps_object_alive_above_zero() {
        DESTROY_CALLS.store(0, Ordering::SeqCst);
        let mut owner = owner_words();
        let mut object = RefcountedVtableObject { vtable: &VTABLE, reference_count: 2 };

        unsafe { refcounted_vtable_release(owner.as_mut_ptr(), &mut object) };

        assert_eq!(object.reference_count, 1);
        assert_eq!(DESTROY_CALLS.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn dispatches_destroy_at_zero() {
        DESTROY_CALLS.store(0, Ordering::SeqCst);
        let mut owner = owner_words();
        let mut object = RefcountedVtableObject { vtable: &VTABLE, reference_count: 1 };

        unsafe { refcounted_vtable_release(owner.as_mut_ptr(), &mut object) };

        assert_eq!(object.reference_count, 0);
        assert_eq!(DESTROY_CALLS.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn wraps_zero_count_without_dispatching() {
        DESTROY_CALLS.store(0, Ordering::SeqCst);
        let mut owner = owner_words();
        let mut object = RefcountedVtableObject { vtable: ptr::null(), reference_count: 0 };

        unsafe { refcounted_vtable_release(owner.as_mut_ptr(), &mut object) };

        assert_eq!(object.reference_count, u32::MAX);
        assert_eq!(DESTROY_CALLS.load(Ordering::SeqCst), 0);
    }
}
