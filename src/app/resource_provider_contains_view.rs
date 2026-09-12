//! Membership probe for the resource provider used by views.
//!
//! `resource_provider_contains_view` — original: `FUN_08124a9c` @
//! **0x08124a9c** (88 bytes; the next function begins at `0x08124af4`).
//!
//! Eight verified, unconditional direct `bl` call sites and no predicated
//! direct calls reach this routine. It calls the provider's vtable slots +8
//! and +12 around an optional membership-index vtable call at +0x4c. The
//! membership call receives a pointer to a stack copy of `view`; its return
//! value denotes membership unless it is exactly `-1` (`0xffff_ffff`).
//!
//! Deliberate host deviation: retailOS stores 32-bit vtable pointers and
//! function words, while host pointers are wider. The host representation uses
//! named pointer fields at the recovered slots; ARM builds load the actual
//! 32-bit object and vtable words directly.

/// Host representation of the recovered provider vtable slots.
#[cfg(not(target_arch = "arm"))]
#[repr(C)]
pub struct ResourceProviderContainsViewVtable {
    pub unused_slots_before_lifecycle: [usize; 2],
    pub begin_membership_query: unsafe extern "C" fn(*mut ResourceProviderContainsView),
    pub end_membership_query: unsafe extern "C" fn(*mut ResourceProviderContainsView),
}

/// Host representation of the provider's first two target words.
#[cfg(not(target_arch = "arm"))]
#[repr(C)]
pub struct ResourceProviderContainsView {
    pub vtable: *const ResourceProviderContainsViewVtable,
    pub membership_index: *mut ResourceProviderMembershipIndex,
}

/// Host representation of the membership index vtable's +0x4c slot.
#[cfg(not(target_arch = "arm"))]
#[repr(C)]
pub struct ResourceProviderMembershipIndexVtable {
    pub unused_slots_before_contains_view: [usize; 19],
    pub contains_view: unsafe extern "C" fn(
        *mut ResourceProviderMembershipIndex,
        *mut *mut u8,
    ) -> i32,
}

/// Host representation of the optional membership index at provider +4.
#[cfg(not(target_arch = "arm"))]
#[repr(C)]
pub struct ResourceProviderMembershipIndex {
    pub vtable: *const ResourceProviderMembershipIndexVtable,
}

/// resource_provider_contains_view — original: `FUN_08124a9c` @ `0x08124a9c`
/// (88 bytes; eight verified unconditional direct `bl` call sites).
///
/// Begins a provider membership query through vtable slot +8. When the
/// optional index at provider +4 is non-NULL, calls its vtable slot +0x4c with
/// a pointer to a local copy of `view`; any result other than `-1` reports
/// membership. It always ends the query through provider vtable slot +12 and
/// returns zero or one. The routine itself has no NULL guard for `provider` or
/// either vtable pointer.
///
/// # Safety
///
/// On ARM, `provider` must reference the retail two-word header with callable
/// vtable slots +8 and +12. Its optional +4 membership-index pointer, when
/// non-NULL, must likewise have a callable +0x4c slot accepting `&mut view`.
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn resource_provider_contains_view(
    provider: *mut ResourceProviderContainsView,
    view: *mut u8,
) -> u32 {
    let provider_vtable = &*(*provider).vtable;
    (provider_vtable.begin_membership_query)(provider);

    let mut view_argument = view;
    let contains = if (*provider).membership_index.is_null() {
        false
    } else {
        let membership_index = (*provider).membership_index;
        let membership_vtable = &*(*membership_index).vtable;
        (membership_vtable.contains_view)(membership_index, &mut view_argument) != -1
    };

    (provider_vtable.end_membership_query)(provider);
    contains as u32
}

/// ARM ABI implementation using the retail 32-bit object layout directly.
#[cfg(target_arch = "arm")]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn resource_provider_contains_view(
    provider: *mut u32,
    view: *mut u8,
) -> u32 {
    type Lifecycle = unsafe extern "C" fn(*mut u32);
    type ContainsView = unsafe extern "C" fn(*mut u32, *mut *mut u8) -> u32;

    let provider_vtable = *(provider as *const *const u32);
    let begin: Lifecycle = core::mem::transmute(*provider_vtable.add(2));
    begin(provider);

    let mut view_argument = view;
    let membership_index = *provider.add(1) as *mut u32;
    let contains = if membership_index.is_null() {
        false
    } else {
        let membership_vtable = *(membership_index as *const *const u32);
        let contains_view: ContainsView = core::mem::transmute(*membership_vtable.add(19));
        contains_view(membership_index, &mut view_argument) != u32::MAX
    };

    let end: Lifecycle = core::mem::transmute(*provider_vtable.add(3));
    end(provider);
    contains as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicI32, AtomicU32, AtomicUsize, Ordering};
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static QUERY_PHASE: AtomicU32 = AtomicU32::new(0);
    static MEMBERSHIP_STATUS: AtomicI32 = AtomicI32::new(-1);
    static OBSERVED_VIEW: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn begin(provider: *mut ResourceProviderContainsView) {
        assert!(!provider.is_null());
        assert_eq!(QUERY_PHASE.swap(1, Ordering::SeqCst), 0);
    }

    unsafe extern "C" fn contains(
        membership_index: *mut ResourceProviderMembershipIndex,
        view: *mut *mut u8,
    ) -> i32 {
        assert!(!membership_index.is_null());
        assert_eq!(QUERY_PHASE.swap(2, Ordering::SeqCst), 1);
        OBSERVED_VIEW.store(*view as usize, Ordering::SeqCst);
        MEMBERSHIP_STATUS.load(Ordering::SeqCst)
    }

    unsafe extern "C" fn end(provider: *mut ResourceProviderContainsView) {
        assert!(!provider.is_null());
        let phase = QUERY_PHASE.load(Ordering::SeqCst);
        assert!(phase == 1 || phase == 2);
        QUERY_PHASE.store(3, Ordering::SeqCst);
    }

    static PROVIDER_VTABLE: ResourceProviderContainsViewVtable =
        ResourceProviderContainsViewVtable {
            unused_slots_before_lifecycle: [0; 2],
            begin_membership_query: begin,
            end_membership_query: end,
        };
    static MEMBERSHIP_VTABLE: ResourceProviderMembershipIndexVtable =
        ResourceProviderMembershipIndexVtable {
            unused_slots_before_contains_view: [0; 19],
            contains_view: contains,
        };

    #[test]
    fn membership_result_is_false_only_for_minus_one() {
        let _guard = TEST_LOCK.lock();
        let mut membership_index = ResourceProviderMembershipIndex {
            vtable: &MEMBERSHIP_VTABLE,
        };
        let mut provider = ResourceProviderContainsView {
            vtable: &PROVIDER_VTABLE,
            membership_index: &mut membership_index,
        };
        let mut view = 0u8;

        for (status, expected) in [(-1, 0), (0, 1), (-2, 1), (i32::MAX, 1)] {
            QUERY_PHASE.store(0, Ordering::SeqCst);
            MEMBERSHIP_STATUS.store(status, Ordering::SeqCst);
            OBSERVED_VIEW.store(0, Ordering::SeqCst);

            assert_eq!(
                unsafe { resource_provider_contains_view(&mut provider, &mut view) },
                expected
            );
            assert_eq!(QUERY_PHASE.load(Ordering::SeqCst), 3);
            assert_eq!(OBSERVED_VIEW.load(Ordering::SeqCst), &mut view as *mut u8 as usize);
        }
    }

    #[test]
    fn null_membership_index_skips_probe_but_balances_lifecycle() {
        let _guard = TEST_LOCK.lock();
        let mut provider = ResourceProviderContainsView {
            vtable: &PROVIDER_VTABLE,
            membership_index: core::ptr::null_mut(),
        };

        QUERY_PHASE.store(0, Ordering::SeqCst);
        OBSERVED_VIEW.store(usize::MAX, Ordering::SeqCst);
        assert_eq!(
            unsafe { resource_provider_contains_view(&mut provider, core::ptr::null_mut()) },
            0
        );
        assert_eq!(QUERY_PHASE.load(Ordering::SeqCst), 3);
        assert_eq!(OBSERVED_VIEW.load(Ordering::SeqCst), usize::MAX);
    }
}
