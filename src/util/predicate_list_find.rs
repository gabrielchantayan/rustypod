//! predicate_list_find_matching_payload — original: `FUN_082435dc` @
//! **0x082435dc** (128 bytes, `0x082435dc..0x08243658`; the next separately
//! linked function starts with `push {r4-r10,lr}` at `0x0824365c`).
//!
//! A complete decode of every ARM B/BL immediate in `osos.dec` finds six direct
//! inbound call sites, all unconditional `bl`: 0x082409d8, 0x0824197c,
//! 0x08241990, 0x082419a4, 0x08242c70, and 0x08253c0c. No predicated call
//! reaches this body. The function selects a kind-specific predicate through
//! the ported `predicate_for_kind`, walks the list at `list + 0x10`, and
//! invokes that predicate only for nodes whose byte kind at `+0xc8` equals the
//! requested full-width kind. The first accepted node yields its `+0xbc` word,
//! either directly when bit 1 of `+0xc4` is set or as an offset from `list`.
//!
//! Deliberate deviations: none on the target. Host tests retain a local
//! selector seam because their predicate objects live at fixture addresses;
//! target builds directly call the ported selector. Host predicate-vtable
//! pointers are native-width, while target pointers remain four-byte `repr(C)`
//! fields.

use core::ptr;

/// The predicate object selected by `FUN_082432c8`.
#[repr(C)]
struct PredicateObject {
    vtable: *const PredicateVtable,
}

/// The only predicate-vtable member observed by this function.
#[repr(C)]
struct PredicateVtable {
    _unknown: usize,
    accepts: NodePredicate,
}

/// Predicate ABI: selector object, node's `+0x08` data, and caller query.
type NodePredicate = unsafe extern "C" fn(*mut PredicateObject, *mut u8, *mut u8) -> u32;

/// The list's first-node target word is at `+0x10`.
#[repr(C)]
struct PredicateList {
    _unknown_00: [u32; 4],
    first: u32,
}

/// Target-width node fields read by the original. `u32` pointer words retain
/// their 32-bit target layout under host tests.
#[repr(C)]
struct PredicateNode {
    _unknown_00: u32,
    next: u32,
    predicate_data: [u32; 45],
    payload: u32,
    _unknown_c0: u32,
    payload_flags: u32,
    kind: u8,
}

/// Stock selector which maps a kind to its runtime predicate object.
type PredicateForKind = unsafe extern "C" fn(u32) -> *mut PredicateObject;

#[cfg(target_os = "none")]
unsafe fn predicate_for_kind(kind: u32) -> *mut PredicateObject {
    crate::util::predicate_for_kind::predicate_for_kind(kind) as usize as *mut PredicateObject
}

#[cfg(all(not(target_os = "none"), test))]
static mut PREDICATE_FOR_KIND: PredicateForKind = missing_predicate_for_kind;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_predicate_for_kind(_kind: u32) -> *mut PredicateObject {
    panic!("predicate_list_find_matching_payload requires selector 0x082432c8")
}

#[cfg(all(not(target_os = "none"), test))]
unsafe fn predicate_for_kind(kind: u32) -> *mut PredicateObject {
    unsafe { PREDICATE_FOR_KIND(kind) }
}

#[cfg(all(not(target_os = "none"), not(test)))]
unsafe fn predicate_for_kind(kind: u32) -> *mut PredicateObject {
    unsafe { missing_predicate_for_kind(kind) }
}

/// Returns the first predicate-accepted node payload for `kind`, or zero.
///
/// # Safety
///
/// `list` must name a readable target-width list through `+0x10`; every
/// nonzero node link must name a readable node through `+0xc8`. The selected
/// predicate object, its vtable, and every predicate callback must be valid.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.predicate_list_find_matching_payload")]
pub unsafe extern "C" fn predicate_list_find_matching_payload(
    list: *mut u8,
    kind: u32,
    query: *mut u8,
) -> u32 {
    let predicate = unsafe { predicate_for_kind(kind) };
    let list_fields = list.cast::<PredicateList>();
    let mut node = unsafe { ptr::addr_of!((*list_fields).first).read() as usize as *mut PredicateNode };

    while !node.is_null() {
        if unsafe { ptr::addr_of!((*node).kind).read() as u32 } == kind {
            let vtable = unsafe { ptr::addr_of!((*predicate).vtable).read() };
            let accepts = unsafe { ptr::addr_of!((*vtable).accepts).read() };
            let predicate_data = unsafe {
                node.cast::<u8>()
                    .add(core::mem::offset_of!(PredicateNode, predicate_data))
            };

            if unsafe { accepts(predicate, predicate_data, query) } != 0 {
                let payload = unsafe { ptr::addr_of!((*node).payload).read() };
                let flags = unsafe { ptr::addr_of!((*node).payload_flags).read() };
                return if flags & 2 == 0 {
                    (list as usize as u32).wrapping_add(payload)
                } else {
                    payload
                };
            }
        }

        node = unsafe { ptr::addr_of!((*node).next).read() as usize as *mut PredicateNode };
    }

    0
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::{LazyLock, Mutex};

    const SLAB_LEN: usize = 0x1000;
    const FIRST_NODE_OFFSET: usize = 0x100;
    const SECOND_NODE_OFFSET: usize = 0x300;
    const QUERY_OFFSET: usize = 0x800;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static SLAB: LazyLock<usize> = LazyLock::new(|| {
        try_map_u32_slab(hints::PREDICATE_LIST_FIND, SLAB_LEN).map_or(0, |slab| slab as usize)
    });
    static mut SELECTED_PREDICATE: *mut PredicateObject = ptr::null_mut();
    static mut SELECTOR_KIND: u32 = 0;
    static mut SELECTOR_CALLS: u32 = 0;
    static mut PREDICATE_DATA: *mut u8 = ptr::null_mut();
    static mut PREDICATE_QUERY: *mut u8 = ptr::null_mut();
    static mut PREDICATE_CALLS: u32 = 0;
    static mut REJECT_FIRST: bool = false;

    fn slab() -> Option<*mut u8> {
        let address = *SLAB;
        (address != 0).then_some(address as *mut u8)
    }

    fn target_word(pointer: *mut u8) -> u32 {
        u32::try_from(pointer as usize).expect("slab pointer must fit target word")
    }

    unsafe extern "C" fn select_predicate(kind: u32) -> *mut PredicateObject {
        unsafe {
            SELECTOR_KIND = kind;
            SELECTOR_CALLS += 1;
            SELECTED_PREDICATE
        }
    }

    unsafe extern "C" fn record_predicate(
        _predicate: *mut PredicateObject,
        data: *mut u8,
        query: *mut u8,
    ) -> u32 {
        unsafe {
            PREDICATE_DATA = data;
            PREDICATE_QUERY = query;
            PREDICATE_CALLS += 1;
            if REJECT_FIRST && PREDICATE_CALLS == 1 { 0 } else { 1 }
        }
    }

    struct SelectorGuard {
        old: PredicateForKind,
    }

    impl SelectorGuard {
        unsafe fn install() -> Self {
            let old = unsafe { PREDICATE_FOR_KIND };
            unsafe { PREDICATE_FOR_KIND = select_predicate };
            Self { old }
        }
    }

    impl Drop for SelectorGuard {
        fn drop(&mut self) {
            unsafe { PREDICATE_FOR_KIND = self.old };
        }
    }

    unsafe fn reset(slab: *mut u8, object: *mut PredicateObject) {
        unsafe {
            ptr::write_bytes(slab, 0, SLAB_LEN);
            SELECTED_PREDICATE = object;
            SELECTOR_KIND = 0;
            SELECTOR_CALLS = 0;
            PREDICATE_DATA = ptr::null_mut();
            PREDICATE_QUERY = ptr::null_mut();
            PREDICATE_CALLS = 0;
            REJECT_FIRST = false;
        }
    }

    unsafe fn node(slab: *mut u8, offset: usize) -> *mut PredicateNode {
        unsafe { slab.add(offset).cast::<PredicateNode>() }
    }

    #[test]
    fn selects_the_requested_predicate_and_returns_relative_payload() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some(slab) = slab() else {
            assert!(note_missing_u32_fixture("util/predicate_list_find"));
            return;
        };
        let vtable = PredicateVtable { _unknown: 0, accepts: record_predicate };
        let mut object = PredicateObject { vtable: &vtable };
        let _selector = unsafe { SelectorGuard::install() };
        unsafe { reset(slab, &mut object) };

        let first = unsafe { node(slab, FIRST_NODE_OFFSET) };
        let second = unsafe { node(slab, SECOND_NODE_OFFSET) };
        unsafe {
            ptr::write(first, PredicateNode {
                _unknown_00: 0,
                next: target_word(second.cast()),
                predicate_data: [0; 45],
                payload: 0,
                _unknown_c0: 0,
                payload_flags: 0,
                kind: 2,
            });
            ptr::write(second, PredicateNode {
                _unknown_00: 0,
                next: 0,
                predicate_data: [0; 45],
                payload: 0x6c0,
                _unknown_c0: 0,
                payload_flags: 0,
                kind: 3,
            });
            ptr::addr_of_mut!((*slab.cast::<PredicateList>()).first).write(target_word(first.cast()));
        }
        let query = unsafe { slab.add(QUERY_OFFSET) };

        assert_eq!(unsafe { predicate_list_find_matching_payload(slab, 3, query) }, target_word(unsafe { slab.add(0x6c0) }));
        unsafe {
            assert_eq!(SELECTOR_KIND, 3);
            assert_eq!(SELECTOR_CALLS, 1);
            assert_eq!(PREDICATE_CALLS, 1);
            assert_eq!(PREDICATE_DATA, second.cast::<u8>().add(core::mem::offset_of!(PredicateNode, predicate_data)));
            assert_eq!(PREDICATE_QUERY, query);
        }
    }

    #[test]
    fn rejected_match_advances_to_later_node_and_preserves_absolute_payload() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some(slab) = slab() else {
            assert!(note_missing_u32_fixture("util/predicate_list_find"));
            return;
        };
        let vtable = PredicateVtable { _unknown: 0, accepts: record_predicate };
        let mut object = PredicateObject { vtable: &vtable };
        let _selector = unsafe { SelectorGuard::install() };
        unsafe { reset(slab, &mut object) };
        unsafe { REJECT_FIRST = true };

        let first = unsafe { node(slab, FIRST_NODE_OFFSET) };
        let second = unsafe { node(slab, SECOND_NODE_OFFSET) };
        unsafe {
            ptr::write(first, PredicateNode {
                _unknown_00: 0,
                next: target_word(second.cast()),
                predicate_data: [0; 45],
                payload: 0x100,
                _unknown_c0: 0,
                payload_flags: 0,
                kind: 4,
            });
            ptr::write(second, PredicateNode {
                _unknown_00: 0,
                next: 0,
                predicate_data: [0; 45],
                payload: 0xdead_beef,
                _unknown_c0: 0,
                payload_flags: 2,
                kind: 4,
            });
            ptr::addr_of_mut!((*slab.cast::<PredicateList>()).first).write(target_word(first.cast()));
        }

        assert_eq!(unsafe { predicate_list_find_matching_payload(slab, 4, ptr::null_mut()) }, 0xdead_beef);
        assert_eq!(unsafe { PREDICATE_CALLS }, 2);
    }

    #[test]
    fn empty_and_out_of_byte_range_kinds_return_zero_without_predicate_call() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some(slab) = slab() else {
            assert!(note_missing_u32_fixture("util/predicate_list_find"));
            return;
        };
        let vtable = PredicateVtable { _unknown: 0, accepts: record_predicate };
        let mut object = PredicateObject { vtable: &vtable };
        let _selector = unsafe { SelectorGuard::install() };
        unsafe { reset(slab, &mut object) };

        assert_eq!(unsafe { predicate_list_find_matching_payload(slab, 6, ptr::null_mut()) }, 0);
        unsafe {
            assert_eq!(SELECTOR_CALLS, 1);
            assert_eq!(PREDICATE_CALLS, 0);
        }

        let first = unsafe { node(slab, FIRST_NODE_OFFSET) };
        unsafe {
            ptr::write(first, PredicateNode {
                _unknown_00: 0,
                next: 0,
                predicate_data: [0; 45],
                payload: 0x100,
                _unknown_c0: 0,
                payload_flags: 2,
                kind: 6,
            });
            ptr::addr_of_mut!((*slab.cast::<PredicateList>()).first).write(target_word(first.cast()));
            SELECTOR_CALLS = 0;
        }

        assert_eq!(unsafe { predicate_list_find_matching_payload(slab, 0x106, ptr::null_mut()) }, 0);
        unsafe {
            assert_eq!(SELECTOR_KIND, 0x106);
            assert_eq!(SELECTOR_CALLS, 1);
            assert_eq!(PREDICATE_CALLS, 0);
        }
    }
}
