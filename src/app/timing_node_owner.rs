//! Teardown of an owner's three timing-wheel nodes.

use super::animation::timing_wheel_remove_global;

#[cfg(not(target_os = "none"))]
static HOST_DESTRUCTOR: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

unsafe fn delete_node(node: *mut u32) {
    #[cfg(target_os = "none")]
    let entry = ((*node as usize as *const u32).add(1)).read_volatile() as usize;
    // Same host dispatch model as refcounted_value: ARM function pointers
    // cannot represent native 64-bit callbacks. Target dispatch has no seam.
    #[cfg(not(target_os = "none"))]
    let entry = HOST_DESTRUCTOR.load(core::sync::atomic::Ordering::SeqCst);
    let destructor: unsafe extern "C" fn(*mut u32) = core::mem::transmute(entry);
    destructor(node);
}

/// timing_node_owner_destroy — FUN_081446cc @ 0x081446cc, 100 bytes.
/// Raw words span [0x081446cc, 0x08144730); the next function pushes r4-r8.
/// Whole-image ARM decoding finds two incoming plain BLs (0x08145e38,
/// 0x081463a0), zero predicated BLs. Outgoing: three plain BLs to the verified
/// timing_wheel_remove_global @ 0x08273a2c, two BLXNEs and a final BXNE tail
/// dispatch through deleting-destructor vtable slot +4.
///
/// Unlink owner words 49, 50, 51 in ascending order, then reload and delete
/// each non-null node in reverse order. Do not clear slots; callbacks may
/// change later slots, so loads must not be hoisted across calls. Initial
/// slots must all hold live nodes (unlink has no null guard); each node must
/// have the six-word wheel prefix and a valid deleting-destructor vtable.
/// Owner storage must contain at least 52 aligned words and remain live
/// throughout callbacks. No meaningful return value is specified.
/// Deliberate deviation: host dispatch uses a native callback instead of
/// 32-bit ARM vtable addresses, following the existing refcounted-value model.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn timing_node_owner_destroy(owner: *mut u32) {
    for slot in 49..52 {
        let node = owner.add(slot).read_volatile() as usize as *mut u32;
        timing_wheel_remove_global(node);
    }
    for slot in (49..52).rev() {
        let node = owner.add(slot).read_volatile() as usize as *mut u32;
        if !node.is_null() {
            delete_node(node);
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use super::super::animation::scheduler_table;
    use crate::testing::{try_map_u32_slab, SCHEDULER_TABLE_TEST_LOCK};
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::LazyLock;

    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(crate::testing::hints::TIMING_NODE_OWNER_DESTROY, 0x1000)
            .map(|p| p as usize)
    });
    static EVENTS: [AtomicUsize; 3] = [const { AtomicUsize::new(0) }; 3];
    static EVENT_COUNT: AtomicUsize = AtomicUsize::new(0);
    static OWNER: AtomicUsize = AtomicUsize::new(0);
    static MUTATE: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn deleting_destructor(node: *mut u32) {
        let owner = OWNER.load(Ordering::SeqCst) as *mut u32;
        // All three must already be unlinked before the first destruction.
        for i in 0..3 {
            assert_eq!(*owner.add(64 + i * 8 + 5) & 1, 0);
            assert_eq!(*scheduler_table().add(i), 0);
        }
        let index = EVENT_COUNT.fetch_add(1, Ordering::SeqCst);
        EVENTS[index].store(node as usize, Ordering::SeqCst);
        if MUTATE.swap(0, Ordering::SeqCst) != 0 {
            *owner.add(50) = 0;
            *owner.add(49) = *owner.add(51);
        }
    }

    #[test]
    fn unlink_before_reverse_delete_and_reload_callback_mutations() {
        let _lock = SCHEDULER_TABLE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let Some(base) = *SLAB else {
            crate::testing::note_missing_u32_fixture("timing_node_owner_destroy");
            return;
        };
        unsafe {
            let owner = base as *mut u32;
            OWNER.store(base, Ordering::SeqCst);
            HOST_DESTRUCTOR.store(deleting_destructor as *const () as usize, Ordering::SeqCst);
            for mutate in [false, true] {
                core::ptr::write_bytes(owner, 0, 128);
                for i in 0..3 {
                    let node = owner.add(64 + i * 8);
                    *owner.add(49 + i) = node as usize as u32;
                    *node.add(2) = (i + 1) as u32;
                    *node.add(5) = 0xa5;
                    *scheduler_table().add(i) = node as usize as u32;
                }
                let slots = [*owner.add(49), *owner.add(50), *owner.add(51)];
                EVENT_COUNT.store(0, Ordering::SeqCst);
                MUTATE.store(mutate as usize, Ordering::SeqCst);
                timing_node_owner_destroy(owner);
                let expected = if mutate {
                    std::vec![slots[2] as usize, slots[2] as usize]
                } else {
                    std::vec![slots[2] as usize, slots[1] as usize, slots[0] as usize]
                };
                assert_eq!(EVENT_COUNT.load(Ordering::SeqCst), expected.len());
                for (event, expected) in EVENTS.iter().zip(expected) {
                    assert_eq!(event.load(Ordering::SeqCst), expected);
                }
                for i in 0..3 {
                    assert_eq!(*owner.add(64 + i * 8 + 5), 0xa4);
                }
                assert_eq!(*owner.add(51), slots[2]);
                assert_eq!(*owner.add(50), if mutate { 0 } else { slots[1] });
                assert_eq!(*owner.add(49), if mutate { slots[2] } else { slots[0] });
            }
            HOST_DESTRUCTOR.store(0, Ordering::SeqCst);
        }
    }
}
