//! Activate a collection entry — FUN_08211bac @ 0x08211bac.
//! True extent: 44 bytes, through 0x08211bd7; next entered prologue 0x08211bd8.
//! Raw A32 decoding: two inbound plain BLs, one outbound plain BL, no
//! predicated BLs. If entry state is 2, append its value to context+0x50
//! using synchronized_list_append, then write state 1 after the call.
//! Deviations: reuse the typed entry layout (pointer fields widen on hosts);
//! omit incidental r0 contents, ignored by both callers. No NULL guards.

use super::collection_entries_retire::RetirableEntry;
use crate::util::synchronized_list_append::synchronized_list_append;

/// # Safety
/// `entry` is a live writable entry. In state 2, `context+0x50` must expose
/// the synchronized-list owner's aligned target-width words and satisfy
/// the append callee's allocation, mutex, and cleanup contracts.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn collection_entry_activate(context: *mut u8, entry: *mut RetirableEntry) {
    if (*entry).state != 2 { return; }
    synchronized_list_append(context.add(0x50).cast(), (*entry).value);
    (*entry).state = 1;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::synchronized_list_append::{SynchronizedListOps, SYNCHRONIZED_LIST_OPS, TEST_LOCK};
    static mut NODE: [u32; 2] = [0; 2];
    static mut ENTRY: *mut RetirableEntry = core::ptr::null_mut();
    unsafe extern "C" fn allocate(_: usize) -> *mut u32 {
        core::ptr::addr_of_mut!(NODE).cast()
    }
    unsafe extern "C" fn append(list: *mut u32, node: *mut u32) {
        // State must remain pending during the append, not be committed early.
        assert_eq!((*ENTRY).state, 2);
        list.write(node.add(1).read());
        list.add(1).write(list.add(1).read() + 1);
    }
    unsafe extern "C" fn cleanup(_: *mut u32) {}
    unsafe extern "C" fn mutex(_: *mut u32) {}
    struct Reset(SynchronizedListOps);
    impl Drop for Reset {
        fn drop(&mut self) { unsafe { SYNCHRONIZED_LIST_OPS = self.0; } }
    }
    fn entry(state: u8, value: u32) -> RetirableEntry {
        RetirableEntry { unresolved: 0xfeed, handle: core::ptr::null_mut(),
            retire_requested: 7, state, value }
    }
    #[test]
    fn all_nonpending_states_leave_entry_untouched_without_context() {
        for state in 0..=255 {
            if state == 2 { continue; }
            let mut e = entry(state, 0xdead_beef);
            unsafe { collection_entry_activate(core::ptr::null_mut(), &mut e); }
            assert_eq!((e.state, e.value, e.retire_requested, e.unresolved),
                (state, 0xdead_beef, 7, 0xfeed));
            assert!(e.handle.is_null());
        }
    }
    #[test]
    fn pending_values_commit_after_append_and_do_not_append_twice() {
        let _lock = TEST_LOCK.lock();
        unsafe {
            let _reset = Reset(SYNCHRONIZED_LIST_OPS);
            SYNCHRONIZED_LIST_OPS = SynchronizedListOps {
                allocate, append, cleanup, lock: mutex, unlock: mutex,
            };
            for value in [0, 1, u32::MAX, 0x8000_0000] {
                let mut context = [0u32; 32];
                let mut e = entry(2, value);
                ENTRY = &mut e;
                collection_entry_activate(context.as_mut_ptr().cast(), &mut e);
                assert_eq!((context[21], context[22], e.state), (value, 1, 1));
                collection_entry_activate(context.as_mut_ptr().cast(), &mut e);
                assert_eq!((context[21], context[22], e.state), (value, 1, 1));
                assert_eq!((e.value, e.retire_requested, e.unresolved), (value, 7, 0xfeed));
                assert!(e.handle.is_null());
            }
            ENTRY = core::ptr::null_mut();
        }
    }
}
