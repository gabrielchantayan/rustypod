//! `child_table_reconcile` — original: `FUN_083925cc` @ `0x083925cc`
//! (**80 bytes**, `0x083925cc..0x0839261c`; next separately linked function
//! begins at `0x0839261c`).
//!
//! A nullable child-table walker. For a non-null table it reads the signed
//! count at +0x00 and its entry array at +0x0c, then forwards entry word +0x00
//! in ascending order to `FUN_08392498`, preserving its context, selector,
//! and replacement arguments. Counts less than or equal to zero leave the
//! entry pointer untouched.
//!
//! Decoding every ARM B/BL immediate in `osos.dec` finds six direct calls:
//! five unconditional `bl` (`0x082ce8dc`, `0x082ce8fc`, `0x08392644`,
//! `0x08392658`, `0x0839266c`) and one `blne` (`0x082ce940`). There are no
//! direct tail branches or aligned raw-word references to this entry. The
//! predicated call demonstrates that this function's NULL guard is relied on
//! by at least one caller.
//!
//! Deliberate deviation: `FUN_08392498` is not ported. ARM calls it at its
//! verified fixed address; host tests replace that dependency with a recording
//! seam. The child-table and entry layouts model only the words this function
//! reads, and `repr(C)` keeps their 32-bit target fields distinct while host
//! pointers remain naturally sized.

use core::ffi::c_void;

/// The only entry word consumed by [`child_table_reconcile`].
#[repr(C)]
pub struct ChildTableEntry {
    pub child: *mut c_void,
    pub remaining_words: [u32; 2],
}

/// The child table layout consumed by [`child_table_reconcile`].
#[repr(C)]
pub struct ChildTable {
    /// Signed element count at target offset +0x00.
    pub count: i32,
    pub remaining_header_words: [u32; 2],
    /// Entry array at target offset +0x0c.
    pub entries: *const ChildTableEntry,
}

/// `FUN_08392498`, which reconciles one child node.
pub type ChildNodeReconcile = unsafe extern "C" fn(*mut c_void, *mut c_void, u32, *mut c_void);

#[cfg(test)]
pub(crate) static CHILD_TABLE_RECONCILE_TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_child_node_reconcile(
    _context: *mut c_void,
    _child: *mut c_void,
    _selector: u32,
    _replacement: *mut c_void,
) {
}

/// Host replacement for the unported child reconciler at `0x08392498`.
#[cfg(not(target_arch = "arm"))]
pub static mut CHILD_NODE_RECONCILE: ChildNodeReconcile = missing_child_node_reconcile;

#[cfg(target_arch = "arm")]
#[inline(always)]
unsafe fn reconcile_child(
    context: *mut c_void,
    child: *mut c_void,
    selector: u32,
    replacement: *mut c_void,
) {
    let reconcile: ChildNodeReconcile = core::mem::transmute(0x0839_2498usize);
    reconcile(context, child, selector, replacement)
}

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
unsafe fn reconcile_child(
    context: *mut c_void,
    child: *mut c_void,
    selector: u32,
    replacement: *mut c_void,
) {
    core::ptr::read_volatile(core::ptr::addr_of!(CHILD_NODE_RECONCILE))(
        context,
        child,
        selector,
        replacement,
    )
}

/// Walks a nullable child table and reconciles every entry in ascending order.
///
/// # Safety
///
/// A non-null `children` must point to a valid [`ChildTable`]. If `count` is
/// positive, `entries` must designate at least `count` valid entries. The
/// child reconciler receives every entry's `child` pointer unchanged; its
/// validity requirements remain the caller's responsibility. This matches the
/// retail ARM routine, which has no additional bounds or alignment guards.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn child_table_reconcile(
    context: *mut c_void,
    children: *const ChildTable,
    selector: u32,
    replacement: *mut c_void,
) {
    if children.is_null() {
        return;
    }

    let table = &*children;
    for index in 0..table.count {
        let entry = &*table.entries.add(index as usize);
        reconcile_child(context, entry.child, selector, replacement);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use parking_lot::Mutex;
    use std::sync::LazyLock;
    use std::vec::Vec;

    static CALLS: LazyLock<Mutex<Vec<(usize, usize, u32, usize)>>> =
        LazyLock::new(|| Mutex::new(Vec::new()));

    unsafe extern "C" fn record_child_reconcile(
        context: *mut c_void,
        child: *mut c_void,
        selector: u32,
        replacement: *mut c_void,
    ) {
        CALLS.lock().push((
            context as usize,
            child as usize,
            selector,
            replacement as usize,
        ));
    }

    unsafe fn install_recording_seam() {
        CHILD_NODE_RECONCILE = record_child_reconcile;
        CALLS.lock().clear();
    }

    unsafe fn reset_seam() {
        CHILD_NODE_RECONCILE = missing_child_node_reconcile;
        CALLS.lock().clear();
    }

    #[test]
    fn null_table_does_not_call_the_reconciler() {
        let _guard = CHILD_TABLE_RECONCILE_TEST_LOCK.lock();
        unsafe {
            install_recording_seam();
            child_table_reconcile(
                0x1000usize as *mut c_void,
                core::ptr::null(),
                0x55aa,
                0x2000usize as *mut c_void,
            );
            assert!(CALLS.lock().is_empty());
            reset_seam();
        }
    }

    #[test]
    fn nonpositive_counts_leave_the_entry_pointer_untouched() {
        let _guard = CHILD_TABLE_RECONCILE_TEST_LOCK.lock();
        unsafe {
            install_recording_seam();
            for count in [0, -1, i32::MIN] {
                let table = ChildTable {
                    count,
                    remaining_header_words: [0; 2],
                    entries: core::ptr::null(),
                };
                child_table_reconcile(
                    core::ptr::null_mut(),
                    &table,
                    0,
                    core::ptr::null_mut(),
                );
            }
            assert!(CALLS.lock().is_empty());
            reset_seam();
        }
    }

    #[test]
    fn reconciles_each_child_in_table_order_with_unchanged_arguments() {
        let _guard = CHILD_TABLE_RECONCILE_TEST_LOCK.lock();
        let entries = [
            ChildTableEntry {
                child: 0x3000usize as *mut c_void,
                remaining_words: [0; 2],
            },
            ChildTableEntry {
                child: core::ptr::null_mut(),
                remaining_words: [0; 2],
            },
            ChildTableEntry {
                child: 0x5000usize as *mut c_void,
                remaining_words: [0; 2],
            },
        ];
        let table = ChildTable {
            count: entries.len() as i32,
            remaining_header_words: [0; 2],
            entries: entries.as_ptr(),
        };

        unsafe {
            install_recording_seam();
            child_table_reconcile(
                0x1000usize as *mut c_void,
                &table,
                0xdead_beef,
                0x2000usize as *mut c_void,
            );
            assert_eq!(
                *CALLS.lock(),
                std::vec![
                    (0x1000, 0x3000, 0xdead_beef, 0x2000),
                    (0x1000, 0, 0xdead_beef, 0x2000),
                    (0x1000, 0x5000, 0xdead_beef, 0x2000),
                ]
            );
            reset_seam();
        }
    }
}
