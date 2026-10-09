//! Recursive 'plst' task completion.
//!
//! Original `FUN_080e421c` at `0x080e421c`, true size 60 bytes: fifteen
//! A32 words ending at `0x080e4254`, before the next prologue at `0x080e4258`.
//! Verified inbound calls: two plain BLs (0x0806127c and self-call 0x080e4244),
//! zero predicated BLs. Outbound: one plain recursive BL, zero predicated BLs,
//! and a conditional tail branch to `plst_task_complete` at 0x08048a0c.
//!
//! Bit 2 completes this task immediately, taking precedence over bit 0.
//! Otherwise bit 0 walks children at +0x20, caching each next pointer at +8
//! before recursion and discarding child results. Containers return zero;
//! ordinary leaves preserve the input pointer in r0. Deliberate deviations:
//! none in behavior; Rust represents the mixed pointer/status r0 as usize
//! and sign-extends the completion status on hosts (ARM remains 32-bit).

use super::plst_task_complete::plst_task_complete;

/// # Safety
/// `task` must be aligned and readable through byte +0x1d. Container tasks
/// also require word +0x20 and a finite, acyclic child graph whose nodes have
/// readable next words at +8. Bit-2 tasks obey `plst_task_complete`'s contract.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn plst_task_complete_tree(task: *mut u32) -> usize {
    let flags = task.cast::<u8>().add(0x1d).read();
    if flags & 4 != 0 {
        return plst_task_complete(task) as isize as usize;
    }
    if flags & 1 == 0 {
        return task as usize;
    }
    let mut child = task.add(8).read() as usize as *mut u32;
    while !child.is_null() {
        let next = child.add(2).read() as usize as *mut u32;
        plst_task_complete_tree(child);
        child = next;
    }
    0
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    #[test]
    fn leaf_preserves_pointer_and_empty_container_returns_zero() {
        let mut task = [0u32; 9];
        let pointer = task.as_mut_ptr();
        for flags in [0u8, 2, 8, 0xfa] {
            unsafe { pointer.cast::<u8>().add(0x1d).write(flags); }
            assert_eq!(unsafe { plst_task_complete_tree(pointer) }, pointer as usize);
        }
        unsafe { pointer.cast::<u8>().add(0x1d).write(1); }
        assert_eq!(unsafe { plst_task_complete_tree(pointer) }, 0);
    }

    #[test]
    fn completion_precedes_children_and_preserves_error_status() {
        let mut task = [0u32; 9];
        task[8] = 1; // Invalid child must not be touched on completion path.
        for flags in [4u8, 5, 0xff] {
            unsafe { task.as_mut_ptr().cast::<u8>().add(0x1d).write(flags); }
            assert_eq!(unsafe { plst_task_complete_tree(task.as_mut_ptr()) }, -50isize as usize);
        }
    }

    #[test]
    fn nested_sibling_walk_discards_completion_errors() {
        let Some(base) = try_map_u32_slab(hints::PLST_TASK_COMPLETE_TREE, 0x1000) else {
            assert!(note_missing_u32_fixture("ui/plst_task_complete_tree")); return;
        };
        unsafe {
            base.write_bytes(0, 0x1000);
            let root = base.cast::<u32>();
            let first = base.add(0x100).cast::<u32>();
            let second = base.add(0x200).cast::<u32>();
            let nested = base.add(0x300).cast::<u32>();
            root.cast::<u8>().add(0x1d).write(1);
            root.add(8).write(first as usize as u32);
            first.cast::<u8>().add(0x1d).write(4); // NULL element: -50.
            first.add(2).write(second as usize as u32);
            second.cast::<u8>().add(0x1d).write(1);
            second.add(8).write(nested as usize as u32);
            nested.cast::<u8>().add(0x1d).write(4);
            assert_eq!(plst_task_complete_tree(first), -50isize as usize);
            assert_eq!(plst_task_complete_tree(root), 0);
            assert_eq!(root.add(8).read(), first as usize as u32);
            assert_eq!(first.add(2).read(), second as usize as u32);
        }
    }
}
