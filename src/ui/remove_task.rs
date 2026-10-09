//! Task removal — FUN_080da878 @ 0x080da878, 120 bytes.
//! Raw extent 0x080da878..0x080da8f0, followed by an independent push-prologue.
//! Two inbound plain BLs (0x08048a90, 0x080e69f4), no predicated inbound
//! BLs; zero outbound BLs, two conditional tail branches. Unflagged tasks
//! are unlinked from parent+0x24 through next links at +0x28. Return the
//! remaining head, or request an empty-list result when requested. Flagged
//! tasks return themselves unless release is requested, then release the
//! element's embedded string-pool ID. Deliberate deviation: the unregistered
//! tail helper at 0x08048b34 is expressed using its raw-verified zeroed
//! four-word record and the existing Tdat port, not a guessed callee seam.
//! Target words remain u32 on hosts; return usize preserves native pointers
//! and the target's mixed pointer/status result.

use crate::util::string_pool::{string_pool_release, StringPool};
use super::tdat_message_dispatch::tdat_dispatch_message;

/// # Safety
/// Task and all traversed links must be valid target-word objects. A flagged
/// release requires a valid StringPool at element+0xcc; empty-list dispatch
/// requires the parent's first word to name a valid Tdat element.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn remove_task(task: *mut u32, release: u32, notify_empty: u32) -> usize {
    if task.cast::<u8>().add(0x1d).read() & 1 != 0 {
        if release == 0 { return task as usize; }
        let id = task.add(10).read() as i32;
        let element = task.read() as usize as *mut u8;
        return string_pool_release(element.add(0xcc).cast::<StringPool>(), id) as u32 as usize;
    }
    let parent = task.add(8).read() as usize as *mut u32;
    let mut current = parent.add(9).read();
    let mut previous: *mut u32 = core::ptr::null_mut();
    while current != 0 {
        let node = current as usize as *mut u32;
        if node == task {
            let next = node.add(10).read();
            if previous.is_null() { parent.add(9).write(next); }
            else { previous.add(10).write(next); }
            break;
        }
        previous = node;
        current = node.add(10).read();
    }
    let head = parent.add(9).read();
    if head != 0 || notify_empty == 0 { return head as usize; }
    let mut arguments = [parent as usize as u32, 0, 0, 0];
    tdat_dispatch_message(parent.read() as usize as *mut u8, 0x7464_6474, arguments.as_mut_ptr().cast());
    arguments[0] as usize
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, try_map_u32_slab};

    #[test]
    fn unlink_head_middle_tail_absent_and_empty() {
        unsafe {
            let slab = try_map_u32_slab(hints::REMOVE_TASK, 0x1000).expect("low-address fixture");
            slab.write_bytes(0, 0x1000);
            let parent = slab.cast::<u32>();
            let a = slab.add(0x100).cast::<u32>();
            let b = slab.add(0x200).cast::<u32>();
            let c = slab.add(0x300).cast::<u32>();
            let absent = slab.add(0x400).cast::<u32>();
            for node in [a, b, c, absent] { node.add(8).write(parent as usize as u32); }
            for (removed, expected) in [(a, b), (b, a), (c, a), (absent, a)] {
                parent.add(9).write(a as usize as u32);
                a.add(10).write(b as usize as u32); b.add(10).write(c as usize as u32); c.add(10).write(0);
                assert_eq!(remove_task(removed, 0, 0), expected as usize);
                assert_eq!(parent.add(9).read(), expected as usize as u32);
                if removed == b { assert_eq!(a.add(10).read(), c as usize as u32); }
                if removed == c { assert_eq!(b.add(10).read(), 0); }
                if removed == absent { assert_eq!(a.add(10).read(), b as usize as u32); }
                assert_eq!(removed.add(10).read(), if removed == a { b as usize as u32 } else if removed == b { c as usize as u32 } else { 0 });
            }
            parent.add(9).write(a as usize as u32); a.add(10).write(0);
            assert_eq!(remove_task(a, 1, 0), 0);
            assert_eq!(parent.add(9).read(), 0);
            // Rejected Tdat dispatch leaves the zeroed record's parent word intact.
            assert_eq!(remove_task(absent, 0, 1), parent as usize);
            assert_eq!(parent.add(9).read(), 0);
        }
    }

    #[test]
    fn flagged_passthrough_and_pool_rejection() {
        unsafe {
            let mut task = [0u32; 11];
            task.as_mut_ptr().cast::<u8>().add(0x1d).write(1);
            assert_eq!(remove_task(task.as_mut_ptr(), 0, 1), task.as_mut_ptr() as usize);
            // Pool is aligned at slab+0x100; its enclosing element starts +0x34.
            let slab = try_map_u32_slab(hints::REMOVE_TASK_POOL, 0x1000).expect("low-address fixture");
            slab.write_bytes(0, 0x1000);
            task[0] = slab.add(0x34) as usize as u32;
            task[10] = 1;
            assert_eq!(remove_task(task.as_mut_ptr(), 1, 1), (-50i32) as u32 as usize);
            let pool = slab.add(0x100).cast::<StringPool>();
            (*pool).tag = 0x7374_7263;
            task[10] = 0;
            assert_eq!(remove_task(task.as_mut_ptr(), 1, 0), 0);
            task[10] = u32::MAX;
            assert_eq!(remove_task(task.as_mut_ptr(), 1, 0), (-50i32) as u32 as usize);
            let mut entry = crate::util::string_pool::PoolEntry { blob_offset: 12, length: 7 };
            let mut entries = &mut entry as *mut _;
            (*pool).entries = &mut entries;
            (*pool).entry_count = 1;
            task[10] = 1;
            assert_eq!(remove_task(task.as_mut_ptr(), 1, 0), 0);
            assert_eq!(entry.blob_offset, 0x8000_0001);
            assert_eq!((*pool).reclaimable_bytes, 7);
        }
    }
}
