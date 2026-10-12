//! Task disposal message — FUN_08048b34 @ 0x08048b34.
//! Raw extent 0x08048b34..0x08048b68: 48 instruction bytes and the
//! 0x74646474 literal (52 bytes total), then an independent push-prologue.
//! Two inbound plain BLs (0x0806a7ec, 0x080d7260), no predicated BLs,
//! and one BNE tail caller (0x080da8e8). Two outbound plain BLs, no
//! predicated BLs: bzero and tdat_dispatch_message. Load the task's element,
//! zero four argument words, put the task address in word zero, dispatch
//! 'tddt', and return words zero and one in r0:r1 regardless of status.
//! Deliberate deviations: initialize the record directly instead of bzero;
//! model the observable r0:r1 result as u64, not incidental restored r2:r3.
//! All record fields remain target-width words on hosts.

use super::tdat_message_dispatch::tdat_dispatch_message;

type MessageDispatch = unsafe extern "C" fn(*mut u8, u32, *mut u8) -> u32;

/// # Safety
/// `task` must point to a readable target word. Its first word must be NULL
/// or name a valid element for the Tdat dispatcher. The virtual handler must
/// obey the dispatch ABI and may modify the four-word temporary record.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn task_dispose_message(task: *mut u32) -> u64 {
    dispose_with(task, tdat_dispatch_message)
}

#[inline(always)]
unsafe fn dispose_with(task: *mut u32, dispatch: MessageDispatch) -> u64 {
    let element = task.read() as usize as *mut u8;
    let mut arguments = [task as usize as u32, 0, 0, 0];
    dispatch(element, 0x7464_6474, arguments.as_mut_ptr().cast());
    u64::from(arguments[0]) | (u64::from(arguments[1]) << 32)
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn complete_disposal(
        _element: *mut u8, message: u32, record: *mut u8,
    ) -> u32 {
        assert_eq!(message, 0x7464_6474);
        let words = record.cast::<u32>();
        assert_ne!(words.read(), 0);
        for index in 1..4 { assert_eq!(words.add(index).read(), 0); }
        // Handler results belong to the record, not the dispatcher status.
        words.write(0x8000_0001);
        words.add(1).write(0xffff_ffff);
        words.add(2).write(0xdead_beef);
        words.add(3).write(0xcafe_babe);
        0xffff_ffce
    }

    #[test]
    fn rejected_element_preserves_task_and_zero_high_word() {
        let mut task = [0u32];
        assert_eq!(unsafe { task_dispose_message(task.as_mut_ptr()) },
            task.as_mut_ptr() as usize as u32 as u64);
        assert_eq!(task, [0]);
        // The internal boundary permits a native fixture without truncating it.
        unsafe extern "C" fn reject(_: *mut u8, message: u32, record: *mut u8) -> u32 {
            let mut other = [0u32; 21];
            other[1] = 0x706c_7374;
            tdat_dispatch_message(other.as_mut_ptr().cast(), message, record)
        }
        assert_eq!(unsafe { dispose_with(task.as_mut_ptr(), reject) },
            task.as_mut_ptr() as usize as u32 as u64);
    }

    #[test]
    fn handler_record_overrides_status_and_preserves_full_result_width() {
        let mut task = [0u32];
        assert_eq!(unsafe { dispose_with(task.as_mut_ptr(), complete_disposal) },
            0xffff_ffff_8000_0001);
        assert_eq!(task, [0]);
    }
}
