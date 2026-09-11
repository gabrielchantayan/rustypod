//! Debug task selector — `FUN_082d0b80` @ `0x082d0b80`.
//!
//! Raw `osos.dec` has 172 bytes of instructions (`0x082d0b80..0x082d0c2c`)
//! followed by this function's 28-byte literal pool (`0x082d0c2c..0x082d0c48`);
//! the next separately linked function starts at `0x082d0c48`, so its full
//! binary extent is 200 bytes. Decoding every ARM B/BL word finds 9 direct
//! callers, all unconditional `bl` (none predicated): `0x082bf6c0`,
//! `0x08393e7c`, `0x08393e98`, `0x08393ea8`, `0x08393eb8`, `0x0839400c`,
//! `0x0839401c`, `0x08394054`, and `0x08394094`. No data word references the
//! entry, so it is not indirectly dispatched.
//!
//! # Algorithm
//!
//! Print the semihosting prompt `"\nTask (# or name)> "`, read at most 15 bytes
//! into a 16-byte stack buffer through the unported debug-console line reader
//! @ `0x082d670c`, then print a newline. A leading `'-'` selects every task
//! (`-1`). A leading digit is parsed by `atoi_dead_sign` and accepted only when
//! it is in `1..=task_count` (the mutable task count at IRAM `0x22008a54`). Any
//! other first byte is compared, case-sensitively, with the scheduler label of
//! every one-based task identifier; the matching identifier is returned, or 0
//! when none matches.
//!
//! Deliberate deviations: none on target. Host tests replace the unported line
//! reader, the semihosting SWI, the mutable task-count word, and the existing
//! scheduler-label lookup seam. The raw helper is known only as a debug-console
//! reader from its `:tt` SYS_OPEN and SYS_READ sequence; this port does not
//! assign it a broader firmware identity.

use core::ptr;

use crate::libc::strcmp::strcmp;
use crate::semihost::{semihost_swi, SYS_WRITE0};
use crate::strto::atoi_dead_sign::atoi_dead_sign;
use crate::util::scheduler_label_lookup::scheduler_label_lookup;

const TASK_PROMPT: &[u8] = b"\nTask (# or name)> \0";
const NEWLINE: &[u8] = b"\n\0";
const TASK_COUNT_ADDRESS: *const i32 = 0x2200_8a54 as *const i32;

/// ABI of the unported debug-console line reader @ `0x082d670c`.
pub type DebugConsoleReadFn = unsafe extern "C" fn(buffer: *mut u8, capacity: u32);

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_debug_console_read(buffer: *mut u8, capacity: u32) {
    let reader: DebugConsoleReadFn = unsafe { core::mem::transmute(0x082d_670cusize) };
    unsafe { reader(buffer, capacity) };
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_debug_console_read(_buffer: *mut u8, _capacity: u32) {
    panic!("debug_task_selector requires debug-console reader 0x082d670c")
}

#[cfg(target_os = "none")]
const DEFAULT_DEBUG_CONSOLE_READ: DebugConsoleReadFn = firmware_debug_console_read;
#[cfg(not(target_os = "none"))]
const DEFAULT_DEBUG_CONSOLE_READ: DebugConsoleReadFn = missing_debug_console_read;

/// The line reader called by the original after writing its task prompt.
/// Target builds call `0x082d670c`; host tests install a fixture reader.
pub static mut DEBUG_CONSOLE_READ: DebugConsoleReadFn = DEFAULT_DEBUG_CONSOLE_READ;

#[cfg(not(target_os = "none"))]
static mut HOST_TASK_COUNT: i32 = 0;

#[inline(always)]
fn task_count() -> i32 {
    #[cfg(target_os = "none")]
    unsafe {
        ptr::read_volatile(TASK_COUNT_ADDRESS)
    }
    #[cfg(not(target_os = "none"))]
    unsafe {
        ptr::read_volatile(ptr::addr_of!(HOST_TASK_COUNT))
    }
}

#[inline(always)]
fn debug_console_read() -> DebugConsoleReadFn {
    unsafe { ptr::read_volatile(ptr::addr_of!(DEBUG_CONSOLE_READ)) }
}

#[inline(always)]
unsafe fn select_task_from_input(input: *const u8) -> i32 {
    let first = unsafe { ptr::read(input) };
    if first == b'-' {
        return -1;
    }

    let count = task_count();
    if first.wrapping_sub(b'0') <= 9 {
        let identifier = unsafe { atoi_dead_sign(input) };
        return if identifier > 0 && identifier <= count { identifier } else { 0 };
    }

    for identifier in 1..=count {
        let label = scheduler_label_lookup(identifier) as usize as *const u8;
        if unsafe { strcmp(input, label) } == 0 {
            return identifier;
        }
    }
    0
}

/// debug_task_selector — original `FUN_082d0b80` @ `0x082d0b80` (200 bytes).
///
/// Prompts on the Angel debug console, reads one task number or scheduler label,
/// and returns `-1` for `'-'`, a one-based selected identifier, or 0 on invalid
/// input. The task-count load and label comparisons deliberately have no NULL
/// guards, matching the original's direct memory and string accesses.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn debug_task_selector() -> i32 {
    let mut input = [0u8; 16];
    unsafe {
        semihost_swi()(SYS_WRITE0, TASK_PROMPT.as_ptr().cast());
        debug_console_read()(input.as_mut_ptr(), input.len() as u32);
        semihost_swi()(SYS_WRITE0, NEWLINE.as_ptr().cast());
        select_task_from_input(input.as_ptr())
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::semihost::tests::{restore_swi, SWI_LOCK};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab, SCHEDULER_LABEL_FIND_TEST_LOCK};
    use crate::util::scheduler_label_lookup::{SchedulerLabelFind, SCHEDULER_LABEL_FIND, DEFAULT_SCHEDULER_LABEL_FIND};
    use core::slice;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut INPUT: [u8; 16] = [0; 16];
    static mut INPUT_CAPACITY: u32 = 0;
    static mut WRITE0_LOG: Vec<Vec<u8>> = Vec::new();
    static mut LABEL_BASE: usize = 0;

    unsafe extern "C" fn recording_console_read(buffer: *mut u8, capacity: u32) {
        unsafe {
            INPUT_CAPACITY = capacity;
            ptr::copy_nonoverlapping(INPUT.as_ptr(), buffer, core::cmp::min(capacity as usize, INPUT.len()));
        }
    }

    unsafe extern "C" fn recording_swi(op: usize, block: *const usize) -> i32 {
        assert_eq!(op, SYS_WRITE0);
        let text = block.cast::<u8>();
        let mut len = 0;
        unsafe {
            while text.add(len).read() != 0 {
                len += 1;
            }
            WRITE0_LOG.push(slice::from_raw_parts(text, len).to_vec());
        }
        0
    }

    unsafe extern "C" fn fixture_label_find(identifier: i32, out_label: *mut u32) -> u32 {
        let offset = match identifier {
            1 => 0,
            2 => 16,
            3 => 32,
            _ => return 0,
        };
        unsafe {
            out_label.write((LABEL_BASE + offset) as u32);
        }
        1
    }

    struct Reset;

    impl Drop for Reset {
        fn drop(&mut self) {
            unsafe {
                ptr::addr_of_mut!(DEBUG_CONSOLE_READ).write(DEFAULT_DEBUG_CONSOLE_READ);
                ptr::addr_of_mut!(HOST_TASK_COUNT).write(0);
                ptr::addr_of_mut!(SCHEDULER_LABEL_FIND).write(DEFAULT_SCHEDULER_LABEL_FIND);
                ptr::addr_of_mut!(INPUT).write([0; 16]);
                ptr::addr_of_mut!(INPUT_CAPACITY).write(0);
                (*ptr::addr_of_mut!(WRITE0_LOG)).clear();
                ptr::addr_of_mut!(LABEL_BASE).write(0);
            }
            restore_swi();
        }
    }

    fn set_input(input: &[u8]) {
        assert!(input.len() <= 16);
        unsafe {
            let mut line = [0u8; 16];
            line[..input.len()].copy_from_slice(input);
            ptr::addr_of_mut!(INPUT).write(line);
        }
    }

    fn install(input: &[u8], count: i32) -> Reset {
        set_input(input);
        unsafe {
            ptr::addr_of_mut!(HOST_TASK_COUNT).write(count);
            ptr::addr_of_mut!(DEBUG_CONSOLE_READ).write(recording_console_read);
            ptr::addr_of_mut!(crate::semihost::SEMIHOST_SWI).write(recording_swi);
            (*ptr::addr_of_mut!(WRITE0_LOG)).clear();
        }
        Reset
    }

    fn lock<T>(lock: &'static Mutex<T>) -> MutexGuard<'static, T> {
        lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[test]
    fn selector_prompts_reads_and_accepts_bounded_numeric_index() {
        let _swi_guard = lock(&SWI_LOCK);
        let _label_guard = lock(&SCHEDULER_LABEL_FIND_TEST_LOCK);
        let _guard = lock(&TEST_LOCK);
        let _reset = install(b"2\0", 3);

        assert_eq!(debug_task_selector(), 2);
        assert_eq!(unsafe { INPUT_CAPACITY }, 16);
        assert_eq!(unsafe { &*ptr::addr_of!(WRITE0_LOG) }, &[TASK_PROMPT[..TASK_PROMPT.len() - 1].to_vec(), b"\n".to_vec()]);
    }

    #[test]
    fn selector_reserves_dash_for_all_tasks_and_rejects_bad_numbers() {
        let _swi_guard = lock(&SWI_LOCK);
        let _label_guard = lock(&SCHEDULER_LABEL_FIND_TEST_LOCK);
        let _guard = lock(&TEST_LOCK);
        let _reset = install(b"-anything\0", 3);

        assert_eq!(debug_task_selector(), -1);
        set_input(b"0\0");
        assert_eq!(debug_task_selector(), 0);
        set_input(b"4\0");
        assert_eq!(debug_task_selector(), 0);
    }

    #[test]
    fn selector_matches_scheduler_labels_case_sensitively() {
        let _swi_guard = lock(&SWI_LOCK);
        let _label_guard = lock(&SCHEDULER_LABEL_FIND_TEST_LOCK);
        let _guard = lock(&TEST_LOCK);
        let Some(labels) = try_map_u32_slab(hints::DEBUG_TASK_SELECTOR_LABELS, 0x1000) else {
            note_missing_u32_fixture("kernel::debug_task_selector");
            return;
        };
        unsafe {
            labels.add(0).copy_from_nonoverlapping(b"idle\0".as_ptr(), 5);
            labels.add(16).copy_from_nonoverlapping(b"audio\0".as_ptr(), 6);
            labels.add(32).copy_from_nonoverlapping(b"render\0".as_ptr(), 7);
            ptr::addr_of_mut!(LABEL_BASE).write(labels as usize);
            ptr::addr_of_mut!(SCHEDULER_LABEL_FIND).write(fixture_label_find as SchedulerLabelFind);
        }
        let _reset = install(b"audio\0", 3);
        unsafe { ptr::addr_of_mut!(SCHEDULER_LABEL_FIND).write(fixture_label_find as SchedulerLabelFind) };

        assert_eq!(debug_task_selector(), 2);
        set_input(b"Audio\0");
        assert_eq!(debug_task_selector(), 0);
    }
}
