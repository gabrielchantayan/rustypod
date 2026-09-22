//! `collection_item_process_if_limit` — original: `FUN_08211e20` @ `0x08211e20`
//! (**64 bytes**, `0x08211e20..0x08211e60`).
//!
//! The routine returns zero without side effects when `item_present` is zero.
//! Otherwise it compares the word at `processed_count` with `limit`: below the
//! limit it invokes the within-limit item processor and increments the count;
//! at or above the limit it invokes the at-limit item processor. It then returns
//! one. Raw ARM decoding confirms two direct outbound `bl` instructions, both
//! unconditional (`0x08211e40` and `0x08211e54`), and zero predicated `bl`
//! instructions; the next separately linked function begins at `0x08211e60`.
//!
//! Deliberate deviation: the two unported processors are fixed-address calls on
//! ARM and replaceable host seams for behavior tests.

pub type CollectionItemProcessor = unsafe extern "C" fn(*mut u8, u32, *mut u32, u32);

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_collection_item_processor(_context: *mut u8, _item_present: u32, _processed_count: *mut u32, _limit: u32) {}

/// Host replacement for the within-limit processor at `0x08211ca4`.
#[cfg(not(target_arch = "arm"))]
pub static mut COLLECTION_ITEM_PROCESS_WITHIN_LIMIT: CollectionItemProcessor = missing_collection_item_processor;

/// Host replacement for the at-limit processor at `0x08211d34`.
#[cfg(not(target_arch = "arm"))]
pub static mut COLLECTION_ITEM_PROCESS_AT_LIMIT: CollectionItemProcessor = missing_collection_item_processor;

#[cfg(test)]
pub(crate) static COLLECTION_ITEM_PROCESS_IF_LIMIT_TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

#[cfg(target_arch = "arm")]
#[inline(always)]
unsafe fn process_within_limit(context: *mut u8, item_present: u32, processed_count: *mut u32, limit: u32) {
    let processor: CollectionItemProcessor = core::mem::transmute(0x0821_1ca4usize);
    processor(context, item_present, processed_count, limit)
}

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
unsafe fn process_within_limit(context: *mut u8, item_present: u32, processed_count: *mut u32, limit: u32) {
    core::ptr::read_volatile(core::ptr::addr_of!(COLLECTION_ITEM_PROCESS_WITHIN_LIMIT))(context, item_present, processed_count, limit)
}

#[cfg(target_arch = "arm")]
#[inline(always)]
unsafe fn process_at_limit(context: *mut u8, item_present: u32, processed_count: *mut u32, limit: u32) {
    let processor: CollectionItemProcessor = core::mem::transmute(0x0821_1d34usize);
    processor(context, item_present, processed_count, limit)
}

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
unsafe fn process_at_limit(context: *mut u8, item_present: u32, processed_count: *mut u32, limit: u32) {
    core::ptr::read_volatile(core::ptr::addr_of!(COLLECTION_ITEM_PROCESS_AT_LIMIT))(context, item_present, processed_count, limit)
}

/// Processes a present collection item and counts only within-limit processing.
///
/// # Safety
///
/// `processed_count` must be a valid, aligned mutable word. `context` and the
/// other arguments must satisfy the selected retail processor's requirements.
/// The original has no guards for these requirements.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn collection_item_process_if_limit(context: *mut u8, item_present: u32, processed_count: *mut u32, limit: u32) -> u32 {
    if item_present == 0 {
        return 0;
    }

    if processed_count.read() < limit {
        process_within_limit(context, item_present, processed_count, limit);
        processed_count.write(processed_count.read().wrapping_add(1));
    } else {
        process_at_limit(context, item_present, processed_count, limit);
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    static mut WITHIN_CALLS: u32 = 0;
    static mut AT_LIMIT_CALLS: u32 = 0;
    static mut LAST_CONTEXT: *mut u8 = core::ptr::null_mut();
    static mut LAST_ITEM_PRESENT: u32 = 0;
    static mut LAST_COUNT: *mut u32 = core::ptr::null_mut();
    static mut LAST_LIMIT: u32 = 0;

    unsafe extern "C" fn record_within_limit(context: *mut u8, item_present: u32, processed_count: *mut u32, limit: u32) {
        WITHIN_CALLS += 1;
        LAST_CONTEXT = context;
        LAST_ITEM_PRESENT = item_present;
        LAST_COUNT = processed_count;
        LAST_LIMIT = limit;
    }

    unsafe extern "C" fn record_at_limit(context: *mut u8, item_present: u32, processed_count: *mut u32, limit: u32) {
        AT_LIMIT_CALLS += 1;
        LAST_CONTEXT = context;
        LAST_ITEM_PRESENT = item_present;
        LAST_COUNT = processed_count;
        LAST_LIMIT = limit;
    }

    unsafe fn reset_seams() {
        COLLECTION_ITEM_PROCESS_WITHIN_LIMIT = record_within_limit;
        COLLECTION_ITEM_PROCESS_AT_LIMIT = record_at_limit;
        WITHIN_CALLS = 0;
        AT_LIMIT_CALLS = 0;
        LAST_CONTEXT = core::ptr::null_mut();
        LAST_ITEM_PRESENT = 0;
        LAST_COUNT = core::ptr::null_mut();
        LAST_LIMIT = 0;
    }

    #[test]
    fn absent_item_returns_zero_without_processing() {
        let _guard = COLLECTION_ITEM_PROCESS_IF_LIMIT_TEST_LOCK.lock();
        let mut count = 3;
        unsafe {
            reset_seams();
            assert_eq!(collection_item_process_if_limit(0x1234usize as *mut u8, 0, &mut count, 4), 0);
            assert_eq!(count, 3);
            assert_eq!(WITHIN_CALLS, 0);
            assert_eq!(AT_LIMIT_CALLS, 0);
        }
    }

    #[test]
    fn below_limit_processes_and_increments_afterward() {
        let _guard = COLLECTION_ITEM_PROCESS_IF_LIMIT_TEST_LOCK.lock();
        let mut count = 2;
        let context = 0x1234usize as *mut u8;
        unsafe {
            reset_seams();
            assert_eq!(collection_item_process_if_limit(context, 7, &mut count, 3), 1);
            assert_eq!(count, 3);
            assert_eq!(WITHIN_CALLS, 1);
            assert_eq!(AT_LIMIT_CALLS, 0);
            assert_eq!(LAST_CONTEXT, context);
            assert_eq!(LAST_ITEM_PRESENT, 7);
            assert_eq!(LAST_COUNT, core::ptr::addr_of_mut!(count));
            assert_eq!(LAST_LIMIT, 3);
        }
    }

    #[test]
    fn at_or_above_limit_processes_without_incrementing() {
        let _guard = COLLECTION_ITEM_PROCESS_IF_LIMIT_TEST_LOCK.lock();
        for (initial, limit) in [(3, 3), (4, 3), (u32::MAX, 0)] {
            let mut count = initial;
            unsafe {
                reset_seams();
                assert_eq!(collection_item_process_if_limit(core::ptr::null_mut(), 1, &mut count, limit), 1);
                assert_eq!(count, initial);
                assert_eq!(WITHIN_CALLS, 0);
                assert_eq!(AT_LIMIT_CALLS, 1);
            }
        }
    }
}
