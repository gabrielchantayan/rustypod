//! Collects matching records from an entire source collection.
//!
//! `record_collection_collect_all` — `FUN_0826a2c0` at `0x0826a2c0`,
//! 24 bytes, ending at the next real prologue at `0x0826a2d8`.
//! Whole-image raw ARM scan: two incoming plain BLs (0x08269ea0,
//! 0x0826a264), zero predicated BLs; one outgoing plain BL, zero predicated.
//! Calls the unported collection operation at 0x0826a2d8 with page index,
//! page size and completion pointer all zero. A zero page size selects the
//! entire source; the callee filters record pairs and appends accepted pairs
//! and flags to the context, returning whether anything was appended.
//! The wrapper preserves that result (despite Ghidra's void signature).
//! Deliberate deviations: host builds require an installed callee fixture;
//! target builds call the verified stock address, not an invented identity.
//! ARM codegen review: LLVM uses a literal-address BLX instead of the stock
//! relative BL and adds a frame pointer; the three zero arguments, preserved
//! context/source registers, stock target and returned r0 remain unchanged.

/// ABI of the still-unported operation at 0x0826a2d8.
pub type RecordCollectionOperation = unsafe extern "C" fn(*mut u8, *mut u8, u32, u32, *mut u8) -> u32;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_collection_operation(_: *mut u8, _: *mut u8, _: u32, _: u32, _: *mut u8) -> u32 {
    panic!("install stock record collection operation fixture")
}

#[cfg(not(target_os = "none"))]
pub static mut RECORD_COLLECTION_OPERATION: RecordCollectionOperation = missing_collection_operation;

/// # Safety
/// Both opaque pointers must satisfy the stock collection operation's contracts:
/// a valid collection context and a valid source collection. No null checks are
/// introduced; the callee dereferences both pointers.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn record_collection_collect_all(context: *mut u8, source: *mut u8) -> u32 {
    #[cfg(target_os = "none")]
    let operation: RecordCollectionOperation = unsafe { core::mem::transmute(0x0826_a2d8usize) };
    #[cfg(not(target_os = "none"))]
    let operation = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(RECORD_COLLECTION_OPERATION)) };
    unsafe { operation(context, source, 0, 0, core::ptr::null_mut()) }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());

    struct Context { accepted: std::vec::Vec<[u32; 2]>, minimum: u32 }
    struct Source { records: std::vec::Vec<[u32; 2]> }

    // Behavioral model of the observed stock zero-page-size path. Fixtures use
    // native pointers only inside this host operation, never ARM field offsets.
    unsafe extern "C" fn collect(context: *mut u8, source: *mut u8, page: u32, size: u32, done: *mut u8) -> u32 {
        let context = unsafe { &mut *context.cast::<Context>() };
        let source = unsafe { &*source.cast::<Source>() };
        let start = page.wrapping_mul(size) as usize;
        let end = if size == 0 { source.records.len() } else {
            source.records.len().min(start + size as usize)
        };
        if !done.is_null() { unsafe { done.write((end == source.records.len()) as u8); } }
        let mut changed = 0;
        for record in &source.records[start..end] {
            if record[0] >= context.minimum {
                context.accepted.push(*record);
                changed = 1;
            }
        }
        changed
    }

    #[test]
    fn empty_and_fully_filtered_sources_preserve_existing_records() {
        let _lock = LOCK.lock();
        unsafe { RECORD_COLLECTION_OPERATION = collect; }
        let mut context = Context { accepted: std::vec![[9, 90]], minimum: 5 };
        for records in [std::vec![], std::vec![[1, 10], [4, 40]]] {
            let mut source = Source { records };
            let result = unsafe { record_collection_collect_all((&mut context as *mut Context).cast(), (&mut source as *mut Source).cast()) };
            assert_eq!(result, 0);
            assert_eq!(context.accepted, [[9, 90]]);
        }
        unsafe { RECORD_COLLECTION_OPERATION = missing_collection_operation; }
    }

    #[test]
    fn collects_all_accepted_pairs_in_order_including_final_record() {
        let _lock = LOCK.lock();
        unsafe { RECORD_COLLECTION_OPERATION = collect; }
        let mut context = Context { accepted: std::vec![[9, 90]], minimum: 5 };
        let mut source = Source { records: std::vec![[5, 50], [4, 40], [u32::MAX, 7]] };
        let result = unsafe { record_collection_collect_all((&mut context as *mut Context).cast(), (&mut source as *mut Source).cast()) };
        assert_eq!(result, 1);
        assert_eq!(context.accepted, [[9, 90], [5, 50], [u32::MAX, 7]]);
        assert_eq!(source.records, [[5, 50], [4, 40], [u32::MAX, 7]]);
        unsafe { RECORD_COLLECTION_OPERATION = missing_collection_operation; }
    }
}
