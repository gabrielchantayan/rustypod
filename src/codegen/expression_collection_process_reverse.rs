//! Reverse expression-collection processing wrapper.
//!
//! `cg_expression_collection_process_reverse` — original: `FUN_082cd88c` @
//! `0x082cd88c` (56 bytes, `0x082cd88c..0x082cd8c3`; two direct inbound plain
//! `bl` call sites at `0x082cd358` and `0x0838da0c`, no predicated inbound
//! `bl`). Raw A32 words show the next independently linked function begins at
//! `0x082cd8c4` with `push {r4-r8,lr}`. The body has one plain outbound `bl`
//! at `0x082cd8b0` to the still-unclassified `FUN_082ccf94`, and no predicated
//! `bl` instructions.
//!
//! ## Algorithm
//!
//! Reads the signed count at collection word 2, then invokes the resident
//! collection-item processor once for each index in descending order, passing
//! `(context, collection, index)`.
//!
//! ## Deliberate deviations
//!
//! `FUN_082ccf94` has no verified semantic identity in `names.yaml`. Device
//! builds call its verified retail address; host tests replace the volatile
//! seam to observe the recovered argument order and iteration bounds.

/// Still-stock `FUN_082ccf94`, which processes one collection index.
pub const COLLECTION_ITEM_PROCESSOR_ADDRESS: usize = 0x082c_cf94;

/// ABI of the still-stock collection-item processor.
pub type CollectionItemProcessor = unsafe extern "C" fn(*mut u8, *const u32, i32);

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_collection_item_processor(
    context: *mut u8,
    collection: *const u32,
    index: i32,
) {
    let processor: CollectionItemProcessor = unsafe { core::mem::transmute(COLLECTION_ITEM_PROCESSOR_ADDRESS) };
    unsafe { processor(context, collection, index) };
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn retail_collection_item_processor(_: *mut u8, _: *const u32, _: i32) {
    panic!("cg_expression_collection_process_reverse requires FUN_082ccf94 @ 0x082ccf94")
}

/// Target default preserves the retail `bl 0x082ccf94` behavior.
pub static mut COLLECTION_ITEM_PROCESSOR: CollectionItemProcessor = retail_collection_item_processor;

#[inline(always)]
unsafe fn collection_item_processor() -> CollectionItemProcessor {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(COLLECTION_ITEM_PROCESSOR)) }
}

/// Process a counted expression collection from its final index to its first.
///
/// `collection` must have a readable count at target word offset 2. The
/// resident item processor owns all further layout and validity requirements.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_expression_collection_process_reverse(
    context: *mut u8,
    collection: *const u32,
) {
    let mut index = unsafe { collection.add(2).read() as i32 }.wrapping_sub(1);
    while index >= 0 {
        unsafe { collection_item_processor()(context, collection, index) };
        index = index.wrapping_sub(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut OBSERVED_CONTEXT: *mut u8 = core::ptr::null_mut();
    static mut OBSERVED_COLLECTION: *const u32 = core::ptr::null();
    static mut OBSERVED_INDICES: [i32; 4] = [0; 4];
    static mut CALLS: usize = 0;

    unsafe extern "C" fn record_item_processor(context: *mut u8, collection: *const u32, index: i32) {
        unsafe {
            OBSERVED_CONTEXT = context;
            OBSERVED_COLLECTION = collection;
            OBSERVED_INDICES[CALLS] = index;
            CALLS += 1;
        }
    }

    #[test]
    fn processes_all_indices_in_reverse_order() {
        let _lock = TEST_LOCK.lock();
        let mut collection = [0u32; 3];
        let mut context = 0u8;
        collection[2] = 4;
        unsafe {
            COLLECTION_ITEM_PROCESSOR = record_item_processor;
            OBSERVED_CONTEXT = core::ptr::null_mut();
            OBSERVED_COLLECTION = core::ptr::null();
            OBSERVED_INDICES = [0; 4];
            CALLS = 0;
            cg_expression_collection_process_reverse(&mut context, collection.as_ptr());
            assert_eq!(CALLS, 4);
            assert_eq!(OBSERVED_CONTEXT, core::ptr::addr_of_mut!(context));
            assert_eq!(OBSERVED_COLLECTION, collection.as_ptr());
            assert_eq!(OBSERVED_INDICES, [3, 2, 1, 0]);
            COLLECTION_ITEM_PROCESSOR = retail_collection_item_processor;
        }
    }

    #[test]
    fn empty_collection_does_not_call_processor() {
        let _lock = TEST_LOCK.lock();
        let collection = [0u32; 3];
        unsafe {
            COLLECTION_ITEM_PROCESSOR = record_item_processor;
            CALLS = 0;
            cg_expression_collection_process_reverse(core::ptr::null_mut(), collection.as_ptr());
            assert_eq!(CALLS, 0);
            COLLECTION_ITEM_PROCESSOR = retail_collection_item_processor;
        }
    }
}
