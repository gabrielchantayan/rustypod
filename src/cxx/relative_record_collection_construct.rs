//! Relative-record collection constructor — FUN_0826bac4 @ 0x0826bac4.
//! True extent: 200 bytes (196 code + vtable literal); next entry 0x0826bb8c.
//! Raw A32 scan: two inbound plain BLs, zero predicated BLs; body has eight
//! plain BL instructions, zero predicated BLs, and one virtual BLX.
//! Initializes the root, installs vtable 0x089a59a0, allocates an observable
//! array, initializes byte bounds to 127/0, then walks signed-count records.
//! Each record begins with a relative length word; its payload flags choose
//! a 36-byte or 44-byte resident item constructor. Invokes slot +0x4c before
//! appending the returned item. Reloads count and length after callbacks.
//! Deviations: existing Rust base/array/allocator ports replace direct BLs;
//! unported item constructors and append execute at verified resident addresses.
//! No class identity is inferred from the literal. Host tests inject those
//! resident operations into the same algorithm; pointer fields remain u32.

use super::observable_array::{framework_object_construct, observable_array_construct};

#[repr(C)]
pub struct RelativeRecordCollection {
    pub vtable: u32,
    pub items: u32,
    pub lower: u8,
    pub upper: u8,
    pub padding: [u8; 2],
}

struct Operations {
    allocate: unsafe extern "C" fn(usize) -> *mut u8,
    simple: unsafe extern "C" fn(*mut u8, *const u8) -> *mut u32,
    contextual: unsafe extern "C" fn(*mut u8, u32, *const u8, u32) -> *mut u32,
    initialize: unsafe fn(*mut u32),
    append: unsafe extern "C" fn(*mut RelativeRecordCollection, *mut u32),
}

unsafe fn initialize_item(item: *mut u32) {
    let vtable = item.read() as usize as *const u32;
    let method: unsafe extern "C" fn(*mut u32) = core::mem::transmute(vtable.add(19).read() as usize);
    method(item);
}

unsafe fn construct(
    storage: *mut RelativeRecordCollection, context: u32, records: *const u32,
    operations: &Operations,
) -> *mut RelativeRecordCollection {
    let collection = framework_object_construct(storage.cast()).cast::<RelativeRecordCollection>();
    core::ptr::addr_of_mut!((*collection).vtable).write(0x089a_59a0);
    let array = observable_array_construct((operations.allocate)(16).cast());
    core::ptr::addr_of_mut!((*collection).items).write(array as usize as u32);
    core::ptr::addr_of_mut!((*collection).lower).write(127);
    core::ptr::addr_of_mut!((*collection).upper).write(0);
    let mut record = records.add(1);
    let mut index = 0i32;
    while (records.read_volatile() as i32) > index {
        let payload = record.add(1).cast::<u8>();
        let item = if payload.read() & 0x20 == 0 {
            (operations.simple)((operations.allocate)(36), payload)
        } else {
            (operations.contextual)((operations.allocate)(44), context, payload, 0)
        };
        (operations.initialize)(item);
        (operations.append)(collection, item);
        let length = record.read_volatile();
        index = index.wrapping_add(1);
        record = (record as usize).wrapping_add(length as usize).wrapping_add(4) as *const u32;
    }
    collection
}

/// # Safety
/// Storage holds 12 writable bytes; records and resident item descriptors are
/// valid for the signed count and relative lengths. Allocations must succeed.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn relative_record_collection_construct(
    storage: *mut RelativeRecordCollection, context: u32, records: *const u32,
) -> *mut RelativeRecordCollection {
    #[cfg(target_os = "none")]
    let operations = Operations {
        allocate: crate::heap::veneers::operator_new,
        simple: core::mem::transmute(0x0818_61e4usize),
        contextual: core::mem::transmute(0x081b_9668usize),
        initialize: initialize_item,
        append: core::mem::transmute(0x0826_b784usize),
    };
    #[cfg(not(target_os = "none"))]
    let operations = Operations {
        allocate: crate::heap::veneers::operator_new,
        simple: host_simple,
        contextual: host_contextual,
        initialize: initialize_item,
        append: host_append,
    };
    construct(storage, context, records, &operations)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_simple(_: *mut u8, _: *const u8) -> *mut u32 {
    panic!("resident item constructor requires firmware")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_contextual(_: *mut u8, _: u32, _: *const u8, _: u32) -> *mut u32 {
    panic!("resident contextual item constructor requires firmware")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_append(_: *mut RelativeRecordCollection, _: *mut u32) {
    panic!("resident collection append requires firmware")
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use parking_lot::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());
    static mut SLAB: *mut u8 = core::ptr::null_mut();
    static mut OFFSET: usize = 0;
    static mut RECORDS: *mut u32 = core::ptr::null_mut();
    static mut EVENTS: std::vec::Vec<(u32, u32)> = std::vec::Vec::new();
    unsafe extern "C" fn allocate(size: usize) -> *mut u8 {
        EVENTS.push((0, size as u32));
        let pointer = SLAB.add(OFFSET);
        OFFSET += 64;
        pointer
    }
    unsafe extern "C" fn simple(storage: *mut u8, payload: *const u8) -> *mut u32 {
        EVENTS.push((1, payload.read() as u32));
        storage.cast::<u32>().write(11);
        storage.cast()
    }
    unsafe extern "C" fn contextual(storage: *mut u8, context: u32, payload: *const u8, extra: u32) -> *mut u32 {
        assert_eq!(extra, 0);
        EVENTS.push((2, context));
        assert_eq!(payload.read(), 0x20);
        storage.cast::<u32>().write(22);
        storage.cast()
    }
    unsafe fn initialize(item: *mut u32) {
        EVENTS.push((3, item.read()));
        item.write(item.read() + 1);
    }
    unsafe extern "C" fn append(collection: *mut RelativeRecordCollection, item: *mut u32) {
        EVENTS.push((4, item.read()));
        (*collection).upper += 1;
        // Mutate both the loop limit and the current record length: the next
        // iteration must observe the post-callback values, not cached inputs.
        if item.read() == 12 {
            RECORDS.write(2);
            RECORDS.add(1).write(12);
        }
    }
    #[test]
    fn signed_empty_counts_and_callback_modified_relative_walk() {
        let _guard = LOCK.lock();
        unsafe {
            SLAB = crate::testing::try_map_u32_slab(
                crate::testing::hints::RELATIVE_RECORD_COLLECTION_CONSTRUCT, 4096,
            ).expect("low-address collection allocation fixture");
            let operations = Operations { allocate, simple, contextual, initialize, append };
            let mut storage = RelativeRecordCollection {
                vtable: 0, items: 0, lower: 0, upper: 255, padding: [0xa5, 0x5a],
            };
            for count in [0u32, u32::MAX, 0x8000_0000] {
                EVENTS.clear(); OFFSET = 0;
                let records = [count];
                assert_eq!(construct(&mut storage, 77, records.as_ptr(), &operations), &mut storage as *mut _);
                assert_eq!((storage.vtable, storage.lower, storage.upper, storage.padding),
                    (0x089a_59a0, 127, 0, [0xa5, 0x5a]));
                assert_eq!(core::slice::from_raw_parts(storage.items as usize as *const u32, 4),
                    &[super::super::observable_array::OBSERVABLE_ARRAY_VTABLE, 0, 0, 0]);
                assert_eq!(EVENTS.as_slice(), &[(0, 16)]);
            }
            EVENTS.clear(); OFFSET = 0;
            let mut records = [1u32, 4, 0, 0xdead_beef, 0xdead_beef, 4, 0x20];
            RECORDS = records.as_mut_ptr();
            construct(&mut storage, 77, RECORDS, &operations);
            assert_eq!(storage.upper, 2);
            assert_eq!(EVENTS.as_slice(), &[
                (0, 16), (0, 36), (1, 0), (3, 11), (4, 12),
                (0, 44), (2, 77), (3, 22), (4, 23),
            ]);
        }
    }
}
