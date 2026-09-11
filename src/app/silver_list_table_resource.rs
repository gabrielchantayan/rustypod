//! `silver_list_table_process_resource` — original: `FUN_0812d7bc` @
//! **0x0812d7bc** (68 bytes, all code; the next function starts at
//! 0x0812d800). A complete ARM B/BL scan finds **10 `bl` call sites**, all
//! unconditional; there are no predicated BL forms or direct tail branches.
//!
//! Allocates a 0x30-byte [`SilverListTable`], constructs and populates it for
//! `resource_id`, processes every populated item through `FUN_08147360`, then
//! tail-dispatches the table's virtual destructor at vtable +4. The first
//! ABI argument is passed at every call site but is dead: the 17 instruction
//! words never read r0 before overwriting it with 0x30 for `operator_new`.
//!
//! The NULL comparison follows both the constructor and item processor; it is
//! therefore only a destructor guard, not an allocation-failure guard. A NULL
//! allocator result faults in the constructor before the compare, exactly as
//! the retail body does.
//!
//! # Deliberate deviations
//!
//! `FUN_08147360` is unported, so the target default calls its verified load
//! address directly. The vtable +4 word at 0x08986438 is 0x4015622b in this
//! image, which is not a decodable osos function entry; its identity is not
//! invented here and the original virtual dispatch is retained. The operation
//! table makes those two boundaries, plus allocation and construction,
//! replaceable by host tests; target defaults call the existing Rust ports for
//! `operator_new` and `silver_list_table_ctor` directly.

use crate::app::silver_list_table::{silver_list_table_ctor, SilverListTable};

/// RetailOS dependencies of [`silver_list_table_process_resource`].
///
/// `process` is `FUN_08147360`, which walks the table's populated map and
/// invokes `FUN_081e06f4` on each item. `destroy` is the table vtable's +4
/// slot; its concrete target is the runtime anomaly documented above.
#[derive(Clone, Copy)]
pub struct SilverListTableResourceOps {
    pub allocate: unsafe extern "C" fn(usize) -> *mut u8,
    pub construct: unsafe extern "C" fn(*mut SilverListTable, u32, i32) -> *mut SilverListTable,
    pub process: unsafe extern "C" fn(*mut SilverListTable, u32),
    pub destroy: unsafe extern "C" fn(*mut SilverListTable) -> *mut SilverListTable,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_process(table: *mut SilverListTable, resource_id: u32) {
    let process: unsafe extern "C" fn(*mut SilverListTable, u32) =
        unsafe { core::mem::transmute(0x0814_7360usize) };
    unsafe { process(table, resource_id) }
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_destroy(table: *mut SilverListTable) -> *mut SilverListTable {
    let destroy_address = unsafe { ((*(table)).vtable as *const u32).add(1).read() };
    let destroy: unsafe extern "C" fn(*mut SilverListTable) -> *mut SilverListTable =
        unsafe { core::mem::transmute(destroy_address as usize) };
    unsafe { destroy(table) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_process(_table: *mut SilverListTable, _resource_id: u32) {
    panic!("silver_list_table_process_resource requires item processor 0x08147360")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_destroy(_table: *mut SilverListTable) -> *mut SilverListTable {
    panic!("silver_list_table_process_resource requires the table vtable +4 destructor")
}

/// Target defaults retain the original direct calls and virtual dispatch.
#[cfg(target_os = "none")]
pub const DEFAULT_SILVER_LIST_TABLE_RESOURCE_OPS: SilverListTableResourceOps =
    SilverListTableResourceOps {
        allocate: crate::heap::veneers::operator_new,
        construct: silver_list_table_ctor,
        process: firmware_process,
        destroy: firmware_destroy,
    };

/// Host defaults expose dependencies that cannot run without retail resources.
#[cfg(not(target_os = "none"))]
pub const DEFAULT_SILVER_LIST_TABLE_RESOURCE_OPS: SilverListTableResourceOps =
    SilverListTableResourceOps {
        allocate: crate::heap::veneers::operator_new,
        construct: silver_list_table_ctor,
        process: missing_process,
        destroy: missing_destroy,
    };

/// Active dependencies. Firmware integration leaves the target defaults in
/// place; host tests replace the whole table with deterministic fixtures.
pub static mut SILVER_LIST_TABLE_RESOURCE_OPS: SilverListTableResourceOps =
    DEFAULT_SILVER_LIST_TABLE_RESOURCE_OPS;

#[inline(always)]
unsafe fn resource_ops() -> SilverListTableResourceOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(SILVER_LIST_TABLE_RESOURCE_OPS)) }
}

/// `silver_list_table_process_resource` — original: `FUN_0812d7bc` @
/// **0x0812d7bc** (68 bytes, all code; **10 unconditional `bl` call
/// sites**, binary-scanned).
///
/// Creates a populated 0x30-byte Silver list table for `resource_id`, runs the
/// table item processor, and returns the value supplied by its virtual
/// destructor. `context` is ABI-preserved but deliberately unused: raw ARM
/// overwrites r0 before its first call and never reloads it.
///
/// The item processor receives its third retail ABI argument as 1 because the
/// preceding constructor call leaves r2 unchanged. Its decompiled prototype
/// drops that argument, but its raw body never reads r2; this port exposes the
/// two arguments actually consumed.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn silver_list_table_process_resource(
    _context: *mut u8,
    resource_id: u32,
) -> *mut SilverListTable {
    let ops = unsafe { resource_ops() };
    let table = (ops.allocate)(0x30) as *mut SilverListTable;
    let table = (ops.construct)(table, resource_id, 1);
    (ops.process)(table, resource_id);
    if table.is_null() {
        return core::ptr::null_mut();
    }
    unsafe { (ops.destroy)(table) }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::app::silver_list_table::SilverItemMap;
    use core::ptr;
    use core::sync::atomic::{AtomicU32, Ordering};
    use std::boxed::Box;
    use parking_lot::Mutex;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static EVENTS: AtomicU32 = AtomicU32::new(0);
    static RESOURCE_ID: AtomicU32 = AtomicU32::new(0);

    unsafe extern "C" fn allocate(size: usize) -> *mut u8 {
        assert_eq!(size, 0x30);
        assert_eq!(EVENTS.load(Ordering::SeqCst), 0);
        EVENTS.store(1, Ordering::SeqCst);
        Box::into_raw(Box::new(SilverListTable {
            vtable: ptr::null(),
            resource_id: 0,
            reserved_08: 0,
            items: SilverItemMap {
                reserved_00: [0; 4],
                header: ptr::null_mut(),
                reserved_14: 0,
                allow_duplicates: 0,
                comparator: 0,
                reserved_1a: [0; 2],
            },
            name: ptr::null_mut(),
            state: 0,
        })) as *mut u8
    }

    unsafe extern "C" fn construct(
        table: *mut SilverListTable,
        resource_id: u32,
        populate: i32,
    ) -> *mut SilverListTable {
        assert_eq!(EVENTS.load(Ordering::SeqCst), 1);
        assert_eq!(populate, 1);
        (*table).resource_id = resource_id;
        RESOURCE_ID.store(resource_id, Ordering::SeqCst);
        EVENTS.store(12, Ordering::SeqCst);
        table
    }

    unsafe extern "C" fn process(table: *mut SilverListTable, resource_id: u32) {
        assert_eq!(EVENTS.load(Ordering::SeqCst), 12);
        assert_eq!((*table).resource_id, resource_id);
        assert_eq!(RESOURCE_ID.load(Ordering::SeqCst), resource_id);
        EVENTS.store(123, Ordering::SeqCst);
    }

    unsafe extern "C" fn destroy(table: *mut SilverListTable) -> *mut SilverListTable {
        assert_eq!(EVENTS.load(Ordering::SeqCst), 123);
        EVENTS.store(1234, Ordering::SeqCst);
        unsafe { drop(Box::from_raw(table)) };
        table
    }

    #[test]
    fn constructs_processes_and_destroys_one_resource_table() {
        let _guard = OPS_LOCK.lock();
        let saved = unsafe { SILVER_LIST_TABLE_RESOURCE_OPS };
        unsafe {
            SILVER_LIST_TABLE_RESOURCE_OPS = SilverListTableResourceOps {
                allocate,
                construct,
                process,
                destroy,
            };
        }
        EVENTS.store(0, Ordering::SeqCst);
        let result = unsafe {
            silver_list_table_process_resource(usize::MAX as *mut u8, 0x0dad_035c)
        };
        assert!(!result.is_null());
        assert_eq!(EVENTS.load(Ordering::SeqCst), 1234);
        assert_eq!(RESOURCE_ID.load(Ordering::SeqCst), 0x0dad_035c);
        unsafe { SILVER_LIST_TABLE_RESOURCE_OPS = saved };
    }
}
