//! `silver_list_table_item` — original: `FUN_081473c0` @ 0x081473c0
//! (24 bytes, **all code — no literal-pool word**; **128 `bl` and 0 `b`
//! call sites**, binary-scanned by decoding every B/BL word in
//! `work/firmware/osos.dec`).
//!
//! The by-id accessor of the **Silver** framework's resource-backed item
//! table: the id-keyed map the table builds from its `"SLst"` resource,
//! indexed once and dereferenced.
//!
//! ```text
//! 081473c0  push {r0, r1, r4, lr}   @ spills item_id at [sp+4]
//! 081473c4  add  r1, sp, #4         @ &item_id  (the spilled copy)
//! 081473c8  add  r0, r0, #12        @ &this->items
//! 081473cc  bl   0x083db92c         @ map[key] -> &value
//! 081473d0  ldr  r0, [r0]           @ the value word
//! 081473d4  pop  {r2, r3, r4, pc}   @ drops the two scratch words
//! ```
//!
//! `push {r0, r1, ...}` is not a register save here — it is how ADS
//! carves the two-word scratch frame this function needs, and the
//! matching `pop {r2, r3, ...}` discards it. The only thing that
//! survives is that the *key is passed by pointer to a private copy*, so
//! the callee cannot disturb the caller's value.
//!
//! # The class this is a method of
//!
//! Its constructor is the very next function, `FUN_081473d8`
//! (`table, resource_id, populate`), and it lays the object out as:
//!
//! ```text
//! +0x00  vtable (0x08986434)
//! +0x04  resource_id          @ the ctor's r1
//! +0x08  0
//! +0x0c  items                @ the map this accessor indexes
//! +0x28  a handle whose vtable is 0x08b31810
//! +0x2c  2
//! ```
//!
//! When `populate` is nonzero the constructor runs `FUN_081472b0`, which
//! is what puts entries in the map:
//!
//! ```text
//! provider = FUN_0819fe10()
//! list     = load_resource_list(provider, resource_id, "SLst")   @ 0x08184fd4
//! for i in 0 .. list.count():                                    @ 0x08184f84
//!     record = list.at(i)->[8]                                   @ 0x08184f98
//!     item   = FUN_081e0bac(operator_new(0x5c), record[0],
//!                           record[1] & 0xff, record)
//!     item->[0x58] = table
//!     *map_value_slot(&table->items, &record[0]) = item          @ 0x083db92c
//! ```
//!
//! so the map is `record[0] -> 0x5c-byte item`, and this accessor is the
//! reader of exactly that map. The constructor then resolves
//! `("SCST", resource_id)` through the provider-tagged resource find
//! `FUN_0811ca58` and stores the result as the +0x28 handle.
//!
//! `"SLst"` (0x534c7374) and `"SCST"` (0x53435354) are both kinds in the
//! resource directory table @ 0x0840b1c0, alongside `IMAG`, `ITEM`,
//! `mTDL`, `SEVT`, `SIEM`, `SLyt`, `SORC`, `SSin`, `"Str "` and `TEVT`;
//! `SCST` and `SLst` carry the same record count, 0x95. The `S`-prefixed
//! kinds are the Silver UI framework's own — the image carries 159
//! distinct `TSilver*` mangled class names (`TSilverCntlr`,
//! `TSilverBridgeView`, 124 `TSilverCntlrTransitionAddon<T>`
//! instantiations, ...). The class's own name is **not** in the image:
//! its vtable literal 0x08986434 points at runtime data, and no
//! constructor in the family hands a name to the class-name factory. So
//! the port names the table for the resource kind it is built from
//! rather than inventing a class name.
//!
//! # The map
//!
//! `FUN_083db92c` (56 bytes; exactly 2 `bl` sites — this function and the
//! populator @ 0x08147328) is `operator[]` on an ordered associative
//! container:
//!
//! ```text
//! key   = *keyp
//! value_type pair = { key, 0 }               @ built on the stack
//! ret   = insert_unique(&pair)               @ 0x083c8aa8, pair<iter,bool>
//! return (char *)ret.first + 20              @ &node->second
//! ```
//!
//! `FUN_083c8aa8` is a textbook red-black `insert_unique`: it descends
//! from the header node at container +0x10 comparing `node + 16` through
//! the comparator at container +0x19, following the child words at
//! `node + 8` / `node + 12`. Hence the node layout `{color, parent, left,
//! right, key, value}` and the `+ 20` this accessor dereferences.
//!
//! **A miss is not free**: `operator[]` *inserts* a zero-valued entry for
//! an absent key, so this accessor grows the map on a miss and answers
//! NULL. The three stack-constructed callers (0x0816d418, 0x0816d440,
//! 0x08184010) ignore that; the 125 Silver controller call sites in
//! 0x0839f870..0x083b4xxx treat NULL as fatal — `movs r6, r0` followed
//! by `bleq 0x08030f44` (`heap_panic`).
//!
//! # Deviations
//!
//! - `FUN_083db92c` is **not ported** (its `insert_unique` pulls in the
//!   whole red-black tree), so it goes through the
//!   [`SILVER_LIST_TABLE_OPS`] `read_volatile` dispatch table (house
//!   pattern — see `cxx/string_object.rs`'s
//!   `STRING_OBJECT_ASSIGN_CSTR_OPS`). The wired default models an
//!   **empty** table: it hands back a shared always-NULL slot, so every
//!   lookup misses. This port is therefore **NOT HOOK-READY** until
//!   0x083db92c is ported — branching stock code here today would make
//!   every controller's item lookup panic.
//! - The port takes `item_id` by value and spills it into a local, which
//!   is exactly what the original's `push {r0, r1, ...}` +
//!   `add r1, sp, #4` does; the caller's register is never aliased.

/// Byte offset of the map inside the table (`add r0, r0, #12`), kept as
/// a named constant only for documentation — the port addresses the map
/// through the [`SilverListTable::items`] field.
pub const SILVER_LIST_TABLE_ITEMS_OFFSET: usize = 0x0c;

/// Byte offset of a node's value word inside the map's nodes, the `+ 20`
/// `FUN_083db92c` returns.
pub const SILVER_ITEM_MAP_NODE_VALUE_OFFSET: usize = 20;

/// The ordered map at table +0x0c, modeled down to the fields the
/// container implementation is observed to use. This accessor treats it
/// as opaque — only its address crosses the seam.
#[repr(C)]
pub struct SilverItemMap {
    /// +0x00..+0x0f: container state the constructor zeroes.
    pub reserved_00: [u32; 4],
    /// +0x10: the header/sentinel node `FUN_083c8404` allocates; its
    /// `next`/`prev` words at +8/+12 point back at itself when empty.
    pub header: *mut u8,
    /// +0x14: container state the constructor zeroes.
    pub reserved_14: u32,
    /// +0x18: the flag byte `FUN_083c8aa8` tests before splicing.
    pub allow_duplicates: u8,
    /// +0x19: the (empty) key comparator object.
    pub comparator: u8,
    /// +0x1a..+0x1b: padding to the container's word size.
    pub reserved_1a: [u8; 2],
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x10] = [0; core::mem::offset_of!(SilverItemMap, header)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x18] = [0; core::mem::offset_of!(SilverItemMap, allow_duplicates)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x19] = [0; core::mem::offset_of!(SilverItemMap, comparator)];

/// The `"SLst"`-backed item table, modeled down to the map this accessor
/// indexes. The fields past the map belong to the constructor
/// `FUN_081473d8` and are not touched here.
#[repr(C)]
pub struct SilverListTable {
    /// +0x00: the table's vtable (0x08986434 on device).
    pub vtable: *const u8,
    /// +0x04: the resource id both the `"SLst"` list and the `"SCST"`
    /// record are looked up under.
    pub resource_id: u32,
    /// +0x08: cleared by the constructor.
    pub reserved_08: u32,
    /// +0x0c: the `item_id -> item` map.
    pub items: SilverItemMap,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; SILVER_LIST_TABLE_ITEMS_OFFSET] =
    [0; core::mem::offset_of!(SilverListTable, items)];

/// Injection point for `FUN_083db92c`, the map's `operator[]`: the
/// address of the value word for `key`, inserting a zero-valued entry
/// when the key is absent.
pub type SilverItemMapValueSlot = unsafe extern "C" fn(
    map: *mut SilverItemMap,
    key: *const u32,
) -> *mut *mut u8;

/// The one unported retailOS dependency of [`silver_list_table_item`].
#[derive(Clone, Copy)]
pub struct SilverListTableOps {
    /// `FUN_083db92c` — `map[key]`, default-inserting.
    pub map_value_slot: SilverItemMapValueSlot,
}

/// The value slot [`unported_map_value_slot`] hands out. It stays NULL:
/// nothing in this crate writes through it.
static mut EMPTY_TABLE_VALUE_SLOT: *mut u8 = core::ptr::null_mut();

/// Wired default for [`SilverListTableOps::map_value_slot`]: models an
/// empty table, where every key misses and `operator[]` would return a
/// freshly zeroed value slot.
unsafe extern "C" fn unported_map_value_slot(
    _map: *mut SilverItemMap,
    _key: *const u32,
) -> *mut *mut u8 {
    core::ptr::addr_of_mut!(EMPTY_TABLE_VALUE_SLOT)
}

/// Wired defaults for [`SILVER_LIST_TABLE_OPS`].
pub const DEFAULT_SILVER_LIST_TABLE_OPS: SilverListTableOps =
    SilverListTableOps { map_value_slot: unported_map_value_slot };

/// Active model of the unported map indexer. Target integration replaces
/// the slot when 0x083db92c is ported; host tests install a real map.
pub static mut SILVER_LIST_TABLE_OPS: SilverListTableOps = DEFAULT_SILVER_LIST_TABLE_OPS;

#[inline(always)]
unsafe fn map_value_slot_op() -> SilverItemMapValueSlot {
    core::ptr::read_volatile(core::ptr::addr_of!(SILVER_LIST_TABLE_OPS.map_value_slot))
}

/// silver_list_table_item — original: `FUN_081473c0` @ 0x081473c0
/// (24 bytes; **128 `bl` call sites**, binary-scanned).
///
/// The item registered under `item_id` in this table's `"SLst"`-built
/// map, or NULL when the id is not in it.
///
/// The lookup goes through the map's default-inserting `operator[]`, so
/// a miss leaves a NULL-valued entry behind — the original's behavior,
/// reproduced rather than optimized away. There is no NULL guard on
/// `table`: the original computes `table + 12` and hands it straight to
/// the map.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn silver_list_table_item(
    table: *mut SilverListTable,
    item_id: u32,
) -> *mut u8 {
    let key = item_id;
    let slot = (map_value_slot_op())(
        core::ptr::addr_of_mut!((*table).items),
        core::ptr::addr_of!(key),
    );
    core::ptr::read_volatile(slot)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::ptr;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    static OPS_LOCK: Mutex<()> = Mutex::new(());

    /// A host stand-in for the ordered map: `(key, value)` pairs plus the
    /// map address each lookup was handed.
    static mut ENTRIES: Vec<(u32, *mut u8)> = Vec::new();
    static mut LOOKUPS: Vec<(*mut SilverItemMap, u32)> = Vec::new();

    fn entries() -> &'static mut Vec<(u32, *mut u8)> {
        unsafe { &mut *ptr::addr_of_mut!(ENTRIES) }
    }

    fn lookups() -> &'static mut Vec<(*mut SilverItemMap, u32)> {
        unsafe { &mut *ptr::addr_of_mut!(LOOKUPS) }
    }

    unsafe extern "C" fn mock_map_value_slot(
        map: *mut SilverItemMap,
        key: *const u32,
    ) -> *mut *mut u8 {
        let key = key.read();
        lookups().push((map, key));
        if let Some(index) = entries().iter().position(|(k, _)| *k == key) {
            return ptr::addr_of_mut!(entries()[index].1);
        }
        // operator[] default-inserts on a miss and returns the new slot.
        entries().push((key, ptr::null_mut()));
        let last = entries().len() - 1;
        ptr::addr_of_mut!(entries()[last].1)
    }

    unsafe fn install_map() -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        entries().clear();
        lookups().clear();
        SILVER_LIST_TABLE_OPS = SilverListTableOps { map_value_slot: mock_map_value_slot };
        guard
    }

    unsafe fn restore() {
        SILVER_LIST_TABLE_OPS = DEFAULT_SILVER_LIST_TABLE_OPS;
        entries().clear();
        lookups().clear();
    }

    fn table() -> SilverListTable {
        SilverListTable {
            vtable: 0x0898_6434usize as *const u8,
            resource_id: 0x0dad_05b8,
            reserved_08: 0,
            items: SilverItemMap {
                reserved_00: [0; 4],
                header: ptr::null_mut(),
                reserved_14: 0,
                allow_duplicates: 0,
                comparator: 0,
                reserved_1a: [0; 2],
            },
        }
    }

    #[test]
    fn a_registered_id_yields_its_item_and_indexes_the_embedded_map() {
        let mut table = table();
        let item = 0x1000_0000usize as *mut u8;

        unsafe {
            let guard = install_map();
            entries().push((0x0dad_05be, 0x2000_0000usize as *mut u8));
            entries().push((0x0dad_05bf, item));

            let found = silver_list_table_item(ptr::addr_of_mut!(table), 0x0dad_05bf);

            assert_eq!(found, item);
            assert_eq!(lookups().len(), 1, "exactly one map index per call");
            assert_eq!(
                lookups()[0],
                (ptr::addr_of_mut!(table.items), 0x0dad_05bf),
                "the map subobject is indexed, not the table"
            );
            assert_eq!(entries().len(), 2, "a hit inserts nothing");
            restore();
            drop(guard);
        }
    }

    #[test]
    fn a_missing_id_answers_null_and_leaves_the_default_inserted_entry() {
        let mut table = table();

        unsafe {
            let guard = install_map();
            entries().push((0x0dad_05bf, 0x1000_0000usize as *mut u8));

            let found = silver_list_table_item(ptr::addr_of_mut!(table), 0x0dad_0000);

            assert!(found.is_null(), "operator[] hands back a zeroed value slot");
            assert_eq!(
                entries().len(),
                2,
                "the miss grew the map — the original does not avoid that"
            );
            assert_eq!(entries()[1], (0x0dad_0000, ptr::null_mut()));
            restore();
            drop(guard);
        }
    }

    #[test]
    fn a_zero_id_is_an_ordinary_key() {
        // Nothing in the original special-cases 0; the id goes straight
        // into the map as a key like any other.
        let mut table = table();

        unsafe {
            let guard = install_map();
            entries().push((0, 0x3000_0000usize as *mut u8));

            let found = silver_list_table_item(ptr::addr_of_mut!(table), 0);

            assert_eq!(found, 0x3000_0000usize as *mut u8);
            assert_eq!(lookups()[0].1, 0);
            restore();
            drop(guard);
        }
    }

    #[test]
    fn the_key_crosses_the_seam_by_pointer_to_a_private_copy() {
        // `push {r0, r1, ...}` + `add r1, sp, #4`: the callee reads the
        // key through a pointer, and that pointer is never the caller's.
        static mut SEEN: *const u32 = ptr::null();
        static mut SEEN_VALUE: u32 = 0;

        unsafe extern "C" fn capture(
            _map: *mut SilverItemMap,
            key: *const u32,
        ) -> *mut *mut u8 {
            SEEN = key;
            SEEN_VALUE = key.read();
            ptr::addr_of_mut!(EMPTY_TABLE_VALUE_SLOT)
        }

        let mut table = table();
        let caller_owned: u32 = 0x0dad_05bf;

        unsafe {
            let guard = OPS_LOCK.lock().unwrap_or_else(|p| p.into_inner());
            SILVER_LIST_TABLE_OPS = SilverListTableOps { map_value_slot: capture };

            let found = silver_list_table_item(ptr::addr_of_mut!(table), caller_owned);

            assert!(found.is_null());
            assert_eq!(SEEN_VALUE, caller_owned, "the key arrives by value, intact");
            assert_ne!(
                SEEN,
                ptr::addr_of!(caller_owned),
                "the callee sees a private spill, not the caller's storage"
            );
            restore();
            drop(guard);
        }
    }

    #[test]
    fn the_wired_default_models_an_empty_table() {
        let mut table = table();

        unsafe {
            let guard = OPS_LOCK.lock().unwrap_or_else(|p| p.into_inner());
            SILVER_LIST_TABLE_OPS = DEFAULT_SILVER_LIST_TABLE_OPS;

            assert!(silver_list_table_item(ptr::addr_of_mut!(table), 0x0dad_05bf).is_null());
            assert!(silver_list_table_item(ptr::addr_of_mut!(table), 0).is_null());
            drop(guard);
        }
    }
}
