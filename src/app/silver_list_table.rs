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
//! +0x28  name                 @ an ADS COW `basic_string` word: built
//!                             empty (the shared empty rep's data,
//!                             0x08b31810), then assigned the resolved
//!                             `"SCST"` record's bytes
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
//! reader of exactly that map.
//!
//! The constructor then resolves `("SCST", resource_id)` through the
//! provider-tagged resource find `FUN_0811ca58` into a borrowed
//! `(byte_length, bytes)` record and assigns the bytes to the +0x28
//! string; a failed resolution is fatal (`heap_panic`).
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

/// Byte offset of the name string inside the table (`str r1, [r5, #40]`),
/// where the constructor plants the empty-rep data pointer 0x08b31810.
pub const SILVER_LIST_TABLE_NAME_OFFSET: usize = 0x28;

/// Byte offset of the state word the constructor sets to 2
/// (`mov r0, #2; str r0, [r5, #44]`).
pub const SILVER_LIST_TABLE_STATE_OFFSET: usize = 0x2c;

/// The value the constructor stores at [`SILVER_LIST_TABLE_STATE_OFFSET`].
pub const SILVER_LIST_TABLE_STATE_INIT: u32 = 2;

/// The resource kind whose record names the table: the ADS
/// multi-character literal `'SCST'` (0x53435354) in the constructor's
/// literal pool @ 0x081474b4, looked up through the tagged resolver.
pub const SILVER_LIST_NAME_TAG: u32 = 0x5343_5354;

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
/// indexes and the two words the constructor [`silver_list_table_ctor`]
/// writes past it.
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
    /// +0x28: the table's resource name, an ADS COW `basic_string` word
    /// (a pointer into the string rep's data). The constructor builds it
    /// empty, then assigns the `"SCST"` record's resolved bytes.
    pub name: *mut u8,
    /// +0x2c: set to 2 by the constructor; nothing in the family
    /// re-writes it.
    pub state: u32,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; SILVER_LIST_TABLE_ITEMS_OFFSET] =
    [0; core::mem::offset_of!(SilverListTable, items)];
#[cfg(target_pointer_width = "32")]
const _: [u8; SILVER_LIST_TABLE_NAME_OFFSET] =
    [0; core::mem::offset_of!(SilverListTable, name)];
#[cfg(target_pointer_width = "32")]
const _: [u8; SILVER_LIST_TABLE_STATE_OFFSET] =
    [0; core::mem::offset_of!(SilverListTable, state)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x30] = [0; core::mem::size_of::<SilverListTable>()];

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

/// The retailOS dependencies of [`silver_list_table_ctor`].
///
/// `map_header_alloc` (`FUN_083c8404`), `populate` (`FUN_081472b0`) and
/// `registry` (`FUN_0819fdb0`) are unported; `resolve` (`FUN_0811ca58`,
/// ported as [`crate::app::string_resolve::app_string_resolver_resolve`])
/// and `fail` (`FUN_08030f44`, ported as
/// [`crate::heap::veneers::heap_panic`]) sit behind the seam anyway — the
/// same call-boundary decision [`crate::app::event_list`] makes for this
/// exact dependency triple — so the constructor is hook-ready on device
/// without wiring `APP_STRING_RESOLVE_OPS`, and the fatal path is
/// observable in host tests.
#[derive(Clone, Copy)]
pub struct SilverListTableCtorOps {
    /// `FUN_083c8404` — allocates the map's header/sentinel node from the
    /// container's embedded chunk pool (initial chunk 32 nodes, 1.625x
    /// growth). Returns the uninitialized node.
    pub map_header_alloc: unsafe extern "C" fn(map: *mut SilverItemMap) -> *mut u8,
    /// `FUN_081472b0` — loads the `"SLst"` resource list for
    /// `table.resource_id` and inserts one 0x5c-byte item per record.
    pub populate: unsafe extern "C" fn(table: *mut SilverListTable),
    /// `FUN_0819fdb0` — the tagged string registry getter: the
    /// `FUN_0819fe10` provider's `+4` object, or NULL.
    pub registry: unsafe extern "C" fn() -> *mut u8,
    /// `FUN_0811ca58` — the tagged resolver. Resolves `value` under
    /// `tag`; on success writes the record's byte length through
    /// `length_out` and returns its bytes, on failure returns NULL.
    pub resolve: unsafe extern "C" fn(
        registry: *mut u8,
        tag: u32,
        value: u32,
        length_out: *mut u32,
    ) -> *const u8,
    /// `FUN_08030f44` (`heap_panic`) — retailOS's failed-resolution path;
    /// it does not return. Host test replacements may return, in which
    /// case the constructor stops at the failed resolution.
    pub fail: unsafe extern "C" fn(),
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_map_header_alloc(map: *mut SilverItemMap) -> *mut u8 {
    let alloc: unsafe extern "C" fn(*mut SilverItemMap) -> *mut u8 =
        unsafe { core::mem::transmute(0x083c_8404usize) };
    unsafe { alloc(map) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_map_header_alloc(_map: *mut SilverItemMap) -> *mut u8 {
    panic!("silver_list_table_ctor requires map node allocator 0x083c8404")
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_silver_list_populate(table: *mut SilverListTable) {
    let populate: unsafe extern "C" fn(*mut SilverListTable) =
        unsafe { core::mem::transmute(0x0814_72b0usize) };
    unsafe { populate(table) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_silver_list_populate(_table: *mut SilverListTable) {
    panic!("silver_list_table_ctor requires SLst populator 0x081472b0")
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_silver_registry() -> *mut u8 {
    let getter: unsafe extern "C" fn() -> *mut u8 = unsafe { core::mem::transmute(0x0819_fdb0usize) };
    unsafe { getter() }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_silver_registry() -> *mut u8 {
    panic!("silver_list_table_ctor requires registry getter 0x0819fdb0")
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_silver_resolve(
    registry: *mut u8,
    tag: u32,
    value: u32,
    length_out: *mut u32,
) -> *const u8 {
    let resolve: unsafe extern "C" fn(*mut u8, u32, u32, *mut u32) -> *const u8 =
        unsafe { core::mem::transmute(0x0811_ca58usize) };
    unsafe { resolve(registry, tag, value, length_out) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_silver_resolve(
    _registry: *mut u8,
    _tag: u32,
    _value: u32,
    _length_out: *mut u32,
) -> *const u8 {
    panic!("silver_list_table_ctor requires tagged resolver 0x0811ca58")
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_silver_fail() {
    let fail: unsafe extern "C" fn() -> ! = unsafe { core::mem::transmute(0x0803_0f44usize) };
    unsafe { fail() }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_silver_fail() {
    panic!("silver_list_table_ctor encountered an unresolved SCST record")
}

/// Wired defaults for [`SILVER_LIST_TABLE_CTOR_OPS`].
#[cfg(target_os = "none")]
pub const DEFAULT_SILVER_LIST_TABLE_CTOR_OPS: SilverListTableCtorOps =
    SilverListTableCtorOps {
        map_header_alloc: firmware_map_header_alloc,
        populate: firmware_silver_list_populate,
        registry: firmware_silver_registry,
        resolve: firmware_silver_resolve,
        fail: firmware_silver_fail,
    };

/// Wired defaults for [`SILVER_LIST_TABLE_CTOR_OPS`].
#[cfg(not(target_os = "none"))]
pub const DEFAULT_SILVER_LIST_TABLE_CTOR_OPS: SilverListTableCtorOps =
    SilverListTableCtorOps {
        map_header_alloc: missing_map_header_alloc,
        populate: missing_silver_list_populate,
        registry: missing_silver_registry,
        resolve: missing_silver_resolve,
        fail: missing_silver_fail,
    };

/// Active model of the constructor's retailOS dependencies. Target
/// integration replaces the slots as 0x083c8404 / 0x081472b0 /
/// 0x0819fdb0 are ported; host tests install recording mocks.
pub static mut SILVER_LIST_TABLE_CTOR_OPS: SilverListTableCtorOps =
    DEFAULT_SILVER_LIST_TABLE_CTOR_OPS;

#[inline(always)]
unsafe fn ctor_ops() -> SilverListTableCtorOps {
    core::ptr::read_volatile(core::ptr::addr_of!(SILVER_LIST_TABLE_CTOR_OPS))
}

/// silver_list_table_ctor — original: `FUN_081473d8` @ 0x081473d8
/// (**224 bytes**: 212 of code plus the three-word literal pool Ghidra's
/// 212-byte extent drops — vtable 0x08986434 @ 0x081474ac, empty-rep data
/// 0x08b31810 @ 0x081474b0, `'SCST'` 0x53435354 @ 0x081474b4; the next
/// function opens `push {r4, lr}` @ 0x081474b8. **132 `bl` and 0 `b`
/// call sites**, binary-scanned by decoding every B/BL word in
/// `work/firmware/osos.dec`; all 132 are unconditional `bl`).
///
/// The two-argument form of the class constructor (this, resource_id,
/// populate) for the `"SLst"`-backed item table
/// [`silver_list_table_item`] reads:
///
/// 1. Plants the vtable 0x08986434 at +0x00, `resource_id` at +0x04 and
///    zeroes +0x08 and the whole embedded map at +0x0c (pool words,
///    header word, flag byte +0x24, comparator byte +0x25).
/// 2. Allocates the map's header node through the container's embedded
///    chunk-pool allocator `FUN_083c8404` and links it as the empty
///    sentinel: `header->+4 = 0`, `header->+8 = header`,
///    `header->+12 = header` (parent, left, right in the red-black node
///    layout `FUN_083c8aa8` descends).
/// 3. Stores 2 at +0x2c, parks the +0x28 COW string on the shared empty
///    rep, and — only when `populate` is nonzero — runs `FUN_081472b0`,
///    which fills the map from the `"SLst"` resource list.
/// 4. Resolves `("SCST", resource_id)` through the registry from
///    `FUN_0819fdb0` and the tagged resolver `FUN_0811ca58`, re-reading
///    `resource_id` from the object *after* the populator ran. A failed
///    resolution calls `heap_panic`, which does not return.
/// 5. Builds a temporary COW string from the resolved `(length, bytes)`
///    record, assigns it to the +0x28 name and releases the temporary.
///
/// Returns `this`.
///
/// # Deviations
///
/// - The empty name parks on the crate's own shared empty rep
///   ([`crate::cxx::string::empty_rep_data`]) rather than the firmware
///   word 0x08b31810 — the standing `cxx/string.rs` deviation; every
///   crate string consumer shares that rep.
/// - The string temporary is zero-initialized where the original passes
///   the saved-`resource_id` stack word: `cxx_string_from_buffer` never
///   reads the slot's old value, so the difference is unobservable.
/// - `resolve`/`fail` ride the [`SILVER_LIST_TABLE_CTOR_OPS`] seam even
///   though both are ported (see its docs); the string construction,
///   assignment and release call the ported `cxx/string.rs` functions
///   directly.
///
/// There is no NULL guard on `table`: the original writes the vtable
/// through `r0` unconditionally.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn silver_list_table_ctor(
    table: *mut SilverListTable,
    resource_id: u32,
    populate: i32,
) -> *mut SilverListTable {
    let ops = ctor_ops();
    (*table).vtable = 0x0898_6434usize as *const u8;
    (*table).resource_id = resource_id;
    (*table).reserved_08 = 0;
    (*table).items = SilverItemMap {
        reserved_00: [0; 4],
        header: core::ptr::null_mut(),
        reserved_14: 0,
        allow_duplicates: 0,
        comparator: 0,
        reserved_1a: [0; 2],
    };
    let header = (ops.map_header_alloc)(core::ptr::addr_of_mut!((*table).items));
    (*table).items.header = header;
    let words = header as *mut u32;
    words.add(1).write(0);
    words.add(2).write(header as usize as u32);
    words.add(3).write(header as usize as u32);
    (*table).state = SILVER_LIST_TABLE_STATE_INIT;
    (*table).name = crate::cxx::string::empty_rep_data();
    if populate != 0 {
        (ops.populate)(table);
    }
    let registry = (ops.registry)();
    let mut length: u32 = 0;
    // The original re-reads +0x04 after the populator ran; keep the
    // reload so a populator that rewrites resource_id is honored.
    let bytes = (ops.resolve)(
        registry,
        SILVER_LIST_NAME_TAG,
        (*table).resource_id,
        core::ptr::addr_of_mut!(length),
    );
    if bytes.is_null() {
        (ops.fail)();
        // heap_panic does not return; a swapped-in host hook may, in
        // which case construction stops at the failed resolution.
        return table;
    }
    let mut temporary: *mut u8 = core::ptr::null_mut();
    crate::cxx::string::cxx_string_from_buffer(
        core::ptr::addr_of_mut!(temporary),
        bytes,
        length,
    );
    crate::cxx::string::cxx_string_assign(
        core::ptr::addr_of_mut!((*table).name),
        core::ptr::addr_of!(temporary),
    );
    crate::cxx::string::cxx_string_release(core::ptr::addr_of_mut!(temporary));
    table
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
            name: ptr::null_mut(),
            state: 0,
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

    // ---- silver_list_table_ctor ----

    use crate::heap::types::{HeapDescriptor, HeapDescriptorDescriptor};
    use crate::heap::veneers::HEAP_OPS;

    /// The borrowed record the mock resolver hands out: byte length
    /// through the output slot, bytes as the return value.
    static RESOLVED_NAME: &[u8] = b"silver.list.table.main";

    /// The header node `FUN_083c8404` would carve out of the map's
    /// embedded chunk pool. 16 bytes cover the three words the
    /// constructor links; the ctor never dereferences the links, so a
    /// plain aligned buffer stands in for the pool node.
    #[repr(C, align(4))]
    struct HeaderNode([u32; 4]);
    static mut HEADER_NODE: HeaderNode = HeaderNode([0xdead_beef; 4]);

    /// Bump arena backing the real COW string construction — the shared
    /// heap mock hands out fixed fake addresses that cannot be written
    /// (cxx/string.rs's test pattern).
    const CTOR_ARENA_SIZE: usize = 4096;
    #[repr(C, align(8))]
    struct CtorArena([u8; CTOR_ARENA_SIZE]);
    static mut CTOR_ARENA: CtorArena = CtorArena([0; CTOR_ARENA_SIZE]);
    static mut CTOR_ARENA_USED: usize = 0;

    unsafe extern "C" fn ctor_arena_alloc(
        _heap: *mut HeapDescriptorDescriptor,
        size: usize,
        _tag: usize,
    ) -> *mut u8 {
        let used = CTOR_ARENA_USED;
        let aligned = (size + 7) & !7;
        if used + aligned > CTOR_ARENA_SIZE {
            return ptr::null_mut();
        }
        CTOR_ARENA_USED = used + aligned;
        ptr::addr_of_mut!(CTOR_ARENA.0).cast::<u8>().add(used)
    }

    unsafe extern "C" fn ctor_arena_free(
        _heap: *mut HeapDescriptorDescriptor,
        _ptr: *mut u8,
        _tag: usize,
    ) {
    }

    unsafe extern "C" fn ctor_arena_create(
        desc: *mut HeapDescriptor,
        _start: *mut u8,
        _size: usize,
    ) -> *mut HeapDescriptorDescriptor {
        desc as *mut HeapDescriptorDescriptor
    }

    /// Dependency call log, in order.
    static mut EVENTS: Vec<&'static str> = Vec::new();
    static mut ALLOC_SEEN_MAP: *mut SilverItemMap = ptr::null_mut();
    static mut POPULATE_SEEN: *mut SilverListTable = ptr::null_mut();
    static mut RESOLVE_SEEN: (*mut u8, u32, u32) = (ptr::null_mut(), 0, 0);
    static mut REGISTRY_OBJECT: [u8; 8] = [0; 8];
    /// When set, the mock populator rewrites the table's resource_id,
    /// proving the constructor re-reads +0x04 after populating.
    static mut POPULATE_REWRITE_ID: u32 = 0;

    fn events() -> &'static mut Vec<&'static str> {
        unsafe { &mut *ptr::addr_of_mut!(EVENTS) }
    }

    unsafe extern "C" fn mock_header_alloc(map: *mut SilverItemMap) -> *mut u8 {
        events().push("alloc");
        ALLOC_SEEN_MAP = map;
        ptr::addr_of_mut!(HEADER_NODE).cast::<u8>()
    }

    unsafe extern "C" fn mock_populate(table: *mut SilverListTable) {
        events().push("populate");
        POPULATE_SEEN = table;
        if POPULATE_REWRITE_ID != 0 {
            (*table).resource_id = POPULATE_REWRITE_ID;
        }
    }

    unsafe extern "C" fn mock_registry() -> *mut u8 {
        events().push("registry");
        ptr::addr_of_mut!(REGISTRY_OBJECT).cast::<u8>()
    }

    unsafe extern "C" fn mock_resolve(
        registry: *mut u8,
        tag: u32,
        value: u32,
        length_out: *mut u32,
    ) -> *const u8 {
        events().push("resolve");
        RESOLVE_SEEN = (registry, tag, value);
        length_out.write(RESOLVED_NAME.len() as u32);
        RESOLVED_NAME.as_ptr()
    }

    unsafe extern "C" fn mock_resolve_miss(
        _registry: *mut u8,
        _tag: u32,
        _value: u32,
        _length_out: *mut u32,
    ) -> *const u8 {
        events().push("resolve");
        ptr::null()
    }

    unsafe extern "C" fn mock_fail() {
        // heap_panic does not return; this host mock does, so the ctor's
        // documented stop-at-the-failed-resolution path runs.
        events().push("fail");
    }

    /// Serializes both ops tables and the heap arena: mine first, then
    /// the heap lock (never a second guard of the same lock in one test).
    unsafe fn install_ctor(hit: bool) -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        events().clear();
        ALLOC_SEEN_MAP = ptr::null_mut();
        POPULATE_SEEN = ptr::null_mut();
        RESOLVE_SEEN = (ptr::null_mut(), 0, 0);
        POPULATE_REWRITE_ID = 0;
        SILVER_LIST_TABLE_CTOR_OPS = SilverListTableCtorOps {
            map_header_alloc: mock_header_alloc,
            populate: mock_populate,
            registry: mock_registry,
            resolve: if hit { mock_resolve } else { mock_resolve_miss },
            fail: mock_fail,
        };
        guard
    }

    unsafe fn restore_ctor() {
        SILVER_LIST_TABLE_CTOR_OPS = DEFAULT_SILVER_LIST_TABLE_CTOR_OPS;
        events().clear();
    }

    fn install_arena() -> MutexGuard<'static, ()> {
        let guard = crate::heap::veneers::tests::mock_heap();
        unsafe {
            CTOR_ARENA_USED = 0;
            let ops = ptr::addr_of_mut!(HEAP_OPS);
            (*ops).alloc = ctor_arena_alloc;
            (*ops).free = ctor_arena_free;
            (*ops).create = ctor_arena_create;
        }
        guard
    }

    unsafe fn name_bytes(name: *mut u8) -> &'static [u8] {
        let rep = crate::cxx::string::data_rep(name);
        core::slice::from_raw_parts(name, (*rep).length as usize)
    }

    #[test]
    fn ctor_initializes_every_word_and_links_the_empty_map_sentinel() {
        let mut table = table();
        table.vtable = ptr::null();
        table.resource_id = 0;
        table.state = 0xffff_ffff;

        unsafe {
            let guard = install_ctor(true);
            let _heap = install_arena();

            let built = silver_list_table_ctor(ptr::addr_of_mut!(table), 0x0dad_05b8, 1);

            assert_eq!(built, ptr::addr_of_mut!(table), "the ctor returns this");
            assert_eq!(table.vtable, 0x0898_6434usize as *const u8, "vtable @ +0x00");
            assert_eq!(table.resource_id, 0x0dad_05b8, "resource_id @ +0x04");
            assert_eq!(table.reserved_08, 0, "+0x08 cleared");
            assert_eq!(table.items.reserved_00, [0; 4], "map pool words cleared");
            assert_eq!(table.items.reserved_14, 0);
            assert_eq!(table.items.allow_duplicates, 0, "flag byte +0x24 cleared");
            assert_eq!(table.items.comparator, 0, "comparator byte +0x25 cleared");

            let header = ptr::addr_of_mut!(HEADER_NODE).cast::<u8>();
            assert_eq!(table.items.header, header, "the pool-allocated node is the header");
            let words = HEADER_NODE.0;
            assert_eq!(words[0], 0xdead_beef, "the ctor does not touch node +0 (color)");
            assert_eq!(words[1], 0, "header +4 (parent) cleared");
            assert_eq!(words[2], header as usize as u32, "header +8 (left) self-links");
            assert_eq!(words[3], header as usize as u32, "header +12 (right) self-links");

            assert_eq!(table.state, SILVER_LIST_TABLE_STATE_INIT, "+0x2c set to 2");
            assert_eq!(name_bytes(table.name), RESOLVED_NAME, "the SCST record names the table");
            assert_ne!(table.name, crate::cxx::string::empty_rep_data());

            assert_eq!(
                events().as_slice(),
                ["alloc", "populate", "registry", "resolve"],
                "alloc -> populate -> registry -> resolve, in the original's order"
            );
            assert_eq!(ALLOC_SEEN_MAP, ptr::addr_of_mut!(table.items));
            assert_eq!(POPULATE_SEEN, ptr::addr_of_mut!(table));
            assert_eq!(
                RESOLVE_SEEN,
                (
                    ptr::addr_of_mut!(REGISTRY_OBJECT).cast::<u8>(),
                    SILVER_LIST_NAME_TAG,
                    0x0dad_05b8
                ),
                "the registry object resolves 'SCST' under resource_id"
            );
            restore_ctor();
            drop(guard);
        }
    }

    #[test]
    fn ctor_with_zero_populate_skips_the_slst_load_but_still_resolves() {
        let mut table = table();

        unsafe {
            let guard = install_ctor(true);
            let _heap = install_arena();

            silver_list_table_ctor(ptr::addr_of_mut!(table), 0x0dad_05b8, 0);

            assert_eq!(
                events().as_slice(),
                ["alloc", "registry", "resolve"],
                "no populate call when the flag is zero"
            );
            assert_eq!(name_bytes(table.name), RESOLVED_NAME);
            restore_ctor();
            drop(guard);
        }
    }

    #[test]
    fn ctor_treats_any_nonzero_populate_as_true() {
        // `cmp r7, #0` + `blne`: the flag is a truthiness test, not a
        // comparison against 1.
        let mut table = table();

        unsafe {
            let guard = install_ctor(true);
            let _heap = install_arena();

            silver_list_table_ctor(ptr::addr_of_mut!(table), 0x0dad_05b8, -1);

            assert!(events().contains(&"populate"), "-1 populates");
            restore_ctor();
            drop(guard);
        }
    }

    #[test]
    fn ctor_resolves_the_id_the_populator_left_behind() {
        // The original re-reads [r5, #4] after FUN_081472b0 ran
        // (ldr r2, [r5, #4] @ 0x08147460), so a populator that rewrites
        // resource_id changes what 'SCST' resolves.
        let mut table = table();

        unsafe {
            let guard = install_ctor(true);
            let _heap = install_arena();
            POPULATE_REWRITE_ID = 0x0dad_9999;

            silver_list_table_ctor(ptr::addr_of_mut!(table), 0x0dad_05b8, 1);

            assert_eq!(table.resource_id, 0x0dad_9999);
            assert_eq!(RESOLVE_SEEN.2, 0x0dad_9999, "resolve sees the reloaded id");
            restore_ctor();
            drop(guard);
        }
    }

    #[test]
    fn ctor_failed_resolution_is_fatal_and_builds_no_string() {
        let mut table = table();

        unsafe {
            let guard = install_ctor(false);
            let _heap = install_arena();

            let built = silver_list_table_ctor(ptr::addr_of_mut!(table), 0x0dad_05b8, 1);

            assert_eq!(built, ptr::addr_of_mut!(table));
            assert_eq!(
                events().as_slice(),
                ["alloc", "populate", "registry", "resolve", "fail"],
                "heap_panic fires immediately after the failed resolve"
            );
            assert_eq!(CTOR_ARENA_USED, 0, "no string rep was ever allocated");
            assert_eq!(
                table.name,
                crate::cxx::string::empty_rep_data(),
                "the name stays parked on the empty rep"
            );
            restore_ctor();
            drop(guard);
        }
    }
}
