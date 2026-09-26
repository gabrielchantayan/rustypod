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
//! # Deliberate deviations
//!
//! - On the host, the unported `insert_unique` callee is an explicit test
//!   seam. On device it remains a direct call to 0x083c8aa8. This is
//!   necessary because this port is the caller, not the red-black tree
//!   implementation.
//! - Host pointers are wider than retailOS words. Host callers of
//!   [`silver_list_table_item`] read the returned slot as one `u32`, while
//!   device code reads the native four-byte pointer.
//! - The key remains a local private copy, mirroring the original's stack
//!   pair rather than exposing the caller's storage.

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

/// A red-black map node returned by `FUN_083c8aa8`. Its value word is at
/// target offset +20.
pub type SilverItemMapNode = u32;

/// The temporary `value_type` which `FUN_083db92c` constructs on its stack.
#[repr(C)]
pub struct SilverItemMapPair {
    pub key: u32,
    pub value: u32,
}

/// `FUN_083c8aa8`: inserts the pair if absent and returns `{node, inserted}`.
/// This caller observes only the first word, the node pointer.
pub type SilverItemMapInsertUnique = unsafe extern "C" fn(
    result: *mut *mut SilverItemMapNode,
    map: *mut SilverItemMap,
    pair: *const SilverItemMapPair,
);

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn map_insert_unique(
    result: *mut *mut SilverItemMapNode,
    map: *mut SilverItemMap,
    pair: *const SilverItemMapPair,
) {
    let insert_unique: SilverItemMapInsertUnique = core::mem::transmute(0x083c_8aa8usize);
    insert_unique(result, map, pair);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_map_insert_unique(
    _result: *mut *mut SilverItemMapNode,
    _map: *mut SilverItemMap,
    _pair: *const SilverItemMapPair,
) {
    panic!("silver_item_map_value_slot requires map insert_unique 0x083c8aa8")
}

/// Host-test seam for the unported `FUN_083c8aa8` direct callee.
#[cfg(not(target_os = "none"))]
pub static mut SILVER_ITEM_MAP_INSERT_UNIQUE: SilverItemMapInsertUnique = missing_map_insert_unique;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn map_insert_unique(
    result: *mut *mut SilverItemMapNode,
    map: *mut SilverItemMap,
    pair: *const SilverItemMapPair,
) {
    core::ptr::read_volatile(core::ptr::addr_of!(SILVER_ITEM_MAP_INSERT_UNIQUE))(result, map, pair);
}

/// `silver_item_map_value_slot` — original: `FUN_083db92c` @ 0x083db92c
/// (**56 bytes**, all code; **1 plain `bl`, 0 predicated `bl`** in its body;
/// exactly **2 incoming `bl` sites**, binary-decoded).
///
/// Copies `*key` into the stack `value_type { key, 0 }`, asks the ordered
/// map's `insert_unique` for its `{node, inserted}` result, and returns the
/// address of the node's value word at +20. Thus an absent key is inserted
/// with a zero value; this is C++ `operator[]`, not a lookup.
///
/// # Deliberate deviations
///
/// The direct retailOS callee `FUN_083c8aa8` remains unported. Device builds
/// call it at its verified load address; host builds expose it as the narrow
/// [`SILVER_ITEM_MAP_INSERT_UNIQUE`] test seam. The host seam returns a
/// target-width node address so the +20 target offset remains literal.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn silver_item_map_value_slot(
    map: *mut SilverItemMap,
    key: *const u32,
) -> *mut *mut u8 {
    let pair = SilverItemMapPair { key: key.read(), value: 0 };
    let mut node: *mut SilverItemMapNode = core::ptr::null_mut();
    map_insert_unique(core::ptr::addr_of_mut!(node), map, core::ptr::addr_of!(pair));
    node.add(5).cast()
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
    let slot = silver_item_map_value_slot(
        core::ptr::addr_of_mut!((*table).items),
        core::ptr::addr_of!(key),
    );
    #[cfg(target_os = "none")]
    { core::ptr::read_volatile(slot) }
    #[cfg(not(target_os = "none"))]
    { core::ptr::read_volatile(slot.cast::<u32>()) as usize as *mut u8 }
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
    static mut ENTRIES: Vec<(u32, *mut u32)> = Vec::new();
    static mut LOOKUPS: Vec<(*mut SilverItemMap, u32)> = Vec::new();

    fn entries() -> &'static mut Vec<(u32, *mut u32)> {
        unsafe { &mut *ptr::addr_of_mut!(ENTRIES) }
    }

    fn lookups() -> &'static mut Vec<(*mut SilverItemMap, u32)> {
        unsafe { &mut *ptr::addr_of_mut!(LOOKUPS) }
    }

    static mut NODE_COUNT: usize = 0;
    static MAP_NODES: std::sync::LazyLock<Option<usize>> = std::sync::LazyLock::new(|| {
        crate::testing::try_map_u32_slab(crate::testing::hints::SILVER_ITEM_MAP_VALUE_SLOT, 0x100)
            .map(|pointer| pointer as usize)
    });

    unsafe fn node_at(index: usize) -> *mut SilverItemMapNode {
        let base = MAP_NODES.expect("target-width map node fixture");
        (base as *mut SilverItemMapNode).add(index * 6)
    }

    unsafe extern "C" fn mock_map_insert_unique(
        result: *mut *mut SilverItemMapNode,
        map: *mut SilverItemMap,
        pair: *const SilverItemMapPair,
    ) {
        let pair = pair.read();
        lookups().push((map, pair.key));
        if let Some(index) = entries().iter().position(|(key, _)| *key == pair.key) {
            result.write(entries()[index].1.cast());
            return;
        }
        let node = node_at(NODE_COUNT);
        NODE_COUNT += 1;
        node.write_bytes(0, 6);
        node.add(4).write(pair.key);
        node.add(5).write(pair.value);
        entries().push((pair.key, node.cast()));
        result.write(node);
    }

    unsafe fn install_map() -> Option<MutexGuard<'static, ()>> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        if MAP_NODES.is_none() {
            return None;
        }
        entries().clear();
        lookups().clear();
        NODE_COUNT = 0;
        SILVER_ITEM_MAP_INSERT_UNIQUE = mock_map_insert_unique;
        Some(guard)
    }

    unsafe fn restore() {
        SILVER_ITEM_MAP_INSERT_UNIQUE = missing_map_insert_unique;
        entries().clear();
        lookups().clear();
        NODE_COUNT = 0;
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
    fn map_value_slot_returns_the_value_word_of_an_existing_node() {
        let mut table = table();
        unsafe {
            let Some(guard) = install_map() else { return };
            let node = node_at(0);
            NODE_COUNT = 1;
            node.write_bytes(0, 6);
            node.add(4).write(0x0dad_05bf);
            node.add(5).write(0x1000_0000);
            entries().push((0x0dad_05bf, node.cast()));
            let key = 0x0dad_05bf;
            let slot = silver_item_map_value_slot(ptr::addr_of_mut!(table.items), ptr::addr_of!(key));
            assert_eq!(slot.cast::<u32>(), node.add(5));
            assert_eq!(slot.cast::<u32>().read(), 0x1000_0000);
            assert_eq!(lookups(), &[(ptr::addr_of_mut!(table.items), key)]);
            restore();
            drop(guard);
        }
    }

    #[test]
    fn map_value_slot_default_inserts_zero_for_a_missing_or_zero_key() {
        let mut table = table();
        unsafe {
            let Some(guard) = install_map() else { return };
            for key in [0x0dad_0000, 0] {
                let slot = silver_item_map_value_slot(ptr::addr_of_mut!(table.items), ptr::addr_of!(key));
                assert_eq!(slot.cast::<u32>().read(), 0);
            }
            assert_eq!(entries().len(), 2);
            assert_eq!(entries()[0].0, 0x0dad_0000);
            assert_eq!(entries()[1].0, 0);
            restore();
            drop(guard);
        }
    }

    #[test]
    fn table_item_reads_the_default_inserted_value_slot() {
        let mut table = table();
        unsafe {
            let Some(guard) = install_map() else { return };
            let found = silver_list_table_item(ptr::addr_of_mut!(table), 0x0dad_05bf);
            assert!(found.is_null());
            assert_eq!(entries().len(), 1);
            restore();
            drop(guard);
        }
    }

    #[test]
    fn map_value_slot_passes_a_private_zero_initialized_pair() {
        static mut SEEN_PAIR: *const SilverItemMapPair = ptr::null();

        unsafe extern "C" fn capture(
            result: *mut *mut SilverItemMapNode,
            _map: *mut SilverItemMap,
            pair: *const SilverItemMapPair,
        ) {
            SEEN_PAIR = pair;
            result.write(node_at(0));
        }

        let mut table = table();
        let caller_owned = 0x0dad_05bf;
        unsafe {
            let guard = OPS_LOCK.lock().unwrap_or_else(|p| p.into_inner());
            if MAP_NODES.is_none() {
                return;
            }
            node_at(0).write_bytes(0, 6);
            SILVER_ITEM_MAP_INSERT_UNIQUE = capture;
            let slot = silver_item_map_value_slot(
                ptr::addr_of_mut!(table.items),
                ptr::addr_of!(caller_owned),
            );
            assert_eq!((*SEEN_PAIR).key, caller_owned);
            assert_eq!((*SEEN_PAIR).value, 0);
            assert_ne!(
                SEEN_PAIR.cast::<u32>(),
                ptr::addr_of!(caller_owned),
                "the retail pair is private stack storage"
            );
            assert_eq!(slot.cast::<u32>(), node_at(0).add(5));
            restore();
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
