//! Localized-string table membership test — the predicate Silver UI code
//! runs before fetching a string value for a key.
//!
//! - [`string_table_has_string`] — original: `FUN_08101edc` @
//!   0x08101edc (184 bytes, 0x08101edc..0x08101f94 — extent confirmed
//!   against raw bytes: the next function's `push` sits at 0x08101f94;
//!   **38 `bl` call sites**, all unconditional, verified by decoding
//!   every B/BL word in osos.dec — zero predicated forms, so no caller
//!   gates the call on a flag and the callee needs no NULL guard).
//!
//! # Object under test
//!
//! `this` is the localization string-table singleton (the global callers
//! load as `DAT_08219384` / `DAT_081de518`): an inline array of
//! string-keyed maps (the `StringKeyMap` family of `cxx/string_map.rs`,
//! 0x1c-byte stride, header-node pointer at map + 0x10, one-word
//! comparator object at map + 0x19) plus a selector:
//!
//! ```text
//! +0x00  table[0]  StringKeyMap (0x1c bytes)
//! +0x1c  table[1]  StringKeyMap
//! +0x38  table[2]  StringKeyMap — the fallback (default-language) table
//! +0x54  current table index (word)
//! ```
//!
//! Keys and mapped values are COW `basic_string`s (rep data pointer;
//! size word at data - 4). Callers build a key with
//! `cxx_string_from_cstr` @ 0x083d8b5c (e.g. `"AlarmToneAt"`,
//! `"RefreshingGenius"`, `"CreatingGeniusMix"`), run this predicate, and
//! only then fetch the value through the getter family @ 0x08102168 /
//! the veneer @ 0x08101ed4 (`this + 0x38; b 0x083c4778` — the
//! fallback-table `operator[]`).
//!
//! # Algorithm (from the raw bytes)
//!
//! ```text
//! map  = table + table->current_index * 0x1c        // index re-read
//! find(&node, map, key)                             //   across the call
//! if node != map->header && !empty(node->value):    // value at node+0x14
//!     return 1
//! find(&node, table + 0x38, key)                    // fallback table
//! return node != fallback->header && !empty(node->value)
//! ```
//!
//! i.e. 1 iff `key` resolves to a **non-empty** string, looking in the
//! current table first and in the fallback table otherwise (a hit whose
//! value is empty also falls through to the fallback). The
//! iterator-equality compare against the map header is the miss test:
//! `find` returns the header node when the key is absent.
//!
//! # Callees (all real `bl` boundaries in the original)
//!
//! - `FUN_083db55c` @ 0x083db55c — `map<string,string>::find`:
//!   lower_bound walk from the root (header + 4) comparing
//!   `cxx_string_less` @ 0x083d74f4 (ported) of node key at node + 0x10
//!   vs the query, then the equal-range recheck via the node-key
//!   accessor @ 0x083b6acc (`node + 16`); writes the found node — or
//!   the header node on a miss — through its first argument. **Not
//!   ported**; Ghidra's C for our function mis-renders this call as a
//!   buffer copy, which it is not.
//! - [`crate::cxx::templates::iterator_equal`] @ 0x083cf848 — iterator
//!   equality: `*a == *b`, directly ported as the header-node miss test.
//! - `FUN_083d6f0c` @ 0x083d6f0c — `basic_string::empty`: reads the
//!   size word at `(*string) - 4`, returns 1 iff it is 0
//!   (`rsbs r0, r0, #1; movcc r0, #0` — 1 for size 0, 0 for any
//!   nonzero size). **Not ported.**
//!
//! # Deviations
//!
//! - The two unported callees ride the [`STRING_TABLE_OPS`]
//!   `read_volatile` dispatch table (house pattern). Iterator equality
//!   directly calls the Rust port; target defaults transmute the real
//!   firmware addresses 0x083db55c / 0x083d6f0c, while host defaults panic
//!   until a test installs the remaining mocks.
//! - The original spills r0..r3 on entry and reuses those stack slots
//!   as the two `find` out-slots and the header-temporary; the port
//!   uses ordinary locals.
//! - The current-index word at `this + 0x54` is re-read after the first
//!   `find` call for the header compare, exactly as the original
//!   reloads `ldr r0, [r4, #84]` across the `bl`.
//! - Pointer-to-word seam arguments are typed `*const u32`, not
//!   `*const *mut u8`: the pointees are 32-bit target words (node
//!   pointers, string data pointers) on both target and host fixtures.

/// Word index of the current-table selector at `this + 0x54`.
const CURRENT_TABLE_INDEX_WORD: usize = 0x54 / 4;

/// Byte stride of one inline `StringKeyMap` (7 words).
const TABLE_STRIDE: usize = 0x1c;

/// Word index of the header-node pointer inside a map (+ 0x10).
const MAP_HEADER_WORD: usize = 0x10 / 4;

/// Byte offset of the fixed fallback table (`this + 0x38` == table[2]).
const FALLBACK_TABLE_OFFSET: usize = 0x38;

/// Byte offset of the mapped-value string word inside a node (+ 0x14).
const NODE_VALUE_OFFSET: usize = 0x14;

/// Reads the word at `base + index * 4`. All fields touched here are
/// word-aligned in the original (`ldr`/`str`, never `ldrb`), so these
/// are aligned reads on target.
#[inline(always)]
unsafe fn word(base: *const u8, index: usize) -> u32 {
    (base as *const u32).add(index).read()
}

/// The retailOS dependencies of [`string_table_has_string`]. Every
/// pointee behind a `*const u32` is a 32-bit firmware word.
#[derive(Clone, Copy)]
pub struct StringTableOps {
    /// `FUN_083db55c` @ 0x083db55c — the string-map `find`: writes the
    /// found node pointer, or the map's header node on a miss, to
    /// `*out`. `key` points at the query string's data-pointer word.
    pub find: unsafe extern "C" fn(out: *mut u32, map: *mut u8, key: *const u32),
    /// `FUN_083cf848` @ 0x083cf848 — iterator equality: 1 iff the two
    /// pointee words are equal (node == header is the miss test).
    pub iter_eq: unsafe extern "C" fn(a: *const u32, b: *const u32) -> u32,
    /// `FUN_083d6f0c` @ 0x083d6f0c — `basic_string::empty` on the word
    /// at `string`: 1 iff the size word at `(*string) - 4` is 0.
    pub string_empty: unsafe extern "C" fn(string: *const u32) -> u32,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_string_map_find(out: *mut u32, map: *mut u8, key: *const u32) {
    let find: unsafe extern "C" fn(*mut u32, *mut u8, *const u32) =
        unsafe { core::mem::transmute(0x083d_b55cusize) };
    unsafe { find(out, map, key) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_string_map_find(_out: *mut u32, _map: *mut u8, _key: *const u32) {
    panic!("string_table_has_string requires string-map find 0x083db55c")
}


#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_string_empty(string: *const u32) -> u32 {
    let empty: unsafe extern "C" fn(*const u32) -> u32 =
        unsafe { core::mem::transmute(0x083d_6f0cusize) };
    unsafe { empty(string) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_string_empty(_string: *const u32) -> u32 {
    panic!("string_table_has_string requires basic_string::empty 0x083d6f0c")
}

/// Wired defaults for [`STRING_TABLE_OPS`]: iterator equality is ported;
/// target calls retain the two unported retailOS dependencies.
#[cfg(target_os = "none")]
pub const DEFAULT_STRING_TABLE_OPS: StringTableOps = StringTableOps {
    find: firmware_string_map_find,
    iter_eq: crate::cxx::templates::iterator_equal,
    string_empty: firmware_string_empty,
};

/// Wired defaults for [`STRING_TABLE_OPS`]: iterator equality is ported;
/// the remaining unported dependencies panic on host until mocked.
#[cfg(not(target_os = "none"))]
pub const DEFAULT_STRING_TABLE_OPS: StringTableOps = StringTableOps {
    find: missing_string_map_find,
    iter_eq: crate::cxx::templates::iterator_equal,
    string_empty: missing_string_empty,
};

/// Active model of the retailOS dependencies still unported in this module.
/// Target integration may replace `find` / `string_empty` as 0x083db55c /
/// 0x083d6f0c are ported; iterator equality calls its Rust port directly.
pub static mut STRING_TABLE_OPS: StringTableOps = DEFAULT_STRING_TABLE_OPS;

#[inline(always)]
unsafe fn string_table_ops() -> StringTableOps {
    core::ptr::read_volatile(core::ptr::addr_of!(STRING_TABLE_OPS))
}

/// string_table_has_string — original: `FUN_08101edc` @ 0x08101edc
/// (184 bytes; 38 unconditional `bl` call sites, binary-scanned).
///
/// Returns 1 iff `key` maps to a non-empty string in the current table
/// (selected by the index word at `this + 0x54`), or — on a miss or an
/// empty value there — in the fallback table at `this + 0x38`; 0
/// otherwise. See the module header for the object layout, the callee
/// contracts, and the deviations.
///
/// There is no NULL guard on `this` or `key`, as in the original.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn string_table_has_string(table: *mut u8, key: *const u32) -> u32 {
    let ops = string_table_ops();
    let mut node: u32 = 0;

    let index = word(table, CURRENT_TABLE_INDEX_WORD) as usize;
    let current = table.add(index * TABLE_STRIDE);
    (ops.find)(&mut node, current, key);
    // The original reloads the index word across the find call.
    let header = word(
        table.add(word(table, CURRENT_TABLE_INDEX_WORD) as usize * TABLE_STRIDE),
        MAP_HEADER_WORD,
    );
    if (ops.iter_eq)(&node, &header) == 0
        && (ops.string_empty)((node as usize + NODE_VALUE_OFFSET) as *const u32) == 0
    {
        return 1;
    }

    let fallback = table.add(FALLBACK_TABLE_OFFSET);
    (ops.find)(&mut node, fallback, key);
    let header = word(fallback, MAP_HEADER_WORD);
    ((ops.iter_eq)(&node, &header) == 0
        && (ops.string_empty)((node as usize + NODE_VALUE_OFFSET) as *const u32) == 0)
        as u32
}
/// The unported string-table value lookup called by
/// [`string_table_parse_i32`]. `FUN_08101c14` selects a non-empty current
/// table value or the fallback table value, then returns the address of its
/// COW-string data-pointer word.
#[derive(Clone, Copy)]
pub struct StringTableParseOps {
    /// `FUN_08101c14` @ 0x08101c14 — resolves `key` in `table` and returns
    /// the address of the selected mapped COW string's data-pointer word.
    pub lookup: unsafe extern "C" fn(table: *mut u8, key: *const u32) -> *const u32,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_string_table_value(
    table: *mut u8,
    key: *const u32,
) -> *const u32 {
    let lookup: unsafe extern "C" fn(*mut u8, *const u32) -> *const u32 =
        unsafe { core::mem::transmute(0x0810_1c14usize) };
    unsafe { lookup(table, key) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_string_table_value(
    _table: *mut u8,
    _key: *const u32,
) -> *const u32 {
    panic!("string_table_parse_i32 requires string-table lookup 0x08101c14")
}

/// Active model of the unported `FUN_08101c14` lookup. Target builds retain
/// the verified firmware call boundary; host tests install a low-address
/// target-word fixture.
#[cfg(target_os = "none")]
pub static mut STRING_TABLE_PARSE_OPS: StringTableParseOps = StringTableParseOps {
    lookup: firmware_string_table_value,
};

/// Active model of the unported `FUN_08101c14` lookup. The host default
/// rejects accidental traversal into the unported COW string-table lookup.
#[cfg(not(target_os = "none"))]
pub static mut STRING_TABLE_PARSE_OPS: StringTableParseOps = StringTableParseOps {
    lookup: missing_string_table_value,
};

#[inline(always)]
unsafe fn string_table_parse_ops() -> StringTableParseOps {
    core::ptr::read_volatile(core::ptr::addr_of!(STRING_TABLE_PARSE_OPS))
}

/// Parses the exact single `"%d"` conversion used by the original wrapper.
///
/// The scanf integer worker skips C whitespace, accepts one sign, collects
/// base-10 digits with modulo-2^32 arithmetic, and leaves the caller's
/// pre-zeroed output unchanged when no digit is present.
#[inline(always)]
unsafe fn scan_signed_decimal(input: *const u8) -> u32 {
    let mut cursor = input;
    while matches!(cursor.read(), b' ' | b'\t' | b'\n' | b'\x0b' | b'\x0c' | b'\r') {
        cursor = cursor.add(1);
    }

    let negative = match cursor.read() {
        b'+' => {
            cursor = cursor.add(1);
            false
        }
        b'-' => {
            cursor = cursor.add(1);
            true
        }
        _ => false,
    };

    let mut value = 0u32;
    let mut saw_digit = false;
    loop {
        let digit = cursor.read().wrapping_sub(b'0');
        if digit > 9 {
            break;
        }
        saw_digit = true;
        value = value.wrapping_mul(10).wrapping_add(digit as u32);
        cursor = cursor.add(1);
    }
    if saw_digit && negative {
        value.wrapping_neg()
    } else {
        value
    }
}

/// `string_table_parse_i32` — original: `FUN_08102168` @ **0x08102168**
/// (40 bytes, 0x08102168..0x08102190; the trailing `"%d\0"` literal occupies
/// 0x08102190..0x08102193 and the sibling function starts at 0x08102194).
///
/// Decoding every aligned ARM B/BL word in `osos.dec` finds **11 direct `bl`
/// call sites**, all unconditional; there are no predicated forms. Resolves
/// `key` through `FUN_08101c14`, scans the resulting COW-string data as one
/// signed decimal `"%d"` conversion into a zero-initialized local, and returns
/// that local as the 32-bit result. There is no NULL guard on either input or
/// on the returned COW data pointer.
///
/// Deliberate deviation: the existing Rust `sscanf` veneer cannot consume its
/// C-varargs destination (the original passes the local in r2), so this port
/// inlines the already-ported scanf integer worker's `%d` behavior. The
/// unported lookup remains a `read_volatile` ops seam at its verified target
/// address 0x08101c14.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn string_table_parse_i32(table: *mut u8, key: *const u32) -> u32 {
    let value = unsafe { (string_table_parse_ops().lookup)(table, key).read() };
    unsafe { scan_signed_decimal(value as usize as *const u8) }
}


/// The unported string-table assignment helper used by
/// [`string_table_set_decimal`](crate::app::string_table::string_table_set_decimal).
/// `FUN_08101da0` selects the current 0x1c-byte table from `table + 0x54`,
/// obtains the mapped COW-string slot for `key`, then assigns `value` into it.
#[derive(Clone, Copy)]
pub struct StringTableAssignOps {
    /// `FUN_08101da0` @ 0x08101da0 — assigns the COW string object at
    /// `value` to the current table's mapped-value slot for `key`.
    pub assign: unsafe extern "C" fn(
        table: *mut u8,
        key: *mut *mut u8,
        value: *mut *mut u8,
    ),
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_string_table_assign(
    table: *mut u8,
    key: *mut *mut u8,
    value: *mut *mut u8,
) {
    let assign: unsafe extern "C" fn(*mut u8, *mut *mut u8, *mut *mut u8) =
        unsafe { core::mem::transmute(0x0810_1da0usize) };
    unsafe { assign(table, key, value) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_string_table_assign(
    _table: *mut u8,
    _key: *mut *mut u8,
    _value: *mut *mut u8,
) {
    panic!("string_table_set_decimal requires string-table assignment 0x08101da0")
}

/// Active model of `FUN_08101da0`. The target default reaches the retail
/// helper; host tests install a recorder until that helper is ported.
#[cfg(target_os = "none")]
pub static mut STRING_TABLE_ASSIGN_OPS: StringTableAssignOps = StringTableAssignOps {
    assign: firmware_string_table_assign,
};

/// Active model of `FUN_08101da0`. The host default reports an accidental
/// unmocked traversal into the still-unported helper.
#[cfg(not(target_os = "none"))]
pub static mut STRING_TABLE_ASSIGN_OPS: StringTableAssignOps = StringTableAssignOps {
    assign: missing_string_table_assign,
};

#[inline(always)]
unsafe fn string_table_assign_ops() -> StringTableAssignOps {
    core::ptr::read_volatile(core::ptr::addr_of!(STRING_TABLE_ASSIGN_OPS))
}

/// `string_table_set_decimal` — original: `FUN_08101d4c` @ 0x08101d4c
/// (80 bytes, 0x08101d4c..0x08101d9c; the next function opens at
/// 0x08101da0; **19 unconditional `bl` call sites**, decoded from every
/// ARM B/BL word in osos.dec).
///
/// Dereferences `decimal`, renders the signed 32-bit value through `"%d"`
/// into the original's 512-byte stack buffer, constructs a temporary COW
/// string, assigns it to `key` in the string table, and releases the
/// temporary. There is no NULL guard on any argument.
///
/// The formatter port takes an explicit va-list pointer rather than C
/// varargs, so `&number` replaces the original r2 value at the `sprintf`
/// boundary. `FUN_08101da0` is not ported and remains a volatile dispatch
/// seam; its target default is the verified retail load address.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn string_table_set_decimal(
    table: *mut u8,
    key: *mut *mut u8,
    decimal: *const i32,
) {
    let number = unsafe { decimal.read() };
    let mut buffer = core::mem::MaybeUninit::<[u8; 512]>::uninit();
    let buffer = buffer.as_mut_ptr().cast::<u8>();
    let arguments = &number as *const i32 as *const u32;
    unsafe {
        crate::printf::printf_api::sprintf(buffer, b"%d\0".as_ptr(), arguments);
    }

    let mut value = core::mem::MaybeUninit::<*mut u8>::uninit();
    let value = unsafe {
        crate::cxx::string::cxx_string_from_cstr(value.as_mut_ptr(), buffer)
    };
    unsafe {
        (string_table_assign_ops().assign)(table, key, value);
        crate::cxx::string::cxx_string_release(value);
    }
}

/// The unported fallback-table value-slot lookup used by
/// [`string_table_set_hex`]. `FUN_083db69c` copy-constructs a (key,
/// empty-string) node pair from `key`, runs the string map's
/// find-or-insert @ 0x083c4884 against the 0x1c-byte map at `map`,
/// destroys the pair temporaries, and returns the address of the found
/// node's mapped-value COW-string word (node + 0x14).
#[derive(Clone, Copy)]
pub struct StringTableSlotOps {
    /// `FUN_083db69c` @ 0x083db69c — resolves the mapped-value string
    /// word for `key` in the map at `map`, inserting an empty value when
    /// the key is absent.
    pub value_slot: unsafe extern "C" fn(map: *mut u8, key: *mut *mut u8) -> *mut *mut u8,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_string_table_value_slot(
    map: *mut u8,
    key: *mut *mut u8,
) -> *mut *mut u8 {
    let slot: unsafe extern "C" fn(*mut u8, *mut *mut u8) -> *mut *mut u8 =
        unsafe { core::mem::transmute(0x083d_b69cusize) };
    unsafe { slot(map, key) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_string_table_value_slot(
    _map: *mut u8,
    _key: *mut *mut u8,
) -> *mut *mut u8 {
    panic!("string_table_set_hex requires fallback-table value-slot lookup 0x083db69c")
}

/// Active model of `FUN_083db69c`. The target default reaches the retail
/// helper; host tests install a recorder until that helper is ported.
#[cfg(target_os = "none")]
pub static mut STRING_TABLE_SLOT_OPS: StringTableSlotOps = StringTableSlotOps {
    value_slot: firmware_string_table_value_slot,
};

/// Active model of `FUN_083db69c`. The host default reports an accidental
/// unmocked traversal into the still-unported helper.
#[cfg(not(target_os = "none"))]
pub static mut STRING_TABLE_SLOT_OPS: StringTableSlotOps = StringTableSlotOps {
    value_slot: missing_string_table_value_slot,
};

#[inline(always)]
unsafe fn string_table_slot_ops() -> StringTableSlotOps {
    core::ptr::read_volatile(core::ptr::addr_of!(STRING_TABLE_SLOT_OPS))
}

/// string_table_set_hex — original: `FUN_08101f94` @ 0x08101f94 (84 bytes,
/// 0x08101f94..0x08101fe8: code through `pop {r4,r5,r6,pc}` @ 0x08101fe4
/// plus the trailing "%lx" literal word @ 0x08101fe8; the next function's
/// `push {r4,r5,r6,lr}` sits at 0x08101fec; **13 unconditional `bl` call
/// sites, zero predicated forms, zero `b` references, zero data-word
/// references**, verified by decoding every ARM B/BL word and every word
/// equal to the address in osos.dec).
///
/// Renders `value` through `sprintf(buffer, "%lx", value)` into the
/// original's 512-byte stack buffer, builds a temporary COW string from
/// the text with `cxx_string_from_cstr` @ 0x083d8b5c, resolves the
/// mapped-value slot for `key` in the FALLBACK table at `table + 0x38`
/// via the unported lookup @ 0x083db69c, assigns the temporary into that
/// slot with `cxx_string_assign` @ 0x083d8d1c, and releases the temporary
/// with `cxx_string_release` @ 0x083d8b04. There is no NULL guard on any
/// argument.
///
/// Unlike its sibling [`string_table_set_decimal`] — which routes through
/// the current-table assign helper @ 0x08101da0 and takes its number by
/// pointer — this function takes `value` BY VALUE in r2 and stores into
/// the fallback (default-language) table; sampled callers pass UI-state
/// keys ("SelectAlbum", "SelectArtist") with selection-handle values.
/// Ghidra's C for the original DROPS the third parameter entirely, and
/// its three-argument rendering of the two-argument `cxx_string_from_cstr`
/// call is register residue, not a real argument.
///
/// Deviations: the formatter port takes an explicit va-list pointer, so
/// `&value` replaces the original r2 at the `sprintf` boundary; the
/// 0x083db69c lookup rides the [`STRING_TABLE_SLOT_OPS`] volatile
/// dispatch seam (the verified retail load address on target, a
/// panicking default on host).
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn string_table_set_hex(table: *mut u8, key: *mut *mut u8, value: u32) {
    let mut buffer = core::mem::MaybeUninit::<[u8; 512]>::uninit();
    let buffer = buffer.as_mut_ptr().cast::<u8>();
    let arguments = &value as *const u32;
    unsafe {
        crate::printf::printf_api::sprintf(buffer, b"%lx\0".as_ptr(), arguments);
    }

    let mut text = core::mem::MaybeUninit::<*mut u8>::uninit();
    let text = unsafe { crate::cxx::string::cxx_string_from_cstr(text.as_mut_ptr(), buffer) };
    unsafe {
        let slot = (string_table_slot_ops().value_slot)(table.add(FALLBACK_TABLE_OFFSET), key);
        crate::cxx::string::cxx_string_assign(slot, text);
        crate::cxx::string::cxx_string_release(text);
    }
}

#[cfg(test)]
mod set_decimal_tests {
    extern crate std;

    use super::*;
    use crate::printf::printf_api::{PrintfEngineFn, PRINTF_ENGINE};
    use crate::heap::types::{HeapDescriptor, HeapDescriptorDescriptor};
    use crate::heap::veneers::{HeapVeneerOps, HEAP_OPS};
    use core::ffi::c_void;
    use core::ptr;
    use std::ffi::CStr;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut ASSIGNMENT: Option<(usize, Vec<u8>, Vec<u8>)> = None;

    const ARENA_SIZE: usize = 1024;

    #[repr(C, align(8))]
    struct Arena([u8; ARENA_SIZE]);

    static mut ARENA: Arena = Arena([0; ARENA_SIZE]);
    static mut ARENA_USED: usize = 0;

    struct OpsGuard {
        assign: StringTableAssignOps,
        engine: PrintfEngineFn,
    }

    impl Drop for OpsGuard {
        fn drop(&mut self) {
            unsafe {
                ptr::write_volatile(ptr::addr_of_mut!(STRING_TABLE_ASSIGN_OPS), self.assign);
                ptr::write_volatile(ptr::addr_of_mut!(PRINTF_ENGINE), self.engine);
            }
        }
    }

    struct ArenaGuard {
        ops: HeapVeneerOps,
    }

    impl Drop for ArenaGuard {
        fn drop(&mut self) {
            unsafe {
                ptr::write_volatile(ptr::addr_of_mut!(HEAP_OPS), self.ops);
            }
        }
    }

    unsafe extern "C" fn decimal_engine(
        fmt: *const u8,
        putc: unsafe extern "C" fn(u8, *mut c_void),
        context: *mut c_void,
        arguments: *const u32,
    ) -> i32 {
        assert_eq!(unsafe { CStr::from_ptr(fmt.cast()).to_bytes() }, b"%d");
        let text = std::format!("{}", unsafe { arguments.cast::<i32>().read() });
        for byte in text.bytes() {
            unsafe { putc(byte, context) };
        }
        text.len() as i32
    }

    unsafe extern "C" fn record_assign(
        table: *mut u8,
        key: *mut *mut u8,
        value: *mut *mut u8,
    ) {
        let key = unsafe { CStr::from_ptr((*key).cast()).to_bytes().to_vec() };
        let value = unsafe { CStr::from_ptr((*value).cast()).to_bytes().to_vec() };
        unsafe { ASSIGNMENT = Some((table as usize, key, value)) };
    }

    unsafe extern "C" fn arena_alloc(
        _heap: *mut HeapDescriptorDescriptor,
        size: usize,
        _tag: usize,
    ) -> *mut u8 {
        let used = unsafe { ARENA_USED };
        let aligned = (size + 7) & !7;
        if used + aligned > ARENA_SIZE {
            return ptr::null_mut();
        }
        unsafe {
            ARENA_USED = used + aligned;
            ptr::addr_of_mut!(ARENA.0).cast::<u8>().add(used)
        }
    }

    unsafe extern "C" fn arena_free(
        _heap: *mut HeapDescriptorDescriptor,
        _ptr: *mut u8,
        _tag: usize,
    ) {
    }

    unsafe extern "C" fn arena_create(
        descriptor: *mut HeapDescriptor,
        _start: *mut u8,
        _size: usize,
    ) -> *mut HeapDescriptorDescriptor {
        descriptor.cast()
    }


    fn install() -> (MutexGuard<'static, ()>, OpsGuard) {
        let lock = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            let guard = OpsGuard {
                assign: ptr::read_volatile(ptr::addr_of!(STRING_TABLE_ASSIGN_OPS)),
                engine: ptr::read_volatile(ptr::addr_of!(PRINTF_ENGINE)),
            };
            ptr::write_volatile(
                ptr::addr_of_mut!(STRING_TABLE_ASSIGN_OPS),
                StringTableAssignOps { assign: record_assign },
            );
            ptr::write_volatile(ptr::addr_of_mut!(PRINTF_ENGINE), decimal_engine);
            ASSIGNMENT = None;
            (lock, guard)
        }
    }

    #[test]
    fn formats_signed_decimal_and_preserves_key_for_assignment() {
        let (_lock, _restore) = install();
        let _heap = crate::heap::veneers::tests::mock_heap();
        let _arena = unsafe {
            ARENA_USED = 0;
            let previous = ptr::read_volatile(ptr::addr_of!(HEAP_OPS));
            let mut active = previous;
            active.alloc = arena_alloc;
            active.free = arena_free;
            active.create = arena_create;
            ptr::write_volatile(ptr::addr_of_mut!(HEAP_OPS), active);
            ArenaGuard { ops: previous }
        };
        let mut key_data = *b"NowPlayingStartTime\0";
        let mut key = key_data.as_mut_ptr();

        for number in [0, 42, -17, i32::MIN] {
            unsafe {
                string_table_set_decimal(0x1234usize as *mut u8, &mut key, &number);
                assert_eq!(
                    ASSIGNMENT,
                    Some((
                        0x1234,
                        b"NowPlayingStartTime".to_vec(),
                        std::format!("{number}").into_bytes(),
                    )),
                );
            }
        }

    }
}

#[cfg(test)]
mod set_hex_tests {
    extern crate std;

    use super::*;
    use crate::printf::printf_api::{PrintfEngineFn, PRINTF_ENGINE};
    use crate::heap::types::{HeapDescriptor, HeapDescriptorDescriptor};
    use crate::heap::veneers::{HeapVeneerOps, HEAP_OPS};
    use core::ffi::c_void;
    use core::ptr;
    use std::ffi::CStr;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut LOOKUP: Option<(usize, Vec<u8>)> = None;
    /// The one-word mapped-value string object the lookup seam returns.
    static mut SLOT: *mut u8 = ptr::null_mut();

    const ARENA_SIZE: usize = 1024;

    #[repr(C, align(8))]
    struct Arena([u8; ARENA_SIZE]);

    static mut ARENA: Arena = Arena([0; ARENA_SIZE]);
    static mut ARENA_USED: usize = 0;

    struct OpsGuard {
        slot: StringTableSlotOps,
        engine: PrintfEngineFn,
    }

    impl Drop for OpsGuard {
        fn drop(&mut self) {
            unsafe {
                ptr::write_volatile(ptr::addr_of_mut!(STRING_TABLE_SLOT_OPS), self.slot);
                ptr::write_volatile(ptr::addr_of_mut!(PRINTF_ENGINE), self.engine);
            }
        }
    }

    struct ArenaGuard {
        ops: HeapVeneerOps,
    }

    impl Drop for ArenaGuard {
        fn drop(&mut self) {
            unsafe {
                ptr::write_volatile(ptr::addr_of_mut!(HEAP_OPS), self.ops);
            }
        }
    }

    unsafe extern "C" fn hex_engine(
        fmt: *const u8,
        putc: unsafe extern "C" fn(u8, *mut c_void),
        context: *mut c_void,
        arguments: *const u32,
    ) -> i32 {
        assert_eq!(unsafe { CStr::from_ptr(fmt.cast()).to_bytes() }, b"%lx");
        let text = std::format!("{:x}", unsafe { arguments.read() });
        for byte in text.bytes() {
            unsafe { putc(byte, context) };
        }
        text.len() as i32
    }

    unsafe extern "C" fn record_value_slot(map: *mut u8, key: *mut *mut u8) -> *mut *mut u8 {
        let key = unsafe { CStr::from_ptr((*key).cast()).to_bytes().to_vec() };
        unsafe { LOOKUP = Some((map as usize, key)) };
        unsafe { ptr::addr_of_mut!(SLOT) }
    }

    unsafe extern "C" fn arena_alloc(
        _heap: *mut HeapDescriptorDescriptor,
        size: usize,
        _tag: usize,
    ) -> *mut u8 {
        let used = unsafe { ARENA_USED };
        let aligned = (size + 7) & !7;
        if used + aligned > ARENA_SIZE {
            return ptr::null_mut();
        }
        unsafe {
            ARENA_USED = used + aligned;
            ptr::addr_of_mut!(ARENA.0).cast::<u8>().add(used)
        }
    }

    unsafe extern "C" fn arena_free(
        _heap: *mut HeapDescriptorDescriptor,
        _ptr: *mut u8,
        _tag: usize,
    ) {
    }

    unsafe extern "C" fn arena_create(
        descriptor: *mut HeapDescriptor,
        _start: *mut u8,
        _size: usize,
    ) -> *mut HeapDescriptorDescriptor {
        descriptor.cast()
    }

    fn install() -> (MutexGuard<'static, ()>, OpsGuard) {
        let lock = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            let guard = OpsGuard {
                slot: ptr::read_volatile(ptr::addr_of!(STRING_TABLE_SLOT_OPS)),
                engine: ptr::read_volatile(ptr::addr_of!(PRINTF_ENGINE)),
            };
            ptr::write_volatile(
                ptr::addr_of_mut!(STRING_TABLE_SLOT_OPS),
                StringTableSlotOps { value_slot: record_value_slot },
            );
            ptr::write_volatile(ptr::addr_of_mut!(PRINTF_ENGINE), hex_engine);
            LOOKUP = None;
            (lock, guard)
        }
    }

    #[test]
    fn formats_unsigned_hex_and_assigns_into_fallback_table_slot() {
        let (_lock, _restore) = install();
        let _heap = crate::heap::veneers::tests::mock_heap();
        let _arena = unsafe {
            ARENA_USED = 0;
            let previous = ptr::read_volatile(ptr::addr_of!(HEAP_OPS));
            let mut active = previous;
            active.alloc = arena_alloc;
            active.free = arena_free;
            active.create = arena_create;
            ptr::write_volatile(ptr::addr_of_mut!(HEAP_OPS), active);
            ArenaGuard { ops: previous }
        };
        let mut key_data = *b"SelectAlbum\0";
        let mut key = key_data.as_mut_ptr();
        // The recorder never dereferences the map pointer, so a fixed
        // stand-in address proves the `table + 0x38` fallback arithmetic.
        let table = 0x2000usize as *mut u8;

        for value in [0u32, 0x2a, 0xdead_beef, 0xffff_ffff] {
            unsafe {
                // A fresh empty mapped value for the lookup to return.
                crate::cxx::string::cxx_string_from_cstr(ptr::addr_of_mut!(SLOT), b"\0".as_ptr());
                string_table_set_hex(table, &mut key, value);
                assert_eq!(
                    LOOKUP,
                    Some((
                        table as usize + FALLBACK_TABLE_OFFSET,
                        b"SelectAlbum".to_vec(),
                    )),
                );
                assert_eq!(
                    CStr::from_ptr(SLOT.cast()).to_bytes(),
                    std::format!("{value:x}").as_bytes(),
                );
                crate::cxx::string::cxx_string_release(ptr::addr_of_mut!(SLOT));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{
        hints, note_missing_u32_fixture, try_map_u32_slab, STRING_TABLE_OPS_TEST_LOCK,
    };
    use core::ptr;
    use std::sync::MutexGuard;
    use std::vec::Vec;


    /// Restores the seam table even if a test panics mid-run.
    struct SeamGuard;

    impl Drop for SeamGuard {
        fn drop(&mut self) {
            unsafe {
                ptr::write_volatile(ptr::addr_of_mut!(STRING_TABLE_OPS), DEFAULT_STRING_TABLE_OPS);
                ptr::write_volatile(
                    ptr::addr_of_mut!(STRING_TABLE_PARSE_OPS),
                    StringTableParseOps {
                        lookup: missing_string_table_value,
                    },
                );
            }
        }
    }

    fn lock() -> (MutexGuard<'static, ()>, SeamGuard) {
        let guard = STRING_TABLE_OPS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        (guard, SeamGuard)
    }

    // ---- Fixture layout inside the u32 slab -----------------------------
    //
    // table base T:
    //   T + 0x00  map[0]   (header word at T + 0x10)
    //   T + 0x1c  map[1]   (header word at T + 0x2c)
    //   T + 0x38  map[2]   (fallback; header word at T + 0x48)
    //   T + 0x54  current index
    // then three header nodes, two value-string reps and two result
    // nodes, all as u32 words:
    //   header node H<n>: only its address matters (the miss sentinel).
    //   result node N:    value string pointer word at N + 0x14.
    //   string rep:       size word at S - 4, data at S.

    const SLAB_SIZE: usize = 0x1000;
    const MAP0: usize = 0x000;
    const MAP1: usize = 0x01c;
    const MAP2: usize = 0x038;
    const INDEX_WORD: usize = 0x054;
    const HEADER0: usize = 0x100;
    const HEADER1: usize = 0x120;
    const HEADER2: usize = 0x140;
    const NODE_A: usize = 0x200; // non-empty value
    const NODE_B: usize = 0x240; // empty value
    const REP_A_SIZE: usize = 0x300; // size word; data follows at +4
    const REP_B_SIZE: usize = 0x310;

    struct Fixture {
        base: *mut u8,
    }

    impl Fixture {
        fn map() -> Option<Fixture> {
            try_map_u32_slab(hints::STRING_TABLE, SLAB_SIZE).map(|base| {
                unsafe { ptr::write_bytes(base, 0, SLAB_SIZE) };
                let f = Fixture { base };
                // Header pointers at map + 0x10.
                f.set_word(MAP0 + 0x10, f.addr(HEADER0));
                f.set_word(MAP1 + 0x10, f.addr(HEADER1));
                f.set_word(MAP2 + 0x10, f.addr(HEADER2));
                // Node value string pointers at node + 0x14.
                f.set_word(NODE_A + NODE_VALUE_OFFSET, f.addr(REP_A_SIZE + 4));
                f.set_word(NODE_B + NODE_VALUE_OFFSET, f.addr(REP_B_SIZE + 4));
                // String reps: non-empty vs empty size words.
                f.set_word(REP_A_SIZE, 7);
                f.set_word(REP_B_SIZE, 0);
                f
            })
        }

        fn addr(&self, off: usize) -> u32 {
            unsafe { self.base.add(off) as usize as u32 }
        }

        fn set_word(&self, off: usize, value: u32) {
            unsafe {
                (self.base.add(off) as *mut u32).write(value);
            }
        }

        fn set_index(&self, index: u32) {
            self.set_word(INDEX_WORD, index);
        }
    }

    // ---- Faithful-semantics mocks ----------------------------------------
    //
    // iter_eq and string_empty implement the exact decoded semantics of
    // 0x083cf848 / 0x083d6f0c over fixture memory; find is scripted
    // (the tree walk itself is the unported 0x083db55c's business) but
    // records every argument tuple.

    /// (map address, key address) of every find call, in order.
    static mut FIND_CALLS: Vec<(u32, u32)> = Vec::new();
    /// Scripted results: find call N writes RESULTS[N] to *out.
    static mut FIND_RESULTS: Vec<u32> = Vec::new();
    /// When set, the find mock rewrites the table index word mid-call.
    static mut FIND_SETS_INDEX: Option<(*mut u8, u32)> = None;

    const PARSE_SLAB_SIZE: usize = 0x1000;
    const PARSE_TEXT_OFFSET: usize = 0x100;
    static mut PARSE_VALUE_WORD: *const u32 = ptr::null();
    static mut PARSE_LOOKUP_CALLS: u32 = 0;
    static mut PARSE_LOOKUP_ARGUMENTS: Option<(usize, usize)> = None;

    unsafe extern "C" fn mock_parse_value(
        table: *mut u8,
        key: *const u32,
    ) -> *const u32 {
        PARSE_LOOKUP_CALLS += 1;
        PARSE_LOOKUP_ARGUMENTS = Some((table as usize, key as usize));
        PARSE_VALUE_WORD
    }

    fn find_calls() -> &'static mut Vec<(u32, u32)> {
        unsafe { &mut *ptr::addr_of_mut!(FIND_CALLS) }
    }

    fn find_results() -> &'static mut Vec<u32> {
        unsafe { &mut *ptr::addr_of_mut!(FIND_RESULTS) }
    }

    unsafe extern "C" fn mock_find(out: *mut u32, map: *mut u8, key: *const u32) {
        find_calls().push((map as usize as u32, key as usize as u32));
        let call = find_calls().len() - 1;
        if let Some((table, index)) = FIND_SETS_INDEX {
            (table.add(INDEX_WORD) as *mut u32).write(index);
        }
        out.write(find_results()[call]);
    }

    /// 0x083cf848 exactly: 1 iff *a == *b.
    unsafe extern "C" fn mock_iter_eq(a: *const u32, b: *const u32) -> u32 {
        (a.read() == b.read()) as u32
    }

    /// 0x083d6f0c exactly: 1 iff the size word at (*string) - 4 is 0.
    unsafe extern "C" fn mock_string_empty(string: *const u32) -> u32 {
        let data = string.read() as usize;
        (((data - 4) as *const u32).read() == 0) as u32
    }

    /// Installs the mocks and scripts `find`. `results` are u32 node (or
    /// header) addresses written to *out on successive calls.
    unsafe fn install(results: &[u32]) {
        find_calls().clear();
        find_results().clear();
        find_results().extend_from_slice(results);
        FIND_SETS_INDEX = None;
        ptr::write_volatile(
            ptr::addr_of_mut!(STRING_TABLE_OPS),
            StringTableOps {
                find: mock_find,
                iter_eq: mock_iter_eq,
                string_empty: mock_string_empty,
            },
        );
    }

    const KEY: u32 = 0xcafe;

    #[test]
    fn hit_current_nonempty_returns_one_without_fallback() {
        let (_guard, _seam) = lock();
        let Some(f) = Fixture::map() else {
            assert!(note_missing_u32_fixture("app/string_table"));
            return;
        };
        f.set_index(0);
        unsafe { install(&[f.addr(NODE_A)]) };
        let result = unsafe { string_table_has_string(f.base, KEY as *const u32) };
        assert_eq!(result, 1);
        assert_eq!(find_calls().as_slice(), &[(f.addr(MAP0), KEY)]);
    }

    #[test]
    fn miss_current_falls_back_to_table_two() {
        let (_guard, _seam) = lock();
        let Some(f) = Fixture::map() else {
            assert!(note_missing_u32_fixture("app/string_table"));
            return;
        };
        f.set_index(1);
        // Miss in table[1] (find returns the header), hit in fallback.
        unsafe { install(&[f.addr(HEADER1), f.addr(NODE_A)]) };
        let result = unsafe { string_table_has_string(f.base, KEY as *const u32) };
        assert_eq!(result, 1);
        assert_eq!(
            find_calls().as_slice(),
            &[(f.addr(MAP1), KEY), (f.addr(MAP2), KEY)]
        );
    }

    #[test]
    fn miss_in_both_returns_zero() {
        let (_guard, _seam) = lock();
        let Some(f) = Fixture::map() else {
            assert!(note_missing_u32_fixture("app/string_table"));
            return;
        };
        f.set_index(0);
        unsafe { install(&[f.addr(HEADER0), f.addr(HEADER2)]) };
        let result = unsafe { string_table_has_string(f.base, KEY as *const u32) };
        assert_eq!(result, 0);
        assert_eq!(
            find_calls().as_slice(),
            &[(f.addr(MAP0), KEY), (f.addr(MAP2), KEY)]
        );
    }

    #[test]
    fn empty_value_in_current_still_falls_back() {
        let (_guard, _seam) = lock();
        let Some(f) = Fixture::map() else {
            assert!(note_missing_u32_fixture("app/string_table"));
            return;
        };
        f.set_index(2);
        // Hit in the current table (table[2] here) but with an empty
        // value; the fallback (also table[2]) then hits non-empty.
        unsafe { install(&[f.addr(NODE_B), f.addr(NODE_A)]) };
        let result = unsafe { string_table_has_string(f.base, KEY as *const u32) };
        assert_eq!(result, 1);
        assert_eq!(
            find_calls().as_slice(),
            &[(f.addr(MAP2), KEY), (f.addr(MAP2), KEY)]
        );
    }

    #[test]
    fn empty_value_in_both_returns_zero() {
        let (_guard, _seam) = lock();
        let Some(f) = Fixture::map() else {
            assert!(note_missing_u32_fixture("app/string_table"));
            return;
        };
        f.set_index(0);
        unsafe { install(&[f.addr(NODE_B), f.addr(NODE_B)]) };
        let result = unsafe { string_table_has_string(f.base, KEY as *const u32) };
        assert_eq!(result, 0);
    }

    #[test]
    fn empty_fallback_value_returns_zero() {
        let (_guard, _seam) = lock();
        let Some(f) = Fixture::map() else {
            assert!(note_missing_u32_fixture("app/string_table"));
            return;
        };
        f.set_index(1);
        unsafe { install(&[f.addr(HEADER1), f.addr(NODE_B)]) };
        let result = unsafe { string_table_has_string(f.base, KEY as *const u32) };
        assert_eq!(result, 0);
    }

    #[test]
    fn current_index_selects_the_map() {
        let (_guard, _seam) = lock();
        let Some(f) = Fixture::map() else {
            assert!(note_missing_u32_fixture("app/string_table"));
            return;
        };
        for index in 0..3u32 {
            f.set_index(index);
            let header = [HEADER0, HEADER1, HEADER2][index as usize];
            // Miss everywhere: isolate the map address each index picks.
            unsafe { install(&[f.addr(header), f.addr(HEADER2)]) };
            let result = unsafe { string_table_has_string(f.base, KEY as *const u32) };
            assert_eq!(result, 0);
            assert_eq!(
                find_calls().as_slice(),
                &[
                    (f.addr(TABLE_STRIDE * index as usize), KEY),
                    (f.addr(MAP2), KEY)
                ],
                "index {index}"
            );
        }
    }

    #[test]
    fn index_word_is_reloaded_across_the_first_find() {
        let (_guard, _seam) = lock();
        let Some(f) = Fixture::map() else {
            assert!(note_missing_u32_fixture("app/string_table"));
            return;
        };
        f.set_index(0);
        // The original re-reads this + 0x54 after the first find call
        // for the header compare. Script find to bump the index to 1
        // and to return table[1]'s header as the "found" node: with the
        // reload this reads as a miss (node == header) and the fallback
        // runs; without it the stale index-0 header compares unequal
        // and the port would wrongly probe node + 0x14 as a hit.
        unsafe {
            install(&[f.addr(HEADER1), f.addr(NODE_A)]);
            FIND_SETS_INDEX = Some((f.base, 1));
        };
        let result = unsafe { string_table_has_string(f.base, KEY as *const u32) };
        assert_eq!(result, 1);
        assert_eq!(
            find_calls().as_slice(),
            &[(f.addr(MAP0), KEY), (f.addr(MAP2), KEY)]
        );
    }

    #[test]
    fn short_circuit_never_probes_value_on_a_miss() {
        let (_guard, _seam) = lock();
        let Some(f) = Fixture::map() else {
            assert!(note_missing_u32_fixture("app/string_table"));
            return;
        };
        f.set_index(0);
        // A miss hands back the header node, and the port must not
        // even evaluate string_empty on that path — the original
        // branches away first. Prove the short-circuit by counting
        // empty probes.
        static mut EMPTY_CALLS: u32 = 0;
        unsafe extern "C" fn counting_empty(string: *const u32) -> u32 {
            EMPTY_CALLS += 1;
            mock_string_empty(string)
        }
        unsafe {
            EMPTY_CALLS = 0;
            install(&[f.addr(HEADER0), f.addr(NODE_A)]);
            ptr::write_volatile(
                ptr::addr_of_mut!(STRING_TABLE_OPS),
                StringTableOps {
                    find: mock_find,
                    iter_eq: mock_iter_eq,
                    string_empty: counting_empty,
                },
            );
        }
        let result = unsafe { string_table_has_string(f.base, KEY as *const u32) };
        assert_eq!(result, 1);
        // One probe total: the fallback hit. The current-table miss
        // must not have probed.
        unsafe { assert_eq!(EMPTY_CALLS, 1) };
    }

    #[test]
    fn parses_signed_decimal_value_from_lookup_result() {
        let (_guard, _seam) = lock();
        let Some(base) = try_map_u32_slab(hints::STRING_TABLE_PARSE_I32, PARSE_SLAB_SIZE) else {
            assert!(note_missing_u32_fixture("app/string_table"));
            return;
        };
        let value_word = base.cast::<u32>();
        let text = unsafe { base.add(PARSE_TEXT_OFFSET) };
        let table = 0x1234usize as *mut u8;
        let key = 0x5678usize as *const u32;
        unsafe {
            ptr::write_bytes(base, 0, PARSE_SLAB_SIZE);
            value_word.write(text as usize as u32);
            PARSE_VALUE_WORD = value_word;
            PARSE_LOOKUP_CALLS = 0;
            PARSE_LOOKUP_ARGUMENTS = None;
            ptr::write_volatile(
                ptr::addr_of_mut!(STRING_TABLE_PARSE_OPS),
                StringTableParseOps {
                    lookup: mock_parse_value,
                },
            );

            for (input, expected) in [
                (&b"42\0"[..], 42u32),
                (&b" \t+123 trailing\0"[..], 123),
                (&b"-2147483648\0"[..], 0x8000_0000),
                (&b"4294967296\0"[..], 0),
                (&b"0x10\0"[..], 0),
                (&b"nonnumeric\0"[..], 0),
            ] {
                ptr::write_bytes(text, 0, PARSE_SLAB_SIZE - PARSE_TEXT_OFFSET);
                ptr::copy_nonoverlapping(input.as_ptr(), text, input.len());
                assert_eq!(string_table_parse_i32(table, key), expected, "{input:?}");
            }
            assert_eq!(PARSE_LOOKUP_CALLS, 6);
            assert_eq!(PARSE_LOOKUP_ARGUMENTS, Some((table as usize, key as usize)));
        }
    }

}
