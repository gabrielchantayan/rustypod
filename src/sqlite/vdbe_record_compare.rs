//! The record comparator — how the engine weighs a packed OP_MakeRecord
//! blob against an already-parsed key during an index seek.
//!
//! - `vdbe_record_compare` — original: `FUN_0838c87c` @ 0x0838c87c (372
//!   bytes, 0x0838c87c..0x0838c9f0; **3 `bl` call sites**: 0x0837208c and
//!   0x083720cc inside FUN_08371e54 — the `sqlite3BtreeMoveto` analog,
//!   whose two calls are upstream btree.c's — and 0x0838b450 inside
//!   FUN_0838b380, the `sqlite3VdbeIdxKeyCompare` analog). Upstream
//!   SQLite 3.5.9's `sqlite3VdbeRecordCompare` (vdbeaux.c:
//!   `int sqlite3VdbeRecordCompare(int nKey1, const void *pKey1,
//!   UnpackedRecord *pPKey2)`), verified against the 3.5.9 source.
//!   functions.csv's 372 bytes is exact: the next `stmdb` is 0x0838c9f0
//!   (the `sqlite3VdbeRecordUnpack` analog, which builds the
//!   UnpackedRecord this one consumes) and the function has no literal
//!   pool.
//!
//! ### Algorithm
//!
//! The scratch `mem1`'s `db`/`enc` are seeded from the KeyInfo and its
//! `flags`/`zMalloc` cleared. The header-size varint is decoded with the
//! build-wide convention — a first byte under 0x80 is the inline
//! one-byte case (value = byte, length 1), anything else calls
//! `sqlite3GetVarint` @ 0x0837ac30 (ported, [`get_varint`]) — yielding
//! `szHdr1`; the payload cursor `d1` starts there and the header cursor
//! `idx1` right after the varint. While `idx1 < szHdr1` AND `i <
//! pPKey2->nField` (both bounds reloaded per iteration): decode the next
//! serial type the same way; if the payload is already exhausted (`d1 >=
//! nKey1`, UNSIGNED) and the type has a nonzero length per
//! `sqlite3VdbeSerialTypeLen` @ 0x0838cfe8, stop; otherwise
//! `sqlite3VdbeSerialGet` @ 0x0838cc1c decodes the field into `mem1` and
//! advances `d1` by its return, then `sqlite3MemCompare` @ 0x0837d47c
//! weighs `mem1` against `aMem[i]` under `aColl[i]` (a NULL coll once
//! `i` reaches the KeyInfo's `nField`, which is loaded once before the
//! loop). A nonzero comparison breaks out with `rc` set. Afterwards
//! `mem1.zMalloc`, if any, goes to [`mem_release`] @ 0x0838c04c (ported;
//! in practice the retail serial_get never allocates, so the call is
//! dead but present — upstream's "No memory allocation is ever used on
//! mem1" comment made code).
//!
//! Endgame: a zero `rc` becomes -1 when `incrKey` is set (the parsed key
//! is treated as larger), else stays 0 when `prefixIsEqual` is set, else
//! becomes 1 when key1 has unconsumed payload (`d1 < nKey1`, unsigned —
//! key1 carries more fields and is therefore larger). A nonzero `rc` is
//! negated when `aSortOrder` exists, `i` is still below the KeyInfo's
//! (reloaded) `nField`, and `aSortOrder[i]` is set — a descending
//! column.
//!
//! ### Deviations
//!
//! - `sqlite3VdbeSerialTypeLen` @ 0x0838cfe8, `sqlite3VdbeSerialGet` @
//!   0x0838cc1c and `sqlite3MemCompare` @ 0x0837d47c are not ported.
//!   They are the [`VDBE_RECORD_COMPARE_OPS`] seam: target builds branch
//!   to the retailOS load addresses, host tests install reference
//!   implementations. (The serial_type_len jump-table datum at
//!   0x088fce10 is not readable in the decrypted image — runtime
//!   initialized, like the other post-image tables — but its
//!   disassembly is upstream's `aSize[]` lookup / `(t-12)>>1` shape
//!   verbatim.)
//! - [`get_varint`] and [`mem_release`] ARE ported and are called
//!   directly, per the porting rules. The varint out-param widens to
//!   u64 through the port and truncates back (`as u32`) — bit-identical
//!   to the original's u32 store, per `sqlite/get_varint.rs`.
//! - [`KeyInfo`]/[`UnpackedRecord`] are typed `repr(C)` structs (the
//!   `sqlite/vdbe.rs` pattern); their pointer fields widen on a 64-bit
//!   host, and the 32-bit static asserts below pin the original's
//!   offsets. The scratch `mem1` and the `aMem` elements stay RAW
//!   0x28-byte Mems at the original's offsets, because `mem1` interops
//!   with the ported raw-offset [`mem_release`]; the scratch buffer is
//!   0x30 bytes so [`mem_release`]'s native-width NULLing of `zMalloc`
//!   at +0x24 stays in bounds on a host, and it is zero-filled where the
//!   original leaves `u`/`z`/`n`/`type`/`xDel` uninitialized (nothing
//!   reads those before the serial_get seam writes them).

use super::get_varint::get_varint;
use super::mem_release::{mem_release, Z_MALLOC_OFFSET};
use super::value_new::{MEM_DB_OFFSET, MEM_FLAGS_OFFSET, MEM_SIZE};
use super::value_text::MEM_ENC_OFFSET;

/// The collation and sort-order descriptor of one index — SQLite
/// 3.5.9's `KeyInfo`, laid out per this function's own loads
/// (`ldr r6,[r2,#0x0]` then `ldrb r0,[r6,#0x4]`, `ldrb r0,[r6,#0x5]`,
/// `ldrb r0,[r6,#0x6]`, `ldr r11,[r6,#0x8]`, `ldr r0,[r6,#0xc]`,
/// `ldrlt r2,[r6+i*4,#0x10]`).
#[repr(C)]
pub struct KeyInfo {
    /// +0x00: the owning connection (`sqlite3 *`).
    pub db: *mut u8,
    /// +0x04: text encoding — one of the `SQLITE_UTF*` values.
    pub enc: u8,
    /// +0x05: when the fields compare equal, treat the parsed key as
    /// larger (`OP_IdxGE` and friends).
    pub incr_key: u8,
    /// +0x06: when the fields compare equal, keep the result zero even
    /// if key1 carries unconsumed payload (prefix search).
    pub prefix_is_equal: u8,
    /// +0x07: alignment pad.
    pub _pad_07: u8,
    /// +0x08: number of columns `a_sort_order`/`a_coll` describe.
    pub n_field: i32,
    /// +0x0c: per-column descending flags, or NULL for all-ascending.
    pub a_sort_order: *const u8,
    /// +0x10: per-column collations — `n_field` entries in the original
    /// (a flexible array member; indexed through the pointer here).
    pub a_coll: [*const u8; 1],
}

/// A parsed key — SQLite 3.5.9's `UnpackedRecord`, laid out per this
/// function's loads (`ldrh r0,[r10,#0x4]`, `ldr r0,[r10,#0x8]`). The
/// +0x05/+0x06 ownership bytes are the `sqlite3VdbeRecordUnpack`
/// analog's (@ 0x0838c9f0) writes; this function never reads them.
#[repr(C)]
pub struct UnpackedRecord {
    /// +0x00: collation and sort-order information.
    pub key_info: *const KeyInfo,
    /// +0x04: number of parsed fields in `a_mem`.
    pub n_field: u16,
    /// +0x05: the record was heap-allocated (upstream `needFree`).
    pub need_free: u8,
    /// +0x06: the `a_mem` values hold resources (upstream
    /// `needDestroy`).
    pub need_destroy: u8,
    /// +0x08: the parsed fields — `n_field` raw 0x28-byte `Mem`s.
    pub a_mem: *mut u8,
}

// The original's byte offsets, asserted on the 32-bit target. On a
// 64-bit host the pointer fields widen and these shift — harmless,
// because all access goes through the typed structs (the
// `sqlite/vdbe.rs` pattern).
#[cfg(target_pointer_width = "32")]
const _KEY_INFO_N_FIELD_OFFSET: [u8; 0x08] = [0; core::mem::offset_of!(KeyInfo, n_field)];
#[cfg(target_pointer_width = "32")]
const _KEY_INFO_A_SORT_ORDER_OFFSET: [u8; 0x0c] =
    [0; core::mem::offset_of!(KeyInfo, a_sort_order)];
#[cfg(target_pointer_width = "32")]
const _KEY_INFO_A_COLL_OFFSET: [u8; 0x10] = [0; core::mem::offset_of!(KeyInfo, a_coll)];
#[cfg(target_pointer_width = "32")]
const _UNPACKED_N_FIELD_OFFSET: [u8; 0x04] = [0; core::mem::offset_of!(UnpackedRecord, n_field)];
#[cfg(target_pointer_width = "32")]
const _UNPACKED_A_MEM_OFFSET: [u8; 0x08] = [0; core::mem::offset_of!(UnpackedRecord, a_mem)];

/// `sqlite3VdbeSerialTypeLen(serial_type)` @ 0x0838cfe8: the payload
/// byte length of one field with this serial type.
pub type VdbeSerialTypeLenFn = unsafe extern "C" fn(serial_type: u32) -> u32;

/// `sqlite3VdbeSerialGet(buf, serial_type, pMem)` @ 0x0838cc1c: decode
/// the field at `buf` into the 0x28-byte `Mem` at `p_mem` and return
/// the payload bytes consumed.
pub type VdbeSerialGetFn =
    unsafe extern "C" fn(buf: *const u8, serial_type: u32, p_mem: *mut u8) -> u32;

/// `sqlite3MemCompare(p1, p2, pColl)` @ 0x0837d47c: weigh two `Mem`s
/// under a collation (a NULL coll selects the KeyInfo default).
pub type SqliteMemCompareFn =
    unsafe extern "C" fn(p1: *const u8, p2: *const u8, coll: *const u8) -> i32;

/// RetailOS load address of `sqlite3VdbeSerialTypeLen`.
pub const VDBE_SERIAL_TYPE_LEN_ADDRESS: usize = 0x0838_cfe8;
/// RetailOS load address of `sqlite3VdbeSerialGet`.
pub const VDBE_SERIAL_GET_ADDRESS: usize = 0x0838_cc1c;
/// RetailOS load address of `sqlite3MemCompare`.
pub const SQLITE_MEM_COMPARE_ADDRESS: usize = 0x0837_d47c;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_vdbe_serial_type_len(serial_type: u32) -> u32 {
    let serial_type_len: VdbeSerialTypeLenFn =
        core::mem::transmute(VDBE_SERIAL_TYPE_LEN_ADDRESS);
    serial_type_len(serial_type)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_vdbe_serial_type_len(_serial_type: u32) -> u32 {
    panic!("vdbe_record_compare requires sqlite3VdbeSerialTypeLen @ 0x0838cfe8")
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_vdbe_serial_get(
    buf: *const u8,
    serial_type: u32,
    p_mem: *mut u8,
) -> u32 {
    let serial_get: VdbeSerialGetFn = core::mem::transmute(VDBE_SERIAL_GET_ADDRESS);
    serial_get(buf, serial_type, p_mem)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_vdbe_serial_get(
    _buf: *const u8,
    _serial_type: u32,
    _p_mem: *mut u8,
) -> u32 {
    panic!("vdbe_record_compare requires sqlite3VdbeSerialGet @ 0x0838cc1c")
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_sqlite_mem_compare(
    p1: *const u8,
    p2: *const u8,
    coll: *const u8,
) -> i32 {
    let mem_compare: SqliteMemCompareFn = core::mem::transmute(SQLITE_MEM_COMPARE_ADDRESS);
    mem_compare(p1, p2, coll)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_sqlite_mem_compare(
    _p1: *const u8,
    _p2: *const u8,
    _coll: *const u8,
) -> i32 {
    panic!("vdbe_record_compare requires sqlite3MemCompare @ 0x0837d47c")
}

/// Indirect dispatch for the unported serial-type length table, field
/// decoder, and Mem comparator. Host tests replace these slots; target
/// defaults call the retailOS entries directly.
#[derive(Clone, Copy)]
pub struct VdbeRecordCompareOps {
    /// `sqlite3VdbeSerialTypeLen(serial_type)` @ 0x0838cfe8.
    pub serial_type_len: VdbeSerialTypeLenFn,
    /// `sqlite3VdbeSerialGet(&aKey1[d1], serial_type, &mem1)` @
    /// 0x0838cc1c.
    pub serial_get: VdbeSerialGetFn,
    /// `sqlite3MemCompare(&mem1, &aMem[i], coll)` @ 0x0837d47c.
    pub mem_compare: SqliteMemCompareFn,
}

/// Target default: branch to the three remaining retailOS helpers.
#[cfg(target_os = "none")]
pub const DEFAULT_VDBE_RECORD_COMPARE_OPS: VdbeRecordCompareOps = VdbeRecordCompareOps {
    serial_type_len: retail_vdbe_serial_type_len,
    serial_get: retail_vdbe_serial_get,
    mem_compare: retail_sqlite_mem_compare,
};

/// Host default: fail loudly until a test supplies the unported helpers.
#[cfg(not(target_os = "none"))]
pub const DEFAULT_VDBE_RECORD_COMPARE_OPS: VdbeRecordCompareOps = VdbeRecordCompareOps {
    serial_type_len: missing_vdbe_serial_type_len,
    serial_get: missing_vdbe_serial_get,
    mem_compare: missing_sqlite_mem_compare,
};

/// Active length/decoder/comparator triple. Host tests install
/// reference implementations.
pub static mut VDBE_RECORD_COMPARE_OPS: VdbeRecordCompareOps =
    DEFAULT_VDBE_RECORD_COMPARE_OPS;

/// Reads the length slot volatile so host replacements cannot be folded
/// into the default.
#[inline(always)]
unsafe fn serial_type_len_op() -> VdbeSerialTypeLenFn {
    core::ptr::read_volatile(core::ptr::addr_of!(VDBE_RECORD_COMPARE_OPS.serial_type_len))
}

/// Reads the decoder slot volatile (same pattern).
#[inline(always)]
unsafe fn serial_get_op() -> VdbeSerialGetFn {
    core::ptr::read_volatile(core::ptr::addr_of!(VDBE_RECORD_COMPARE_OPS.serial_get))
}

/// Reads the comparator slot volatile (same pattern).
#[inline(always)]
unsafe fn mem_compare_op() -> SqliteMemCompareFn {
    core::ptr::read_volatile(core::ptr::addr_of!(VDBE_RECORD_COMPARE_OPS.mem_compare))
}

/// The build's `getVarint32` idiom: a first byte under 0x80 is the
/// one-byte case inline (value = byte, length 1); anything else calls
/// the ported [`get_varint`], whose u64 out-param truncates to the u32
/// the original's callee stored (see `sqlite/get_varint.rs`).
unsafe fn get_varint32_fast(p: *const u8, out: *mut u32) -> u32 {
    let first = *p;
    if first < 0x80 {
        *out = first as u32;
        1
    } else {
        let mut wide = 0u64;
        let len = get_varint(p, &mut wide);
        *out = wide as u32;
        len
    }
}

/// vdbe_record_compare — original: `FUN_0838c87c` @ 0x0838c87c (372
/// bytes; 3 `bl` call sites).
///
/// `sqlite3VdbeRecordCompare`: compare the packed record `{n_key1,
/// p_key1}` against the parsed key `p_key2`, returning a negative,
/// zero, or positive integer as key1 is less than, equal to, or
/// greater than key2. See the module header for the algorithm and the
/// endgame rules (`incrKey`, `prefixIsEqual`, trailing payload,
/// descending columns).
///
/// Register usage: r0 = nKey1, r1 = pKey1, r2 = pPKey2; r6 = the
/// KeyInfo, r7 = d1, r5 = idx1, r4 = i, r8 = rc, r9 = pKey1, r10 =
/// pPKey2, r11 = the KeyInfo's nField.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vdbe_record_compare(
    n_key1: i32,
    p_key1: *const u8,
    p_key2: *const UnpackedRecord,
) -> i32 {
    let key_info = (*p_key2).key_info;
    // The scratch Mem the original keeps at sp+0x08. 0x30 bytes, not
    // the target's 0x28, so the ported mem_release's native-width
    // NULLing of zMalloc at +0x24 stays in bounds on a 64-bit host.
    let mut mem1 = [0usize; 6];
    let mem1 = mem1.as_mut_ptr() as *mut u8;
    (mem1.add(MEM_ENC_OFFSET)).write((*key_info).enc);
    (mem1.add(MEM_DB_OFFSET) as *mut *mut u8).write((*key_info).db);
    (mem1.add(MEM_FLAGS_OFFSET) as *mut u16).write(0);
    (mem1.add(Z_MALLOC_OFFSET) as *mut *mut u8).write(core::ptr::null_mut());

    let mut sz_hdr1: u32 = 0;
    let mut idx1 = get_varint32_fast(p_key1, &mut sz_hdr1);
    let mut d1 = sz_hdr1;
    let n_field = (*key_info).n_field;
    let mut i: i32 = 0;
    let mut rc: i32 = 0;
    while idx1 < sz_hdr1 && i < (*p_key2).n_field as i32 {
        let mut serial_type1: u32 = 0;
        idx1 = idx1.wrapping_add(get_varint32_fast(p_key1.add(idx1 as usize), &mut serial_type1));
        // Original: `cmp r7,r0; bcc` (unsigned d1 >= nKey1) then
        // `cmp r0,#0x0; bgt` (signed length > 0 — the table/formula
        // never sets bit 31, so the signed read is exact).
        if d1 >= n_key1 as u32 && (serial_type_len_op())(serial_type1) as i32 > 0 {
            break;
        }
        d1 = d1.wrapping_add((serial_get_op())(p_key1.add(d1 as usize), serial_type1, mem1));
        let coll = if i < n_field {
            (*key_info).a_coll.as_ptr().add(i as usize).read()
        } else {
            core::ptr::null()
        };
        rc = (mem_compare_op())(mem1, (*p_key2).a_mem.add(i as usize * MEM_SIZE as usize), coll);
        if rc != 0 {
            break;
        }
        i += 1;
    }
    if !(mem1.add(Z_MALLOC_OFFSET) as *const *mut u8).read().is_null() {
        mem_release(mem1);
    }
    if rc == 0 {
        if (*key_info).incr_key != 0 {
            rc = -1;
        } else if (*key_info).prefix_is_equal == 0 && d1 < n_key1 as u32 {
            rc = 1;
        }
    } else {
        let a_sort_order = (*key_info).a_sort_order;
        if !a_sort_order.is_null()
            && i < (*key_info).n_field
            && *a_sort_order.add(i as usize) != 0
        {
            rc = -rc;
        }
    }
    rc
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::tracked::{BLOCK_HEADER_SIZE, TAG_TRACKED};
    use crate::heap::types::HeapDescriptorDescriptor;
    use crate::heap::veneers::{tests::mock_heap, HEAP_OPS};
    use std::sync::Mutex;
    use std::vec::Vec;

    /// Serializes tests that swap the shared dispatch slots, the event
    /// log, and the fixture arena.
    static OPS_LOCK: Mutex<()> = Mutex::new(());

    /// Every helper call the code under test made, in order.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Event {
        TypeLen(u32),
        SerialGet(usize, u32),
        Compare(usize, usize, usize),
        RawFree(usize, usize),
    }

    static mut EVENTS: Vec<Event> = Vec::new();

    /// Records and text payloads live here so a text `Mem`'s `z` can be
    /// a u32 offset from the arena base: the raw 0x28-byte `Mem` cannot
    /// hold a host-width `z` at +0x14 AND `n` at +0x18 on a 64-bit host
    /// (the widened pointer overlaps `n`), so the reference model
    /// encodes `z` as an offset. On target the retail serial_get stores
    /// a real 4-byte pointer at +0x14; nothing here depends on the
    /// encoding the unported callee would use.
    static mut ARENA: [u8; 0x2000] = [0; 0x2000];
    static mut ARENA_CURSOR: usize = 0;

    fn events() -> Vec<Event> {
        unsafe { (*core::ptr::addr_of!(EVENTS)).clone() }
    }

    fn arena_base() -> usize {
        core::ptr::addr_of_mut!(ARENA) as usize
    }

    /// Copies `bytes` into the arena, returning the offset.
    fn arena_write(bytes: &[u8]) -> usize {
        unsafe {
            let cursor = *core::ptr::addr_of!(ARENA_CURSOR);
            let arena = &mut *core::ptr::addr_of_mut!(ARENA);
            arena[cursor..cursor + bytes.len()].copy_from_slice(bytes);
            *core::ptr::addr_of_mut!(ARENA_CURSOR) = cursor + bytes.len();
            cursor
        }
    }

    // Raw-Mem field offsets the reference model touches (the others
    // come from the ported modules).
    const MEM_U_OFFSET: usize = 0x00;
    const MEM_R_OFFSET: usize = 0x08;
    const MEM_Z_OFFSET: usize = 0x14;
    const MEM_N_OFFSET: usize = 0x18;
    const MEM_X_DEL_OFFSET: usize = 0x20;

    /// The type bits as the retail serial_get @ 0x0838cc1c stamps them:
    /// `MEM_Null`, `MEM_Int` and `MEM_Real` are the upstream numbers;
    /// text is 0x110 (`moveq r0,#0x110`), blob 0x102 (the literal pool
    /// entry @ 0x0838ce00, verified in osos.dec).
    const FLAG_NULL: u16 = 0x1;
    const FLAG_INT: u16 = 0x4;
    const FLAG_REAL: u16 = 0x8;
    const FLAG_TEXT: u16 = 0x110;
    const FLAG_BLOB: u16 = 0x102;

    /// `sqlite3VdbeSerialTypeLen`'s upstream `aSize[]` (the retail
    /// table datum is not in the image — see the module header).
    const A_SIZE: [u32; 12] = [0, 1, 2, 3, 4, 6, 8, 8, 0, 0, 0, 0];

    unsafe fn rd_u16(p: *const u8, off: usize) -> u16 {
        (p.add(off) as *const u16).read()
    }
    unsafe fn wr_u16(p: *mut u8, off: usize, v: u16) {
        (p.add(off) as *mut u16).write(v);
    }
    unsafe fn wr_u32(p: *mut u8, off: usize, v: u32) {
        (p.add(off) as *mut u32).write(v);
    }
    unsafe fn wr_i32(p: *mut u8, off: usize, v: i32) {
        (p.add(off) as *mut i32).write(v);
    }
    unsafe fn wr_u64(p: *mut u8, off: usize, v: u64) {
        (p.add(off) as *mut u64).write(v);
    }
    unsafe fn wr_ptr(p: *mut u8, off: usize, v: *const u8) {
        (p.add(off) as *mut *const u8).write(v);
    }

    /// Reference `sqlite3VdbeSerialTypeLen`: the upstream table for
    /// types < 12, `(t - 12) / 2` above — the retail shape exactly.
    unsafe extern "C" fn ref_serial_type_len(serial_type: u32) -> u32 {
        (*core::ptr::addr_of_mut!(EVENTS)).push(Event::TypeLen(serial_type));
        if serial_type < 12 {
            A_SIZE[serial_type as usize]
        } else {
            (serial_type - 12) / 2
        }
    }

    /// Reference `sqlite3VdbeSerialGet`, mirroring the retail jump
    /// table @ 0x0838cc1c case for case: big-endian sign-extended ints
    /// (types 1..=6), an 8-byte real with NaN collapsing to NULL (7),
    /// the constants 0/1 (8/9), and the string/blob tail with
    /// `n = (t - 12) / 2`, `xDel = 0`. Text `z` is the arena-offset
    /// encoding described on [`ARENA`].
    unsafe extern "C" fn ref_serial_get(buf: *const u8, serial_type: u32, p_mem: *mut u8) -> u32 {
        (*core::ptr::addr_of_mut!(EVENTS)).push(Event::SerialGet(buf as usize, serial_type));
        match serial_type {
            0 => {
                wr_u16(p_mem, MEM_FLAGS_OFFSET, FLAG_NULL);
                0
            }
            1..=6 => {
                let len = [0usize, 1, 2, 3, 4, 6, 8][serial_type as usize];
                let mut v = *buf as i8 as i64;
                for k in 1..len {
                    v = v << 8 | *buf.add(k) as i64;
                }
                wr_u64(p_mem, MEM_U_OFFSET, v as u64);
                wr_u16(p_mem, MEM_FLAGS_OFFSET, FLAG_INT);
                len as u32
            }
            7 => {
                let mut bits = 0u64;
                for k in 0..8 {
                    bits = bits << 8 | *buf.add(k) as u64;
                }
                let value = f64::from_bits(bits);
                (p_mem.add(MEM_R_OFFSET) as *mut f64).write(value);
                wr_u16(
                    p_mem,
                    MEM_FLAGS_OFFSET,
                    if value.is_nan() { FLAG_NULL } else { FLAG_REAL },
                );
                8
            }
            8 | 9 => {
                wr_u64(p_mem, MEM_U_OFFSET, (serial_type - 8) as u64);
                wr_u16(p_mem, MEM_FLAGS_OFFSET, FLAG_INT);
                0
            }
            _ => {
                let n = ((serial_type - 12) / 2) as i32;
                wr_u32(p_mem, MEM_Z_OFFSET, (buf as usize - arena_base()) as u32);
                wr_i32(p_mem, MEM_N_OFFSET, n);
                wr_ptr(p_mem, MEM_X_DEL_OFFSET, core::ptr::null());
                wr_u16(
                    p_mem,
                    MEM_FLAGS_OFFSET,
                    if serial_type & 1 != 0 { FLAG_BLOB } else { FLAG_TEXT },
                );
                n as u32
            }
        }
    }

    /// The numeric payload of a decoded Mem: the integer arm or the
    /// real arm as an f64.
    unsafe fn numeric(p: *const u8, flags: u16) -> f64 {
        if flags & FLAG_INT != 0 {
            (p.add(MEM_U_OFFSET) as *const u64).read() as i64 as f64
        } else {
            (p.add(MEM_R_OFFSET) as *const f64).read()
        }
    }

    /// The (z, n) of a text/blob Mem in the arena-offset encoding.
    unsafe fn text_of(p: *const u8) -> (*const u8, i32) {
        let z_off = (p.add(MEM_Z_OFFSET) as *const u32).read();
        let n = (p.add(MEM_N_OFFSET) as *const i32).read();
        ((arena_base() + z_off as usize) as *const u8, n)
    }

    /// Reference `sqlite3MemCompare`, restricted to what the fixtures
    /// exercise: NULL sorts first (upstream's
    /// `(f2 & MEM_Null) - (f1 & MEM_Null)`), numerics compare
    /// numerically, text/blob compare bytewise with the
    /// shorter-is-smaller prefix rule (upstream's BINARY collation).
    unsafe extern "C" fn ref_mem_compare(p1: *const u8, p2: *const u8, coll: *const u8) -> i32 {
        (*core::ptr::addr_of_mut!(EVENTS))
            .push(Event::Compare(p1 as usize, p2 as usize, coll as usize));
        let f1 = rd_u16(p1, MEM_FLAGS_OFFSET);
        let f2 = rd_u16(p2, MEM_FLAGS_OFFSET);
        let combined = f1 | f2;
        if combined & FLAG_NULL != 0 {
            return (f2 & FLAG_NULL) as i32 - (f1 & FLAG_NULL) as i32;
        }
        if combined & (FLAG_INT | FLAG_REAL) != 0 {
            assert!(
                f1 & (FLAG_INT | FLAG_REAL) != 0 && f2 & (FLAG_INT | FLAG_REAL) != 0,
                "reference model: numeric fields compare against numerics only"
            );
            let a = numeric(p1, f1);
            let b = numeric(p2, f2);
            return if a < b {
                -1
            } else if a > b {
                1
            } else {
                0
            };
        }
        assert!(
            f1 & 0x100 != 0 && f2 & 0x100 != 0,
            "reference model: ephemeral text/blob flags on both sides"
        );
        let (z1, n1) = text_of(p1);
        let (z2, n2) = text_of(p2);
        for k in 0..n1.min(n2) {
            let a = *z1.add(k as usize);
            let b = *z2.add(k as usize);
            if a != b {
                return a as i32 - b as i32;
            }
        }
        n1 - n2
    }

    /// One fixture column.
    #[derive(Clone)]
    enum Val {
        Null,
        Int(i64),
        Real(f64),
        Text(Vec<u8>),
        Blob(Vec<u8>),
    }

    /// The smallest upstream serial type holding `v` (types 8/9 are the
    /// constants 0/1).
    fn int_field(v: i64) -> (u32, Vec<u8>) {
        if v == 0 {
            return (8, Vec::new());
        }
        if v == 1 {
            return (9, Vec::new());
        }
        let bytes = v.to_be_bytes();
        for (serial_type, len) in [(1u32, 1usize), (2, 2), (3, 3), (4, 4), (5, 6), (6, 8)] {
            let tail = &bytes[8 - len..];
            let mut extended = [if v < 0 { 0xff } else { 0 }; 8];
            extended[8 - len..].copy_from_slice(tail);
            if i64::from_be_bytes(extended) == v {
                return (serial_type, tail.to_vec());
            }
        }
        unreachable!("i64 always fits the 8-byte serial type")
    }

    /// The (serial type, payload bytes) of one fixture column.
    fn field(val: &Val) -> (u32, Vec<u8>) {
        match val {
            Val::Null => (0, Vec::new()),
            Val::Int(v) => int_field(*v),
            Val::Real(v) => (7, v.to_bits().to_be_bytes().to_vec()),
            Val::Text(t) => (12 + 2 * t.len() as u32, t.clone()),
            Val::Blob(b) => (13 + 2 * b.len() as u32, b.clone()),
        }
    }

    /// Canonical `sqlite3PutVarint`: 7-bit groups, most significant
    /// first, continuation bit on all but the last.
    fn put_varint(mut v: u64, out: &mut Vec<u8>) {
        let mut groups = [0u8; 9];
        let mut n = 0;
        loop {
            groups[n] = (v & 0x7f) as u8;
            v >>= 7;
            n += 1;
            if v == 0 {
                break;
            }
        }
        for i in (0..n).rev() {
            let mut byte = groups[i];
            if i != 0 {
                byte |= 0x80;
            }
            out.push(byte);
        }
    }

    /// A record built into the arena: its own byte offset, its length,
    /// and each field's serial type and absolute payload address (what
    /// the serial_get seam must be handed, in order).
    struct BuiltKey {
        ptr: *const u8,
        n: i32,
        serial_types: Vec<u32>,
        payload_addrs: Vec<usize>,
    }

    fn build_key(vals: &[Val]) -> BuiltKey {
        let fields: Vec<(u32, Vec<u8>)> = vals.iter().map(field).collect();
        let mut header: Vec<u8> = Vec::new();
        for (serial_type, _) in &fields {
            put_varint(*serial_type as u64, &mut header);
        }
        // The header-size varint counts itself; one growth step is
        // enough at these sizes (0x7f -> 0x81 crosses exactly one
        // boundary).
        let mut sz_hdr = header.len() + 1;
        if sz_hdr >= 0x80 {
            sz_hdr = header.len() + 2;
        }
        let mut record: Vec<u8> = Vec::new();
        put_varint(sz_hdr as u64, &mut record);
        record.extend_from_slice(&header);
        let mut payload_addrs = Vec::new();
        for (_, payload) in &fields {
            payload_addrs.push(record.len());
            record.extend_from_slice(payload);
        }
        let off = arena_write(&record);
        BuiltKey {
            ptr: (arena_base() + off) as *const u8,
            n: record.len() as i32,
            serial_types: fields.iter().map(|(t, _)| *t).collect(),
            payload_addrs: payload_addrs
                .iter()
                .map(|relative| arena_base() + off + relative)
                .collect(),
        }
    }

    /// The aMem array: `vals.len()` raw 0x28-byte Mems (u64 backing for
    /// alignment), text/blob payloads in the arena.
    struct AMem {
        block: [u64; 0x28 * 140 / 8],
    }

    impl AMem {
        fn ptr(&mut self) -> *mut u8 {
            self.block.as_mut_ptr() as *mut u8
        }
    }

    fn build_a_mem(vals: &[Val]) -> AMem {
        let mut a_mem = AMem {
            block: [0; 0x28 * 140 / 8],
        };
        for (i, val) in vals.iter().enumerate() {
            let el = unsafe { a_mem.ptr().add(i * MEM_SIZE as usize) };
            unsafe {
                match val {
                    Val::Null => wr_u16(el, MEM_FLAGS_OFFSET, FLAG_NULL),
                    Val::Int(v) => {
                        wr_u64(el, MEM_U_OFFSET, *v as u64);
                        wr_u16(el, MEM_FLAGS_OFFSET, FLAG_INT);
                    }
                    Val::Real(v) => {
                        (el.add(MEM_R_OFFSET) as *mut f64).write(*v);
                        wr_u16(el, MEM_FLAGS_OFFSET, FLAG_REAL);
                    }
                    Val::Text(t) | Val::Blob(t) => {
                        let off = arena_write(t);
                        wr_u32(el, MEM_Z_OFFSET, off as u32);
                        wr_i32(el, MEM_N_OFFSET, t.len() as i32);
                        wr_u16(
                            el,
                            MEM_FLAGS_OFFSET,
                            if matches!(val, Val::Text(_)) {
                                FLAG_TEXT
                            } else {
                                FLAG_BLOB
                            },
                        );
                    }
                }
            }
        }
        a_mem
    }

    /// Room for every fixture's collation array (the largest walk
    /// below reads 130 of them).
    const MAX_COLLS: usize = 140;

    /// A KeyInfo fixture with backing storage for the flexible aColl
    /// array and the sort-order bytes.
    #[repr(C)]
    struct KeyInfoFixture {
        head: KeyInfo,
        extra_colls: [*const u8; MAX_COLLS - 1],
        sort_order: Vec<u8>,
    }

    fn build_key_info(
        incr_key: u8,
        prefix_is_equal: u8,
        n_field: i32,
        sort_order: Vec<u8>,
        colls: &[*const u8],
    ) -> KeyInfoFixture {
        let mut fixture = KeyInfoFixture {
            head: KeyInfo {
                db: 0x0bad_babeusize as *mut u8,
                enc: 1,
                incr_key,
                prefix_is_equal,
                _pad_07: 0,
                n_field,
                a_sort_order: core::ptr::null(),
                a_coll: [core::ptr::null(); 1],
            },
            extra_colls: [core::ptr::null(); MAX_COLLS - 1],
            sort_order,
        };
        if !fixture.sort_order.is_empty() {
            fixture.head.a_sort_order = fixture.sort_order.as_ptr();
        }
        fixture.head.a_coll[0] = *colls.first().unwrap_or(&core::ptr::null());
        for (i, coll) in colls.iter().enumerate().skip(1) {
            fixture.extra_colls[i - 1] = *coll;
        }
        fixture
    }

    /// An UnpackedRecord fixture over a KeyInfo and an aMem array.
    fn build_unpacked(key_info: *const KeyInfo, n_field: u16, a_mem: *mut u8) -> UnpackedRecord {
        UnpackedRecord {
            key_info,
            n_field,
            need_free: 0,
            need_destroy: 0,
            a_mem,
        }
    }

    /// Installs the reference helpers, runs `body`, restores the host
    /// defaults. Serialized on [`OPS_LOCK`].
    fn with_ops(body: impl FnOnce()) {
        let _guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            (*core::ptr::addr_of_mut!(EVENTS)).clear();
            *core::ptr::addr_of_mut!(ARENA_CURSOR) = 0;
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(VDBE_RECORD_COMPARE_OPS),
                VdbeRecordCompareOps {
                    serial_type_len: ref_serial_type_len,
                    serial_get: ref_serial_get,
                    mem_compare: ref_mem_compare,
                },
            );
        }
        body();
        unsafe {
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(VDBE_RECORD_COMPARE_OPS),
                DEFAULT_VDBE_RECORD_COMPARE_OPS,
            );
        }
    }

    /// Compares `key` against a parsed key built from `key2_vals`,
    /// under `key_info`.
    fn compare(key: &BuiltKey, key2_vals: &[Val], key_info: &KeyInfoFixture) -> i32 {
        let mut a_mem = build_a_mem(key2_vals);
        let unpacked = build_unpacked(&key_info.head, key2_vals.len() as u16, a_mem.ptr());
        unsafe { vdbe_record_compare(key.n, key.ptr, &unpacked) }
    }

    /// Builds a key from `vals` and compares it against a parsed key of
    /// the same values.
    fn run(vals: &[Val], key_info: &KeyInfoFixture) -> i32 {
        let key = build_key(vals);
        compare(&key, vals, key_info)
    }

    /// The SerialGet events of a run, in order.
    fn serial_get_events() -> Vec<Event> {
        events()
            .iter()
            .filter(|e| matches!(e, Event::SerialGet(_, _)))
            .cloned()
            .collect()
    }

    /// The Compare events of a run, in order.
    fn compare_events() -> Vec<Event> {
        events()
            .iter()
            .filter(|e| matches!(e, Event::Compare(_, _, _)))
            .cloned()
            .collect()
    }

    #[test]
    fn equal_records_compare_zero_and_walk_every_field() {
        with_ops(|| {
            let key_info = build_key_info(0, 0, 4, Vec::new(), &[core::ptr::null(); 4]);
            let vals = std::vec![
                Val::Int(5),
                Val::Text(b"media".to_vec()),
                Val::Int(-2),
                Val::Real(2.5),
            ];
            let key = build_key(&vals);
            let rc = compare(&key, &vals, &key_info);

            assert_eq!(rc, 0, "identical records compare equal");
            // One serial_get per field, in field order, handed the exact
            // payload addresses — idx1/d1 tracking made observable.
            let expected: Vec<Event> = key
                .serial_types
                .iter()
                .zip(key.payload_addrs.iter())
                .map(|(serial_type, addr)| Event::SerialGet(*addr, *serial_type))
                .collect();
            assert_eq!(serial_get_events(), expected);
            assert_eq!(compare_events().len(), vals.len(), "one compare per field");
        });
    }

    #[test]
    fn first_differing_field_decides_and_stops_the_walk() {
        with_ops(|| {
            let key_info = build_key_info(0, 0, 2, Vec::new(), &[core::ptr::null(); 2]);
            let key = build_key(&[Val::Int(1), Val::Int(99)]);
            let rc = compare(&key, &[Val::Int(2), Val::Int(0)], &key_info);
            assert_eq!(rc, -1, "1 < 2 in the first field");
            assert_eq!(
                compare_events().len(),
                1,
                "a nonzero rc breaks out of the loop"
            );
        });
    }

    #[test]
    fn descending_sort_order_negates_a_nonzero_result() {
        with_ops(|| {
            // Difference in the first field, descending first column.
            let desc_first = build_key_info(0, 0, 2, std::vec![1, 0], &[core::ptr::null(); 2]);
            let key = build_key(&[Val::Int(1), Val::Int(99)]);
            let rc = compare(&key, &[Val::Int(2), Val::Int(0)], &desc_first);
            assert_eq!(rc, 1, "descending first column flips the sign");

            // Equal first field, descending second column.
            let desc_second = build_key_info(0, 0, 2, std::vec![0, 1], &[core::ptr::null(); 2]);
            let key = build_key(&[Val::Int(1), Val::Int(9)]);
            let rc = compare(&key, &[Val::Int(1), Val::Int(8)], &desc_second);
            assert_eq!(rc, -1, "9 > 8 raw, negated by the second column's flag");
        });
    }

    #[test]
    fn sort_order_beyond_n_field_is_not_consulted() {
        with_ops(|| {
            // KeyInfo declares zero columns: aSortOrder exists but i is
            // never < nField, so the nonzero rc survives unnegated.
            let key_info = build_key_info(0, 0, 0, std::vec![1], &[]);
            let key = build_key(&[Val::Int(1)]);
            let rc = compare(&key, &[Val::Int(2)], &key_info);
            assert_eq!(rc, -1, "i < nField fails: no negation");
        });
    }

    #[test]
    fn trailing_payload_in_key1_makes_it_greater() {
        with_ops(|| {
            let key_info = build_key_info(0, 0, 1, Vec::new(), &[core::ptr::null(); 1]);
            // key2 parses one field; key1 carries a second one the loop
            // never reaches.
            let key = build_key(&[Val::Int(1), Val::Int(2)]);
            let rc = compare(&key, &[Val::Int(1)], &key_info);
            assert_eq!(rc, 1, "d1 < nKey1: key1 has more fields, key1 is larger");
        });
    }

    #[test]
    fn incr_key_treats_the_parsed_key_as_larger() {
        with_ops(|| {
            let key_info = build_key_info(1, 0, 1, Vec::new(), &[core::ptr::null(); 1]);
            let key = build_key(&[Val::Int(1), Val::Int(2)]);
            let rc = compare(&key, &[Val::Int(1)], &key_info);
            assert_eq!(rc, -1, "incrKey wins over the trailing-payload rule");
        });
    }

    #[test]
    fn prefix_is_equal_keeps_a_zero_result_with_trailing_payload() {
        with_ops(|| {
            let key_info = build_key_info(0, 1, 1, Vec::new(), &[core::ptr::null(); 1]);
            let key = build_key(&[Val::Int(1), Val::Int(2)]);
            let rc = compare(&key, &[Val::Int(1)], &key_info);
            assert_eq!(rc, 0, "prefixIsEqual suppresses the key1-is-larger rule");
        });
    }

    #[test]
    fn null_fields_compare_and_null_sorts_first() {
        with_ops(|| {
            let key_info = build_key_info(0, 0, 1, Vec::new(), &[core::ptr::null(); 1]);
            let key = build_key(&[Val::Null]);
            let rc = compare(&key, &[Val::Int(1)], &key_info);
            assert_eq!(rc, -1, "NULL sorts before any value");

            let key_info = build_key_info(0, 0, 1, Vec::new(), &[core::ptr::null(); 1]);
            let rc = run(&[Val::Null], &key_info);
            assert_eq!(rc, 0, "two NULLs are equal");
        });
    }

    #[test]
    fn real_fields_compare_numerically() {
        with_ops(|| {
            let key_info = build_key_info(0, 0, 1, Vec::new(), &[core::ptr::null(); 1]);
            let key = build_key(&[Val::Real(1.5)]);
            let rc = compare(&key, &[Val::Real(2.5)], &key_info);
            assert_eq!(rc, -1, "1.5 < 2.5");
        });
    }

    #[test]
    fn short_key1_breaks_before_touching_the_payload() {
        with_ops(|| {
            // Header claims two 1-byte integer fields but nKey1 ends at
            // the header: d1 >= nKey1 with a nonzero field length stops
            // the walk before serial_get runs.
            let key_info = build_key_info(0, 0, 2, Vec::new(), &[core::ptr::null(); 2]);
            let mut a_mem = build_a_mem(&[Val::Int(1), Val::Int(1)]);
            let unpacked = build_unpacked(&key_info.head, 2, a_mem.ptr());
            let key_off = arena_write(&[0x03, 0x01, 0x01]);
            let key_ptr = (arena_base() + key_off) as *const u8;

            let rc = unsafe { vdbe_record_compare(3, key_ptr, &unpacked) };

            assert_eq!(rc, 0, "nothing compared, d1 == nKey1: equal");
            assert_eq!(
                events(),
                std::vec![Event::TypeLen(1)],
                "the length table is consulted once; serial_get and compare never run"
            );
        });
    }

    #[test]
    fn zero_length_field_past_key1_end_still_compares() {
        with_ops(|| {
            // A NULL serial type has length zero: the exhausted-payload
            // break does not fire and the field is still decoded and
            // compared.
            let key_info = build_key_info(0, 0, 1, Vec::new(), &[core::ptr::null(); 1]);
            let mut a_mem = build_a_mem(&[Val::Int(7)]);
            let unpacked = build_unpacked(&key_info.head, 1, a_mem.ptr());
            let key_off = arena_write(&[0x02, 0x00]);
            let key_ptr = (arena_base() + key_off) as *const u8;

            let rc = unsafe { vdbe_record_compare(2, key_ptr, &unpacked) };

            assert_eq!(rc, -1, "the NULL field still compares (NULL < 7)");
            let got = events();
            assert_eq!(
                got[..2],
                [Event::TypeLen(0), Event::SerialGet(key_ptr as usize + 2, 0)],
                "the length check runs, then the zero-length field decodes"
            );
            assert_eq!(compare_events().len(), 1, "and it is compared once");
        });
    }

    #[test]
    fn multi_byte_header_varint_walks_all_fields() {
        with_ops(|| {
            // 130 NULL fields: the header-size varint needs two bytes
            // (132 >= 0x80), exercising the get_varint call in the
            // prologue.
            let vals = std::vec![Val::Null; 130];
            let key_info = build_key_info(0, 0, 130, Vec::new(), &[core::ptr::null(); 130]);
            let rc = run(&vals, &key_info);

            assert_eq!(rc, 0, "130 equal NULL fields");
            let got = events();
            assert_eq!(
                got.iter()
                    .filter(|e| matches!(e, Event::SerialGet(_, _)))
                    .count(),
                130,
                "every header entry decoded"
            );
            assert_eq!(
                got.iter()
                    .filter(|e| matches!(e, Event::Compare(_, _, _)))
                    .count(),
                130,
                "every field compared"
            );
            let type_lens: Vec<Event> = got
                .iter()
                .filter(|e| matches!(e, Event::TypeLen(_)))
                .cloned()
                .collect();
            // An all-NULL record has no payload, so d1 == nKey1 from
            // the first field on: the length table is consulted for
            // every field and answers zero each time.
            assert_eq!(
                type_lens,
                std::vec![Event::TypeLen(0); 130],
                "every zero-length field consults the table and survives it"
            );
        });
    }

    #[test]
    fn multi_byte_serial_type_varint_and_text_and_blob() {
        with_ops(|| {
            let text = std::vec![b'a'; 60]; // serial type 132: two varint bytes
            let blob = b"xy".to_vec();
            let vals = std::vec![Val::Text(text), Val::Blob(blob)];
            let key_info = build_key_info(0, 0, 2, Vec::new(), &[core::ptr::null(); 2]);
            let key = build_key(&vals);
            let rc = compare(&key, &vals, &key_info);

            assert_eq!(rc, 0, "equal text and blob fields");
            assert_eq!(
                key.serial_types,
                std::vec![132, 17],
                "60-byte text is type 132, 2-byte blob is type 17"
            );
            assert_eq!(
                serial_get_events(),
                std::vec![
                    Event::SerialGet(key.payload_addrs[0], 132),
                    Event::SerialGet(key.payload_addrs[1], 17),
                ],
                "the multi-byte serial varint decoded and d1 advanced 60 bytes"
            );
        });
    }

    #[test]
    fn text_order_is_bytewise_with_the_prefix_rule() {
        with_ops(|| {
            let key_info = build_key_info(0, 0, 1, Vec::new(), &[core::ptr::null(); 1]);
            let key = build_key(&[Val::Text(b"abc".to_vec())]);
            let rc = compare(&key, &[Val::Text(b"abd".to_vec())], &key_info);
            assert_eq!(rc, -1, "'c' - 'd'");

            let key_info = build_key_info(0, 0, 1, Vec::new(), &[core::ptr::null(); 1]);
            let key = build_key(&[Val::Text(b"ab".to_vec())]);
            let rc = compare(&key, &[Val::Text(b"abc".to_vec())], &key_info);
            assert_eq!(rc, -1, "the shorter prefix sorts first");
        });
    }

    #[test]
    fn coll_comes_from_the_key_info_until_n_field() {
        with_ops(|| {
            let marker = 0x0c01_1ec0usize as *const u8;
            // KeyInfo covers one column; the parsed key carries two.
            let key_info = build_key_info(0, 0, 1, Vec::new(), &[marker]);
            let vals = std::vec![Val::Int(1), Val::Int(2)];
            let rc = run(&vals, &key_info);

            assert_eq!(rc, 0);
            let colls: Vec<usize> = events()
                .iter()
                .filter_map(|e| match e {
                    Event::Compare(_, _, coll) => Some(*coll),
                    _ => None,
                })
                .collect();
            assert_eq!(
                colls,
                std::vec![marker as usize, 0],
                "aColl[0] for the first field, NULL past the KeyInfo's nField"
            );
        });
    }

    /// A hand-built tag-57 tracked block (layout: `heap::tracked`), the
    /// same fixture `sqlite/mem_release.rs` uses: raw block at offset 0
    /// of a 32-aligned buffer, payload at raw + 32, pad word
    /// 32 - BLOCK_HEADER_SIZE.
    #[repr(align(32))]
    struct TrackedBlock([u8; 64]);

    impl TrackedBlock {
        fn new() -> Self {
            let mut block = TrackedBlock([0; 64]);
            block.0[0..4].copy_from_slice(&24i32.to_le_bytes());
            let pad = (32 - BLOCK_HEADER_SIZE) as u32;
            block.0[28..32].copy_from_slice(&pad.to_le_bytes());
            block
        }
        fn raw(&mut self) -> *mut u8 {
            self.0.as_mut_ptr()
        }
        fn payload(&mut self) -> *mut u8 {
            // In-bounds by construction (64-byte block, payload at 32).
            unsafe { self.0.as_mut_ptr().add(32) }
        }
    }

    static mut PENDING_Z_MALLOC: *mut u8 = core::ptr::null_mut();

    /// A serial_get that leaves a live zMalloc behind — the only way
    /// the original's `if( mem1.zMalloc ) sqlite3VdbeMemRelease(&mem1)`
    /// can fire.
    unsafe extern "C" fn allocating_serial_get(
        buf: *const u8,
        serial_type: u32,
        p_mem: *mut u8,
    ) -> u32 {
        let payload = *core::ptr::addr_of!(PENDING_Z_MALLOC);
        wr_ptr(p_mem, Z_MALLOC_OFFSET, payload);
        ref_serial_get(buf, serial_type, p_mem)
    }

    unsafe extern "C" fn recording_heap_free(
        _heap: *mut HeapDescriptorDescriptor,
        ptr: *mut u8,
        tag: usize,
    ) {
        (*core::ptr::addr_of_mut!(EVENTS)).push(Event::RawFree(ptr as usize, tag));
    }

    #[test]
    fn a_z_malloc_left_by_serial_get_is_released_after_the_loop() {
        let _heap_guard = mock_heap();
        with_ops(|| {
            unsafe {
                (*core::ptr::addr_of_mut!(HEAP_OPS)).free = recording_heap_free;
                core::ptr::write_volatile(
                    core::ptr::addr_of_mut!(VDBE_RECORD_COMPARE_OPS),
                    VdbeRecordCompareOps {
                        serial_type_len: ref_serial_type_len,
                        serial_get: allocating_serial_get,
                        mem_compare: ref_mem_compare,
                    },
                );
            }
            let mut z_malloc_block = TrackedBlock::new();
            let z_malloc_raw = z_malloc_block.raw();
            unsafe {
                *core::ptr::addr_of_mut!(PENDING_Z_MALLOC) = z_malloc_block.payload();
            }

            let key_info = build_key_info(0, 0, 1, Vec::new(), &[core::ptr::null(); 1]);
            let key = build_key(&[Val::Int(1)]);
            let rc = compare(&key, &[Val::Int(2)], &key_info);

            assert_eq!(rc, -1);
            assert!(
                events().contains(&Event::RawFree(z_malloc_raw as usize, TAG_TRACKED)),
                "mem1.zMalloc went to the ported mem_release after the loop"
            );
        });
    }
}
