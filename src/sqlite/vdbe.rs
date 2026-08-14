//! The VDBE code builder — SQLite's bytecode emitter, and by call count
//! the busiest cluster in osos' database engine.
//!
//! Every SQL statement is compiled into an array of 20-byte `VdbeOp`
//! records hanging off the `Vdbe` at +0x14; the whole code generator
//! (0x082b4124, 0x082b5660, 0x082c39e0, ... — hundreds of sites) speaks to
//! it through the four `add_op` arities and the label/patch helpers here.
//!
//! Originals (sizes from `decomp/functions.csv`; call-site counts from
//! decoding `bl`/`b` words in osos.dec, not from osos.asm, which drops
//! lines):
//!
//! - `vdbe_add_op3` — `FUN_08386840` @ 0x08386840 (132 bytes;
//!   **282 `bl` call sites**). `sqlite3VdbeAddOp3`: append one opcode with
//!   three operands, return its address (the index it landed at).
//! - `vdbe_add_op2` — `FUN_08386824` @ 0x08386824 (28 bytes; 126 `bl` +
//!   1 tail `b`). `sqlite3VdbeAddOp2` — [`vdbe_add_op3`] with `p3 = 0`.
//! - `vdbe_add_op1` — `FUN_08386810` @ 0x08386810 (20 bytes; 56 `bl` +
//!   1 tail `b`). `sqlite3VdbeAddOp1` — `p2 = p3 = 0`.
//! - `vdbe_add_op4` — `FUN_083868c8` @ 0x083868c8 (68 bytes; 76 `bl`).
//!   `sqlite3VdbeAddOp4` — append, then attach the P4 operand.
//! - `vdbe_change_p4` — `FUN_08386aa4` @ 0x08386aa4 (304 bytes;
//!   24 `bl` + 2 tail `b`). `sqlite3VdbeChangeP4`: attach the fourth
//!   operand to an already-emitted op, releasing the old one.
//! - `vdbe_resize_op_array` — `FUN_08367f88` @ 0x08367f88 (48 bytes;
//!   2 `bl`). SQLite's `resizeOpArray`.
//! - `vdbe_change_p2` — `FUN_08386a44` @ 0x08386a44 (48 bytes; 66 `bl` +
//!   2 tail `b`). `sqlite3VdbeChangeP2`: back-patch a jump target.
//! - `vdbe_change_p5` — `FUN_08386bd4` @ 0x08386bd4 (32 bytes; 19 `bl` +
//!   1 tail `b`). `sqlite3VdbeChangeP5`: set P5 on the op just emitted.
//! - `vdbe_make_label` — `FUN_0838b8fc` @ 0x0838b8fc (88 bytes; 30 `bl`).
//!   `sqlite3VdbeMakeLabel`: reserve a forward-reference slot.
//! - `vdbe_resolve_label` — `FUN_0838cc04` @ 0x0838cc04 (24 bytes;
//!   32 `bl`). `sqlite3VdbeResolveLabel`: bind a label to the current
//!   address.
//!
//! ### Identification evidence
//!
//! The layouts below are not guesses; each offset is pinned by more than
//! one function. `vdbe_change_p5` writes the byte at `aOp + nOp*20 - 17`,
//! which is only `aOp[nOp-1] + 3` if the stride is 20 and `nOp` is at
//! +0x0c; `vdbe_resolve_label` writes `p->nOp` into `p->aLabel[-1-x]`,
//! reading `nOp` from +0x0c and `aLabel` from +0x20, matching
//! `vdbe_make_label`'s own view of +0x18/+0x1c/+0x20. `vdbe_add_op3`
//! stores `p1/p2/p3` with a single `stmib` into +4/+8/+12 and the byte
//! fields into +0/+1/+3, leaving +2 (`opflags`) untouched — exactly
//! SQLite's `VdbeOp`. The growth policy `nOpAlloc ? nOpAlloc*2 : 51` is
//! SQLite's `(int)(1024/sizeof(Op))` with `sizeof(Op) == 20`.
//!
//! ### Deviations
//!
//! - `freeP4` @ 0x082cf388 (148 bytes — the tag-dispatch destructor
//!   `vdbe_change_p4` calls to release old/dropped P4 payloads) is not
//!   ported; it is the [`VDBE_P4_OPS`] dispatch boundary (house
//!   pattern — see `heap/block_region.rs`). The default slot is a
//!   documented no-op: an unconfigured build leaks P4 payloads rather
//!   than freeing through the wrong destructor.
//! - `strlen` @ 0x08392478, `__rt_memcpy` @ 0x08037db0 and
//!   `db_str_ndup` @ 0x08374a40 are called directly through their
//!   ported twins; the KeyInfo copy's `sqlite3_malloc` @ 0x08390b14
//!   goes through the [`DB_MEM_OPS`](crate::sqlite::mem::DB_MEM_OPS)
//!   dispatch boundary, per the porting rules.
//! - `Vdbe` and `VdbeOp` are typed `#[repr(C)]` structs rather than raw
//!   byte offsets, so the pointer fields stay disjoint on a 64-bit test
//!   host. The exact original byte offsets are statically asserted on
//!   32-bit targets (`_VDBE_*_OFFSET`, `_VDBE_OP_SIZE`).
//! - `vdbe_change_p5` reproduces the original's unchecked `aOp[nOp - 1]`;
//!   the original relies on an `assert( p->nOp>0 )` that is compiled out
//!   here, and every call site emits an op immediately beforehand.

use crate::libc::rt_memcpy::__rt_memcpy;
use crate::libc::strlen::strlen;
use crate::sqlite::mem::{
    db_malloc_op, db_realloc, db_realloc_or_free, malloc_failed, set_malloc_failed,
};
use crate::sqlite::strdup::db_str_ndup;

/// One VDBE instruction — the original's 20-byte `VdbeOp`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VdbeOp {
    /// +0: the opcode.
    pub opcode: u8,
    /// +1: which flavor of pointer `p4` is (`P4_NOTUSED` == 0).
    pub p4type: i8,
    /// +2: per-opcode property bits. Never written by this cluster —
    /// `vdbe_add_op3` deliberately leaves it alone.
    pub opflags: u8,
    /// +3: the fifth, byte-wide operand.
    pub p5: u8,
    /// +4: first operand.
    pub p1: i32,
    /// +8: second operand — the jump destination for branch opcodes.
    pub p2: i32,
    /// +12: third operand.
    pub p3: i32,
    /// +16: fourth operand, a pointer interpreted per `p4type`.
    pub p4: *mut u8,
}

/// A prepared statement under construction. Only the fields this cluster
/// touches are modeled; `_gap*` spans stand for the rest of the original
/// struct and exist to place `expired` at +0xff.
#[repr(C)]
pub struct Vdbe {
    /// +0x00: the owning connection (`sqlite3 *`).
    pub db: *mut u8,
    /// +0x04..+0x0c: unmodeled.
    pub _gap_04: [u8; 8],
    /// +0x0c: number of ops emitted so far.
    pub n_op: i32,
    /// +0x10: number of ops `a_op` has room for.
    pub n_op_alloc: i32,
    /// +0x14: the op array.
    pub a_op: *mut VdbeOp,
    /// +0x18: number of labels handed out.
    pub n_label: i32,
    /// +0x1c: number of labels `a_label` has room for.
    pub n_label_alloc: i32,
    /// +0x20: label -> address table (`-1` while unresolved).
    pub a_label: *mut i32,
    /// +0x24: unmodeled.
    pub _gap_24: [u8; 4],
    /// +0x28: the column-name/decltype array — `n_res_column *
    /// COLNAME_N` [`Mem`]s laid end to end (`aColName`).
    pub a_col_name: *mut Mem,
    /// +0x2c..+0xec: unmodeled.
    pub _gap_2c: [u8; 0xec - 0x2c],
    /// +0xec: number of result columns the statement produces
    /// (`nResColumn`), the stride between the two `a_col_name` planes.
    pub n_res_column: i32,
    /// +0xf0..+0xff: unmodeled.
    pub _gap_f0: [u8; 0xff - 0xf0],
    /// +0xff: set when the schema changed under this statement; every
    /// emitted op clears it.
    pub expired: u8,
}

/// One dynamically-typed SQL value — the original's 40-byte `Mem`
/// (`sqlite3_value`), reconstructed from the firmware rather than from
/// an upstream header.
///
/// Every offset below has two independent witnesses. `sqlite3VdbeMemSetStr`
/// @ 0x0838c158 writes `z` at +0x14, `n` at +0x18, `flags` at +0x1c,
/// `type` at +0x1e, `enc` at +0x1f, `xDel` at +0x20 and `zMalloc` at
/// +0x24 (see `sqlite/value_set_str.rs`); `sqlite3VdbeSetNumCols` @
/// 0x0838d090 allocates `0x28` bytes per element (`mov r0,#0x28; mul
/// r1,r0,r5`) and stamps each one's +0x1c with `MEM_Null`, and
/// [`vdbe_set_col_name`](super::vdbe_set_col_name::vdbe_set_col_name)
/// indexes the same array with a 40-byte stride (`add r0,r0,r0 lsl #2`
/// then `add r4,r3,r0 lsl #3`). That leaves +0x00..+0x14 for upstream's
/// `union u` / `double r` / `sqlite3 *db` triple, which is the SQLite
/// 3.6-era layout exactly.
#[repr(C)]
pub struct Mem {
    /// +0x00: the integer/pointer arm of upstream's value union.
    pub u: u64,
    /// +0x08: the floating-point arm.
    pub r: f64,
    /// +0x10: the owning connection.
    pub db: *mut u8,
    /// +0x14: the string or blob body.
    pub z: *mut u8,
    /// +0x18: byte length of `z`.
    pub n: i32,
    /// +0x1c: `MEM_*` type and ownership bits.
    pub flags: u16,
    /// +0x1e: `SQLITE_NULL`/`SQLITE_TEXT`/... exposed by the API.
    pub value_type: u8,
    /// +0x1f: text encoding of `z`.
    pub enc: u8,
    /// +0x20: destructor for `z`, when the value owns it externally.
    pub x_del: *mut u8,
    /// +0x24: the `sqlite3_malloc` buffer `z` lives in, when the value
    /// owns it itself.
    pub z_malloc: *mut u8,
}

/// `Mem.flags` bit for "`z` points at storage nobody frees"
/// (`MEM_Static`). This build's `MEM_*` numbering is its own — the
/// evidence is `sqlite3VdbeMemSetStr`'s own constants (`MEM_Str` 0x2,
/// `MEM_Blob` 0x10, `MEM_Term` 0x20, `MEM_Dyn` 0x40, `MEM_Static`
/// 0x80), not upstream's 0x0800.
pub const MEM_STATIC: u16 = 0x0080;

/// Number of name planes `a_col_name` holds per column — upstream's
/// `COLNAME_N`. The original's `sqlite3VdbeSetNumCols` @ 0x0838d090
/// sizes the array `nResColumn << 1`, so this build has the two-plane
/// (name, decltype) configuration, not the five-plane metadata one.
pub const COLNAME_N: i32 = 2;

// The original's byte offsets, asserted on the 32-bit target. On a
// 64-bit host the pointer fields widen and these shift — harmless,
// because all access goes through the typed struct.
#[cfg(target_pointer_width = "32")]
const _VDBE_OP_SIZE: [u8; 20] = [0; core::mem::size_of::<VdbeOp>()];
#[cfg(target_pointer_width = "32")]
const _VDBE_N_OP_OFFSET: [u8; 0x0c] = [0; core::mem::offset_of!(Vdbe, n_op)];
#[cfg(target_pointer_width = "32")]
const _VDBE_A_OP_OFFSET: [u8; 0x14] = [0; core::mem::offset_of!(Vdbe, a_op)];
#[cfg(target_pointer_width = "32")]
const _VDBE_A_LABEL_OFFSET: [u8; 0x20] = [0; core::mem::offset_of!(Vdbe, a_label)];
#[cfg(target_pointer_width = "32")]
const _VDBE_A_COL_NAME_OFFSET: [u8; 0x28] = [0; core::mem::offset_of!(Vdbe, a_col_name)];
#[cfg(target_pointer_width = "32")]
const _VDBE_N_RES_COLUMN_OFFSET: [u8; 0xec] = [0; core::mem::offset_of!(Vdbe, n_res_column)];
#[cfg(target_pointer_width = "32")]
const _VDBE_EXPIRED_OFFSET: [u8; 0xff] = [0; core::mem::offset_of!(Vdbe, expired)];
#[cfg(target_pointer_width = "32")]
const _MEM_SIZE: [u8; 0x28] = [0; core::mem::size_of::<Mem>()];
#[cfg(target_pointer_width = "32")]
const _MEM_Z_OFFSET: [u8; 0x14] = [0; core::mem::offset_of!(Mem, z)];
#[cfg(target_pointer_width = "32")]
const _MEM_FLAGS_OFFSET: [u8; 0x1c] = [0; core::mem::offset_of!(Mem, flags)];
#[cfg(target_pointer_width = "32")]
const _MEM_Z_MALLOC_OFFSET: [u8; 0x24] = [0; core::mem::offset_of!(Mem, z_malloc)];

/// First op-array capacity when the array is still empty (original:
/// `mov r1, #51` — SQLite's `1024 / sizeof(Op)` with a 20-byte op).
pub const INITIAL_OP_CAPACITY: i32 = 51;

/// Growth increment for the label table (original: `add r0, #10, r0 lsl #1`
/// — `nLabelAlloc*2 + 10`).
const LABEL_GROWTH_BIAS: i32 = 10;

/// Indirect dispatch for the unported P4 destructor @ 0x082cf388.
#[derive(Clone, Copy)]
pub struct VdbeP4Ops {
    /// `freeP4(p4type, p4)` @ 0x082cf388: release a P4 payload
    /// according to its tag.
    pub free_p4: unsafe extern "C" fn(p4type: i32, p4: *mut u8),
}

/// Default stub: the payload is leaked, not freed (see the module
/// header). Deliberately not a passthrough to a global free — which
/// destructor runs depends on the tag, and guessing wrong corrupts.
unsafe extern "C" fn missing_free_p4(_p4type: i32, _p4: *mut u8) {}

/// Wired default (documented no-op until 0x082cf388 is ported).
pub const DEFAULT_VDBE_P4_OPS: VdbeP4Ops = VdbeP4Ops { free_p4: missing_free_p4 };

/// The active P4 destructor. Host tests install recording mocks.
pub static mut VDBE_P4_OPS: VdbeP4Ops = DEFAULT_VDBE_P4_OPS;

/// Reads the freeP4 slot (volatile — the slot is meant to be swapped at
/// runtime, and a plain read lets LLVM const-fold the default away).
#[inline(always)]
pub(crate) unsafe fn free_p4_op() -> unsafe extern "C" fn(i32, *mut u8) {
    core::ptr::read_volatile(core::ptr::addr_of!(VDBE_P4_OPS.free_p4))
}

/// P4 operand tags, as numbered by THIS build. The evidence is
/// `vdbe_change_p4`'s own `cmn` checks plus the jump table of its
/// `freeP4` (which spans tags -13..=0): this build's KEYINFO is -6,
/// not upstream SQLite's -5, so upstream numbers do not apply.
/// No P4 operand attached.
pub const P4_NOTUSED: i8 = 0;
/// `p4` is an owned [`db_str_ndup`] duplicate; released by freeP4.
pub const P4_DYNAMIC: i32 = -1;
/// `p4` points at storage the statement never owns (upstream's
/// P4_STATIC). Named here because
/// [`vdbe_set_col_name`](super::vdbe_set_col_name::vdbe_set_col_name)
/// tests for it (`cmnne r5,#2`); `vdbe_change_p4` treats it as an
/// ordinary negative tag.
pub const P4_STATIC: i32 = -2;
/// `p4` is a KeyInfo the statement owns (deep-copied on attach);
/// released by freeP4.
pub const P4_KEYINFO: i32 = -6;
/// `value` is an already-owned KeyInfo: stored verbatim and retagged
/// [`P4_KEYINFO`] (upstream's P4_KEYINFO_HANDOFF behavior — the
/// original's -9 branch stores the same -6 byte as the copy path).
pub const P4_KEYINFO_HANDOFF: i32 = -9;
/// `value` is stored verbatim with this tag even when NULL, and is
/// never owned or freed (outside freeP4's -13..=0 table; upstream's
/// P4_ADVANCE role).
pub const P4_ADVANCE: i32 = -14;

/// vdbe_resize_op_array — original: `FUN_08367f88` @ 0x08367f88
/// (48 bytes).
///
/// SQLite's `resizeOpArray`: reallocate `p->aOp` to hold `n_op` records
/// of 20 bytes. On success the capacity and the array pointer are both
/// updated; on failure neither is, and the connection's `mallocFailed`
/// flag (set by [`db_realloc`]) is how the caller finds out.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vdbe_resize_op_array(p: *mut Vdbe, n_op: i32) {
    let bytes = (core::mem::size_of::<VdbeOp>() as i32).wrapping_mul(n_op);
    let new = db_realloc((*p).db, (*p).a_op as *mut u8, bytes);
    if !new.is_null() {
        (*p).n_op_alloc = n_op;
        (*p).a_op = new as *mut VdbeOp;
    }
}

/// vdbe_add_op3 — original: `FUN_08386840` @ 0x08386840 (132 bytes;
/// 282 `bl` call sites).
///
/// `sqlite3VdbeAddOp3`: append `opcode` with operands `p1`, `p2`, `p3`
/// and return the address it was written to (the pre-append `nOp`).
///
/// Growth: when the array is full it is resized to `nOpAlloc * 2`, or to
/// [`INITIAL_OP_CAPACITY`] when it was empty; if the connection reports
/// an allocation failure afterwards the op is *not* appended and the
/// function returns 0 — which is also a valid address, exactly the
/// original's ambiguity (callers detect OOM through the connection).
///
/// The new record is fully initialized except `opflags` at +2, which the
/// original leaves as-is.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vdbe_add_op3(p: *mut Vdbe, opcode: i32, p1: i32, p2: i32, p3: i32) -> i32 {
    let addr = (*p).n_op;
    if (*p).n_op_alloc <= addr {
        let grown = if (*p).n_op_alloc != 0 {
            (*p).n_op_alloc.wrapping_mul(2)
        } else {
            INITIAL_OP_CAPACITY
        };
        vdbe_resize_op_array(p, grown);
        if malloc_failed((*p).db) {
            return 0;
        }
    }
    (*p).n_op = (*p).n_op.wrapping_add(1);
    let op = (*p).a_op.offset(addr as isize);
    (*op).opcode = opcode as u8;
    (*op).p5 = 0;
    (*op).p4 = core::ptr::null_mut();
    (*op).p1 = p1;
    (*op).p2 = p2;
    (*op).p3 = p3;
    (*op).p4type = 0;
    (*p).expired = 0;
    addr
}

/// vdbe_add_op2 — original: `FUN_08386824` @ 0x08386824 (28 bytes;
/// 126 `bl` + 1 tail `b`).
///
/// `sqlite3VdbeAddOp2` — [`vdbe_add_op3`] with `p3 = 0`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vdbe_add_op2(p: *mut Vdbe, opcode: i32, p1: i32, p2: i32) -> i32 {
    vdbe_add_op3(p, opcode, p1, p2, 0)
}

/// vdbe_add_op1 — original: `FUN_08386810` @ 0x08386810 (20 bytes;
/// 56 `bl` + 1 tail `b`).
///
/// `sqlite3VdbeAddOp1` — [`vdbe_add_op3`] with `p2 = p3 = 0`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vdbe_add_op1(p: *mut Vdbe, opcode: i32, p1: i32) -> i32 {
    vdbe_add_op3(p, opcode, p1, 0, 0)
}

/// vdbe_add_op4 — original: `FUN_083868c8` @ 0x083868c8 (68 bytes;
/// 76 `bl` call sites).
///
/// `sqlite3VdbeAddOp4`: [`vdbe_add_op3`] followed by
/// [`vdbe_change_p4`] on the address just returned. Returns that
/// address.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vdbe_add_op4(
    p: *mut Vdbe,
    opcode: i32,
    p1: i32,
    p2: i32,
    p3: i32,
    p4: *const u8,
    p4type: i32,
) -> i32 {
    let addr = vdbe_add_op3(p, opcode, p1, p2, p3);
    vdbe_change_p4(p, addr, p4, p4type);
    addr
}

/// vdbe_change_p4 — original: `FUN_08386aa4` @ 0x08386aa4 (304 bytes;
/// 24 `bl` + 2 tail `b` call sites).
///
/// `sqlite3VdbeChangeP4`: attach the fourth operand to the op at
/// `addr` (a negative `addr` means the most recently emitted op),
/// releasing whatever P4 the op held before through freeP4. How
/// `value` is treated depends on the tag `n`:
///
/// - [`P4_ADVANCE`] (-14): stored verbatim with the tag, even when
///   NULL (this check comes before the NULL check in the original).
/// - NULL `value`: the op is tagged [`P4_NOTUSED`].
/// - [`P4_KEYINFO`] (-6): the KeyInfo is deep-copied — `nField` is
///   read from `value + 8` and `5*nField + 0x10` bytes are duplicated
///   (`sqlite3_malloc`, then `__rt_memcpy`). OOM leaves the op tagged
///   NOTUSED and sets the connection's sticky `mallocFailed` byte.
/// - [`P4_KEYINFO_HANDOFF`] (-9): stored as-is, retagged KEYINFO.
/// - any other negative `n`: stored as-is, tag truncated to a byte.
/// - `n == 0`: `n` becomes `strlen(value)`, then falls through.
/// - `n > 0`: the string is duplicated (`db_str_ndup`) and tagged
///   [`P4_DYNAMIC`].
///
/// Two guards come first, in the original's order. With no op array or
/// an already-failed connection, the *incoming* value's payload is
/// released through freeP4 — unless it is a KeyInfo, which stays the
/// caller's — and nothing is attached. And an `addr` that is still
/// negative after the `nOp - 1` substitution is a silent no-op.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vdbe_change_p4(p: *mut Vdbe, addr: i32, value: *const u8, n: i32) {
    let a_op = (*p).a_op;
    if a_op.is_null() || malloc_failed((*p).db) {
        // Original: `cmn r5,#0x6` / tail `bne 0x082cf388` — a KeyInfo
        // is the caller's, every other payload is dropped here.
        if n != P4_KEYINFO {
            (free_p4_op())(n, value as *mut u8);
        }
        return;
    }
    let mut addr = addr;
    if addr < 0 {
        addr = (*p).n_op - 1;
        if addr < 0 {
            return;
        }
    }
    let op = a_op.offset(addr as isize);
    (free_p4_op())((*op).p4type as i32, (*op).p4);
    (*op).p4 = core::ptr::null_mut();
    if n == P4_ADVANCE {
        (*op).p4 = value as *mut u8;
        (*op).p4type = P4_ADVANCE as i8;
        return;
    }
    if value.is_null() {
        (*op).p4type = P4_NOTUSED;
        return;
    }
    if n == P4_KEYINFO {
        // Original: `ldr r0,[r6,#0x8]` (nField), `add r0,r0,r0,lsl#2`
        // / `add r5,r0,#0x10` — 5*nField + 16 bytes duplicated.
        let n_field = (value as *const i32).add(2).read();
        let bytes = n_field.wrapping_mul(5).wrapping_add(0x10);
        let copy = (db_malloc_op())(bytes);
        (*op).p4 = copy;
        if copy.is_null() {
            set_malloc_failed((*p).db);
            (*op).p4type = P4_NOTUSED;
            return;
        }
        __rt_memcpy(copy, value, bytes as usize);
        (*op).p4type = P4_KEYINFO as i8;
        return;
    }
    if n == P4_KEYINFO_HANDOFF {
        (*op).p4 = value as *mut u8;
        // Original: the -9 branch shares the copy path's `strb r9`,
        // so the stored tag is -6, not -9.
        (*op).p4type = P4_KEYINFO as i8;
        return;
    }
    if n < 0 {
        (*op).p4 = value as *mut u8;
        (*op).p4type = n as i8;
        return;
    }
    let len = if n == 0 { strlen(value) as i32 } else { n };
    (*op).p4 = db_str_ndup((*p).db, value, len);
    (*op).p4type = P4_DYNAMIC as i8;
}

/// vdbe_change_p2 — original: `FUN_08386a44` @ 0x08386a44 (48 bytes;
/// 66 `bl` + 2 tail `b`).
///
/// `sqlite3VdbeChangeP2`: back-patch the P2 operand (the jump target for
/// branch opcodes) of the op at `addr`. Silently does nothing for a NULL
/// statement, a negative address, an address at or past `nOp`, or an
/// unallocated op array — all four guards are in the original, in that
/// order.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vdbe_change_p2(p: *mut Vdbe, addr: i32, value: i32) {
    if p.is_null() || addr < 0 || (*p).n_op <= addr {
        return;
    }
    let a_op = (*p).a_op;
    if a_op.is_null() {
        return;
    }
    (*a_op.offset(addr as isize)).p2 = value;
}

/// vdbe_change_p5 — original: `FUN_08386bd4` @ 0x08386bd4 (32 bytes;
/// 19 `bl` + 1 tail `b`).
///
/// `sqlite3VdbeChangeP5`: set the byte-wide P5 operand on the most
/// recently emitted op. NULL statement or NULL op array: no-op. `nOp`
/// is not checked (see the module header).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vdbe_change_p5(p: *mut Vdbe, value: u8) {
    if p.is_null() {
        return;
    }
    let a_op = (*p).a_op;
    if a_op.is_null() {
        return;
    }
    (*a_op.offset((*p).n_op as isize - 1)).p5 = value;
}

/// vdbe_make_label — original: `FUN_0838b8fc` @ 0x0838b8fc (88 bytes;
/// 30 `bl` call sites).
///
/// `sqlite3VdbeMakeLabel`: reserve a forward-reference slot and return
/// its negative encoding `-1 - index`, which [`vdbe_change_p2`] call
/// sites store as a jump target until [`vdbe_resolve_label`] binds it.
///
/// `nLabel` is incremented unconditionally, before the capacity check —
/// so a failed table growth still consumes the index, exactly as the
/// original does. The slot is seeded with `-1` (unresolved) only when
/// the table exists.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vdbe_make_label(p: *mut Vdbe) -> i32 {
    let index = (*p).n_label;
    (*p).n_label = index.wrapping_add(1);
    if (*p).n_label_alloc <= index {
        let grown = (*p).n_label_alloc.wrapping_mul(2).wrapping_add(LABEL_GROWTH_BIAS);
        (*p).n_label_alloc = grown;
        let bytes = grown.wrapping_mul(core::mem::size_of::<i32>() as i32);
        (*p).a_label = db_realloc_or_free((*p).db, (*p).a_label as *mut u8, bytes) as *mut i32;
    }
    let a_label = (*p).a_label;
    if !a_label.is_null() {
        a_label.offset(index as isize).write(-1);
    }
    !index
}

/// vdbe_resolve_label — original: `FUN_0838cc04` @ 0x0838cc04 (24 bytes;
/// 32 `bl` call sites).
///
/// `sqlite3VdbeResolveLabel`: bind the label `x` (the negative encoding
/// returned by [`vdbe_make_label`]) to the current code address, so the
/// jumps that reference it can be patched at finalization. Does nothing
/// if the label table was never allocated; `p` itself is *not*
/// NULL-checked in the original.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vdbe_resolve_label(p: *mut Vdbe, x: i32) {
    let index = !x;
    let a_label = (*p).a_label;
    if a_label.is_null() {
        return;
    }
    a_label.offset(index as isize).write((*p).n_op);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::sqlite::mem::tests::{install_recorder, realloc_log, Connection, OPS_LOCK};
    use std::sync::MutexGuard;
    use std::vec::Vec;

    /// The `expired` byte starts set so the tests can watch it clear.
    const EXPIRED: u8 = 1;

    /// A statement plus the connection it points at. The connection is
    /// boxed so its address survives the `Statement` being moved out of
    /// the constructor.
    struct Statement {
        vdbe: Vdbe,
        db: std::boxed::Box<Connection>,
    }

    impl Statement {
        fn new(db: Connection) -> Self {
            let mut db = std::boxed::Box::new(db);
            let vdbe = Vdbe {
                db: db.ptr(),
                _gap_04: [0; 8],
                n_op: 0,
                n_op_alloc: 0,
                a_op: core::ptr::null_mut(),
                n_label: 0,
                n_label_alloc: 0,
                a_label: core::ptr::null_mut(),
                _gap_24: [0; 4],
                a_col_name: core::ptr::null_mut(),
                _gap_2c: [0; 0xec - 0x2c],
                n_res_column: 0,
                _gap_f0: [0; 0xff - 0xf0],
                expired: EXPIRED,
            };
            Statement { vdbe, db }
        }
        fn ptr(&mut self) -> *mut Vdbe {
            &mut self.vdbe
        }
        fn failed_flag(&self) -> u8 {
            self.db.failed_flag()
        }
    }

    /// Backing store for an op array with `n` slots.
    fn op_slab(n: usize) -> Vec<VdbeOp> {
        std::vec![
            VdbeOp {
                opcode: 0xee,
                p4type: -2,
                opflags: 0x5a,
                p5: 0xee,
                p1: -1,
                p2: -1,
                p3: -1,
                p4: 0x1234 as *mut u8,
            };
            n
        ]
    }

    /// Statement with a pre-allocated op array — no allocator needed.
    fn preallocated(slab: &mut [VdbeOp], db: Connection) -> Statement {
        let mut stmt = Statement::new(db);
        stmt.vdbe.a_op = slab.as_mut_ptr();
        stmt.vdbe.n_op_alloc = slab.len() as i32;
        stmt
    }

    /// Locks the ops mutex without installing a recorder (for tests that
    /// must not allocate). One guard per test function — never shadowed.
    fn quiet() -> MutexGuard<'static, ()> {
        OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn add_op3_writes_every_field_but_the_property_byte() {
        let _guard = quiet();
        let mut slab = op_slab(4);
        let mut stmt = preallocated(&mut slab, Connection::healthy());

        let addr = unsafe { vdbe_add_op3(stmt.ptr(), 0x74, 11, 22, 33) };
        assert_eq!(addr, 0);
        assert_eq!(stmt.vdbe.n_op, 1);
        assert_eq!(stmt.vdbe.expired, 0, "every emitted op clears `expired`");

        let op = slab[0];
        assert_eq!(op.opcode, 0x74);
        assert_eq!((op.p1, op.p2, op.p3), (11, 22, 33));
        assert_eq!(op.p5, 0);
        assert_eq!(op.p4type, 0);
        assert!(op.p4.is_null());
        assert_eq!(op.opflags, 0x5a, "+2 is deliberately left untouched");
        assert_eq!(slab[1].opcode, 0xee, "only one slot is written");
    }

    #[test]
    fn addresses_are_handed_out_in_order() {
        let _guard = quiet();
        let mut slab = op_slab(8);
        let mut stmt = preallocated(&mut slab, Connection::healthy());

        for expected in 0..8 {
            let addr = unsafe { vdbe_add_op3(stmt.ptr(), expected + 1, expected, 0, 0) };
            assert_eq!(addr, expected);
        }
        assert_eq!(stmt.vdbe.n_op, 8);
        for (i, op) in slab.iter().enumerate() {
            assert_eq!(op.opcode, i as u8 + 1);
            assert_eq!(op.p1, i as i32);
        }
    }

    #[test]
    fn the_arity_front_ends_zero_the_operands_they_omit() {
        let _guard = quiet();
        let mut slab = op_slab(4);
        let mut stmt = preallocated(&mut slab, Connection::healthy());

        assert_eq!(unsafe { vdbe_add_op1(stmt.ptr(), 0x20, 7) }, 0);
        assert_eq!(unsafe { vdbe_add_op2(stmt.ptr(), 0x62, 8, 9) }, 1);

        assert_eq!((slab[0].p1, slab[0].p2, slab[0].p3), (7, 0, 0));
        assert_eq!((slab[1].p1, slab[1].p2, slab[1].p3), (8, 9, 0));
    }

    /// The op stride the resize helper bills for: 20 on the ARM target
    /// (statically asserted above), wider on a 64-bit host.
    const OP_STRIDE: i32 = core::mem::size_of::<VdbeOp>() as i32;

    #[test]
    fn an_empty_array_grows_to_fifty_one_and_then_doubles() {
        // 51 = 1024 / sizeof(Op) on target; the doubling is the
        // caller's, not the resize helper's.
        let mut slab = op_slab(256);
        let target = slab.as_mut_ptr() as *mut u8;
        let _guard = install_recorder(target);
        let mut stmt = Statement::new(Connection::healthy());

        assert_eq!(unsafe { vdbe_add_op3(stmt.ptr(), 1, 0, 0, 0) }, 0);
        assert_eq!(stmt.vdbe.n_op_alloc, 51);
        assert_eq!(realloc_log(), std::vec![(0, 51 * OP_STRIDE)]);

        // Fill to the boundary without another allocation...
        stmt.vdbe.n_op = 51;
        assert_eq!(unsafe { vdbe_add_op3(stmt.ptr(), 2, 0, 0, 0) }, 51);
        assert_eq!(stmt.vdbe.n_op_alloc, 102, "51 * 2");
        assert_eq!(realloc_log().len(), 2);
        assert_eq!(realloc_log()[1], (target as usize, 102 * OP_STRIDE));
    }

    #[test]
    fn growth_happens_only_at_the_capacity_boundary() {
        let mut slab = op_slab(64);
        let target = slab.as_mut_ptr() as *mut u8;
        let _guard = install_recorder(target);
        let mut stmt = Statement::new(Connection::healthy());
        stmt.vdbe.a_op = slab.as_mut_ptr();
        stmt.vdbe.n_op_alloc = 4;

        for i in 0..4 {
            assert_eq!(unsafe { vdbe_add_op3(stmt.ptr(), 1, i, 0, 0) }, i);
        }
        assert!(realloc_log().is_empty(), "capacity 4 holds four ops");

        assert_eq!(unsafe { vdbe_add_op3(stmt.ptr(), 1, 4, 0, 0) }, 4);
        assert_eq!(realloc_log(), std::vec![(target as usize, 8 * OP_STRIDE)]);
        assert_eq!(stmt.vdbe.n_op_alloc, 8);
    }

    #[test]
    fn a_failed_growth_appends_nothing_and_returns_zero() {
        let _guard = install_recorder(core::ptr::null_mut());
        let mut stmt = Statement::new(Connection::healthy());

        assert_eq!(unsafe { vdbe_add_op3(stmt.ptr(), 0x29, 1, 2, 3) }, 0);
        assert_eq!(stmt.vdbe.n_op, 0, "no op was appended");
        assert_eq!(stmt.vdbe.n_op_alloc, 0, "capacity is untouched on failure");
        assert!(stmt.vdbe.a_op.is_null());
        assert_eq!(stmt.vdbe.expired, EXPIRED, "and `expired` is not cleared");
        assert_eq!(stmt.failed_flag(), 1, "the connection carries the failure");
    }

    #[test]
    fn add_op4_appends_then_attaches_the_p4_operand() {
        let _guard = quiet();
        let mut slab = op_slab(4);
        let mut stmt = preallocated(&mut slab, Connection::healthy());
        stmt.vdbe.n_op = 2;

        let frees = install_free_p4_recorder();
        let text = b"idx\0";
        let addr = unsafe { vdbe_add_op4(stmt.ptr(), 0x58, 1, 2, 3, text.as_ptr(), -2) };
        restore_free_p4();

        assert_eq!(addr, 2);
        assert_eq!(slab[2].opcode, 0x58);
        assert_eq!(slab[2].p4, text.as_ptr() as *mut u8);
        assert_eq!(slab[2].p4type, -2, "a negative tag is stored verbatim");
        // The fresh op holds nothing, so release is a (0, NULL) call.
        assert_eq!(frees(), std::vec![(0, 0)]);
    }

    #[test]
    fn change_p2_patches_only_within_the_emitted_range() {
        let _guard = quiet();
        let mut slab = op_slab(4);
        let mut stmt = preallocated(&mut slab, Connection::healthy());
        for i in 0..3 {
            unsafe { vdbe_add_op3(stmt.ptr(), 1, i, 0, 0) };
        }

        unsafe { vdbe_change_p2(stmt.ptr(), 1, 0x1234) };
        assert_eq!(slab[1].p2, 0x1234);

        // Out of range in both directions, and the guards' order.
        unsafe { vdbe_change_p2(stmt.ptr(), -1, 0x999) };
        unsafe { vdbe_change_p2(stmt.ptr(), 3, 0x999) };
        unsafe { vdbe_change_p2(stmt.ptr(), i32::MAX, 0x999) };
        unsafe { vdbe_change_p2(core::ptr::null_mut(), 0, 0x999) };
        assert_eq!(slab[0].p2, 0);
        assert_eq!(slab[2].p2, 0);
        assert_eq!(slab[3].p2, -1, "slot beyond nOp is never written");
    }

    #[test]
    fn change_p2_ignores_a_statement_with_no_op_array() {
        let _guard = quiet();
        let mut stmt = Statement::new(Connection::healthy());
        stmt.vdbe.n_op = 4;
        // No aOp: must return without dereferencing it.
        unsafe { vdbe_change_p2(stmt.ptr(), 0, 7) };
    }

    #[test]
    fn change_p5_targets_the_op_just_emitted() {
        let _guard = quiet();
        let mut slab = op_slab(4);
        let mut stmt = preallocated(&mut slab, Connection::healthy());
        unsafe { vdbe_add_op3(stmt.ptr(), 1, 0, 0, 0) };
        unsafe { vdbe_add_op3(stmt.ptr(), 2, 0, 0, 0) };

        unsafe { vdbe_change_p5(stmt.ptr(), 0x8f) };
        assert_eq!(slab[1].p5, 0x8f);
        assert_eq!(slab[0].p5, 0, "the earlier op keeps its own P5");

        unsafe { vdbe_change_p5(core::ptr::null_mut(), 0x11) };
        let mut bare = Statement::new(Connection::healthy());
        bare.vdbe.n_op = 3;
        unsafe { vdbe_change_p5(bare.ptr(), 0x11) };
    }

    #[test]
    fn labels_are_handed_out_as_negative_indices() {
        let mut table = std::vec![0i32; 64];
        let _guard = install_recorder(table.as_mut_ptr() as *mut u8);
        let mut stmt = Statement::new(Connection::healthy());

        assert_eq!(unsafe { vdbe_make_label(stmt.ptr()) }, -1);
        assert_eq!(unsafe { vdbe_make_label(stmt.ptr()) }, -2);
        assert_eq!(unsafe { vdbe_make_label(stmt.ptr()) }, -3);
        assert_eq!(stmt.vdbe.n_label, 3);
        assert_eq!(&table[..3], &[-1, -1, -1], "fresh labels read unresolved");
        // 0*2+10 = 10 on the first call, then no growth until index 10.
        assert_eq!(stmt.vdbe.n_label_alloc, 10);
        assert_eq!(realloc_log(), std::vec![(0, 10 * 4)]);
    }

    #[test]
    fn the_label_table_grows_by_doubling_plus_ten() {
        let mut table = std::vec![0i32; 256];
        let target = table.as_mut_ptr() as *mut u8;
        let _guard = install_recorder(target);
        let mut stmt = Statement::new(Connection::healthy());
        stmt.vdbe.a_label = table.as_mut_ptr();
        stmt.vdbe.n_label_alloc = 4;
        stmt.vdbe.n_label = 4;

        assert_eq!(unsafe { vdbe_make_label(stmt.ptr()) }, -5);
        assert_eq!(stmt.vdbe.n_label_alloc, 18, "4 * 2 + 10");
        assert_eq!(realloc_log(), std::vec![(target as usize, 18 * 4)]);
    }

    #[test]
    fn a_failed_label_growth_still_consumes_the_index() {
        let _guard = install_recorder(core::ptr::null_mut());
        let mut stmt = Statement::new(Connection::healthy());

        assert_eq!(unsafe { vdbe_make_label(stmt.ptr()) }, -1);
        assert_eq!(stmt.vdbe.n_label, 1, "nLabel is bumped before the check");
        assert!(stmt.vdbe.a_label.is_null());
        // The capacity field is updated even though the table is gone —
        // the original stores it before the realloc.
        assert_eq!(stmt.vdbe.n_label_alloc, 10);
    }

    #[test]
    fn resolve_label_binds_the_label_to_the_current_address() {
        let mut table = std::vec![0i32; 16];
        let mut slab = op_slab(8);
        let _guard = install_recorder(table.as_mut_ptr() as *mut u8);
        let mut stmt = preallocated(&mut slab, Connection::healthy());

        let label = unsafe { vdbe_make_label(stmt.ptr()) };
        for i in 0..5 {
            unsafe { vdbe_add_op3(stmt.ptr(), 1, i, 0, 0) };
        }
        unsafe { vdbe_resolve_label(stmt.ptr(), label) };
        assert_eq!(table[0], 5, "label 0 now points past the five ops");

        let second = unsafe { vdbe_make_label(stmt.ptr()) };
        assert_eq!(second, -2);
        unsafe { vdbe_add_op3(stmt.ptr(), 1, 9, 0, 0) };
        unsafe { vdbe_resolve_label(stmt.ptr(), second) };
        assert_eq!(table[1], 6);
    }

    #[test]
    fn resolve_label_ignores_a_statement_with_no_label_table() {
        let _guard = quiet();
        let mut stmt = Statement::new(Connection::healthy());
        stmt.vdbe.n_op = 3;
        unsafe { vdbe_resolve_label(stmt.ptr(), -1) };
    }

    #[test]
    fn a_forward_jump_round_trips_through_the_label() {
        // The whole point of the cluster: emit a branch with a label as
        // its target, then bind the label and patch the branch.
        let mut table = std::vec![0i32; 16];
        let mut slab = op_slab(8);
        let _guard = install_recorder(table.as_mut_ptr() as *mut u8);
        let mut stmt = preallocated(&mut slab, Connection::healthy());

        let end = unsafe { vdbe_make_label(stmt.ptr()) };
        let branch = unsafe { vdbe_add_op2(stmt.ptr(), 0x0d, 0, end) };
        unsafe { vdbe_add_op3(stmt.ptr(), 0x29, 1, 2, 3) };
        unsafe { vdbe_resolve_label(stmt.ptr(), end) };

        assert_eq!(slab[branch as usize].p2, end, "still the label encoding");
        let bound = table[(!end) as usize];
        assert_eq!(bound, 2);
        unsafe { vdbe_change_p2(stmt.ptr(), branch, bound) };
        assert_eq!(slab[branch as usize].p2, 2);
    }

    // --- P4 destructor recorder --------------------------------------

    static mut FREE_P4_CALLS: Vec<(i32, usize)> = Vec::new();

    unsafe extern "C" fn recording_free_p4(p4type: i32, p4: *mut u8) {
        (*core::ptr::addr_of_mut!(FREE_P4_CALLS)).push((p4type, p4 as usize));
    }

    /// Installs the freeP4 recorder; the returned closure reads its
    /// log. Callers already hold `OPS_LOCK` through their test guard.
    fn install_free_p4_recorder() -> impl Fn() -> Vec<(i32, usize)> {
        unsafe {
            (*core::ptr::addr_of_mut!(FREE_P4_CALLS)).clear();
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(VDBE_P4_OPS),
                VdbeP4Ops { free_p4: recording_free_p4 },
            );
        }
        || unsafe { (*core::ptr::addr_of!(FREE_P4_CALLS)).clone() }
    }

    fn restore_free_p4() {
        unsafe {
            core::ptr::write_volatile(core::ptr::addr_of_mut!(VDBE_P4_OPS), DEFAULT_VDBE_P4_OPS);
        }
    }

    // --- vdbe_change_p4 ------------------------------------------------

    #[test]
    fn without_an_op_array_the_incoming_payload_is_dropped() {
        let _guard = quiet();
        let mut stmt = Statement::new(Connection::healthy());
        let payload = [0u8; 8];

        let frees = install_free_p4_recorder();
        unsafe { vdbe_change_p4(stmt.ptr(), 0, payload.as_ptr(), -1) };
        assert_eq!(frees(), std::vec![(-1, payload.as_ptr() as usize)]);

        // ... even when the payload pointer itself is NULL (freeP4
        // NULL-checks, ChangeP4 does not).
        unsafe { vdbe_change_p4(stmt.ptr(), 0, core::ptr::null(), -1) };
        assert_eq!(frees().len(), 2);

        // A KeyInfo stays the caller's: no freeP4 call for tag -6.
        unsafe { vdbe_change_p4(stmt.ptr(), 0, payload.as_ptr(), P4_KEYINFO) };
        assert_eq!(frees().len(), 2, "KEYINFO is not freed on the guard path");
        restore_free_p4();
    }

    #[test]
    fn a_failed_connection_takes_the_guard_path_even_with_an_op_array() {
        let _guard = quiet();
        let mut slab = op_slab(4);
        let mut stmt = preallocated(&mut slab, Connection::failed());
        stmt.vdbe.n_op = 2;
        let payload = [0u8; 8];

        let frees = install_free_p4_recorder();
        unsafe { vdbe_change_p4(stmt.ptr(), 0, payload.as_ptr(), -2) };
        restore_free_p4();

        assert_eq!(frees(), std::vec![(-2, payload.as_ptr() as usize)]);
        assert_eq!(slab[0].p4, 0x1234 as *mut u8, "the op is never touched");
    }

    #[test]
    fn a_negative_address_targets_the_most_recent_op() {
        let _guard = quiet();
        let mut slab = op_slab(4);
        let mut stmt = preallocated(&mut slab, Connection::healthy());
        for i in 0..3 {
            unsafe { vdbe_add_op3(stmt.ptr(), 1, i, 0, 0) };
        }
        let payload = [0u8; 8];

        let frees = install_free_p4_recorder();
        unsafe { vdbe_change_p4(stmt.ptr(), -1, payload.as_ptr(), -2) };
        restore_free_p4();

        assert_eq!(slab[2].p4, payload.as_ptr() as *mut u8);
        assert_eq!(slab[2].p4type, -2);
        assert_eq!(slab[0].p4type, 0, "earlier ops are untouched");
        assert_eq!(frees(), std::vec![(0, 0)], "the fresh op held nothing");
    }

    #[test]
    fn a_still_negative_address_is_a_silent_no_op() {
        let _guard = quiet();
        let mut slab = op_slab(4);
        let mut stmt = preallocated(&mut slab, Connection::healthy());
        // nOp == 0: addr -1 becomes -1, nothing is attached or freed.
        let payload = [0u8; 8];

        let frees = install_free_p4_recorder();
        unsafe { vdbe_change_p4(stmt.ptr(), -1, payload.as_ptr(), -2) };
        restore_free_p4();

        assert!(frees().is_empty());
        assert_eq!(slab[0].p4type, -2, "the slab is untouched"); // op_slab seeds -2
    }

    #[test]
    fn the_old_p4_is_released_before_the_new_one_is_attached() {
        let _guard = quiet();
        let mut slab = op_slab(4);
        let mut stmt = preallocated(&mut slab, Connection::healthy());
        stmt.vdbe.n_op = 2;
        slab[1].p4type = -1;
        slab[1].p4 = 0xdead as *mut u8;
        let payload = [0u8; 8];

        let frees = install_free_p4_recorder();
        unsafe { vdbe_change_p4(stmt.ptr(), 1, payload.as_ptr(), -4) };
        restore_free_p4();

        assert_eq!(frees(), std::vec![(-1, 0xdead)], "old tag and pointer");
        assert_eq!(slab[1].p4, payload.as_ptr() as *mut u8);
        assert_eq!(slab[1].p4type, -4);
    }

    #[test]
    fn the_advance_tag_is_kept_even_for_a_null_value() {
        let _guard = quiet();
        let mut slab = op_slab(4);
        let mut stmt = preallocated(&mut slab, Connection::healthy());
        stmt.vdbe.n_op = 2;
        let payload = [0u8; 8];

        let frees = install_free_p4_recorder();
        unsafe { vdbe_change_p4(stmt.ptr(), 0, core::ptr::null(), P4_ADVANCE) };
        unsafe { vdbe_change_p4(stmt.ptr(), 1, payload.as_ptr(), P4_ADVANCE) };
        restore_free_p4();

        assert!(slab[0].p4.is_null());
        assert_eq!(slab[0].p4type, P4_ADVANCE as i8);
        assert_eq!(slab[1].p4, payload.as_ptr() as *mut u8);
        assert_eq!(slab[1].p4type, P4_ADVANCE as i8);
        assert_eq!(frees().len(), 2, "both old payloads were released");
    }

    #[test]
    fn a_null_value_tags_the_op_notused() {
        let _guard = quiet();
        let mut slab = op_slab(4);
        let mut stmt = preallocated(&mut slab, Connection::healthy());
        stmt.vdbe.n_op = 1;
        slab[0].p4type = -1;
        slab[0].p4 = 0xbeef as *mut u8;

        let frees = install_free_p4_recorder();
        unsafe { vdbe_change_p4(stmt.ptr(), 0, core::ptr::null(), -2) };
        restore_free_p4();

        assert_eq!(frees(), std::vec![(-1, 0xbeef)]);
        assert!(slab[0].p4.is_null(), "p4 is zeroed before the NULL check");
        assert_eq!(slab[0].p4type, P4_NOTUSED);
    }

    /// A fake KeyInfo: the original reads `nField` as a word at +8 and
    /// duplicates `5*nField + 0x10` bytes. Word-aligned, as a real
    /// malloc'd KeyInfo is. 64 bytes holds up to nField = 9.
    fn fake_keyinfo(storage: &mut [u32; 16], n_field: i32) -> *const u8 {
        let bytes = storage.as_mut_ptr() as *mut u8;
        for i in 0..64 {
            unsafe { bytes.add(i).write((i as u16 * 29 % 251) as u8 | 1) };
        }
        storage[2] = n_field as u32;
        storage.as_ptr() as *const u8
    }

    #[test]
    fn a_keyinfo_is_deep_copied_into_owned_memory() {
        let mut storage = [0u32; 16];
        let keyinfo = fake_keyinfo(&mut storage, 3);
        let mut arena = [0xa5u8; 0x40];
        let _guard = install_recorder(arena.as_mut_ptr());
        let mut slab = op_slab(4);
        let mut stmt = preallocated(&mut slab, Connection::healthy());
        stmt.vdbe.n_op = 1;

        let frees = install_free_p4_recorder();
        unsafe { vdbe_change_p4(stmt.ptr(), 0, keyinfo, P4_KEYINFO) };
        restore_free_p4();

        assert_eq!(realloc_log(), std::vec![(0, 3 * 5 + 0x10)]);
        assert_eq!(slab[0].p4, arena.as_mut_ptr());
        assert_eq!(
            &arena[..0x1f],
            unsafe { core::slice::from_raw_parts(keyinfo, 0x1f) },
            "5*nField + 0x10 bytes copied"
        );
        assert_eq!(slab[0].p4type, P4_KEYINFO as i8);
        assert_eq!(stmt.failed_flag(), 0);
    }

    #[test]
    fn a_failed_keyinfo_copy_tags_notused_and_sets_malloc_failed() {
        let mut storage = [0u32; 16];
        let keyinfo = fake_keyinfo(&mut storage, 2);
        let _guard = install_recorder(core::ptr::null_mut());
        let mut slab = op_slab(4);
        let mut stmt = preallocated(&mut slab, Connection::healthy());
        stmt.vdbe.n_op = 1;

        let frees = install_free_p4_recorder();
        unsafe { vdbe_change_p4(stmt.ptr(), 0, keyinfo, P4_KEYINFO) };
        restore_free_p4();

        assert_eq!(realloc_log(), std::vec![(0, 2 * 5 + 0x10)]);
        assert!(slab[0].p4.is_null(), "the NULL result is stored");
        assert_eq!(slab[0].p4type, P4_NOTUSED);
        assert_eq!(stmt.failed_flag(), 1, "the sticky byte at db+0x1e");
    }

    #[test]
    fn a_keyinfo_handoff_is_stored_under_the_keyinfo_tag() {
        let _guard = quiet();
        let mut slab = op_slab(4);
        let mut stmt = preallocated(&mut slab, Connection::healthy());
        stmt.vdbe.n_op = 1;
        let mut storage = [0u32; 16];
        let keyinfo = fake_keyinfo(&mut storage, 1);

        let frees = install_free_p4_recorder();
        unsafe { vdbe_change_p4(stmt.ptr(), 0, keyinfo, P4_KEYINFO_HANDOFF) };
        restore_free_p4();

        assert_eq!(slab[0].p4, keyinfo as *mut u8, "no copy is made");
        assert_eq!(slab[0].p4type, P4_KEYINFO as i8, "retagged -6, not -9");
        assert_eq!(stmt.failed_flag(), 0);
    }

    #[test]
    fn other_negative_tags_store_the_pointer_verbatim() {
        let _guard = quiet();
        let mut slab = op_slab(4);
        let mut stmt = preallocated(&mut slab, Connection::healthy());
        stmt.vdbe.n_op = 4;
        let payload = [0u8; 8];

        let frees = install_free_p4_recorder();
        for (i, tag) in [-1i32, -2, -3, -13].iter().enumerate() {
            unsafe { vdbe_change_p4(stmt.ptr(), i as i32, payload.as_ptr(), *tag) };
        }
        restore_free_p4();

        for (i, tag) in [-1i32, -2, -3, -13].iter().enumerate() {
            assert_eq!(slab[i].p4, payload.as_ptr() as *mut u8);
            assert_eq!(slab[i].p4type, *tag as i8);
        }
    }

    #[test]
    fn a_zero_n_measures_the_string_then_duplicates_it() {
        let mut arena = [0xa5u8; 16];
        let _guard = install_recorder(arena.as_mut_ptr());
        let mut slab = op_slab(4);
        let mut stmt = preallocated(&mut slab, Connection::healthy());
        stmt.vdbe.n_op = 1;
        let text = b"idx\0";

        let frees = install_free_p4_recorder();
        unsafe { vdbe_change_p4(stmt.ptr(), 0, text.as_ptr(), 0) };
        restore_free_p4();

        assert_eq!(realloc_log(), std::vec![(0, 4)], "strlen + 1");
        assert_eq!(&arena[..4], b"idx\0");
        assert_eq!(slab[0].p4, arena.as_mut_ptr());
        assert_eq!(slab[0].p4type, P4_DYNAMIC as i8);
    }

    #[test]
    fn a_positive_n_duplicates_exactly_n_bytes() {
        let mut arena = [0xa5u8; 16];
        let _guard = install_recorder(arena.as_mut_ptr());
        let mut slab = op_slab(4);
        let mut stmt = preallocated(&mut slab, Connection::healthy());
        stmt.vdbe.n_op = 1;
        let text = b"collation_sequence_name\0";

        let frees = install_free_p4_recorder();
        unsafe { vdbe_change_p4(stmt.ptr(), 0, text.as_ptr(), 9) };
        restore_free_p4();

        assert_eq!(realloc_log(), std::vec![(0, 10)], "n + 1, no strlen");
        assert_eq!(&arena[..10], b"collation\0");
        assert_eq!(slab[0].p4type, P4_DYNAMIC as i8);
    }
}
