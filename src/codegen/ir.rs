//! Builders for the JIT's IR nodes: virtual registers and instructions.
//! All of them carve their record out of the module's arena
//! ([`super::heap`]) and append it to a singly linked list, relying on
//! `cg_heap_alloc`'s zero-fill for the record's `next` link and for every
//! field they do not write.
//!
//! Ported here (call counts binary-scanned from osos.dec):
//!
//! - `cg_virtual_reg_create` — original: `FUN_082c23dc` @ 0x082c23dc
//!   (80 bytes; **835 `bl` call sites** — the most-called unported
//!   function in the image). Numbers and appends one virtual register.
//! - `cg_inst_create_base` — original: `FUN_082d6c24` @ 0x082d6c24
//!   (72 bytes; 11 `bl` + 1 tail `b` call sites — the twelve instruction
//!   factories at 0x082c17f4-0x082c19b8). Allocates a `size`-byte
//!   instruction record, appends it to the block and stamps its kind and
//!   opcode bytes.
//! - `cg_create_inst_binary` — original: `FUN_082c17f4` @ 0x082c17f4
//!   (48 bytes; **419 `bl` call sites**). Kind 2, 36-byte record.
//! - `cg_create_inst_load_immed` — original: `FUN_082c18ec` @ 0x082c18ec
//!   (40 bytes; **201 `bl` call sites**). Kind 6, 20-byte record.
//! - The rest of the factory family: `cg_create_inst_unary` @ 0x082c1994
//!   (kind 1, 32 bytes), `cg_create_inst_binary_s` @ 0x082c1824 (kind 2
//!   with dest_flags, 36 bytes), `cg_create_inst_compare` @ 0x082c1898
//!   (kind 3, 32 bytes), `cg_create_inst_load` @ 0x082c18c4 (kind 4,
//!   24 bytes), `cg_create_inst_store` @ 0x082c196c (kind 5, 24 bytes),
//!   `cg_create_inst_branch_label` @ 0x082c1878 (kind 7, 20 bytes),
//!   `cg_create_inst_branch_cond` @ 0x082c1850 (kind 8, 20 bytes),
//!   `cg_create_inst_phi` @ 0x082c1914 (kind 9, 20 bytes),
//!   `cg_create_inst_ret` @ 0x082c193c (kind 11, 16 bytes),
//!   `cg_create_inst_ret_value` @ 0x082c194c (kind 11, 16 bytes).
//! - `cg_virtual_reg_list_create` — original: `FUN_082c19bc` @
//!   0x082c19bc (76 bytes; 75 `bl` call sites — every one feeding a
//!   phi). Chains a NULL-terminated run of registers into 8-byte
//!   `{next, reg}` list cells carved from the caller-supplied arena.
//! - `cg_reg_append_bounded` — original: `FUN_082b2f1c` @ 0x082b2f1c
//!   (16 bytes; 9 `bl` + 2 tail `b` call sites). The bounded-store
//!   helper the register collectors append through: store at the
//!   cursor and advance it, unless it already equals `end`.
//! - `cg_proc_create` — original: `FUN_082c2268` @ 0x082c2268
//!   (40 bytes; 6 `bl` call sites — the JIT's procedure-lowering
//!   drivers at 0x082439b0/0x082465bc/0x08248728/0x082498d4/
//!   0x0824a478/0x0824af94). Allocates a 52-byte procedure record and
//!   prepends it to the module's procedure list.
//! - `cg_label_create` — original: `FUN_082c0dec` @ 0x082c0dec
//!   (52 bytes; 4 `bl` call sites). Allocates and initializes a label
//!   record and prepends it to the codegen's label list.
//! - `cg_label_add_fixup` — original: `FUN_082c17ac` @ 0x082c17ac
//!   (64 bytes; 4 `bl` call sites). Prepends the current output position
//!   to a label's fixup list.
//! - `cg_codegen_resolve_label_fixups` — original: `FUN_082c16e0` @
//!   0x082c16e0 (200 bytes + one literal; 1 `bl` call site — the
//!   compile-and-patch driver `FUN_08243138`, reached tail-branch-wise
//!   from its six clones). The label-fixup resolver: walks every bound
//!   label's fixup list and patches each recorded instruction word in
//!   the emitted-code buffer in place — sign-extended 12-bit byte
//!   displacements (tag 0) or 24-bit word displacements (tag 1, the
//!   `B<cond>` branches) spliced under the word's preserved high bits.
//!   The sole caller of `cg_buffer_read_word`/`cg_buffer_write_word`.
//! - `cg_codegen_buffer_create` — original: `FUN_082c22b0` @ 0x082c22b0
//!   (52 bytes; 1 `bl` call site, from the `cg_codegen_t` constructor
//!   `FUN_082c0d7c`). Allocates and initializes the emitted-code
//!   buffer: name pointer, zeroed code-page table, zero offset.
//! - `cg_codegen_create` — original: `FUN_082c0d7c` @ 0x082c0d7c
//!   (104 bytes; 7 `bl` call sites — the JIT's compile-and-patch
//!   drivers at 0x08243138 and its six clones). The `cg_codegen_t`
//!   constructor: a 0x220-byte arena record wiring the arena, the
//!   helper table, the emitted-code buffer and the 16-entry
//!   hardware-register descriptor table.
//! - `cg_buffer_current_offset` — original: `FUN_082c23d4` @ 0x082c23d4
//!   (8 bytes; 8 `bl` call sites). Pure getter for the emitted-code
//!   buffer's current write offset at +0x804.
//! - `cg_buffer_align_offset` — original: `FUN_082c2290` @ 0x082c2290
//!   (32 bytes; 2 `bl` call sites). Rounds the emitted-code buffer's
//!   current offset up to a power-of-two alignment, in place.
//! - `cg_buffer_emit_word` — original: `FUN_082c231c` @ 0x082c231c
//!   (52 bytes; 42 `bl` + 15 tail `b` call sites — the JIT's canonical
//!   word emitter). Aligns the emitted-code buffer to 4, stores one
//!   32-bit word through the code-page accessor and post-increments the
//!   offset by 4 from the aligned value.
//! - `cg_buffer_copy_out` — original: `FUN_082c2350` @ 0x082c2350
//!   (96 bytes; 1 `bl` call site — the compile-and-patch driver
//!   `FUN_08243138`, flattening the emitted code from offset 0 to
//!   `cg_buffer_current_offset`). Copies bytes OUT of the paged
//!   emitted-code buffer into a linear destination, chunked on
//!   code-page boundaries.
//! - `cg_buffer_read_word` — original: `FUN_082c23b0` @ 0x082c23b0
//!   (16 bytes; 2 `bl` call sites — the label-fixup resolver
//!   `FUN_082c16e0`). Reads one 32-bit word back out of the
//!   emitted-code buffer at a byte offset, through the code-page
//!   accessor.
//! - `cg_buffer_write_word` — original: `FUN_082c23c0` @ 0x082c23c0
//!   (20 bytes; 1 `bl` call site — the label-fixup resolver
//!   `FUN_082c16e0`). Writes one 32-bit word into the emitted-code
//!   buffer at a byte offset, through the code-page accessor — the
//!   write-side mirror of `cg_buffer_read_word`.
//! - `cg_codegen_output` — original: `FUN_082c17ec` @ 0x082c17ec
//!   (8 bytes; 1 `bl` call site). Pure getter for the codegen's
//!   emitted-code buffer at +0x10.
//! - `cg_inst_visit_by_kind` — original: `FUN_082c1adc` @ 0x082c1adc
//!   (288 bytes; 4 `bl` call sites). Collects the registers an
//!   instruction DEFINES into a bounded output array, dispatching on the
//!   kind byte through two branch tables.
//! - `cg_inst_collect_used_regs` — original: `FUN_082c1bfc` @ 0x082c1bfc
//!   (388 bytes). Collects an instruction's input registers.
//!
//! Layouts recovered from the assembly (byte offsets are the target's;
//! the port addresses every pointer field by WORD INDEX so the records
//! stay disjoint on a 64-bit test host, as in heap/block_region.rs):
//!
//! ```text
//! cg_module_t                 cg_proc_t (52 bytes)         cg_block_t
//!   +0x00 heap                  +0x00 next                   +0x04 proc
//!   +0x04 procs (head)          +0x04 module                 +0x0c insts (head)
//!                               +0x10 registers (head)       +0x10 last_inst (tail)
//!                               +0x14 last_register (tail)
//!                               +0x20 num_registers
//!
//! cg_virtual_reg_t (40 bytes)  cg_inst_t (base of every instruction)
//!   +0x00 next                   +0x00 next
//!   +0x10 reg_no                 +0x04 block
//!   +0x20 type (u8)              +0x08 kind (u8)
//!                                +0x09 opcode (u8)
//!                                +0x0c first derived field
//!
//! cg_codegen_t (0x220 bytes)   cg_label_t (12 bytes)
//!   +0x00 helpers                +0x00 next
//!   +0x04 status                 +0x04 fixups (head)
//!   +0x08 heap                   +0x08 offset (all-ones while unbound)
//!   +0x0c labels (head)
//!   +0x10 output
//!   +0x20 hw_regs — 16 entries of 28 bytes, one descriptor per ARM
//!       register r0-r15; the constructor stamps each entry's
//!       register-number byte
//!   +0x1e0 id byte of the codegen's embedded descriptor anchor at
//!       +0x1d4, zeroed
//!
//! cg_codegen_buffer_t (0x808 bytes)
//!   +0x00 name ("CSEG", write-only)
//!   +0x04 pages — 512-slot table of lazily allocated 0x1000-byte code
//!       pages (the destructor @ 0x082c22e8 walks +0x04+i*4 freeing each
//!       non-NULL entry; `FUN_082c5b1c` maps a byte offset to
//!       `pages[offset >> 12] + (offset & 0xfff)`)
//!   +0x804 current_offset
//! ```
//!
//! The instruction kinds are a dense enum spanning 0-22: the visitor
//! @ 0x082c1adc reads `inst + 0x8` and dispatches through TWO tables —
//! `cmp r0, #20; addls pc, pc, r0, lsl #2` for kinds 0-20, then a
//! `sub r0, r0, #4; cmp r0, #18` table over the fall-through that also
//! reaches kinds 21 and 22. The twelve factories encode
//! (kind, record size): 1/32, 2/36 (twice — with and without a
//! destination-flags register), 3/32, 4/24, 5/24, 6/20, 7/20, 8/20,
//! 9/20, 11/16 (twice). That sequence — and the field counts — matches
//! Vincent's `cg_inst_kind_t` ordering (unary, binary, compare, load,
//! store, load_immed, branch_label, branch_cond, phi, ...), which is
//! where the names used here come from.
//!
//! Deviations:
//! - Neither builder writes the record's `next`: the original relies on
//!   the arena's zero-fill and so does the port. Anything that replaces
//!   `CG_HEAP_OPS.zero` with a non-zeroing stub breaks list termination.
//! - `cg_virtual_reg_create` re-reads `proc->num_registers` after storing
//!   it into the register (`ldr` / `str` / `ldr` / `add` / `str`); the
//!   port reads once, which is identical because the register record
//!   cannot alias the procedure.
//! - Record sizes are given as target byte counts and scaled by
//!   [`record_size`] so the ports work on a 64-bit host; on target the
//!   scale is 1 and the constants fold to the originals' `mov r1, #36` /
//!   `mov r1, #20` / `mov r1, #40`.
//! - `cg_virtual_reg_list_create` is variadic in the original
//!   (`stmdb sp!, {r0-r3}` builds the argument frame and the walk reads
//!   upward from `&arg1`), an ABI Rust cannot express on this target.
//!   The port takes a pointer to a NULL-terminated array of register
//!   pointers instead — same termination rule, same cell layout, same
//!   allocation sequence; only the argument marshalling differs.
//! - `cg_codegen_buffer_create` allocates through the swappable
//!   [`CG_BUFFER_ALLOC`] slot (default: the ported `malloc` @
//!   0x0802edac, the original's direct `bl` — same scheme as stdio's
//!   `STDIO_ALLOC`) so host tests can observe the requested size
//!   without racing malloc's global ops table, and returns NULL when
//!   the allocation fails, where the original has NO null check and
//!   would memzero 0x800 bytes at address 4 (same deviation as
//!   `fopen`'s fresh-node allocation).
//! - The page accessor `FUN_082c5b1c` @ 0x082c5b1c (32 bytes) is ported
//!   as [`cg_buffer_page_pointer`] and stays the wired default of the
//!   swappable [`CG_BUFFER_PAGE_POINTER`] seam (the same
//!   `read_volatile`-dispatched scheme as [`CG_BUFFER_ALLOC`]), through
//!   which [`cg_buffer_emit_word`] keeps resolving its write pointer —
//!   the `app/vtable_set.rs` `vtable_slot_50_dispatch` precedent: the
//!   seam is retained for hookability, rewiring the emitter to a direct
//!   call is a deliberate follow-up. The accessor's `bl` target, the
//!   lazy page-slot accessor `FUN_082b7edc` @ 0x082b7edc (52 bytes),
//!   stays identified behind the [`CG_BUFFER_PAGE_SLOT`] seam, whose
//!   wired default models its exact body. The default's page allocation
//!   goes through [`CG_BUFFER_ALLOC`] and a failed allocation returns
//!   NULL, where the original calls `malloc` directly and would memzero
//!   0x1000 bytes at address 0
//!   (same deviation as [`cg_codegen_buffer_create`]).

use super::heap::{cg_heap_alloc, CgHeap};
use crate::libc::rt_memcpy::__rt_memcpy;

/// Width of a pointer/word field: 4 on the ARMv5TE target (matching the
/// original layout), 8 on a 64-bit test host.
const WORD: usize = core::mem::size_of::<*mut u8>();

/// Scales a record size given in the target's bytes to the host's word
/// width. Every record size in this cluster is a whole number of 32-bit
/// words, so on target this is the identity.
pub const fn record_size(target_bytes: usize) -> usize {
    target_bytes / 4 * WORD
}

// --- opaque IR objects -------------------------------------------------
// Only the fields listed in the module header are recovered, so these are
// FFI-opaque types addressed through the word indices below.

/// `cg_module_t` — owns the arena every IR record is carved from.
#[repr(C)]
pub struct CgModule {
    _opaque: [u8; 0],
}

/// `cg_codegen_t` — owns the arena and the emitted-code buffer used by
/// label fixups.
#[repr(C)]
pub struct CgCodegen {
    _opaque: [u8; 0],
}

/// `cg_codegen_buffer_t` — the emitted-code buffer owned by
/// `cg_codegen_t::output`: a lazily allocated table of 0x1000-byte code
/// pages plus the current write offset at +0x804.
#[repr(C)]
pub struct CgCodegenBuffer {
    _opaque: [u8; 0],
}

/// `cg_label_t` — a generated-code label and its pending fixups.
#[repr(C)]
pub struct CgLabel {
    _opaque: [u8; 0],
}

/// `cg_label_fixup_t` — one pending patch position on a [`CgLabel`].
#[repr(C)]
pub struct CgLabelFixup {
    _opaque: [u8; 0],
}

/// `cg_proc_t` — one procedure being built: owns the virtual registers.
#[repr(C)]
pub struct CgProc {
    _opaque: [u8; 0],
}

/// `cg_block_t` — one basic block: owns a list of instructions.
#[repr(C)]
pub struct CgBlock {
    _opaque: [u8; 0],
}

/// `cg_virtual_reg_t` — an SSA-ish value of the IR.
#[repr(C)]
pub struct CgVirtualReg {
    _opaque: [u8; 0],
}

/// `cg_inst_t` — the common base of every instruction record.
#[repr(C)]
pub struct CgInst {
    _opaque: [u8; 0],
}

/// `cg_virtual_reg_list_t` — one cell of a NULL-terminated register
/// list, built by [`cg_virtual_reg_list_create`].
#[repr(C)]
pub struct CgVirtualRegList {
    _opaque: [u8; 0],
}

// --- word indices (target byte offset = index * 4) ---------------------

/// `cg_module_t + 0x00` — the IR arena.
pub const CG_MODULE_HEAP: usize = 0;
/// `cg_module_t + 0x04` — head of the module's procedure list, built
/// by [`cg_proc_create`].
pub const CG_MODULE_PROCS: usize = 1;
/// `cg_codegen_t + 0x00` — pointer to the caller's ten-entry table of
/// runtime-helper addresses. Every driver
/// (`FUN_08243138` and its six clones) hands in the same 0x28-byte
/// block of code pointers (0x08025f88, 0x080de95c, 0x0806b32c,
/// 0x0806b27c, 0x080e2468, 0x0809b904 — all mid-function entry points
/// into osos text); the instruction emitters read individual words out
/// of it and emit them INTO the generated code (e.g. `FUN_082c0f4c`
/// reads `helpers[6]` for kind 0x17 and passes it to the word emitter
/// @ 0x082beb4c).
pub const CG_CODEGEN_HELPERS: usize = 0;
/// `cg_codegen_t + 0x04` — pointer to the caller's status cell (every
/// driver passes the address of a zero-initialized stack word). No
/// reader was recovered in the compile/fixup path; the constructor
/// stores it verbatim.
pub const CG_CODEGEN_STATUS: usize = 1;
/// `cg_codegen_t + 0x08` — the JIT arena used for label metadata.
pub const CG_CODEGEN_HEAP: usize = 2;
/// `cg_codegen_t + 0x0c` — head of the codegen's label list, built by
/// [`cg_label_create`].
pub const CG_CODEGEN_LABELS: usize = 3;
/// `cg_codegen_t + 0x10` — the emitted-code buffer.
pub const CG_CODEGEN_OUTPUT: usize = 4;
/// `cg_codegen_buffer_t + 0x804` — current output position, read by
/// [`cg_buffer_current_offset`].
pub const CG_CODEGEN_OUTPUT_OFFSET: usize = 0x804 / 4;
/// `cg_codegen_buffer_t + 0x00` — the buffer's name, a pointer to a
/// static C string stored by [`cg_codegen_buffer_create`]. The only
/// call site passes `"CSEG"` (see [`cg_codegen_create`]) and no
/// function reads it back — the destructor @ 0x082c22e8 walks only the
/// page table, and the emitters/page accessor (0x082c2290, 0x082c231c,
/// 0x082c2350, 0x082b7edc, ...) touch only pages and the offset.
pub const CG_BUFFER_NAME: usize = 0;
/// `cg_codegen_buffer_t + 0x04` — first slot of the code-page table.
pub const CG_BUFFER_PAGES: usize = 1;
/// Size of the code-page table in target bytes (512 pointer slots).
pub const CG_BUFFER_PAGE_TABLE_BYTES: usize = 0x800;
/// Size of `cg_codegen_buffer_t` in target bytes: 4 name + 0x800 page
/// table + 4 offset — the literal-pool constant at 0x082c22e4.
pub const CG_CODEGEN_BUFFER_BYTES: usize = 0x808;
/// Size of one lazily allocated code page in bytes — the page-slot
/// accessor's `mov r0, #0x1000` (FUN_082b7edc @ 0x082b7ef0) and
/// `mov r1, #0x1000` (@ 0x082b7efc).
pub const CG_BUFFER_PAGE_BYTES: usize = 0x1000;
/// Log2 of the code-page size: an offset's page index is
/// `offset >> CG_BUFFER_PAGE_SHIFT` and its in-page byte is
/// `offset & (CG_BUFFER_PAGE_BYTES - 1)` — the page accessor's
/// `mov r1, r1, lsr #0xc` and `mov r4, r2, lsl #0x14; mov r4, r4,
/// lsr #0x14` pair (FUN_082c5b1c @ 0x082c5b24-0x082c5b2c).
pub const CG_BUFFER_PAGE_SHIFT: usize = 12;

/// Size of `cg_codegen_t` in target bytes — the constructor's
/// `mov r1, #0x220` (twice: the arena request and the zero-fill).
pub const CG_CODEGEN_BYTES: usize = 0x220;
/// `cg_codegen_t + 0x20` — the register-number byte of the first
/// hardware-register descriptor. The table runs 16 entries of 28
/// target bytes each, one per ARM register r0-r15; entry `i` starts at
/// `+0x14 + i*0x1c` as a descriptor anchor and the constructor stamps
/// `i` into the byte at `+0x20 + i*0x1c` (anchor `+0x0c`). Field
/// evidence from the walkers `FUN_082cea24` / `FUN_082d7800` / the
/// spill path `FUN_082d7870`: anchor `+0x10` is the head of an
/// intrusive binding list (nodes back-point to the anchor at their
/// `+0x08`) and anchor `+0x18` is a flags word (bit 0x100).
pub const CG_CODEGEN_HW_REGS: usize = 8;
/// Number of hardware-register descriptors — exactly ARM r0-r15.
pub const CG_HW_REG_COUNT: usize = 16;
/// Descriptor stride in words: 28 target bytes (the original's
/// `rsb r1, r0, r0, lsl #3` / `add r1, r4, r1, lsl #2` = i*7*4).
pub const CG_HW_REG_ENTRY_WORDS: usize = 7;
/// `cg_codegen_t + 0x1e0` — the id byte of the codegen's own embedded
/// descriptor anchor at `+0x1d4` (same layout as the register-table
/// anchors: list head at anchor `+0x10` = `+0x1e4`, per `FUN_082d7870`
/// and the fixup-path stores at 0x082c1660). The constructor zeroes it
/// explicitly even though the record-wide zero-fill already did — the
/// same defensive style as the explicit `labels = NULL` store.
pub const CG_CODEGEN_ANCHOR_ID: usize = 0x78;

/// `cg_label_t + 0x00` — next label in the codegen's list.
pub const CG_LABEL_NEXT: usize = 0;
/// `cg_label_t + 0x04` — head of its pending-fixup list.
pub const CG_LABEL_FIXUPS: usize = 1;
/// `cg_label_t + 0x08` — emitted-code offset the label is bound to;
/// [`CG_LABEL_UNBOUND`] until the binder runs.
pub const CG_LABEL_OFFSET: usize = 2;
/// Size of `cg_label_t` in target bytes.
pub const CG_LABEL_BYTES: usize = 12;
/// The all-ones "not yet bound" marker [`cg_label_create`] stamps into
/// [`CG_LABEL_OFFSET`] — exactly the original's `mvn r1, #0`.
pub const CG_LABEL_UNBOUND: usize = !0;

/// `cg_label_fixup_t + 0x00` — next pending fixup.
pub const CG_LABEL_FIXUP_NEXT: usize = 0;
/// `cg_label_fixup_t + 0x04` — one-byte patch encoding tag.
pub const CG_LABEL_FIXUP_TAG: usize = 1;
/// `cg_label_fixup_t + 0x08` — emitted-code offset to patch.
pub const CG_LABEL_FIXUP_OFFSET: usize = 2;
/// Size of `cg_label_fixup_t` in target bytes.
pub const CG_LABEL_FIXUP_BYTES: usize = 12;

/// `cg_proc_t + 0x00` — next procedure in the module's list, written
/// by [`cg_proc_create`] (NULL in the oldest one by the arena's
/// zero-fill).
pub const CG_PROC_NEXT: usize = 0;
/// `cg_proc_t + 0x04` — owning module.
pub const CG_PROC_MODULE: usize = 1;
/// `cg_proc_t + 0x10` — first virtual register.
pub const CG_PROC_REGISTERS: usize = 4;
/// `cg_proc_t + 0x14` — last virtual register.
pub const CG_PROC_LAST_REGISTER: usize = 5;
/// `cg_proc_t + 0x20` — number of registers created so far.
pub const CG_PROC_NUM_REGISTERS: usize = 8;
/// Size of `cg_proc_t` in target bytes — the factory's
/// `mov r1, #0x34` (FUN_082c2268 @ 0x082c2274).
pub const CG_PROC_BYTES: usize = 0x34;

/// `cg_block_t + 0x04` — owning procedure.
pub const CG_BLOCK_PROC: usize = 1;
/// `cg_block_t + 0x0c` — first instruction.
pub const CG_BLOCK_INSTS: usize = 3;
/// `cg_block_t + 0x10` — last instruction.
pub const CG_BLOCK_LAST_INST: usize = 4;

/// `cg_virtual_reg_t + 0x00` — next register in the procedure's list.
pub const CG_VREG_NEXT: usize = 0;
/// `cg_virtual_reg_t + 0x10` — the register's number.
pub const CG_VREG_NO: usize = 4;
/// `cg_virtual_reg_t + 0x20` — the register's type, a single byte.
pub const CG_VREG_TYPE: usize = 8;
/// Size of `cg_virtual_reg_t` in target bytes.
pub const CG_VREG_BYTES: usize = 40;

/// `cg_inst_t + 0x00` — next instruction in the block's list.
pub const CG_INST_NEXT: usize = 0;
/// `cg_inst_t + 0x04` — owning block.
pub const CG_INST_BLOCK: usize = 1;
/// `cg_inst_t + 0x08` — instruction kind, a single byte.
pub const CG_INST_KIND: usize = 2;
/// Byte offset of the opcode inside the kind word (`cg_inst_t + 0x09`).
const CG_INST_OPCODE_IN_KIND_WORD: usize = 1;

/// `cg_inst_binary_t + 0x0c` — destination register.
pub const CG_INST_BINARY_DEST: usize = 3;
/// `cg_inst_binary_t + 0x14` — first source register.
pub const CG_INST_BINARY_SOURCE0: usize = 5;
/// `cg_inst_binary_t + 0x18` — second source register.
pub const CG_INST_BINARY_SOURCE1: usize = 6;
/// Size of `cg_inst_binary_t` in target bytes.
pub const CG_INST_BINARY_BYTES: usize = 36;
/// `cg_inst_kind_t` value the binary factory stamps.
pub const CG_INST_KIND_BINARY: u32 = 2;

/// `cg_inst_load_immed_t + 0x0c` — destination register.
pub const CG_INST_LOAD_IMMED_DEST: usize = 3;
/// `cg_inst_load_immed_t + 0x10` — the immediate.
pub const CG_INST_LOAD_IMMED_VALUE: usize = 4;
/// Size of `cg_inst_load_immed_t` in target bytes.
pub const CG_INST_LOAD_IMMED_BYTES: usize = 20;
/// `cg_inst_kind_t` value the load-immediate factory stamps.
pub const CG_INST_KIND_LOAD_IMMED: u32 = 6;

/// `cg_inst_unary_t + 0x0c` — destination register.
pub const CG_INST_UNARY_DEST: usize = 3;
/// `cg_inst_unary_t + 0x14` — source register. `+0x10` stays NULL by
/// the arena's zero-fill (the dest_flags slot of the binary layout).
pub const CG_INST_UNARY_SOURCE: usize = 5;
/// Size of `cg_inst_unary_t` in target bytes.
pub const CG_INST_UNARY_BYTES: usize = 32;
/// `cg_inst_kind_t` value the unary factory stamps.
pub const CG_INST_KIND_UNARY: u32 = 1;

/// `cg_inst_binary_t + 0x10` — destination-flags register; only the
/// `_s` factory writes it.
pub const CG_INST_BINARY_DEST_FLAGS: usize = 4;
/// `cg_inst_kind_t` value both binary factories stamp.
pub const CG_INST_KIND_BINARY_S: u32 = 2;

/// `cg_inst_compare_t + 0x0c` — destination register.
pub const CG_INST_COMPARE_DEST: usize = 3;
/// `cg_inst_compare_t + 0x10` — first source register (compare has no
/// dest_flags slot; its sources sit one word earlier than binary's).
pub const CG_INST_COMPARE_SOURCE0: usize = 4;
/// `cg_inst_compare_t + 0x14` — second source register.
pub const CG_INST_COMPARE_SOURCE1: usize = 5;
/// Size of `cg_inst_compare_t` in target bytes.
pub const CG_INST_COMPARE_BYTES: usize = 32;
/// `cg_inst_kind_t` value the compare factory stamps.
pub const CG_INST_KIND_COMPARE: u32 = 3;

/// `cg_inst_load_t + 0x0c` — destination register.
pub const CG_INST_LOAD_DEST: usize = 3;
/// `cg_inst_load_t + 0x10` — address register.
pub const CG_INST_LOAD_ADDRESS: usize = 4;
/// Size of `cg_inst_load_t` in target bytes.
pub const CG_INST_LOAD_BYTES: usize = 24;
/// `cg_inst_kind_t` value the load factory stamps.
pub const CG_INST_KIND_LOAD: u32 = 4;

/// `cg_inst_store_t + 0x0c` — value register.
pub const CG_INST_STORE_VALUE: usize = 3;
/// `cg_inst_store_t + 0x10` — address register.
pub const CG_INST_STORE_ADDRESS: usize = 4;
/// Size of `cg_inst_store_t` in target bytes.
pub const CG_INST_STORE_BYTES: usize = 24;
/// `cg_inst_kind_t` value the store factory stamps.
pub const CG_INST_KIND_STORE: u32 = 5;

/// `cg_inst_branch_label_t + 0x0c` — target block.
pub const CG_INST_BRANCH_LABEL_TARGET: usize = 3;
/// Size of `cg_inst_branch_label_t` in target bytes.
pub const CG_INST_BRANCH_LABEL_BYTES: usize = 20;
/// `cg_inst_kind_t` value the branch-label factory stamps.
pub const CG_INST_KIND_BRANCH_LABEL: u32 = 7;

/// `cg_inst_branch_cond_t + 0x0c` — target block (same slot as the
/// branch-label target, but filled from the FOURTH argument).
pub const CG_INST_BRANCH_COND_TARGET: usize = 3;
/// `cg_inst_branch_cond_t + 0x10` — condition register (filled from the
/// third argument — the swapped order of this factory).
pub const CG_INST_BRANCH_COND_CONDITION: usize = 4;
/// Size of `cg_inst_branch_cond_t` in target bytes.
pub const CG_INST_BRANCH_COND_BYTES: usize = 20;
/// `cg_inst_kind_t` value the branch-cond factory stamps.
pub const CG_INST_KIND_BRANCH_COND: u32 = 8;

/// `cg_inst_phi_t + 0x0c` — destination register.
pub const CG_INST_PHI_DEST: usize = 3;
/// `cg_inst_phi_t + 0x10` — head of the register list built by
/// `cg_virtual_reg_list_create`.
pub const CG_INST_PHI_REGS: usize = 4;
/// Size of `cg_inst_phi_t` in target bytes.
pub const CG_INST_PHI_BYTES: usize = 20;
/// `cg_inst_kind_t` value the phi factory stamps.
pub const CG_INST_KIND_PHI: u32 = 9;

/// `cg_inst_ret_value_t + 0x0c` — returned value register.
pub const CG_INST_RET_VALUE_VALUE: usize = 3;
/// Size of both ret records in target bytes.
pub const CG_INST_RET_BYTES: usize = 16;
/// `cg_inst_kind_t` value both ret factories stamp.
pub const CG_INST_KIND_RET: u32 = 11;

/// `cg_virtual_reg_list_t + 0x00` — next cell; NULL in the last one by
/// the arena's zero-fill.
pub const CG_VREG_LIST_NEXT: usize = 0;
/// `cg_virtual_reg_list_t + 0x04` — the register this cell holds.
pub const CG_VREG_LIST_REG: usize = 1;
/// Size of `cg_virtual_reg_list_t` in target bytes.
pub const CG_VREG_LIST_BYTES: usize = 8;

/// `cg_inst_t + 0x0c` — the register [`cg_inst_visit_by_kind`] collects
/// for every defining kind: the destination of the unary/binary/
/// compare/load/load-immediate/phi layouts, and the first register of
/// the unrecovered kinds 12-22.
pub const CG_INST_DEF0: usize = 3;
/// `cg_inst_t + 0x10` — the optional second defined register: the
/// dest_flags slot of the binary_s layout (NULL by the arena's zero-fill
/// for every other factory), collected only when non-NULL.
pub const CG_INST_DEF1: usize = 4;
/// `cg_inst_t + 0x14` — the register kind 10 defines, collected only
/// when non-NULL.
pub const CG_INST_KIND10_DEF: usize = 5;
/// `cg_inst_kind16_t + 0x1c` — the third source register collected by
/// [`cg_inst_collect_used_regs`].
pub const CG_INST_KIND16_SOURCE2: usize = 7;

/// Address of a record's pointer-sized field at word index `index`.
#[inline(always)]
unsafe fn slot(record: *mut u8, index: usize) -> *mut *mut u8 {
    (record as *mut *mut u8).add(index)
}

/// Address of a record's word-sized scalar field at word index `index`.
#[inline(always)]
unsafe fn word(record: *mut u8, index: usize) -> *mut usize {
    (record as *mut usize).add(index)
}

/// The arena backing `module`'s IR (`module->heap`).
#[inline(always)]
unsafe fn module_heap(module: *mut u8) -> *mut CgHeap {
    slot(module, CG_MODULE_HEAP).read() as *mut CgHeap
}

/// Reads a hook slot. Volatile so a build in which nothing rewrites the
/// slot does not constant-fold the default in and delete the dispatch.
#[inline(always)]
fn hook<T: Copy>(slot: *const T) -> T {
    unsafe { core::ptr::read_volatile(slot) }
}

/// Allocator boundary for [`cg_codegen_buffer_create`]; defaults to the
/// ported `malloc` @ 0x0802edac — the original's direct `bl`.
#[cfg_attr(target_os = "none", no_mangle)]
pub static mut CG_BUFFER_ALLOC: unsafe extern "C" fn(usize) -> *mut u8 =
    crate::runtime::malloc_rt::malloc;

/// The page-accessor boundary for [`cg_buffer_emit_word`]: maps a byte
/// offset inside the emitted-code buffer to a host pointer into the
/// lazily allocated code pages. The accessor `FUN_082c5b1c` @ 0x082c5b1c
/// is ported as [`cg_buffer_page_pointer`], which stays the wired
/// default here — the `app/vtable_set.rs` `vtable_slot_50_dispatch`
/// precedent: the seam is retained for hookability and host-test
/// interception, the emitter keeps routing through it, and rewiring to
/// a direct call is a deliberate follow-up (one function per commit).
/// Host tests swap in a recording fake.
#[cfg_attr(target_os = "none", no_mangle)]
pub static mut CG_BUFFER_PAGE_POINTER: unsafe extern "C" fn(
    *mut CgCodegenBuffer,
    usize,
) -> *mut u8 = cg_buffer_page_pointer;

/// cg_buffer_page_pointer — original: `FUN_082c5b1c` @ 0x082c5b1c
/// (32 bytes, 3 `bl` call sites: 0x082c2338 inside the word emitter
/// [`cg_buffer_emit_word`] plus two more; grep on decomp/osos.asm).
///
/// The emitted-code buffer's page accessor: maps a byte offset inside
/// the buffer to a pointer into the lazily allocated 0x1000-byte code
/// pages — `pages[offset >> 12] + (offset & 0xfff)`. The body is
/// verbatim from the original's `mov r4, r2, lsl #0x14; mov r4, r4,
/// lsr #0x14` (the intra-page byte offset), `mov r1, r1, lsr #0xc`
/// (the page index), `bl 0x082b7edc` (the lazy page-slot accessor),
/// `add r0, r0, r4` (base + intra): the offset splits into page index
/// and intra-page byte, the page base comes from the page-slot
/// accessor, and the intra offset is added on.
///
/// The `bl` target — `FUN_082b7edc` @ 0x082b7edc (52 bytes) — stays
/// identified/unported and sits behind the [`CG_BUFFER_PAGE_SLOT`]
/// seam, whose wired default models its exact body (the same scheme as
/// this function's own [`CG_BUFFER_PAGE_POINTER`] seam).
///
/// SEAM DECISION (the `app/vtable_set.rs` `vtable_slot_50_dispatch`
/// precedent): this port stays the wired default of
/// [`CG_BUFFER_PAGE_POINTER`] and [`cg_buffer_emit_word`] keeps routing
/// through the seam — retained for hookability and host-test
/// interception; rewiring the emitter to a direct call is a deliberate
/// follow-up (one function per commit).
///
/// DEVIATION: the original has NO NULL guard on the accessor's result
/// — the `add r0, r0, r4` @ 0x082c5b34 is unconditional, and an
/// allocation failure has already crashed one callee earlier, on the
/// wild 0x1000-byte memzero at address 0 inside `FUN_082b7edc`. The
/// port propagates the page-slot seam's NULL instead, carrying forward
/// the previous seam default's documented deviation, so
/// [`cg_buffer_emit_word`]'s store-through-NULL failure semantics are
/// unchanged.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_buffer_page_pointer(
    output: *mut CgCodegenBuffer,
    offset: usize,
) -> *mut u8 {
    let page = hook(core::ptr::addr_of!(CG_BUFFER_PAGE_SLOT))(
        output,
        offset >> CG_BUFFER_PAGE_SHIFT,
    );
    if page.is_null() {
        return core::ptr::null_mut();
    }
    page.add(offset & (CG_BUFFER_PAGE_BYTES - 1))
}

/// The page-slot boundary for [`cg_buffer_page_pointer`]: resolves a
/// page index to the base of that code page, allocating it lazily. The
/// wired default ([`default_cg_buffer_page_slot`]) models the exact
/// body of the identified-but-unported `FUN_082b7edc` @ 0x082b7edc
/// (52 bytes); host tests swap in a recording fake, and porting
/// 0x082b7edc later replaces the default without touching the
/// accessor.
#[cfg_attr(target_os = "none", no_mangle)]
pub static mut CG_BUFFER_PAGE_SLOT: unsafe extern "C" fn(
    *mut CgCodegenBuffer,
    usize,
) -> *mut u8 = default_cg_buffer_page_slot;

/// The wired default of [`CG_BUFFER_PAGE_SLOT`]: the exact body of the
/// identified page-slot accessor `FUN_082b7edc` @ 0x082b7edc (52 bytes:
/// `add r5, r0, r1, lsl #0x2; ldr r4, [r5, #0x4]; cmp r4, #0x0;
/// bne 0x082b7f08; mov r0, #0x1000; bl malloc; mov r4, r0; mov r1,
/// #0x1000; bl 0x08037dc8; str r4, [r5, #0x4]; mov r0, r4`) — read
/// `buffer->pages[index]`; when NULL, allocate one 0x1000-byte page,
/// zero-fill it through the IRAM veneer 0x08037dc8 (-> 0x220002d4, the
/// relocated copy of `memzero` @ 0x080002d4 — [`crate::libc::memzero::
/// memzero`] here), store it into the slot and return it; a non-NULL
/// slot comes back unchanged. Like the original, there is no bounds
/// check on the 512-slot page table.
///
/// DEVIATIONS (module header): the page allocation goes through the
/// swappable [`CG_BUFFER_ALLOC`] slot where the original `bl`s `malloc`
/// @ 0x0802edac directly (the slot defaults to that same port), and a
/// failed allocation returns NULL where the original has no NULL check
/// and would memzero 0x1000 bytes at address 0 (same deviation as
/// [`cg_codegen_buffer_create`]).
unsafe extern "C" fn default_cg_buffer_page_slot(
    output: *mut CgCodegenBuffer,
    index: usize,
) -> *mut u8 {
    let page_slot = slot(output as *mut u8, CG_BUFFER_PAGES + index);
    let mut page = page_slot.read();
    if page.is_null() {
        page = hook(core::ptr::addr_of!(CG_BUFFER_ALLOC))(record_size(CG_BUFFER_PAGE_BYTES));
        if page.is_null() {
            return core::ptr::null_mut();
        }
        crate::libc::memzero::memzero(page, record_size(CG_BUFFER_PAGE_BYTES));
        page_slot.write(page);
    }
    page
}

/// The segment name [`cg_codegen_create`] stamps into the emitted-code
/// buffer. On target the constructor's `adr r0, 0x82c0de4` picks up
/// this exact eight-byte datum ("CSEG" plus four NUL padding bytes),
/// which sits in the gap between the constructor's last instruction
/// (0x082c0de0) and `cg_label_create` @ 0x082c0dec — verified against
/// osos.dec at file offset 0x2c0de4.
static CODE_SEGMENT_NAME: [u8; 8] = *b"CSEG\0\0\0\0";

/// cg_codegen_create — original: `FUN_082c0d7c` @ 0x082c0d7c
/// (104 bytes, 7 `bl` call sites: the JIT's compile-and-patch drivers
/// `FUN_08243138` @ 0x08243138 and its six clones at 0x08246580,
/// 0x0824854c, 0x082493c0, 0x0824a43c, 0x0824af58, 0x0824bd40, all
/// calling it as `create(*proc_or_module, &helper_table, &status)`).
///
/// The `cg_codegen_t` constructor. Bump-allocates the 0x220-byte record
/// out of the caller's arena (`bl 0x082c1a08` — [`cg_heap_alloc`],
/// called directly) and zeroes it through the IRAM veneer 0x08037db8
/// (`ldr pc,[0x8037dbc]` -> 0x2200027c, the relocated copy of
/// `memzero_aligned` @ 0x0800027c — called directly here, exactly as
/// [`cg_codegen_buffer_create`] does), then wires the record:
///
/// - `+0x08 heap` = the arena argument (pinned by [`cg_label_create`],
///   which reads `codegen + 0x08` as the heap it allocates labels
///   from);
/// - `+0x0c labels` = NULL (explicit store, redundant with the
///   zero-fill — the label list head);
/// - `+0x00 helpers` = the second argument (`stmia r4, {r6, r7}`
///   together with `+0x04`): a pointer to the caller's ten-entry table
///   of runtime-helper addresses, which the emitters later copy words
///   from into the generated code;
/// - `+0x04 status` = the third argument: a pointer to the caller's
///   zero-initialized status cell, stored verbatim;
/// - `+0x10 output` = [`cg_codegen_buffer_create`]'s fresh
///   emitted-code buffer (pinned by [`cg_codegen_output`] and the
///   fixup resolver `FUN_082c16e0`);
/// - the 16-entry hardware-register descriptor table at `+0x20`:
///   16 iterations of `strb i, [codegen + 0x20 + i*28]` stamp each
///   descriptor's register-number byte (NOTE the reference C and the
///   task brief's "zero byte" reading are both wrong — the stored
///   value is the loop counter r0, 0..15, one per ARM register);
/// - `+0x1e0` = 0, the id byte of the codegen's embedded descriptor
///   anchor at `+0x1d4` (explicit `strb`, again redundant with the
///   zero-fill).
///
/// Returns the new record in r0 (`mov r0, r4` before the pop).
///
/// THE `adr` ANOMALY: the `bl cg_codegen_buffer_create` at 0x082c0db4
/// passes r0 = `adr 0x82c0de4`, which is NOT the new codegen record —
/// it is the address of an eight-byte datum sitting in the gap before
/// `cg_label_create` @ 0x082c0dec. That datum is the NUL-padded string
/// `"CSEG"` (osos.dec offset 0x2c0de4: `43 53 45 47 00 00 00 00`), so
/// the buffer's `+0x00` word is a segment NAME, not an owner
/// back-pointer: no function in the image ever reads it back (see
/// [`CG_BUFFER_NAME`]). The port passes a static with identical
/// contents.
///
/// DEVIATION: none of the NULL paths exist in the original — like the
/// rest of the cluster it trusts the GL heap. The port inherits
/// [`cg_codegen_buffer_create`]'s documented deviation (NULL output on
/// allocation failure, stored verbatim) instead of the original's wild
/// zero-fill at address 4.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_codegen_create(
    heap: *mut CgHeap,
    helpers: *const usize,
    status: *mut usize,
) -> *mut CgCodegen {
    let codegen = cg_heap_alloc(heap, record_size(CG_CODEGEN_BYTES));
    crate::libc::memzero::memzero_aligned(codegen, record_size(CG_CODEGEN_BYTES));

    // Same store order as the original: heap, labels = NULL, then the
    // `stmia r4, {r6, r7}` pair.
    slot(codegen, CG_CODEGEN_HEAP).write(heap as *mut u8);
    slot(codegen, CG_CODEGEN_LABELS).write(core::ptr::null_mut());
    slot(codegen, CG_CODEGEN_HELPERS).write(helpers as *mut u8);
    slot(codegen, CG_CODEGEN_STATUS).write(status as *mut u8);

    // `adr r0, 0x82c0de4` + `bl 0x082c22b0`: the "CSEG" name, not the
    // record (see the doc header).
    let output = cg_codegen_buffer_create(CODE_SEGMENT_NAME.as_ptr());
    slot(codegen, CG_CODEGEN_OUTPUT).write(output as *mut u8);

    // 16 descriptors, 28 bytes each: stamp register r0-r15's number.
    for reg in 0..CG_HW_REG_COUNT {
        codegen
            .add((CG_CODEGEN_HW_REGS + reg * CG_HW_REG_ENTRY_WORDS) * WORD)
            .write(reg as u8);
    }
    codegen.add(CG_CODEGEN_ANCHOR_ID * WORD).write(0);

    codegen as *mut CgCodegen
}

/// cg_codegen_buffer_create — original: `FUN_082c22b0` @ 0x082c22b0
/// (52 bytes, 1 `bl` call site: 0x082c0db4, inside the `cg_codegen_t`
/// constructor [`cg_codegen_create`], which stores the result at
/// `codegen->output` (+0x10)).
///
/// The emitted-code buffer constructor. `malloc`s the 0x808-byte record
/// (the size comes from the literal pool at 0x082c22e4: 4 name + 0x800
/// page table + 4 offset), zeroes the 0x800-byte code-page table at
/// +0x04 through the IRAM veneer 0x08037db8 (`ldr pc,[0x8037dbc]` ->
/// 0x2200027c, the relocated copy of `memzero_aligned` @ 0x0800027c —
/// called directly here), sets `current_offset` (+0x804) to 0 and
/// stores `name` at +0x00. The record's layout is pinned by the
/// destructor @ 0x082c22e8, which walks the page table freeing each
/// non-NULL entry, and by [`cg_buffer_current_offset`]. The name is
/// write-only: the constructor passes `"CSEG"` and nothing reads it
/// back (see [`CG_BUFFER_NAME`]).
///
/// DEVIATION: the original does not null-check the `malloc` result —
/// on failure it zeroes 0x800 bytes at address 4. The port returns
/// NULL (module-header deviations).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_codegen_buffer_create(
    name: *const u8,
) -> *mut CgCodegenBuffer {
    let buffer = hook(core::ptr::addr_of!(CG_BUFFER_ALLOC))(record_size(
        CG_CODEGEN_BUFFER_BYTES,
    ));
    if buffer.is_null() {
        return core::ptr::null_mut();
    }
    crate::libc::memzero::memzero_aligned(
        buffer.add(WORD * CG_BUFFER_PAGES),
        record_size(CG_BUFFER_PAGE_TABLE_BYTES),
    );
    word(buffer, CG_CODEGEN_OUTPUT_OFFSET).write(0);
    slot(buffer, CG_BUFFER_NAME).write(name as *mut u8);
    buffer as *mut CgCodegenBuffer
}

/// cg_buffer_current_offset — original: `FUN_082c23d4` @ 0x082c23d4
/// (8 bytes, 8 `bl` call sites).
///
/// A pure field getter — the entire body is `ldr r0, [r0, #0x804];
/// bx lr`: returns `output->current_offset`, the current write position
/// inside the emitted-code buffer. The emitters keep it as a running
/// byte offset across the buffer's lazily allocated 0x1000-byte pages:
/// `FUN_082c2290` aligns it, the word emitters (0x082c231c, 0x082beb4c,
/// ...) store through it and post-increment it by 4, and
/// `FUN_082c5b1c` maps it to a pointer as `page[offset >> 12] +
/// (offset & 0xfff)`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_buffer_current_offset(output: *mut CgCodegenBuffer) -> usize {
    word(output as *mut u8, CG_CODEGEN_OUTPUT_OFFSET).read()
}

/// cg_buffer_align_offset — original: `FUN_082c2290` @ 0x082c2290
/// (32 bytes, 2 `bl` call sites: 0x082c13e4 inside the label-fixup
/// resolver `FUN_082c1360` (aligning the output before the fixup words
/// are emitted) and 0x082c232c inside the word emitter @ 0x082c231c —
/// both passing `align = 4` via `mov r1, #0x4`).
///
/// Rounds `output->current_offset` (+0x804) UP to a multiple of
/// `align`, stores the aligned value back and returns it. The body is
/// the classic power-of-two idiom, verbatim from the original's
/// `ldr r2,[r0,#0x804]; add r2,r2,r1; sub r2,r2,#0x1; sub r1,r1,#0x1;
/// bic r1,r2,r1; str r1,[r0,#0x804]; mov r0,r1; bx lr`:
/// `current_offset = (current_offset + align - 1) & !(align - 1)`.
/// The emitters run it before word stores so every 32-bit instruction
/// lands on a 4-byte boundary within the lazily allocated code pages.
///
/// EDGE SEMANTICS (kept for parity, not sanitized): `align` is ASSUMED
/// to be a power of two — a non-power-of-two `align` clears more low
/// bits than it rounds to. `align == 1` is the identity
/// (`(off + 0) & !0`). `align == 0` is pathological: `align - 1`
/// wraps to all-ones, so the `bic` yields 0 and the buffer rewinds to
/// its start — the original has no guard and neither does the port.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_buffer_align_offset(
    output: *mut CgCodegenBuffer,
    align: usize,
) -> usize {
    let offset = word(output as *mut u8, CG_CODEGEN_OUTPUT_OFFSET);
    let aligned = offset.read().wrapping_add(align).wrapping_sub(1) & !align.wrapping_sub(1);
    offset.write(aligned);
    aligned
}

/// cg_buffer_emit_word — original: `FUN_082c231c` @ 0x082c231c
/// (52 bytes, 42 `bl` + 15 tail `b` call sites — the JIT's canonical
/// 32-bit word emitter; sampled `bl` sites: 0x082b48a4, 0x082b4954,
/// 0x082beb60, 0x082becac, 0x082c111c).
///
/// Emits one word of generated ARM code into the emitted-code buffer:
///
/// 1. aligns the buffer's `current_offset` (+0x804) up to 4 through
///    [`cg_buffer_align_offset`] (`mov r1, #0x4; bl 0x082c2290` —
///    called directly), so every 32-bit instruction lands on a word
///    boundary;
/// 2. re-reads the now-aligned offset (`ldr r1, [r4, #0x804]` — the
///    original ignores the aligner's r0 return and reloads the field)
///    and resolves it to a write pointer through the code-page
///    accessor [`cg_buffer_page_pointer`] (`FUN_082c5b1c` — the
///    [`CG_BUFFER_PAGE_POINTER`] seam, still wired to the ported
///    accessor);
/// 3. stores `value` verbatim at that pointer (`str r5, [r0, #0x0]`);
/// 4. re-reads `current_offset` again and post-increments it by 4 —
///    from the ALIGNED value, not the pre-align one
///    (`ldr r0, [r4, #0x804]; add r0, r0, #0x4; str r0, [r4, #0x804]`).
///
/// The two field reloads are kept verbatim: through the accessor seam
/// a replacement could legally move the offset, and only the reloads
/// reproduce the original's behavior in that case.
///
/// EDGE SEMANTICS (parity, not sanitized): no NULL check on the
/// accessor's result — when the page allocation behind the default
/// accessor fails, the store goes through NULL exactly as the
/// original's would (the original crashes on the wild memzero one
/// callee earlier; see [`cg_buffer_page_pointer`]).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_buffer_emit_word(output: *mut CgCodegenBuffer, value: u32) {
    cg_buffer_align_offset(output, 4);
    let offset = word(output as *mut u8, CG_CODEGEN_OUTPUT_OFFSET).read();
    let write_ptr = hook(core::ptr::addr_of!(CG_BUFFER_PAGE_POINTER))(output, offset);
    (write_ptr as *mut u32).write(value);
    let cursor = word(output as *mut u8, CG_CODEGEN_OUTPUT_OFFSET);
    cursor.write(cursor.read().wrapping_add(4));
}

/// cg_buffer_copy_out — original: `FUN_082c2350` @ 0x082c2350
/// (96 bytes, 1 `bl` call site: 0x0824325c inside the compile-and-patch
/// driver `FUN_08243138` — `copy_out(buffer, 0, dst,
/// cg_buffer_current_offset(buffer))`, flattening the freshly emitted
/// code into its final linear destination).
///
/// Copies `len` bytes OUT of the emitted-code buffer's lazily allocated
/// code pages into the caller's linear buffer `dst`, chunking so no
/// single copy crosses a code-page boundary. The loop, verbatim from
/// the original's register allocation (r8 = buffer, r7 = dst cursor,
/// r5 = offset, r4 = remaining):
///
/// 1. `chunk = 0x1000 - (offset & 0xfff)` — bytes left in the current
///    page (`mov r0,r5,lsl #0x14; mov r0,r0,lsr #0x14;
///    rsb r6,r0,#0x1000`), clamped to `remaining` (`cmp r4,r6;
///    movls r6,r4` — unsigned lower-or-same);
/// 2. resolves the page BASE through the lazy page-slot accessor
///    (`mov r1,r5,lsr #0xc; bl 0x082b7edc` — the
///    [`CG_BUFFER_PAGE_SLOT`] seam, the same `bl` target
///    [`cg_buffer_page_pointer`] routes through);
/// 3. copies `chunk` bytes from the page base to the dst cursor through
///    the ROM thunk 0x08037db0 (-> 0x22000020, `__rt_memcpy` — the
///    ported [`__rt_memcpy`], called directly per house pattern);
/// 4. advances offset, dst and remaining by `chunk`
///    (`add r5,r5,r6; add r7,r7,r6; sub r4,r4,r6`) and loops while
///    `remaining != 0` (`cmp r4,#0x0; bne 0x082c2368`).
///
/// QUIRK (parity, not sanitized): the memcpy source is the page BASE —
/// the original never adds `offset & 0xfff` to it (there is no `add`
/// between the accessor's return and the `bl 0x08037db0`). For a
/// page-aligned `offset` the chunks line up exactly; for a misaligned
/// one the first chunk reads from the page's START while being sized
/// `0x1000 - (offset & 0xfff)`, so the copy comes out shifted early by
/// `offset & 0xfff` bytes. The sole call site passes offset 0
/// (`mov r1,#0x0` @ 0x08243258), so the quirk is latent — the port
/// reproduces it verbatim.
///
/// EDGE SEMANTICS: `len == 0` skips the loop entirely (the original
/// enters through `b 0x082c23a4`, the tail test). No NULL check on the
/// page-slot result — a failed lazy allocation behind the seam's wired
/// default copies through NULL exactly as the original would (same
/// failure semantics as [`cg_buffer_emit_word`]).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_buffer_copy_out(
    output: *mut CgCodegenBuffer,
    offset: usize,
    dst: *mut u8,
    len: usize,
) {
    let mut offset = offset;
    let mut dst = dst;
    let mut remaining = len;
    while remaining != 0 {
        // `mov r0,r5,lsl #0x14; mov r0,r0,lsr #0x14; rsb r6,r0,#0x1000;
        // cmp r4,r6; movls r6,r4`
        let mut chunk = CG_BUFFER_PAGE_BYTES - (offset & (CG_BUFFER_PAGE_BYTES - 1));
        if remaining <= chunk {
            chunk = remaining;
        }
        // `bl 0x082b7edc` — the page-slot seam; base only (see QUIRK).
        let page = hook(core::ptr::addr_of!(CG_BUFFER_PAGE_SLOT))(
            output,
            offset >> CG_BUFFER_PAGE_SHIFT,
        );
        // `bl 0x08037db0` — the ROM __rt_memcpy thunk, ported directly.
        __rt_memcpy(dst, page, chunk);
        offset = offset.wrapping_add(chunk);
        dst = dst.add(chunk);
        remaining -= chunk;
    }
}

/// cg_buffer_read_word — original: `FUN_082c23b0` @ 0x082c23b0
/// (16 bytes, 2 `bl` call sites: 0x082c1720 and 0x082c174c, both
/// inside the label-fixup resolver `FUN_082c16e0` — reading back the
/// previously emitted instruction word at a fixup position so the
/// resolver can splice the resolved branch offset into it while
/// preserving the opcode/condition bits).
///
/// The read-side mirror of [`cg_buffer_emit_word`], verbatim from the
/// original's `bl 0x082c5b1c; ldr r0, [r0, #0x0]`: resolves `offset`
/// to a pointer through the code-page accessor [`cg_buffer_page_pointer`]
/// (the [`CG_BUFFER_PAGE_POINTER`] seam, still wired to the ported
/// accessor — the documented seam scheme, same as the emitter) and
/// returns the 32-bit word stored there. The saved r4 in the
/// original's frame (`stmdb sp!, {r4, lr}` / `ldmia sp!, {r4, pc}`)
/// is never written — the pair only keeps the stack 8-byte aligned
/// across the `bl`.
///
/// Unlike the emitter the offset is NOT aligned first (there is no
/// `bl 0x082c2290`): the resolver's fixup positions are word-aligned
/// by construction — every emitter aligns before storing — so the
/// load hits the word directly.
///
/// EDGE SEMANTICS (parity, not sanitized): no NULL check on the
/// accessor's result — a failed page allocation behind the default
/// accessor loads through NULL exactly as the original's would (same
/// failure semantics as [`cg_buffer_emit_word`]).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_buffer_read_word(
    output: *mut CgCodegenBuffer,
    offset: usize,
) -> u32 {
    // `bl 0x082c5b1c` — the accessor seam; `ldr r0, [r0, #0x0]`.
    let read_ptr = hook(core::ptr::addr_of!(CG_BUFFER_PAGE_POINTER))(output, offset);
    (read_ptr as *const u32).read()
}

/// cg_buffer_write_word — original: `FUN_082c23c0` @ 0x082c23c0
/// (20 bytes, 1 `bl` call site: 0x082c1788, inside the label-fixup
/// resolver `FUN_082c16e0` — storing the patched instruction word
/// back into the emitted-code buffer after the resolver spliced the
/// resolved branch offset into the word it read with
/// [`cg_buffer_read_word`]).
///
/// The write-side mirror of [`cg_buffer_read_word`], verbatim from the
/// original's `mov r4, r2; bl 0x082c5b1c; str r4, [r0, #0x0]`: keeps
/// `value` across the accessor call (the saved r4), resolves `offset`
/// to a pointer through the code-page accessor [`cg_buffer_page_pointer`]
/// (the [`CG_BUFFER_PAGE_POINTER`] seam, still wired to the ported
/// accessor — the documented seam scheme, same as the emitter and the
/// reader) and stores the 32-bit word there.
///
/// Like the reader — and unlike the emitter — the offset is NOT
/// aligned first and the current offset at +0x804 is never touched:
/// the resolver's fixup positions are word-aligned by construction.
///
/// EDGE SEMANTICS (parity, not sanitized): no NULL check on the
/// accessor's result — a failed page allocation behind the default
/// accessor stores through NULL exactly as the original's would (same
/// failure semantics as [`cg_buffer_emit_word`]).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_buffer_write_word(
    output: *mut CgCodegenBuffer,
    offset: usize,
    value: u32,
) {
    // `bl 0x082c5b1c` — the accessor seam; `str r4, [r0, #0x0]`.
    let write_ptr = hook(core::ptr::addr_of!(CG_BUFFER_PAGE_POINTER))(output, offset);
    (write_ptr as *mut u32).write(value);
}

/// cg_codegen_output — original: `FUN_082c17ec` @ 0x082c17ec
/// (8 bytes, 1 `bl` call site: 0x0824320c).
///
/// A pure field getter — the entire body is `ldr r0, [r0, #0x10];
/// bx lr`: returns `codegen->output`, the emitted-code buffer owned by
/// the codegen. The identification is pinned by the object's lifetime:
/// the constructor `FUN_082c0d7c` allocates the 0x220-byte
/// `cg_codegen_t` and fills +0x10 with the buffer `FUN_082c22b0`
/// builds, and the single caller (`FUN_08243138`, the JIT's
/// compile-and-patch driver) invokes this getter back-to-back with the
/// label-fixup resolver `FUN_082c16e0` — which itself reads
/// `codegen + 0x10` as the buffer it patches words into — and with
/// [`cg_buffer_current_offset`] on the returned pointer, matching
/// `output` exactly.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_codegen_output(codegen: *mut CgCodegen) -> *mut CgCodegenBuffer {
    slot(codegen as *mut u8, CG_CODEGEN_OUTPUT).read() as *mut CgCodegenBuffer
}

/// cg_label_create — original: `FUN_082c0dec` @ 0x082c0dec (52 bytes,
/// 4 `bl` call sites: 0x082c12dc, 0x082c12e8, 0x082c136c, 0x082cc11c).
///
/// The label factory of the JIT's code generator. Allocates a 12-byte
/// `cg_label_t` from `codegen->heap` (+0x08), initializes its fixup list
/// head to NULL with an explicit store (`str r1, [r0, #4]` — NOT left to
/// the arena's zero-fill, unlike the sibling builders' `next` links),
/// stamps the bound offset with the all-ones "not yet bound" sentinel
/// (`mvn r1, #0` -> +0x08), and prepends the record to the codegen's
/// label list (`codegen->labels` at +0x0c): the old head becomes
/// `label->next`, then the head slot takes the new record.
///
/// Ghidra types the return void, but every caller consumes r0
/// immediately (`bl` followed by `str r0, [...]` at all four sites), so
/// the port returns the new label. The sentinel is written as the
/// all-ones word, which on target is exactly 0xffffffff.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_label_create(codegen: *mut CgCodegen) -> *mut CgLabel {
    let codegen = codegen as *mut u8;
    let label = cg_heap_alloc(
        slot(codegen, CG_CODEGEN_HEAP).read() as *mut CgHeap,
        record_size(CG_LABEL_BYTES),
    );

    // Same store sequence as the original: fixups = NULL, offset = ~0,
    // then the two list-linking stores.
    slot(label, CG_LABEL_FIXUPS).write(core::ptr::null_mut());
    word(label, CG_LABEL_OFFSET).write(CG_LABEL_UNBOUND);

    let codegen_labels = slot(codegen, CG_CODEGEN_LABELS);
    slot(label, CG_LABEL_NEXT).write(codegen_labels.read());
    codegen_labels.write(label);

    label as *mut CgLabel
}

/// cg_label_add_fixup — original: `FUN_082c17ac` @ 0x082c17ac (64 bytes).
///
/// Allocates a 12-byte pending-label-fixup record from `codegen->heap`,
/// obtains the current emitted-code position through
/// [`cg_buffer_current_offset`] (`codegen->output->current_offset`), and
/// prepends the record to `label->fixups`. The tag is intentionally
/// stored as one byte, exactly as the original's `strb`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_label_add_fixup(
    codegen: *mut CgCodegen,
    label: *mut CgLabel,
    tag: u32,
) {
    let codegen = codegen as *mut u8;
    let label = label as *mut u8;
    let fixup = cg_heap_alloc(
        slot(codegen, CG_CODEGEN_HEAP).read() as *mut CgHeap,
        record_size(CG_LABEL_FIXUP_BYTES),
    );

    // `bl FUN_082c23d4`: return output->current_offset (+0x804).
    let output = slot(codegen, CG_CODEGEN_OUTPUT).read() as *mut CgCodegenBuffer;
    word(fixup, CG_LABEL_FIXUP_OFFSET).write(cg_buffer_current_offset(output));

    let label_fixups = slot(label, CG_LABEL_FIXUPS);
    slot(fixup, CG_LABEL_FIXUP_NEXT).write(label_fixups.read());
    fixup.add(CG_LABEL_FIXUP_TAG * WORD).write(tag as u8);
    label_fixups.write(fixup);
}

/// cg_codegen_resolve_label_fixups — original: `FUN_082c16e0` @
/// 0x082c16e0 (200 bytes + a 4-byte literal pool entry at 0x082c17a8;
/// **1 `bl` call site**: 0x08243204, inside the compile-and-patch
/// driver `FUN_08243138` — its six clones tail-branch into the driver,
/// so every JIT compilation ends here). The sole caller of
/// [`cg_buffer_read_word`] and [`cg_buffer_write_word`].
///
/// The label-fixup resolver: after every label in `codegen->labels`
/// (+0x0c) has been bound to its emitted-code offset (label +0x08, by
/// the binder `FUN_082c1360`), this pass walks the whole label list and
/// patches each pending fixup's instruction word in place in the
/// emitted-code buffer (`codegen->output`, +0x10). For every fixup it
/// reads the word at `fixup->offset` (+0x08) back out of the paged
/// buffer, splices the now-known displacement into the word's immediate
/// field — keeping every other bit verbatim — and stores it back. The
/// patch encoding is selected by the fixup's one-byte tag (+0x04):
///
/// - tag 0 — 12-bit byte displacement (PC-relative literal loads
///   emitted by e.g. `FUN_082beb70`'s caller path): the word's low 12
///   bits are sign-extended from bit 11 (`tst r1, #0x800`, OR-ing the
///   0xfffff000 literal at 0x082c17a8), the byte delta
///   `label->offset - fixup->offset` is added, and the result is
///   masked back to 12 bits under the word's preserved top 20 bits
///   (`mov r0, r0, lsr #0xc` / `mov r0, r0, lsl #0xc`).
/// - tag 1 — 24-bit word displacement (the `B<cond>` branches whose
///   fixups are added at 0x082bcf1c/0x082cbc64): the word's low 24
///   bits are sign-extended from bit 23 (`tst r1, #0x800000`, OR-ing
///   0xff000000), the delta is taken as a LOGICAL shift right by 2
///   (`add r1, r1, r2, lsr #0x2` — branch immediates count words),
///   added, and masked back to 24 bits under the word's preserved top
///   byte (condition code and opcode).
///
/// Fixups with any other tag byte are skipped entirely — the original
/// branches straight to the list advance (`bne 0x082c178c`), without
/// even reading the emitted word.
///
/// Ghidra's decompile drops the tag-1 sign extension (it shows the
/// 24-bit field as unsigned); the `tst`/`orrne` pair at 0x082c1728-
/// 0x082c172c is authoritative and the port replicates it.
///
/// EDGE SEMANTICS (parity, not sanitized): an unbound label still
/// carrying the all-ones [`CG_LABEL_UNBOUND`] sentinel is patched
/// against exactly like a bound one — the original never checks. All
/// arithmetic wraps mod 2^32 before the field mask, as on target.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_codegen_resolve_label_fixups(codegen: *mut CgCodegen) {
    let codegen = codegen as *mut u8;
    let output = slot(codegen, CG_CODEGEN_OUTPUT).read() as *mut CgCodegenBuffer;

    let mut label = slot(codegen, CG_CODEGEN_LABELS).read() as *mut u8;
    while !label.is_null() {
        let label_offset = word(label, CG_LABEL_OFFSET).read();

        let mut fixup = slot(label, CG_LABEL_FIXUPS).read() as *mut u8;
        while !fixup.is_null() {
            let tag = fixup.add(CG_LABEL_FIXUP_TAG * WORD).read();
            let fixup_offset = word(fixup, CG_LABEL_FIXUP_OFFSET).read();

            match tag {
                // Tag 0: 12-bit byte displacement.
                0 => {
                    let emitted = cg_buffer_read_word(output, fixup_offset);
                    let imm12 = emitted & 0x0000_0fff;
                    let signed = if imm12 & 0x800 != 0 {
                        imm12 | 0xffff_f000 // the literal at 0x082c17a8
                    } else {
                        imm12
                    };
                    let delta = label_offset.wrapping_sub(fixup_offset) as u32;
                    let patched = signed.wrapping_add(delta) & 0x0000_0fff;
                    cg_buffer_write_word(output, fixup_offset, (emitted & 0xffff_f000) | patched);
                }
                // Tag 1: 24-bit word displacement (B<cond>).
                1 => {
                    let emitted = cg_buffer_read_word(output, fixup_offset);
                    let imm24 = emitted & 0x00ff_ffff;
                    let signed = if imm24 & 0x0080_0000 != 0 {
                        imm24 | 0xff00_0000
                    } else {
                        imm24
                    };
                    // `lsr #0x2` — a logical shift of the byte delta.
                    let delta = (label_offset.wrapping_sub(fixup_offset) as u32) >> 2;
                    let patched = signed.wrapping_add(delta) & 0x00ff_ffff;
                    cg_buffer_write_word(output, fixup_offset, (emitted & 0xff00_0000) | patched);
                }
                // `bne 0x082c178c`: unknown tags are not even read.
                _ => {}
            }

            fixup = slot(fixup, CG_LABEL_FIXUP_NEXT).read() as *mut u8;
        }

        label = slot(label, CG_LABEL_NEXT).read() as *mut u8;
    }
}

/// cg_proc_create — original: `FUN_082c2268` @ 0x082c2268 (40 bytes,
/// 6 `bl` call sites: 0x082439c4 inside `FUN_082439b0`, 0x082465d0
/// inside `FUN_082465bc`, 0x0824873c inside `FUN_08248728`, 0x082498e8
/// inside `FUN_082498d4`, 0x0824a488 inside `FUN_0824a478` and
/// 0x0824afa4 inside `FUN_0824af94` — the JIT's procedure-lowering
/// drivers, one record per compiled procedure).
///
/// The procedure factory of the JIT's code generator. Allocates a
/// 52-byte `cg_proc_t` from `module->heap` (+0x00) and PREPENDS it to
/// the module's procedure list (+0x04), in the original's exact store
/// order: the old head becomes `proc->next` (+0x00), the head slot
/// takes the new record, and the record back-points to the owning
/// module at +0x04. Everything else — the register list head/tail at
/// +0x10/+0x14 and the register counter at +0x20 — stays NULL by the
/// arena's zero-fill, exactly what [`cg_virtual_reg_create`]'s append
/// and numbering need.
///
/// Ghidra types the return void, but callers consume r0 immediately
/// (`FUN_082465bc` feeds it straight to [`cg_virtual_reg_create`] and
/// stores 3 at proc+0x24), so the port returns the new procedure —
/// the same precedent as [`cg_label_create`]. The 52-byte record's
/// identification as `cg_proc_t` is pinned by that call: only a proc
/// is a legal first argument to `cg_virtual_reg_create`, and the
/// record's +0x04 back-pointer matches the `proc->module` dereference
/// in `cg_virtual_reg_create` and [`cg_inst_create_base`].
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_proc_create(module: *mut CgModule) -> *mut CgProc {
    let module = module as *mut u8;
    let proc = cg_heap_alloc(module_heap(module), record_size(CG_PROC_BYTES));

    // Same store sequence as the original: proc->next = old head,
    // module->procs = proc, proc->module = module.
    let module_procs = slot(module, CG_MODULE_PROCS);
    slot(proc, CG_PROC_NEXT).write(module_procs.read());
    module_procs.write(proc);
    slot(proc, CG_PROC_MODULE).write(module);

    proc as *mut CgProc
}

/// cg_virtual_reg_create — original: `FUN_082c23dc` @ 0x082c23dc
/// (80 bytes, 835 `bl` call sites).
///
/// Carves a 40-byte register record out of `proc->module->heap`, stamps
/// it with the procedure's next register number (post-incrementing the
/// counter) and with `reg_type` as a byte, then appends it to the
/// procedure's register list. The record's `next` stays NULL by virtue of
/// the arena's zero-fill.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_virtual_reg_create(
    proc: *mut CgProc,
    reg_type: u32,
) -> *mut CgVirtualReg {
    let proc = proc as *mut u8;
    let heap = module_heap(slot(proc, CG_PROC_MODULE).read());
    let reg = cg_heap_alloc(heap, record_size(CG_VREG_BYTES));

    let counter = word(proc, CG_PROC_NUM_REGISTERS);
    word(reg, CG_VREG_NO).write(counter.read());
    counter.write(counter.read().wrapping_add(1));
    reg.add(CG_VREG_TYPE * WORD).write(reg_type as u8);

    let head = slot(proc, CG_PROC_REGISTERS);
    let tail = slot(proc, CG_PROC_LAST_REGISTER);
    if head.read().is_null() {
        head.write(reg);
    } else {
        slot(tail.read(), CG_VREG_NEXT).write(reg);
    }
    tail.write(reg);

    reg as *mut CgVirtualReg
}

/// cg_inst_create_base — original: `FUN_082d6c24` @ 0x082d6c24
/// (72 bytes, 11 `bl` + 1 tail `b` call sites).
///
/// Carves a `size`-byte instruction record out of
/// `block->proc->module->heap`, points it back at `block`, appends it to
/// the block's instruction list and writes the `kind` and `opcode`
/// discriminant bytes. `size` is in host words already scaled by
/// [`record_size`].
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_inst_create_base(
    block: *mut CgBlock,
    size: usize,
    kind: u32,
    opcode: u32,
) -> *mut CgInst {
    let block = block as *mut u8;
    let proc = slot(block, CG_BLOCK_PROC).read();
    let heap = module_heap(slot(proc, CG_PROC_MODULE).read());
    let inst = cg_heap_alloc(heap, size);

    slot(inst, CG_INST_BLOCK).write(block);

    let head = slot(block, CG_BLOCK_INSTS);
    let tail = slot(block, CG_BLOCK_LAST_INST);
    if head.read().is_null() {
        head.write(inst);
    } else {
        slot(tail.read(), CG_INST_NEXT).write(inst);
    }
    tail.write(inst);

    let kind_byte = inst.add(CG_INST_KIND * WORD);
    kind_byte.write(kind as u8);
    kind_byte.add(CG_INST_OPCODE_IN_KIND_WORD).write(opcode as u8);

    inst as *mut CgInst
}

/// cg_create_inst_binary — original: `FUN_082c17f4` @ 0x082c17f4
/// (48 bytes, 419 `bl` call sites).
///
/// Appends a kind-2 (binary) instruction: a 36-byte record holding the
/// destination register and two sources. The destination-flags slot
/// (`+0x10`) is left NULL — the sibling factory @ 0x082c1824 is the
/// variant that fills it.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_create_inst_binary(
    block: *mut CgBlock,
    opcode: u32,
    dest: *mut CgVirtualReg,
    source0: *mut CgVirtualReg,
    source1: *mut CgVirtualReg,
) -> *mut CgInst {
    let inst = cg_inst_create_base(
        block,
        record_size(CG_INST_BINARY_BYTES),
        CG_INST_KIND_BINARY,
        opcode,
    ) as *mut u8;
    slot(inst, CG_INST_BINARY_DEST).write(dest as *mut u8);
    slot(inst, CG_INST_BINARY_SOURCE0).write(source0 as *mut u8);
    slot(inst, CG_INST_BINARY_SOURCE1).write(source1 as *mut u8);
    inst as *mut CgInst
}

/// cg_create_inst_load_immed — original: `FUN_082c18ec` @ 0x082c18ec
/// (40 bytes, 201 `bl` call sites).
///
/// Appends a kind-6 (load-immediate) instruction: a 20-byte record
/// holding the destination register and the constant to materialize.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_create_inst_load_immed(
    block: *mut CgBlock,
    opcode: u32,
    dest: *mut CgVirtualReg,
    value: usize,
) -> *mut CgInst {
    let inst = cg_inst_create_base(
        block,
        record_size(CG_INST_LOAD_IMMED_BYTES),
        CG_INST_KIND_LOAD_IMMED,
        opcode,
    ) as *mut u8;
    slot(inst, CG_INST_LOAD_IMMED_DEST).write(dest as *mut u8);
    word(inst, CG_INST_LOAD_IMMED_VALUE).write(value);
    inst as *mut CgInst
}

/// cg_create_inst_unary — original: `FUN_082c1994` @ 0x082c1994
/// (40 bytes, 36 `bl` call sites).
///
/// Appends a kind-1 (unary) instruction: a 32-byte record holding the
/// destination register and one source. `+0x10` stays NULL by the
/// arena's zero-fill.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_create_inst_unary(
    block: *mut CgBlock,
    opcode: u32,
    dest: *mut CgVirtualReg,
    source: *mut CgVirtualReg,
) -> *mut CgInst {
    let inst = cg_inst_create_base(
        block,
        record_size(CG_INST_UNARY_BYTES),
        CG_INST_KIND_UNARY,
        opcode,
    ) as *mut u8;
    slot(inst, CG_INST_UNARY_DEST).write(dest as *mut u8);
    slot(inst, CG_INST_UNARY_SOURCE).write(source as *mut u8);
    inst as *mut CgInst
}

/// cg_create_inst_binary_s — original: `FUN_082c1824` @ 0x082c1824
/// (44 bytes, 7 `bl` call sites).
///
/// The flags-writing twin of [`cg_create_inst_binary`]: same kind-2,
/// 36-byte record, but the destination-flags slot (`+0x10`) is filled
/// too — one `stmia` writes all four derived fields. `dest_flags` and
/// `source0` arrive on the stack in the original (`ldrd r6, r7,
/// [sp, #0x18]`); the C ABI makes that invisible here.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_create_inst_binary_s(
    block: *mut CgBlock,
    opcode: u32,
    dest: *mut CgVirtualReg,
    dest_flags: *mut CgVirtualReg,
    source0: *mut CgVirtualReg,
    source1: *mut CgVirtualReg,
) -> *mut CgInst {
    let inst = cg_inst_create_base(
        block,
        record_size(CG_INST_BINARY_BYTES),
        CG_INST_KIND_BINARY_S,
        opcode,
    ) as *mut u8;
    slot(inst, CG_INST_BINARY_DEST).write(dest as *mut u8);
    slot(inst, CG_INST_BINARY_DEST_FLAGS).write(dest_flags as *mut u8);
    slot(inst, CG_INST_BINARY_SOURCE0).write(source0 as *mut u8);
    slot(inst, CG_INST_BINARY_SOURCE1).write(source1 as *mut u8);
    inst as *mut CgInst
}

/// cg_create_inst_compare — original: `FUN_082c1898` @ 0x082c1898
/// (44 bytes, 35 `bl` call sites).
///
/// Appends a kind-3 (compare) instruction: a 32-byte record holding the
/// destination register and two sources at `+0xc`, `+0x10`, `+0x14` —
/// one word earlier than binary's sources, because compare has no
/// dest_flags slot. `source1` arrives on the stack in the original
/// (`ldr r6, [sp, #0x10]`).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_create_inst_compare(
    block: *mut CgBlock,
    opcode: u32,
    dest: *mut CgVirtualReg,
    source0: *mut CgVirtualReg,
    source1: *mut CgVirtualReg,
) -> *mut CgInst {
    let inst = cg_inst_create_base(
        block,
        record_size(CG_INST_COMPARE_BYTES),
        CG_INST_KIND_COMPARE,
        opcode,
    ) as *mut u8;
    slot(inst, CG_INST_COMPARE_DEST).write(dest as *mut u8);
    slot(inst, CG_INST_COMPARE_SOURCE0).write(source0 as *mut u8);
    slot(inst, CG_INST_COMPARE_SOURCE1).write(source1 as *mut u8);
    inst as *mut CgInst
}

/// cg_create_inst_load — original: `FUN_082c18c4` @ 0x082c18c4
/// (40 bytes, 34 `bl` call sites).
///
/// Appends a kind-4 (load) instruction: a 24-byte record holding the
/// destination register and the address register.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_create_inst_load(
    block: *mut CgBlock,
    opcode: u32,
    dest: *mut CgVirtualReg,
    address: *mut CgVirtualReg,
) -> *mut CgInst {
    let inst = cg_inst_create_base(
        block,
        record_size(CG_INST_LOAD_BYTES),
        CG_INST_KIND_LOAD,
        opcode,
    ) as *mut u8;
    slot(inst, CG_INST_LOAD_DEST).write(dest as *mut u8);
    slot(inst, CG_INST_LOAD_ADDRESS).write(address as *mut u8);
    inst as *mut CgInst
}

/// cg_create_inst_store — original: `FUN_082c196c` @ 0x082c196c
/// (40 bytes, 5 `bl` + 2 tail `b` call sites).
///
/// Appends a kind-5 (store) instruction: a 24-byte record holding the
/// value register and the address register. The caller @ 0x0823cc40
/// passes a freshly computed value in the value slot and the address
/// computation's register in the address slot, which pins the order.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_create_inst_store(
    block: *mut CgBlock,
    opcode: u32,
    value: *mut CgVirtualReg,
    address: *mut CgVirtualReg,
) -> *mut CgInst {
    let inst = cg_inst_create_base(
        block,
        record_size(CG_INST_STORE_BYTES),
        CG_INST_KIND_STORE,
        opcode,
    ) as *mut u8;
    slot(inst, CG_INST_STORE_VALUE).write(value as *mut u8);
    slot(inst, CG_INST_STORE_ADDRESS).write(address as *mut u8);
    inst as *mut CgInst
}

/// cg_create_inst_branch_label — original: `FUN_082c1878` @ 0x082c1878
/// (32 bytes, 16 `bl` call sites).
///
/// Appends a kind-7 (unconditional branch) instruction: a 20-byte
/// record holding only the target block.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_create_inst_branch_label(
    block: *mut CgBlock,
    opcode: u32,
    target: *mut CgBlock,
) -> *mut CgInst {
    let inst = cg_inst_create_base(
        block,
        record_size(CG_INST_BRANCH_LABEL_BYTES),
        CG_INST_KIND_BRANCH_LABEL,
        opcode,
    ) as *mut u8;
    slot(inst, CG_INST_BRANCH_LABEL_TARGET).write(target as *mut u8);
    inst as *mut CgInst
}

/// cg_create_inst_branch_cond — original: `FUN_082c1850` @ 0x082c1850
/// (40 bytes, 41 `bl` call sites).
///
/// Appends a kind-8 (conditional branch) instruction: a 20-byte record
/// holding the target block and the condition register. NOTE the swap,
/// kept from the original: the third argument goes to `+0x10` (the
/// condition) and the fourth to `+0xc` (the target) — the opposite
/// order from every other factory in the family.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_create_inst_branch_cond(
    block: *mut CgBlock,
    opcode: u32,
    condition: *mut CgVirtualReg,
    target: *mut CgBlock,
) -> *mut CgInst {
    let inst = cg_inst_create_base(
        block,
        record_size(CG_INST_BRANCH_COND_BYTES),
        CG_INST_KIND_BRANCH_COND,
        opcode,
    ) as *mut u8;
    slot(inst, CG_INST_BRANCH_COND_CONDITION).write(condition as *mut u8);
    slot(inst, CG_INST_BRANCH_COND_TARGET).write(target as *mut u8);
    inst as *mut CgInst
}

/// cg_create_inst_phi — original: `FUN_082c1914` @ 0x082c1914
/// (40 bytes, 75 `bl` call sites).
///
/// Appends a kind-9 (phi) instruction: a 20-byte record holding the
/// destination register and the head of a register list built by
/// [`cg_virtual_reg_list_create`].
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_create_inst_phi(
    block: *mut CgBlock,
    opcode: u32,
    dest: *mut CgVirtualReg,
    regs: *mut CgVirtualRegList,
) -> *mut CgInst {
    let inst = cg_inst_create_base(
        block,
        record_size(CG_INST_PHI_BYTES),
        CG_INST_KIND_PHI,
        opcode,
    ) as *mut u8;
    slot(inst, CG_INST_PHI_DEST).write(dest as *mut u8);
    slot(inst, CG_INST_PHI_REGS).write(regs as *mut u8);
    inst as *mut CgInst
}

/// cg_create_inst_ret — original: `FUN_082c193c` @ 0x082c193c
/// (16 bytes, 3 `bl` + 1 tail `b` call sites).
///
/// Appends a kind-11 (return) instruction: a 16-byte record with no
/// derived fields at all — the original is a pure tail branch into
/// `cg_inst_create_base`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_create_inst_ret(block: *mut CgBlock, opcode: u32) -> *mut CgInst {
    cg_inst_create_base(block, record_size(CG_INST_RET_BYTES), CG_INST_KIND_RET, opcode)
}

/// cg_create_inst_ret_value — original: `FUN_082c194c` @ 0x082c194c
/// (32 bytes, 2 `bl` call sites).
///
/// The value-returning twin of [`cg_create_inst_ret`]: same kind-11,
/// 16-byte record, plus the returned value register at `+0xc`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_create_inst_ret_value(
    block: *mut CgBlock,
    opcode: u32,
    value: *mut CgVirtualReg,
) -> *mut CgInst {
    let inst = cg_inst_create_base(
        block,
        record_size(CG_INST_RET_BYTES),
        CG_INST_KIND_RET,
        opcode,
    ) as *mut u8;
    slot(inst, CG_INST_RET_VALUE_VALUE).write(value as *mut u8);
    inst as *mut CgInst
}

/// cg_virtual_reg_list_create — original: `FUN_082c19bc` @ 0x082c19bc
/// (76 bytes, 75 `bl` call sites).
///
/// Chains a NULL-terminated run of register pointers into a singly
/// linked list of 8-byte `{next, reg}` cells, each carved straight from
/// the `heap` arena the CALLER passes (unlike the register/instruction
/// builders, which dig the arena out of a module). Every iteration
/// allocates one cell, links it through the previous cell's `next` (or
/// into the head for the first), stores the register at `+0x4`, and
/// leaves the new cell's `next` NULL via the arena's zero-fill — the
/// original relies on exactly that to terminate the list
/// (`str r0, [r4]` / `str r6, [r0, #4]` / `ldr r4, [r4]`, with no
/// store to `+0x0` of the tail cell). Returns the head, NULL when the
/// first entry is already NULL.
///
/// DEVIATION: the original is variadic — `stmdb sp!, {r0-r3}` spills
/// the register arguments and the loop walks upward from `&arg1` until
/// a NULL. Rust cannot express that ABI on this target, so the port
/// takes `regs`, a pointer to a NULL-terminated array of register
/// pointers. The termination rule, cell layout and allocation sequence
/// are unchanged; a hook wanting the exact stock ABI needs an asm
/// thunk that materializes the argument frame as such an array.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_virtual_reg_list_create(
    heap: *mut CgHeap,
    regs: *const *mut CgVirtualReg,
) -> *mut CgVirtualRegList {
    let mut head: *mut u8 = core::ptr::null_mut();
    // The slot the next cell is linked through: starts at `head`, then
    // tracks `&previous_cell->next`, exactly like the original's r4.
    let mut link: *mut *mut u8 = core::ptr::addr_of_mut!(head);
    let mut arg = regs;
    loop {
        let reg = arg.read();
        if reg.is_null() {
            break;
        }
        arg = arg.add(1);
        let cell = cg_heap_alloc(heap, record_size(CG_VREG_LIST_BYTES));
        link.write(cell);
        slot(cell, CG_VREG_LIST_REG).write(reg as *mut u8);
        link = slot(cell, CG_VREG_LIST_NEXT);
    }
    head as *mut CgVirtualRegList
}

/// cg_reg_append_bounded — original: `FUN_082b2f1c` @ 0x082b2f1c
/// (16 bytes, 9 `bl` + 2 tail `b` call sites).
///
/// The bounded-store helper shared by the defined-register collectors
/// ([`cg_inst_visit_by_kind`] and its sibling @ 0x082c1bfc): stores
/// `reg` at `cursor` and advances the cursor by one slot, unless the
/// cursor has already reached `end` — literally `cmp r1, r2; strne r0,
/// [r1], #4; mov r0, r1; bx lr`. The value is stored WITHOUT a NULL
/// check: whatever the caller passes lands in the array as-is. Returns
/// the (possibly advanced) cursor.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_reg_append_bounded(
    reg: *mut CgVirtualReg,
    cursor: *mut *mut CgVirtualReg,
    end: *mut *mut CgVirtualReg,
) -> *mut *mut CgVirtualReg {
    if cursor != end {
        cursor.write(reg);
        cursor.add(1)
    } else {
        cursor
    }
}

/// cg_inst_visit_by_kind — original: `FUN_082c1adc` @ 0x082c1adc
/// (288 bytes, 4 `bl` call sites).
///
/// Collects the registers an instruction DEFINES into the bounded output
/// array `cursor..end` and returns the advanced cursor. Dispatches on
/// the kind byte (`ldrb r0, [r0, #8]`) through two branch tables —
/// kinds 0-20 via `cmp r0, #20; addls pc, pc, r0, lsl #2`, with the
/// fall-through re-classified by `sub r0, r0, #4; cmp r0, #18` (which
/// also reaches kinds 21 and 22):
///
/// - kinds 1 (unary), 2 (binary) and 12-17: append the register at
///   `+0xc`, then the one at `+0x10` when it is not NULL — that slot is
///   the dest_flags of the binary_s layout and stays NULL for the other
///   factories, so unary/binary contribute one register and binary_s
///   two;
/// - kinds 3 (compare), 4 (load), 6 (load-immediate), 9 (phi) and
///   18-22: append only the register at `+0xc`;
/// - kind 10: append the register at `+0x14`, only when it is not NULL;
/// - kinds 0, 5 (store), 7 (branch-label), 8 (branch-cond), 11 (ret)
///   and anything past 22 define no register: the cursor is returned
///   untouched.
///
/// Every append goes through the bounded-store helper @ 0x082b2f1c
/// (16 bytes: `cmp r1, r2; strne r0, [r1], #4; mov r0, r1; bx lr`) —
/// store at the cursor and advance it, unless it already equals `end`.
/// The `+0xc` register is stored WITHOUT a NULL check: a NULL there
/// lands in the array like any other value; only `+0x10` and kind 10's
/// `+0x14` are guarded.
///
/// DEVIATION: the helper @ 0x082b2f1c is ported as its own export
/// ([`cg_reg_append_bounded`]), but this visitor keeps it inlined
/// ([`append_defined_reg`]); on target the original makes one `bl` per
/// append plus a tail `b` for the last one. The stores, cursor
/// arithmetic and NULL handling are identical.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_inst_visit_by_kind(
    inst: *mut CgInst,
    cursor: *mut *mut CgVirtualReg,
    end: *mut *mut CgVirtualReg,
) -> *mut *mut CgVirtualReg {
    let inst = inst as *mut u8;
    let kind = inst.add(CG_INST_KIND * WORD).read() as u32;
    match kind {
        CG_INST_KIND_UNARY | CG_INST_KIND_BINARY | 12..=17 => {
            let first = slot(inst, CG_INST_DEF0).read() as *mut CgVirtualReg;
            let cursor = append_defined_reg(first, cursor, end);
            let second = slot(inst, CG_INST_DEF1).read() as *mut CgVirtualReg;
            if second.is_null() {
                cursor
            } else {
                append_defined_reg(second, cursor, end)
            }
        }
        CG_INST_KIND_COMPARE
        | CG_INST_KIND_LOAD
        | CG_INST_KIND_LOAD_IMMED
        | CG_INST_KIND_PHI
        | 18..=22 => {
            let reg = slot(inst, CG_INST_DEF0).read() as *mut CgVirtualReg;
            append_defined_reg(reg, cursor, end)
        }
        10 => {
            let reg = slot(inst, CG_INST_KIND10_DEF).read() as *mut CgVirtualReg;
            if reg.is_null() {
                cursor
            } else {
                append_defined_reg(reg, cursor, end)
            }
        }
        _ => cursor,
    }
}

/// cg_inst_collect_used_regs — original: `FUN_082c1bfc` @ 0x082c1bfc
/// (388 bytes, 8 `bl` + 2 tail `b` call sites).
///
/// Collects the registers an instruction USES into the bounded output array
/// `cursor..end` and returns the advanced cursor. It dispatches directly on
/// the kind byte at `inst + 0x8` through a 25-entry jump table (kinds 0-24).
/// The input layouts and append order recovered from that table are:
///
/// - kinds 1, 14 and 15 append `+0x14`;
/// - kinds 2, 13 and 17 append `+0x14`, then `+0x18`;
/// - kinds 3, 20 and 22 append `+0x10`, then `+0x14`;
/// - kinds 4, 8, 18 and 21 append `+0x10`;
/// - kinds 5, 19 and 23 append `+0xc`, then `+0x10`;
/// - kinds 9 and 10 walk the `{next, reg}` list rooted at `+0x10`, appending
///   each `reg` in list order;
/// - kind 11 appends `+0xc` only when non-NULL;
/// - kind 16 appends `+0x14`, `+0x18`, then `+0x1c`; and kind 24 appends
///   `+0xc`, `+0x10`, then `+0x14`.
///
/// Kinds 0, 6, 7 and 12, plus values above 24, use no registers. Every
/// selected value is passed to [`cg_reg_append_bounded`] without a NULL
/// check, except kind 11's optional return-value slot. Thus a selected NULL
/// is still a bounded store and advances the cursor when room remains.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_inst_collect_used_regs(
    inst: *mut CgInst,
    cursor: *mut *mut CgVirtualReg,
    end: *mut *mut CgVirtualReg,
) -> *mut *mut CgVirtualReg {
    let inst = inst as *mut u8;
    let kind = inst.add(CG_INST_KIND * WORD).read() as u32;
    match kind {
        1 | 14 | 15 => {
            cg_reg_append_bounded(slot(inst, CG_INST_UNARY_SOURCE).read() as *mut CgVirtualReg, cursor, end)
        }
        CG_INST_KIND_BINARY | 13 | 17 => {
            let cursor = cg_reg_append_bounded(
                slot(inst, CG_INST_BINARY_SOURCE0).read() as *mut CgVirtualReg,
                cursor,
                end,
            );
            cg_reg_append_bounded(
                slot(inst, CG_INST_BINARY_SOURCE1).read() as *mut CgVirtualReg,
                cursor,
                end,
            )
        }
        CG_INST_KIND_COMPARE | 20 | 22 => {
            let cursor = cg_reg_append_bounded(
                slot(inst, CG_INST_COMPARE_SOURCE0).read() as *mut CgVirtualReg,
                cursor,
                end,
            );
            cg_reg_append_bounded(
                slot(inst, CG_INST_COMPARE_SOURCE1).read() as *mut CgVirtualReg,
                cursor,
                end,
            )
        }
        CG_INST_KIND_LOAD | CG_INST_KIND_BRANCH_COND | 18 | 21 => {
            cg_reg_append_bounded(slot(inst, CG_INST_LOAD_ADDRESS).read() as *mut CgVirtualReg, cursor, end)
        }
        CG_INST_KIND_STORE | 19 | 23 => {
            let cursor = cg_reg_append_bounded(
                slot(inst, CG_INST_STORE_VALUE).read() as *mut CgVirtualReg,
                cursor,
                end,
            );
            cg_reg_append_bounded(
                slot(inst, CG_INST_STORE_ADDRESS).read() as *mut CgVirtualReg,
                cursor,
                end,
            )
        }
        CG_INST_KIND_PHI | 10 => {
            let mut node = slot(inst, CG_INST_PHI_REGS).read();
            let mut cursor = cursor;
            while !node.is_null() {
                cursor = cg_reg_append_bounded(
                    slot(node, CG_VREG_LIST_REG).read() as *mut CgVirtualReg,
                    cursor,
                    end,
                );
                node = slot(node, CG_VREG_LIST_NEXT).read();
            }
            cursor
        }
        CG_INST_KIND_RET => {
            let reg = slot(inst, CG_INST_RET_VALUE_VALUE).read() as *mut CgVirtualReg;
            if reg.is_null() {
                cursor
            } else {
                cg_reg_append_bounded(reg, cursor, end)
            }
        }
        16 => {
            let cursor = cg_reg_append_bounded(
                slot(inst, CG_INST_UNARY_SOURCE).read() as *mut CgVirtualReg,
                cursor,
                end,
            );
            let cursor = cg_reg_append_bounded(
                slot(inst, CG_INST_BINARY_SOURCE1).read() as *mut CgVirtualReg,
                cursor,
                end,
            );
            cg_reg_append_bounded(
                slot(inst, CG_INST_KIND16_SOURCE2).read() as *mut CgVirtualReg,
                cursor,
                end,
            )
        }
        24 => {
            let cursor = cg_reg_append_bounded(
                slot(inst, CG_INST_DEF0).read() as *mut CgVirtualReg,
                cursor,
                end,
            );
            let cursor = cg_reg_append_bounded(
                slot(inst, CG_INST_DEF1).read() as *mut CgVirtualReg,
                cursor,
                end,
            );
            cg_reg_append_bounded(
                slot(inst, CG_INST_KIND10_DEF).read() as *mut CgVirtualReg,
                cursor,
                end,
            )
        }
        _ => cursor,
    }
}

/// The bounded-store helper @ 0x082b2f1c (16 bytes), inlined: stores
/// `reg` at `cursor` and advances it, unless `cursor` has already
/// reached `end`. Returns the (possibly advanced) cursor.
#[inline(always)]
unsafe fn append_defined_reg(
    reg: *mut CgVirtualReg,
    cursor: *mut *mut CgVirtualReg,
    end: *mut *mut CgVirtualReg,
) -> *mut *mut CgVirtualReg {
    if cursor != end {
        cursor.write(reg);
        cursor.add(1)
    } else {
        cursor
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::super::heap::{cg_heap_create, cg_heap_destroy, CgHeap, CgHeapOps, CG_HEAP_OPS,
                             DEFAULT_CG_HEAP_OPS};
    use super::*;
    use std::alloc::{alloc as host_alloc_raw, dealloc as host_dealloc_raw, Layout};
    use std::sync::{Mutex, MutexGuard};

    static LOCK: Mutex<()> = Mutex::new(());

    /// Header the test allocator prepends so `free` can rebuild the layout.
    const HDR: usize = 16;

    /// Poisons every allocation, so the zero-fill the builders depend on
    /// (record `next` links, unwritten fields) is actually observable.
    unsafe extern "C" fn poisoning_alloc(size: usize) -> *mut u8 {
        let raw = host_alloc_raw(Layout::from_size_align(size + HDR, 16).unwrap());
        assert!(!raw.is_null());
        (raw as *mut usize).write(size);
        core::ptr::write_bytes(raw.add(HDR), 0x5c, size);
        raw.add(HDR)
    }

    unsafe extern "C" fn poisoning_free(ptr: *mut u8) {
        let raw = ptr.sub(HDR);
        let size = (raw as *mut usize).read();
        host_dealloc_raw(raw, Layout::from_size_align(size + HDR, 16).unwrap());
    }

    /// A module, a procedure and a block over one real arena.
    struct Fixture {
        heap: *mut CgHeap,
        module: [usize; 2],
        proc: [usize; 9],
        block: [usize; 5],
        codegen: [usize; 5],
        output: [usize; CG_CODEGEN_OUTPUT_OFFSET + 1],
    }

    impl Fixture {
        fn new(block_size: usize) -> std::boxed::Box<Fixture> {
            let heap = unsafe { cg_heap_create(block_size) };
            let mut f = std::boxed::Box::new(Fixture {
                heap,
                module: [0; 2],
                proc: [0; 9],
                block: [0; 5],
                codegen: [0; 5],
                output: [0; CG_CODEGEN_OUTPUT_OFFSET + 1],
            });
            f.module[CG_MODULE_HEAP] = heap as usize;
            f.proc[CG_PROC_MODULE] = f.module.as_ptr() as usize;
            f.block[CG_BLOCK_PROC] = f.proc.as_ptr() as usize;
            f.codegen[CG_CODEGEN_HEAP] = heap as usize;
            f.codegen[CG_CODEGEN_OUTPUT] = f.output.as_mut_ptr() as usize;
            f
        }

        fn proc_ptr(&mut self) -> *mut CgProc {
            self.proc.as_mut_ptr() as *mut CgProc
        }

        fn module_ptr(&mut self) -> *mut CgModule {
            self.module.as_mut_ptr() as *mut CgModule
        }

        fn block_ptr(&mut self) -> *mut CgBlock {
            self.block.as_mut_ptr() as *mut CgBlock
        }

        fn codegen_ptr(&mut self) -> *mut CgCodegen {
            self.codegen.as_mut_ptr() as *mut CgCodegen
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            unsafe { cg_heap_destroy(self.heap) };
        }
    }

    fn setup() -> MutexGuard<'static, ()> {
        let guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            core::ptr::addr_of_mut!(CG_HEAP_OPS).write(CgHeapOps {

                alloc: poisoning_alloc,
                free: poisoning_free,
                zero: DEFAULT_CG_HEAP_OPS.zero,
            });
        }
        guard
    }

    fn teardown() {
        unsafe { core::ptr::addr_of_mut!(CG_HEAP_OPS).write(DEFAULT_CG_HEAP_OPS) };
    }

    unsafe fn reg_no(reg: *mut CgVirtualReg) -> usize {
        word(reg as *mut u8, CG_VREG_NO).read()
    }

    unsafe fn reg_type(reg: *mut CgVirtualReg) -> u8 {
        (reg as *mut u8).add(CG_VREG_TYPE * WORD).read()
    }

    unsafe fn reg_next(reg: *mut CgVirtualReg) -> *mut CgVirtualReg {
        slot(reg as *mut u8, CG_VREG_NEXT).read() as *mut CgVirtualReg
    }

    unsafe fn inst_next(inst: *mut CgInst) -> *mut CgInst {
        slot(inst as *mut u8, CG_INST_NEXT).read() as *mut CgInst
    }

    unsafe fn inst_kind(inst: *mut CgInst) -> u8 {
        (inst as *mut u8).add(CG_INST_KIND * WORD).read()
    }

    unsafe fn inst_opcode(inst: *mut CgInst) -> u8 {
        (inst as *mut u8).add(CG_INST_KIND * WORD + 1).read()
    }

    /// Arena stride of a record: `cg_heap_alloc` rounds every request up
    /// to 8 bytes.
    fn stride(target_bytes: usize) -> usize {
        (record_size(target_bytes) + 7) & !7
    }

    #[test]
    fn buffer_current_offset_returns_the_word_at_0x804() {
        const POISON: usize = 0xAAAA_AAAA_AAAA_AAAA;
        let mut output = [POISON; CG_CODEGEN_OUTPUT_OFFSET + 2];

        unsafe {
            let buffer = output.as_mut_ptr() as *mut CgCodegenBuffer;

            output[CG_CODEGEN_OUTPUT_OFFSET] = 0;
            assert_eq!(
                cg_buffer_current_offset(buffer),
                0,
                "a NULL offset comes back as-is"
            );

            let sentinel = output.as_mut_ptr() as usize;
            output[CG_CODEGEN_OUTPUT_OFFSET] = sentinel;
            assert_eq!(
                cg_buffer_current_offset(buffer),
                sentinel,
                "a pointer-sized word at +0x804 comes back exactly"
            );

            assert_eq!(
                output[CG_CODEGEN_OUTPUT_OFFSET - 1],
                POISON,
                "the getter reads no neighboring word"
            );
            assert_eq!(
                output[CG_CODEGEN_OUTPUT_OFFSET + 1],
                POISON,
                "the getter reads no neighboring word"
            );
        }
    }

    #[test]
    fn buffer_align_offset_rounds_up_stores_back_and_leaves_neighbors() {
        const POISON: usize = 0xAAAA_AAAA_AAAA_AAAA;
        let mut output = [POISON; CG_CODEGEN_OUTPUT_OFFSET + 2];

        unsafe {
            let buffer = output.as_mut_ptr() as *mut CgCodegenBuffer;

            output[CG_CODEGEN_OUTPUT_OFFSET] = 8;
            assert_eq!(
                cg_buffer_align_offset(buffer, 4),
                8,
                "an already aligned offset is the identity"
            );
            assert_eq!(
                cg_buffer_current_offset(buffer),
                8,
                "the identity is stored back"
            );

            output[CG_CODEGEN_OUTPUT_OFFSET] = 9;
            assert_eq!(
                cg_buffer_align_offset(buffer, 4),
                12,
                "one past a boundary rounds up to the next"
            );
            assert_eq!(
                cg_buffer_current_offset(buffer),
                12,
                "the rounded value is stored back"
            );

            assert_eq!(
                output[CG_CODEGEN_OUTPUT_OFFSET - 1],
                POISON,
                "the aligner writes no neighboring word"
            );
            assert_eq!(
                output[CG_CODEGEN_OUTPUT_OFFSET + 1],
                POISON,
                "the aligner writes no neighboring word"
            );
        }
    }

    #[test]
    fn buffer_align_offset_sweeps_power_of_two_alignments() {
        let mut output = [0usize; CG_CODEGEN_OUTPUT_OFFSET + 1];

        unsafe {
            let buffer = output.as_mut_ptr() as *mut CgCodegenBuffer;
            for align in [1usize, 2, 4, 8, 0x10] {
                for off in 0..64usize {
                    output[CG_CODEGEN_OUTPUT_OFFSET] = off;
                    let expected = (off + align - 1) & !(align - 1);
                    assert_eq!(
                        cg_buffer_align_offset(buffer, align),
                        expected,
                        "return value for offset {off} align {align}"
                    );
                    assert_eq!(
                        cg_buffer_current_offset(buffer),
                        expected,
                        "store-back for offset {off} align {align}"
                    );
                }
            }
        }
    }

    #[test]
    fn buffer_align_offset_keeps_align_zero_parity() {
        let mut output = [0usize; CG_CODEGEN_OUTPUT_OFFSET + 1];

        unsafe {
            let buffer = output.as_mut_ptr() as *mut CgCodegenBuffer;
            output[CG_CODEGEN_OUTPUT_OFFSET] = 0x1234;
            assert_eq!(
                cg_buffer_align_offset(buffer, 0),
                0,
                "align - 1 wraps to all-ones, so the bic yields 0"
            );
            assert_eq!(
                cg_buffer_current_offset(buffer),
                0,
                "the original rewinds the buffer to its start, unguarded"
            );
        }
    }

    // --- cg_buffer_emit_word ------------------------------------------

    /// Every (buffer, offset) pair the recording fake accessor was
    /// invoked with, and the pointer it hands back.
    static mut PAGE_POINTER_CALLS: std::vec::Vec<(*mut CgCodegenBuffer, usize)> =
        std::vec::Vec::new();
    static mut PAGE_POINTER_RESULT: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn recording_page_pointer(
        output: *mut CgCodegenBuffer,
        offset: usize,
    ) -> *mut u8 {
        PAGE_POINTER_CALLS.push((output, offset));
        PAGE_POINTER_RESULT
    }

    /// A fake accessor honoring the real contract: resolves (buffer,
    /// offset) to `arena + offset`, one flat page standing in for the
    /// original's `pages[offset >> 12] + (offset & 0xfff)`.
    static mut COOP_ARENA: [u8; 64] = [0; 64];

    unsafe extern "C" fn cooperating_page_pointer(
        _output: *mut CgCodegenBuffer,
        offset: usize,
    ) -> *mut u8 {
        (core::ptr::addr_of_mut!(COOP_ARENA) as *mut u8).add(offset)
    }

    #[test]
    fn buffer_emit_word_aligns_stores_verbatim_and_advances_from_the_aligned_offset() {
        let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        const POISON: usize = 0xAAAA_AAAA_AAAA_AAAA;
        let mut output = [POISON; CG_CODEGEN_OUTPUT_OFFSET + 2];
        let mut cell = [0u8; 4];

        unsafe {
            let saved = hook(core::ptr::addr_of!(CG_BUFFER_PAGE_POINTER));
            *core::ptr::addr_of_mut!(CG_BUFFER_PAGE_POINTER) = recording_page_pointer;
            PAGE_POINTER_CALLS.clear();
            PAGE_POINTER_RESULT = cell.as_mut_ptr();

            let buffer = output.as_mut_ptr() as *mut CgCodegenBuffer;
            output[CG_CODEGEN_OUTPUT_OFFSET] = 9;

            cg_buffer_emit_word(buffer, 0xe59f_f018);

            *core::ptr::addr_of_mut!(CG_BUFFER_PAGE_POINTER) = saved;

            assert_eq!(
                PAGE_POINTER_CALLS.as_slice(),
                &[(buffer, 12)],
                "the accessor sees the buffer and the offset ALIGNED up from 9"
            );
            assert_eq!(
                cell,
                0xe59f_f018u32.to_le_bytes(),
                "the word lands at the accessor's pointer bit-exact"
            );
            assert_eq!(
                output[CG_CODEGEN_OUTPUT_OFFSET],
                16,
                "the offset advances by 4 from the aligned 12, not from 9 + 4 = 13"
            );
            assert_eq!(
                output[CG_CODEGEN_OUTPUT_OFFSET - 1],
                POISON,
                "the emitter writes no neighboring word"
            );
            assert_eq!(
                output[CG_CODEGEN_OUTPUT_OFFSET + 1],
                POISON,
                "the emitter writes no neighboring word"
            );
        }
    }

    #[test]
    fn buffer_emit_word_end_to_end_through_a_cooperating_accessor() {
        let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut output = [0usize; CG_CODEGEN_OUTPUT_OFFSET + 1];

        unsafe {
            let saved = hook(core::ptr::addr_of!(CG_BUFFER_PAGE_POINTER));
            *core::ptr::addr_of_mut!(CG_BUFFER_PAGE_POINTER) = cooperating_page_pointer;
            COOP_ARENA = [0; 64];

            let buffer = output.as_mut_ptr() as *mut CgCodegenBuffer;

            output[CG_CODEGEN_OUTPUT_OFFSET] = 0;
            cg_buffer_emit_word(buffer, 0xe3a0_002a); // mov r0, #0x2a at 0
            // A misaligned offset, as a byte/halfword emitter would
            // leave behind: the next word lands at 8, skipping 6..8.
            output[CG_CODEGEN_OUTPUT_OFFSET] = 6;
            cg_buffer_emit_word(buffer, 0xe12f_ff1e); // bx lr at 8
            cg_buffer_emit_word(buffer, 0xea00_0000); // b +8 at 12

            *core::ptr::addr_of_mut!(CG_BUFFER_PAGE_POINTER) = saved;

            let arena = &*core::ptr::addr_of!(COOP_ARENA);
            assert_eq!(
                u32::from_le_bytes(arena[0..4].try_into().unwrap()),
                0xe3a0_002a,
                "first word at offset 0"
            );
            assert_eq!(
                &arena[4..8],
                &[0; 4],
                "the align-up gap is skipped, not written"
            );
            assert_eq!(
                u32::from_le_bytes(arena[8..12].try_into().unwrap()),
                0xe12f_ff1e,
                "the misaligned emit realigned to 8"
            );
            assert_eq!(
                u32::from_le_bytes(arena[12..16].try_into().unwrap()),
                0xea00_0000,
                "the already-aligned emit stores in place"
            );
            assert_eq!(
                cg_buffer_current_offset(buffer),
                16,
                "three words emitted, 12 bytes past the first aligned offset 4... i.e. 16"
            );
        }
    }

    // --- cg_buffer_copy_out (0x082c2350) -----------------------------

    /// Every page index the paged fake page-slot accessor was invoked
    /// with, and the page bases it serves (one per index).
    static mut COPY_SLOT_CALLS: std::vec::Vec<usize> = std::vec::Vec::new();
    static mut COPY_PAGES: [*const u8; 2] = [core::ptr::null(); 2];

    unsafe extern "C" fn paged_copy_slot(
        _output: *mut CgCodegenBuffer,
        index: usize,
    ) -> *mut u8 {
        COPY_SLOT_CALLS.push(index);
        COPY_PAGES[index] as *mut u8
    }

    /// Fill `page` with `seed ^ (i & 0xff)` per byte: position 0 and
    /// position 0xff0 hold distinct values, so the misaligned-offset
    /// quirk (page BASE vs base + offset & 0xfff) is observable.
    fn fill_page(page: &mut [u8], seed: u8) {
        for (i, byte) in page.iter_mut().enumerate() {
            *byte = seed ^ (i & 0xff) as u8;
        }
    }

    #[test]
    fn buffer_copy_out_copies_a_sub_page_run_in_one_chunk() {
        let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut output = [0usize; CG_CODEGEN_OUTPUT_OFFSET + 1];
        let mut page0 = [0u8; CG_BUFFER_PAGE_BYTES];
        fill_page(&mut page0, 0x00);
        let mut dst = [0xccu8; 64 + 8];

        unsafe {
            let saved = hook(core::ptr::addr_of!(CG_BUFFER_PAGE_SLOT));
            *core::ptr::addr_of_mut!(CG_BUFFER_PAGE_SLOT) = paged_copy_slot;
            COPY_SLOT_CALLS.clear();
            COPY_PAGES = [page0.as_ptr(), core::ptr::null()];

            let buffer = output.as_mut_ptr() as *mut CgCodegenBuffer;
            cg_buffer_copy_out(buffer, 0, dst.as_mut_ptr(), 64);

            *core::ptr::addr_of_mut!(CG_BUFFER_PAGE_SLOT) = saved;

            assert_eq!(
                COPY_SLOT_CALLS.as_slice(),
                &[0],
                "a sub-page run resolves exactly one page"
            );
            assert_eq!(&dst[..64], &page0[..64], "bytes copied bit-exact");
            assert_eq!(
                &dst[64..],
                &[0xcc; 8],
                "nothing past len is touched"
            );
        }
    }

    #[test]
    fn buffer_copy_out_chunks_a_copy_spanning_two_pages() {
        let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut output = [0usize; CG_CODEGEN_OUTPUT_OFFSET + 1];
        let mut page0 = [0u8; CG_BUFFER_PAGE_BYTES];
        let mut page1 = [0u8; CG_BUFFER_PAGE_BYTES];
        fill_page(&mut page0, 0x00);
        fill_page(&mut page1, 0xa5);
        let mut dst = [0xccu8; CG_BUFFER_PAGE_BYTES + 0x10 + 8];

        unsafe {
            let saved = hook(core::ptr::addr_of!(CG_BUFFER_PAGE_SLOT));
            *core::ptr::addr_of_mut!(CG_BUFFER_PAGE_SLOT) = paged_copy_slot;
            COPY_SLOT_CALLS.clear();
            COPY_PAGES = [page0.as_ptr(), page1.as_ptr()];

            let buffer = output.as_mut_ptr() as *mut CgCodegenBuffer;
            cg_buffer_copy_out(buffer, 0, dst.as_mut_ptr(), CG_BUFFER_PAGE_BYTES + 0x10);

            *core::ptr::addr_of_mut!(CG_BUFFER_PAGE_SLOT) = saved;

            assert_eq!(
                COPY_SLOT_CALLS.as_slice(),
                &[0, 1],
                "one chunk per page, in offset order"
            );
            assert_eq!(
                &dst[..CG_BUFFER_PAGE_BYTES],
                &page0[..],
                "the full first page lands as one 0x1000-byte chunk"
            );
            assert_eq!(
                &dst[CG_BUFFER_PAGE_BYTES..CG_BUFFER_PAGE_BYTES + 0x10],
                &page1[..0x10],
                "the 0x10-byte remainder comes from the second page's base"
            );
            assert_eq!(
                &dst[CG_BUFFER_PAGE_BYTES + 0x10..],
                &[0xcc; 8],
                "nothing past len is touched"
            );
        }
    }

    #[test]
    fn buffer_copy_out_exact_page_multiple_stops_without_a_third_chunk() {
        let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut output = [0usize; CG_CODEGEN_OUTPUT_OFFSET + 1];
        let mut page0 = [0u8; CG_BUFFER_PAGE_BYTES];
        let mut page1 = [0u8; CG_BUFFER_PAGE_BYTES];
        fill_page(&mut page0, 0x00);
        fill_page(&mut page1, 0xa5);
        let mut dst = [0u8; 2 * CG_BUFFER_PAGE_BYTES];

        unsafe {
            let saved = hook(core::ptr::addr_of!(CG_BUFFER_PAGE_SLOT));
            *core::ptr::addr_of_mut!(CG_BUFFER_PAGE_SLOT) = paged_copy_slot;
            COPY_SLOT_CALLS.clear();
            COPY_PAGES = [page0.as_ptr(), page1.as_ptr()];

            let buffer = output.as_mut_ptr() as *mut CgCodegenBuffer;
            cg_buffer_copy_out(buffer, 0, dst.as_mut_ptr(), 2 * CG_BUFFER_PAGE_BYTES);

            *core::ptr::addr_of_mut!(CG_BUFFER_PAGE_SLOT) = saved;

            assert_eq!(
                COPY_SLOT_CALLS.as_slice(),
                &[0, 1],
                "remaining hits 0 exactly: the loop exits, no index-2 lookup"
            );
            assert_eq!(&dst[..CG_BUFFER_PAGE_BYTES], &page0[..]);
            assert_eq!(&dst[CG_BUFFER_PAGE_BYTES..], &page1[..]);
        }
    }

    #[test]
    fn buffer_copy_out_with_zero_length_copies_nothing() {
        let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut output = [0usize; CG_CODEGEN_OUTPUT_OFFSET + 1];
        let mut dst = [0xccu8; 16];

        unsafe {
            let saved = hook(core::ptr::addr_of!(CG_BUFFER_PAGE_SLOT));
            *core::ptr::addr_of_mut!(CG_BUFFER_PAGE_SLOT) = recording_page_slot;
            PAGE_SLOT_CALLS.clear();
            PAGE_SLOT_RESULT = core::ptr::null_mut();

            let buffer = output.as_mut_ptr() as *mut CgCodegenBuffer;
            cg_buffer_copy_out(buffer, 0x1234, dst.as_mut_ptr(), 0);

            *core::ptr::addr_of_mut!(CG_BUFFER_PAGE_SLOT) = saved;

            assert!(
                PAGE_SLOT_CALLS.is_empty(),
                "len == 0 skips the loop (the original's b-to-tail-test entry)"
            );
            assert_eq!(dst, [0xcc; 16], "the destination is untouched");
        }
    }

    #[test]
    fn buffer_copy_out_keeps_the_page_base_quirk_for_misaligned_offsets() {
        let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut output = [0usize; CG_CODEGEN_OUTPUT_OFFSET + 1];
        let mut page0 = [0u8; CG_BUFFER_PAGE_BYTES];
        let mut page1 = [0u8; CG_BUFFER_PAGE_BYTES];
        fill_page(&mut page0, 0x00);
        fill_page(&mut page1, 0xa5);
        let mut dst = [0u8; 0x20];

        unsafe {
            let saved = hook(core::ptr::addr_of!(CG_BUFFER_PAGE_SLOT));
            *core::ptr::addr_of_mut!(CG_BUFFER_PAGE_SLOT) = paged_copy_slot;
            COPY_SLOT_CALLS.clear();
            COPY_PAGES = [page0.as_ptr(), page1.as_ptr()];

            let buffer = output.as_mut_ptr() as *mut CgCodegenBuffer;
            // offset 0xff0, len 0x20: chunk 0x10 sized as
            // 0x1000 - (0xff0 & 0xfff), then 0x10 more.
            cg_buffer_copy_out(buffer, 0xff0, dst.as_mut_ptr(), 0x20);

            *core::ptr::addr_of_mut!(CG_BUFFER_PAGE_SLOT) = saved;

            assert_eq!(
                COPY_SLOT_CALLS.as_slice(),
                &[0, 1],
                "the chunk sizing still honors the misaligned offset"
            );
            assert_eq!(
                &dst[..0x10],
                &page0[..0x10],
                "QUIRK: the first chunk reads the page BASE, not base + 0xff0"
            );
            assert_ne!(
                &dst[..0x10],
                &page0[0xff0..],
                "...which is NOT what a base + (offset & 0xfff) read would give"
            );
            assert_eq!(
                &dst[0x10..],
                &page1[..0x10],
                "the second chunk reads the next page's base (aligned now)"
            );
        }
    }

    #[test]
    fn buffer_copy_out_flattens_words_emitted_across_a_page_boundary() {
        let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut output = [0usize; CG_CODEGEN_OUTPUT_OFFSET + 1];

        unsafe {
            let saved_alloc = hook(core::ptr::addr_of!(CG_BUFFER_ALLOC));
            *core::ptr::addr_of_mut!(CG_BUFFER_ALLOC) = poisoning_alloc;

            let buffer = output.as_mut_ptr() as *mut CgCodegenBuffer;
            // 0x404 words = 0x1010 bytes: the run spills 0x10 bytes into
            // the second code page. Both seams stay at their wired
            // defaults (ported accessor + exact-body page-slot model).
            let words = 0x404usize;
            for i in 0..words {
                cg_buffer_emit_word(buffer, (0xe000_0000usize | i) as u32);
            }
            let len = cg_buffer_current_offset(buffer);
            assert_eq!(len, words * 4, "every emit advanced the offset by 4");

            let mut flat = [0u8; 0x1020];
            cg_buffer_copy_out(buffer, 0, flat.as_mut_ptr(), len);

            for i in 0..words {
                let expect = ((0xe000_0000usize | i) as u32).to_le_bytes();
                assert_eq!(
                    &flat[i * 4..i * 4 + 4],
                    &expect,
                    "word {i:#x} round-trips through the page boundary"
                );
            }
            assert_eq!(
                &flat[len..],
                &[0; 0x10],
                "nothing past current_offset is copied"
            );

            *core::ptr::addr_of_mut!(CG_BUFFER_ALLOC) = saved_alloc;
            let record = output.as_mut_ptr() as *mut u8;
            for index in 0..=(len >> CG_BUFFER_PAGE_SHIFT) {
                let page = slot(record, CG_BUFFER_PAGES + index).read();
                if !page.is_null() {
                    poisoning_free(page);
                }
            }
        }
    }

    // --- cg_buffer_read_word (0x082c23b0) ----------------------------

    #[test]
    fn buffer_read_word_loads_through_the_page_pointer_seam_with_the_offset_verbatim() {
        let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        const POISON: usize = 0xAAAA_AAAA_AAAA_AAAA;
        let mut output = [POISON; CG_CODEGEN_OUTPUT_OFFSET + 2];
        let mut cell = 0xe12f_ff1eu32; // bx lr

        unsafe {
            let saved = hook(core::ptr::addr_of!(CG_BUFFER_PAGE_POINTER));
            *core::ptr::addr_of_mut!(CG_BUFFER_PAGE_POINTER) = recording_page_pointer;
            PAGE_POINTER_CALLS.clear();
            PAGE_POINTER_RESULT = core::ptr::addr_of_mut!(cell) as *mut u8;

            let buffer = output.as_mut_ptr() as *mut CgCodegenBuffer;
            let value = cg_buffer_read_word(buffer, 6);

            *core::ptr::addr_of_mut!(CG_BUFFER_PAGE_POINTER) = saved;

            assert_eq!(
                value, 0xe12f_ff1e,
                "the word at the accessor's pointer comes back bit-exact"
            );
            assert_eq!(
                PAGE_POINTER_CALLS.as_slice(),
                &[(buffer, 6)],
                "the accessor sees the buffer and the offset VERBATIM — no align-up, unlike the emitter"
            );
            assert_eq!(cell, 0xe12f_ff1e, "the read leaves the cell untouched");
            assert_eq!(
                output[CG_CODEGEN_OUTPUT_OFFSET], POISON,
                "the reader never touches current_offset"
            );
            assert_eq!(
                output[CG_CODEGEN_OUTPUT_OFFSET + 1], POISON,
                "the reader writes no neighboring word"
            );
        }
    }

    #[test]
    fn buffer_read_word_reads_back_words_emitted_across_a_page_boundary() {
        let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut output = [0usize; CG_CODEGEN_OUTPUT_OFFSET + 1];

        unsafe {
            let saved_alloc = hook(core::ptr::addr_of!(CG_BUFFER_ALLOC));
            *core::ptr::addr_of_mut!(CG_BUFFER_ALLOC) = poisoning_alloc;

            let buffer = output.as_mut_ptr() as *mut CgCodegenBuffer;
            // 0x404 words = 0x1010 bytes: the run spills 0x10 bytes into
            // the second code page. Both seams stay at their wired
            // defaults (ported accessor + exact-body page-slot model).
            let words = 0x404usize;
            for i in 0..words {
                cg_buffer_emit_word(buffer, (0xe000_0000usize | i) as u32);
            }
            let len = cg_buffer_current_offset(buffer);

            for i in 0..words {
                assert_eq!(
                    cg_buffer_read_word(buffer, i * 4),
                    (0xe000_0000usize | i) as u32,
                    "word {i:#x} reads back bit-exact through the page boundary"
                );
            }
            assert_eq!(
                word(buffer as *mut u8, CG_CODEGEN_OUTPUT_OFFSET).read(),
                len,
                "0x404 reads never moved the offset"
            );

            *core::ptr::addr_of_mut!(CG_BUFFER_ALLOC) = saved_alloc;
            let record = output.as_mut_ptr() as *mut u8;
            for index in 0..=(len >> CG_BUFFER_PAGE_SHIFT) {
                let page = slot(record, CG_BUFFER_PAGES + index).read();
                if !page.is_null() {
                    poisoning_free(page);
                }
            }
        }
    }

    // --- cg_buffer_write_word (0x082c23c0) ---------------------------

    #[test]
    fn buffer_write_word_stores_through_the_page_pointer_seam_with_the_offset_verbatim() {
        let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        const POISON: usize = 0xAAAA_AAAA_AAAA_AAAA;
        let mut output = [POISON; CG_CODEGEN_OUTPUT_OFFSET + 2];
        let mut cell = 0xe59f_f018u32; // ldr r0, [pc, #0x18] — pre-patch

        unsafe {
            let saved = hook(core::ptr::addr_of!(CG_BUFFER_PAGE_POINTER));
            *core::ptr::addr_of_mut!(CG_BUFFER_PAGE_POINTER) = recording_page_pointer;
            PAGE_POINTER_CALLS.clear();
            PAGE_POINTER_RESULT = core::ptr::addr_of_mut!(cell) as *mut u8;

            let buffer = output.as_mut_ptr() as *mut CgCodegenBuffer;
            cg_buffer_write_word(buffer, 6, 0xea00_0002); // b +8

            *core::ptr::addr_of_mut!(CG_BUFFER_PAGE_POINTER) = saved;

            assert_eq!(
                cell, 0xea00_0002,
                "the patched word lands at the accessor's pointer bit-exact"
            );
            assert_eq!(
                PAGE_POINTER_CALLS.as_slice(),
                &[(buffer, 6)],
                "the accessor sees the buffer and the offset VERBATIM — no align-up, unlike the emitter"
            );
            assert_eq!(
                output[CG_CODEGEN_OUTPUT_OFFSET], POISON,
                "the writer never touches current_offset"
            );
            assert_eq!(
                output[CG_CODEGEN_OUTPUT_OFFSET + 1],
                POISON,
                "the writer writes no neighboring word"
            );
        }
    }

    #[test]
    fn buffer_write_word_patches_words_emitted_across_a_page_boundary() {
        let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut output = [0usize; CG_CODEGEN_OUTPUT_OFFSET + 1];

        unsafe {
            let saved_alloc = hook(core::ptr::addr_of!(CG_BUFFER_ALLOC));
            *core::ptr::addr_of_mut!(CG_BUFFER_ALLOC) = poisoning_alloc;

            let buffer = output.as_mut_ptr() as *mut CgCodegenBuffer;
            // 0x404 words = 0x1010 bytes: the run spills 0x10 bytes into
            // the second code page. Both seams stay at their wired
            // defaults (ported accessor + exact-body page-slot model).
            let words = 0x404usize;
            for i in 0..words {
                cg_buffer_emit_word(buffer, (0xea00_0000usize | i) as u32);
            }
            let len = cg_buffer_current_offset(buffer);

            // The fixup resolver's read-modify-write, at fixup positions
            // on both sides of the page boundary: read the emitted word
            // back, splice the resolved offset into its low bits, store
            // the patched word.
            for &fixup in &[0usize, 0x400, 0x402, 0x403] {
                let word_at = cg_buffer_read_word(buffer, fixup * 4);
                let patched = (word_at & !0x00ff_ffff) | 0x0000_1234;
                cg_buffer_write_word(buffer, fixup * 4, patched);
            }

            for i in 0..words {
                let expected = if [0usize, 0x400, 0x402, 0x403].contains(&i) {
                    0xea00_1234u32
                } else {
                    (0xea00_0000usize | i) as u32
                };
                assert_eq!(
                    cg_buffer_read_word(buffer, i * 4),
                    expected,
                    "word {i:#x} after patching reads back bit-exact through the page boundary"
                );
            }
            assert_eq!(
                word(buffer as *mut u8, CG_CODEGEN_OUTPUT_OFFSET).read(),
                len,
                "the writes never moved the offset"
            );

            *core::ptr::addr_of_mut!(CG_BUFFER_ALLOC) = saved_alloc;
            let record = output.as_mut_ptr() as *mut u8;
            for index in 0..=(len >> CG_BUFFER_PAGE_SHIFT) {
                let page = slot(record, CG_BUFFER_PAGES + index).read();
                if !page.is_null() {
                    poisoning_free(page);
                }
            }
        }
    }

    // --- cg_buffer_page_pointer (0x082c5b1c) through its seams -------

    /// Every (buffer, index) pair the recording fake page-slot accessor
    /// was invoked with, and the page base it hands back.
    static mut PAGE_SLOT_CALLS: std::vec::Vec<(*mut CgCodegenBuffer, usize)> =
        std::vec::Vec::new();
    static mut PAGE_SLOT_RESULT: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn recording_page_slot(
        output: *mut CgCodegenBuffer,
        index: usize,
    ) -> *mut u8 {
        PAGE_SLOT_CALLS.push((output, index));
        PAGE_SLOT_RESULT
    }

    #[test]
    fn page_pointer_seam_stays_wired_to_the_ported_accessor() {
        assert_eq!(
            hook(core::ptr::addr_of!(CG_BUFFER_PAGE_POINTER)) as usize,
            cg_buffer_page_pointer as usize,
            "the vtable_slot_50_dispatch precedent: the seam is retained, \
             wired to the ported body"
        );
        assert_eq!(
            hook(core::ptr::addr_of!(CG_BUFFER_PAGE_SLOT)) as usize,
            default_cg_buffer_page_slot as usize,
            "0x082b7edc stays identified behind its own seam"
        );
    }

    #[test]
    fn buffer_page_pointer_splits_offsets_straddling_page_boundaries() {
        let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut output = [0usize; CG_CODEGEN_OUTPUT_OFFSET + 1];
        let mut page = [0u8; CG_BUFFER_PAGE_BYTES];

        unsafe {
            let saved = hook(core::ptr::addr_of!(CG_BUFFER_PAGE_SLOT));
            *core::ptr::addr_of_mut!(CG_BUFFER_PAGE_SLOT) = recording_page_slot;
            PAGE_SLOT_CALLS.clear();
            let base = page.as_mut_ptr();
            PAGE_SLOT_RESULT = base;

            let buffer = output.as_mut_ptr() as *mut CgCodegenBuffer;
            // Offsets straddling the 0x1000 page pitch: the split is
            // index = offset >> 12, intra = offset & 0xfff, and the
            // result is base + intra verbatim.
            for (offset, intra) in [
                (0x0fffusize, 0x0fffusize),
                (0x1000, 0x000),
                (0x1001, 0x001),
                (0x2000, 0x000),
            ] {
                assert_eq!(
                    cg_buffer_page_pointer(buffer, offset),
                    base.add(intra),
                    "offset {offset:#x}: page base + intra {intra:#x}"
                );
            }

            *core::ptr::addr_of_mut!(CG_BUFFER_PAGE_SLOT) = saved;

            assert_eq!(
                PAGE_SLOT_CALLS.as_slice(),
                &[(buffer, 0), (buffer, 1), (buffer, 1), (buffer, 2)],
                "the page-slot accessor sees the buffer and the EXACT page index"
            );
        }
    }

    #[test]
    fn buffer_page_pointer_propagates_null_from_the_page_slot_seam() {
        let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut output = [0usize; CG_CODEGEN_OUTPUT_OFFSET + 1];

        unsafe {
            let saved = hook(core::ptr::addr_of!(CG_BUFFER_PAGE_SLOT));
            *core::ptr::addr_of_mut!(CG_BUFFER_PAGE_SLOT) = recording_page_slot;
            PAGE_SLOT_CALLS.clear();
            PAGE_SLOT_RESULT = core::ptr::null_mut();

            let buffer = output.as_mut_ptr() as *mut CgCodegenBuffer;
            assert!(
                cg_buffer_page_pointer(buffer, 0x2345).is_null(),
                "the documented deviation: NULL propagates where the original \
                 has no NULL guard (the `add r0, r0, r4` @ 0x082c5b34 is \
                 unconditional) and has already crashed one callee earlier"
            );

            *core::ptr::addr_of_mut!(CG_BUFFER_PAGE_SLOT) = saved;

            assert_eq!(
                PAGE_SLOT_CALLS.as_slice(),
                &[(buffer, 2)],
                "the NULL path still passes the exact page index 0x2345 >> 12"
            );
        }
    }

    #[test]
    fn buffer_page_pointer_lazy_allocates_zeroes_and_reuses_the_page() {
        let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Zeroed record: every page slot NULL, offset 0.
        let mut output = [0usize; CG_CODEGEN_OUTPUT_OFFSET + 1];

        unsafe {
            let saved_alloc = hook(core::ptr::addr_of!(CG_BUFFER_ALLOC));
            *core::ptr::addr_of_mut!(CG_BUFFER_ALLOC) = poisoning_alloc;

            let record = output.as_mut_ptr() as *mut u8;
            let buffer = record as *mut CgCodegenBuffer;
            // The ported accessor itself (also the wired default of
            // CG_BUFFER_PAGE_POINTER), running through the
            // CG_BUFFER_PAGE_SLOT seam's wired default — the exact-body
            // model of FUN_082b7edc.
            let accessor = cg_buffer_page_pointer;

            let first = accessor(buffer, 0x1234);
            let page = slot(record, CG_BUFFER_PAGES + (0x1234 >> CG_BUFFER_PAGE_SHIFT)).read();
            assert!(!page.is_null(), "a miss lazy-allocates the page");
            assert_eq!(
                first,
                page.add(0x234),
                "pages[offset >> 12] + (offset & 0xfff)"
            );
            assert!(
                core::slice::from_raw_parts(page, record_size(CG_BUFFER_PAGE_BYTES))
                    .iter()
                    .all(|&b| b == 0),
                "the fresh page is zero-filled over the allocator's 0x5c poison,\
                 as through the original's IRAM memzero veneer"
            );

            let again = accessor(buffer, 0x1ffc);
            assert_eq!(
                again,
                page.add(0xffc),
                "a resident page is reused, not reallocated"
            );

            let other = accessor(buffer, 0x0800);
            let page0 = slot(record, CG_BUFFER_PAGES).read();
            assert!(!page0.is_null(), "a new index lazy-allocates its own page");
            assert_eq!(other, page0.add(0x800));
            assert_ne!(page0, page, "distinct pages are distinct allocations");

            *core::ptr::addr_of_mut!(CG_BUFFER_ALLOC) = saved_alloc;
            poisoning_free(page0);
            poisoning_free(page);
        }
    }

    #[test]
    fn buffer_page_pointer_returns_null_when_the_page_allocation_fails() {
        let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut output = [0usize; CG_CODEGEN_OUTPUT_OFFSET + 1];

        unsafe {
            let saved_alloc = hook(core::ptr::addr_of!(CG_BUFFER_ALLOC));
            *core::ptr::addr_of_mut!(CG_BUFFER_ALLOC) = failing_alloc;

            let buffer = output.as_mut_ptr() as *mut CgCodegenBuffer;
            assert!(
                cg_buffer_page_pointer(buffer, 0x2000).is_null(),
                "the deviation: NULL where the original would memzero at address 0"
            );

            *core::ptr::addr_of_mut!(CG_BUFFER_ALLOC) = saved_alloc;

            assert!(
                slot(output.as_mut_ptr() as *mut u8, CG_BUFFER_PAGES + 2)
                    .read()
                    .is_null(),
                "the failed page is never stored into the slot"
            );
        }
    }

    #[test]
    fn codegen_output_returns_the_word_at_0x10() {
        const POISON: usize = 0xAAAA_AAAA_AAAA_AAAA;
        let mut codegen = [POISON; CG_CODEGEN_OUTPUT + 2];

        unsafe {
            let record = codegen.as_mut_ptr() as *mut CgCodegen;

            codegen[CG_CODEGEN_OUTPUT] = 0;
            assert_eq!(
                cg_codegen_output(record),
                core::ptr::null_mut(),
                "a NULL output buffer comes back as-is"
            );

            let sentinel = codegen.as_mut_ptr() as usize;
            codegen[CG_CODEGEN_OUTPUT] = sentinel;
            assert_eq!(
                cg_codegen_output(record),
                sentinel as *mut CgCodegenBuffer,
                "a live buffer pointer at +0x10 comes back exactly"
            );

            assert_eq!(
                codegen[CG_CODEGEN_OUTPUT - 1],
                POISON,
                "the getter reads no neighboring word"
            );
            assert_eq!(
                codegen[CG_CODEGEN_OUTPUT + 1],
                POISON,
                "the getter reads no neighboring word"
            );
        }
    }

    /// Alloc hook that always fails, for the NULL-path deviation test.
    unsafe extern "C" fn failing_alloc(_size: usize) -> *mut u8 {
        core::ptr::null_mut()
    }

    /// Byte offset of register `reg`'s number byte inside a host
    /// `cg_codegen_t` record.
    fn hw_reg_no_offset(reg: usize) -> usize {
        (CG_CODEGEN_HW_REGS + reg * CG_HW_REG_ENTRY_WORDS) * WORD
    }

    #[test]
    fn codegen_create_allocates_zeroes_and_wires_the_record() {
        let _g = setup();
        unsafe {
            let saved = hook(core::ptr::addr_of!(CG_BUFFER_ALLOC));
            *core::ptr::addr_of_mut!(CG_BUFFER_ALLOC) = poisoning_alloc;

            let heap = cg_heap_create(4096);
            let helpers = [0x080e2468usize; 10];
            let mut status_cell = 0usize;
            let block = (*heap).current;
            let before = (*block).current;
            let expected = (*block).base.add(before);
            let codegen = cg_codegen_create(
                heap,
                helpers.as_ptr(),
                core::ptr::addr_of_mut!(status_cell),
            ) as *mut u8;

            *core::ptr::addr_of_mut!(CG_BUFFER_ALLOC) = saved;

            // The 0x220-byte record is carved from the front of the
            // arena and returned verbatim.
            assert_eq!(codegen, expected, "the arena carve is the return value");
            assert_eq!(
                (*block).current,
                before + stride(CG_CODEGEN_BYTES),
                "the arena advances by the eight-byte-rounded 0x220 request"
            );

            // Field stores: helpers, status, heap, labels = NULL, and
            // the freshly built output buffer.
            assert_eq!(slot(codegen, CG_CODEGEN_HELPERS).read(), helpers.as_ptr() as *mut u8);
            assert_eq!(
                slot(codegen, CG_CODEGEN_STATUS).read(),
                core::ptr::addr_of_mut!(status_cell) as *mut u8
            );
            assert_eq!(slot(codegen, CG_CODEGEN_HEAP).read(), heap as *mut u8);
            assert!(
                slot(codegen, CG_CODEGEN_LABELS).read().is_null(),
                "the label list starts empty (explicit NULL store)"
            );
            let output = slot(codegen, CG_CODEGEN_OUTPUT).read();
            assert!(!output.is_null());

            // Every other byte of the 0x220 record is zero (the
            // allocator's 0x5c poison proves the zero-fill), except the
            // 16 register-number bytes, which hold 0..=15 at the
            // 28-byte stride — and +0x1e0, which is zero like the rest.
            const FIELD_WORDS: [usize; 5] = [
                CG_CODEGEN_HELPERS,
                CG_CODEGEN_STATUS,
                CG_CODEGEN_HEAP,
                CG_CODEGEN_LABELS,
                CG_CODEGEN_OUTPUT,
            ];
            for w in 0..record_size(CG_CODEGEN_BYTES) / WORD {
                if FIELD_WORDS.contains(&w) {
                    continue;
                }
                for b in 0..WORD {
                    let off = w * WORD + b;
                    let mut want = 0u8;
                    for reg in 0..CG_HW_REG_COUNT {
                        if off == hw_reg_no_offset(reg) {
                            want = reg as u8;
                        }
                    }
                    assert_eq!(codegen.add(off).read(), want, "record byte {off:#x}");
                }
            }
            // Spot-check the stride directly: r0's byte at +0x20,
            // r15's at +0x20 + 15*28, nothing stamped at the byte just
            // past r15's entry (+0x1e0 is the anchor id, zero).
            assert_eq!(codegen.add(hw_reg_no_offset(0)).read(), 0);
            assert_eq!(codegen.add(hw_reg_no_offset(15)).read(), 15);
            assert_eq!(codegen.add(CG_CODEGEN_ANCHOR_ID * WORD).read(), 0);

            // The buffer is the real ported constructor's product: a
            // 0x808-byte malloc'd record whose +0x00 holds the "CSEG"
            // name, pages zeroed, offset zero.
            assert_eq!(
                (output.sub(HDR) as *mut usize).read(),
                record_size(CG_CODEGEN_BUFFER_BYTES),
                "the output buffer is the 0x808-byte malloc"
            );
            let name = slot(output, CG_BUFFER_NAME).read();
            for (i, want) in b"CSEG\0".iter().enumerate() {
                assert_eq!(name.add(i).read(), *want, "the buffer is named CSEG");
            }
            assert_eq!(word(output, CG_CODEGEN_OUTPUT_OFFSET).read(), 0);

            // Layout consistency with the already-ported consumers:
            // cg_codegen_output reads +0x10 back, and cg_label_create
            // allocates from +0x08 and prepends to +0x0c.
            assert_eq!(
                cg_codegen_output(codegen as *mut CgCodegen) as *mut u8,
                output,
                "cg_codegen_output sees the fresh buffer"
            );
            let label = cg_label_create(codegen as *mut CgCodegen) as *mut u8;
            assert_eq!(
                slot(codegen, CG_CODEGEN_LABELS).read(),
                label,
                "cg_label_create prepends to the NULL head the constructor left"
            );
            assert_eq!(word(label, CG_LABEL_OFFSET).read(), CG_LABEL_UNBOUND);

            poisoning_free(output);
            cg_heap_destroy(heap);
        }
    }

    #[test]
    fn codegen_create_stores_a_null_output_when_the_buffer_alloc_fails() {
        let _g = setup();
        unsafe {
            let saved = hook(core::ptr::addr_of!(CG_BUFFER_ALLOC));
            *core::ptr::addr_of_mut!(CG_BUFFER_ALLOC) = failing_alloc;

            let heap = cg_heap_create(4096);
            let codegen =
                cg_codegen_create(heap, core::ptr::null(), core::ptr::null_mut()) as *mut u8;

            *core::ptr::addr_of_mut!(CG_BUFFER_ALLOC) = saved;

            // The inherited buffer_create deviation: NULL is stored
            // verbatim instead of the original's wild zero-fill, and
            // the rest of the record is still wired.
            assert!(
                slot(codegen, CG_CODEGEN_OUTPUT).read().is_null(),
                "documented deviation: NULL output propagates verbatim"
            );
            assert_eq!(slot(codegen, CG_CODEGEN_HEAP).read(), heap as *mut u8);
            assert_eq!(codegen.add(hw_reg_no_offset(15)).read(), 15);

            cg_heap_destroy(heap);
        }
    }

    #[test]
    fn codegen_buffer_create_allocates_zeroes_and_stamps_the_record() {
        let _guard = LOCK.lock().unwrap();
        unsafe {
            let saved = hook(core::ptr::addr_of!(CG_BUFFER_ALLOC));
            *core::ptr::addr_of_mut!(CG_BUFFER_ALLOC) = poisoning_alloc;

            let name = b"CSEG\0";
            let buffer = cg_codegen_buffer_create(name.as_ptr()) as *mut u8;

            *core::ptr::addr_of_mut!(CG_BUFFER_ALLOC) = saved;

            assert!(!buffer.is_null());
            // The allocator's pointer is forwarded as-is (its header is
            // readable) and the requested size is the whole 0x808-byte
            // record — the literal at 0x082c22e4.
            assert_eq!(
                (buffer.sub(HDR) as *mut usize).read(),
                record_size(CG_CODEGEN_BUFFER_BYTES),
                "allocation size forwarded to the allocator"
            );
            // +0x04..+0x803 (the code-page table) is zeroed, proven by
            // the allocator's 0x5c poison.
            let pages = buffer.add(WORD * CG_BUFFER_PAGES);
            for i in 0..record_size(CG_BUFFER_PAGE_TABLE_BYTES) {
                assert_eq!(pages.add(i).read(), 0, "page-table byte {i} not zeroed");
            }
            // +0x804 current_offset starts at 0 and reads back through
            // the getter.
            assert_eq!(word(buffer, CG_CODEGEN_OUTPUT_OFFSET).read(), 0);
            assert_eq!(
                cg_buffer_current_offset(buffer as *mut CgCodegenBuffer),
                0,
                "the getter sees the fresh offset"
            );
            // The name pointer sits at +0x00, stored verbatim.
            assert_eq!(slot(buffer, CG_BUFFER_NAME).read(), name.as_ptr() as *mut u8);

            poisoning_free(buffer);
        }
    }

    #[test]
    fn codegen_buffer_create_returns_null_when_allocation_fails() {
        let _guard = LOCK.lock().unwrap();
        unsafe {
            let saved = hook(core::ptr::addr_of!(CG_BUFFER_ALLOC));
            *core::ptr::addr_of_mut!(CG_BUFFER_ALLOC) = failing_alloc;

            let buffer = cg_codegen_buffer_create(core::ptr::null());

            *core::ptr::addr_of_mut!(CG_BUFFER_ALLOC) = saved;

            assert!(
                buffer.is_null(),
                "documented deviation: no wild zero-fill at address 4"
            );
        }
    }

    #[test]
    fn label_fixup_allocates_stamps_and_prepends_with_a_unit_return() {
        let _g = setup();
        let mut f = Fixture::new(4096);
        let mut label = [0usize; 3];
        let mut prior_fixup = [0usize; 3];
        label[CG_LABEL_FIXUPS] = prior_fixup.as_mut_ptr() as usize;
        f.output[CG_CODEGEN_OUTPUT_OFFSET] = 0x1234_5678;

        unsafe {
            let block = (*f.heap).current;
            let expected = (*block).base.add((*block).current);
            let before = (*block).current;
            let returned: () =
                cg_label_add_fixup(f.codegen_ptr(), label.as_mut_ptr() as *mut CgLabel, 0xfeed_be5a);
            let fixup = label[CG_LABEL_FIXUPS] as *mut u8;

            assert_eq!(fixup, expected, "the 12-byte record comes from codegen->heap");
            assert_eq!(
                (*block).current,
                before + stride(CG_LABEL_FIXUP_BYTES),
                "cg_heap_alloc advances by its eight-byte-rounded request"
            );
            assert_eq!(
                word(fixup, CG_LABEL_FIXUP_OFFSET).read(),
                0x1234_5678,
                "the value returned by cg_buffer_current_offset is the patch position"
            );
            assert_eq!(
                slot(fixup, CG_LABEL_FIXUP_NEXT).read(),
                prior_fixup.as_mut_ptr() as *mut u8,
                "the prior label head is linked before the label head changes"
            );
            assert_eq!(
                fixup.add(CG_LABEL_FIXUP_TAG * WORD).read(),
                0x5a,
                "`strb` retains only the tag's low byte"
            );
            assert_eq!(returned, (), "the ARM function has a void return ABI");
        }
        drop(f);
        teardown();
    }

    #[test]
    fn label_create_allocates_initializes_and_prepends() {
        let _g = setup();
        let mut f = Fixture::new(4096);
        assert_eq!(f.codegen[CG_CODEGEN_LABELS], 0, "the list starts empty");

        unsafe {
            let block = (*f.heap).current;
            let expected = (*block).base.add((*block).current);
            let before = (*block).current;
            let label = cg_label_create(f.codegen_ptr()) as *mut u8;

            assert_eq!(label, expected, "the 12-byte record comes from codegen->heap");
            assert_eq!(
                (*block).current,
                before + stride(CG_LABEL_BYTES),
                "cg_heap_alloc advances by its eight-byte-rounded request"
            );
            assert_eq!(
                slot(label, CG_LABEL_FIXUPS).read(),
                core::ptr::null_mut(),
                "the fixup head is explicitly NULLed, not just zero-filled"
            );
            assert_eq!(
                word(label, CG_LABEL_OFFSET).read(),
                CG_LABEL_UNBOUND,
                "the bound offset starts at the all-ones sentinel (`mvn r1, #0`)"
            );
            assert_eq!(
                slot(label, CG_LABEL_NEXT).read(),
                core::ptr::null_mut(),
                "the first label's next is the NULL old head"
            );
            assert_eq!(
                f.codegen[CG_CODEGEN_LABELS], label as usize,
                "the new record becomes the codegen's label head"
            );
        }
        drop(f);
        teardown();
    }

    #[test]
    fn label_create_chains_labels_newest_first() {
        let _g = setup();
        let mut f = Fixture::new(4096);
        unsafe {
            let first = cg_label_create(f.codegen_ptr()) as *mut u8;
            let second = cg_label_create(f.codegen_ptr()) as *mut u8;

            assert_eq!(f.codegen[CG_CODEGEN_LABELS], second as usize, "head is the newest");
            assert_eq!(
                slot(second, CG_LABEL_NEXT).read(),
                first,
                "the second label links to the first"
            );
            assert_eq!(
                slot(first, CG_LABEL_NEXT).read(),
                core::ptr::null_mut(),
                "the first label terminates the list"
            );
            assert_eq!(
                word(first, CG_LABEL_OFFSET).read(),
                CG_LABEL_UNBOUND,
                "prepending does not disturb an existing record"
            );
        }
        drop(f);
        teardown();
    }

    #[test]
    fn created_label_accepts_fixups_through_the_matching_layout() {
        // Cross-check against cg_label_add_fixup: it must find the fixup
        // head at +0x04 and leave the creator's next/offset words alone.
        let _g = setup();
        let mut f = Fixture::new(4096);
        f.output[CG_CODEGEN_OUTPUT_OFFSET] = 0x200;

        unsafe {
            let label = cg_label_create(f.codegen_ptr()) as *mut u8;
            cg_label_add_fixup(f.codegen_ptr(), label as *mut CgLabel, 7);
            cg_label_add_fixup(f.codegen_ptr(), label as *mut CgLabel, 9);

            let newest = slot(label, CG_LABEL_FIXUPS).read();
            assert!(!newest.is_null(), "the label's fixup head is live");
            assert_eq!(newest.add(CG_LABEL_FIXUP_TAG * WORD).read(), 9);
            assert_eq!(word(newest, CG_LABEL_FIXUP_OFFSET).read(), 0x200);
            let older = slot(newest, CG_LABEL_FIXUP_NEXT).read();
            assert!(!older.is_null(), "fixups chain newest-first");
            assert_eq!(older.add(CG_LABEL_FIXUP_TAG * WORD).read(), 7);
            assert_eq!(
                slot(older, CG_LABEL_FIXUP_NEXT).read(),
                core::ptr::null_mut(),
                "the oldest fixup links to the creator's NULL head"
            );

            assert_eq!(
                word(label, CG_LABEL_OFFSET).read(),
                CG_LABEL_UNBOUND,
                "adding fixups never binds the label"
            );
            assert_eq!(
                slot(label, CG_LABEL_NEXT).read(),
                core::ptr::null_mut(),
                "adding fixups never touches the label list link"
            );
            assert_eq!(f.codegen[CG_CODEGEN_LABELS], label as usize);
        }
        drop(f);
        teardown();
    }

    // --- cg_codegen_resolve_label_fixups (0x082c16e0) ----------------

    /// Binds `label` to an emitted-code offset the way the binder
    /// `FUN_082c1360` would before the resolver runs.
    unsafe fn bind_label(label: *mut CgLabel, offset: usize) {
        word(label as *mut u8, CG_LABEL_OFFSET).write(offset);
    }

    #[test]
    fn resolve_fixups_with_no_labels_or_no_fixups_is_a_no_op() {
        let _g = setup();
        let mut f = Fixture::new(4096);
        let mut cell = 0xe12f_ff1eu32; // bx lr

        unsafe {
            let saved = hook(core::ptr::addr_of!(CG_BUFFER_PAGE_POINTER));
            *core::ptr::addr_of_mut!(CG_BUFFER_PAGE_POINTER) = recording_page_pointer;
            PAGE_POINTER_CALLS.clear();
            PAGE_POINTER_RESULT = core::ptr::addr_of_mut!(cell) as *mut u8;

            // A codegen whose label list is still the fixture's NULL.
            cg_codegen_resolve_label_fixups(f.codegen_ptr());
            // A bound label whose fixup list is the creator's NULL.
            let label = cg_label_create(f.codegen_ptr());
            bind_label(label, 0x80);
            cg_codegen_resolve_label_fixups(f.codegen_ptr());

            *core::ptr::addr_of_mut!(CG_BUFFER_PAGE_POINTER) = saved;

            assert!(
                PAGE_POINTER_CALLS.is_empty(),
                "no label, no fixup: the resolver never touches the buffer"
            );
            assert_eq!(cell, 0xe12f_ff1e, "the emitted word is untouched");
        }
        drop(f);
        teardown();
    }

    #[test]
    fn resolve_fixups_skips_unknown_tags_without_even_reading_the_word() {
        let _g = setup();
        let mut f = Fixture::new(4096);
        let mut cell = 0xdead_beefu32;

        unsafe {
            let saved = hook(core::ptr::addr_of!(CG_BUFFER_PAGE_POINTER));
            *core::ptr::addr_of_mut!(CG_BUFFER_PAGE_POINTER) = recording_page_pointer;
            PAGE_POINTER_CALLS.clear();
            PAGE_POINTER_RESULT = core::ptr::addr_of_mut!(cell) as *mut u8;

            let label = cg_label_create(f.codegen_ptr());
            f.output[CG_CODEGEN_OUTPUT_OFFSET] = 0x40;
            cg_label_add_fixup(f.codegen_ptr(), label, 7); // neither 0 nor 1
            bind_label(label, 0x80);
            cg_codegen_resolve_label_fixups(f.codegen_ptr());

            *core::ptr::addr_of_mut!(CG_BUFFER_PAGE_POINTER) = saved;

            assert!(
                PAGE_POINTER_CALLS.is_empty(),
                "the original branches straight to the list advance (`bne 0x082c178c`)"
            );
            assert_eq!(cell, 0xdead_beef, "the emitted word is untouched");
            assert_eq!(
                f.codegen[CG_CODEGEN_LABELS], label as usize,
                "the label list itself is untouched"
            );
        }
        drop(f);
        teardown();
    }

    #[test]
    fn resolve_fixups_patches_a_tag1_branch_read_modify_write_through_the_seam() {
        let _g = setup();
        let mut f = Fixture::new(4096);
        let mut cell = 0x1a00_0000u32; // bne . — cond nibble must survive

        unsafe {
            let saved = hook(core::ptr::addr_of!(CG_BUFFER_PAGE_POINTER));
            *core::ptr::addr_of_mut!(CG_BUFFER_PAGE_POINTER) = recording_page_pointer;
            PAGE_POINTER_CALLS.clear();
            PAGE_POINTER_RESULT = core::ptr::addr_of_mut!(cell) as *mut u8;

            let buffer = f.output.as_mut_ptr() as *mut CgCodegenBuffer;
            let label = cg_label_create(f.codegen_ptr());
            f.output[CG_CODEGEN_OUTPUT_OFFSET] = 0x100;
            cg_label_add_fixup(f.codegen_ptr(), label, 1);
            bind_label(label, 0x180); // +0x80 bytes = +0x20 words
            cg_codegen_resolve_label_fixups(f.codegen_ptr());

            *core::ptr::addr_of_mut!(CG_BUFFER_PAGE_POINTER) = saved;

            assert_eq!(cell, 0x1a00_0020, "byte delta >> 2 spliced into imm24");
            assert_eq!(
                PAGE_POINTER_CALLS.as_slice(),
                &[(buffer, 0x100), (buffer, 0x100)],
                "read then write, both at the fixup offset VERBATIM"
            );
        }
        drop(f);
        teardown();
    }

    #[test]
    fn resolve_fixups_patches_a_tag0_literal_offset_keeping_the_top_20_bits() {
        let _g = setup();
        let mut f = Fixture::new(4096);
        let mut cell = 0xe59f_f018u32; // ldr r0, [pc, #0x18]

        unsafe {
            let saved = hook(core::ptr::addr_of!(CG_BUFFER_PAGE_POINTER));
            *core::ptr::addr_of_mut!(CG_BUFFER_PAGE_POINTER) = recording_page_pointer;
            PAGE_POINTER_CALLS.clear();
            PAGE_POINTER_RESULT = core::ptr::addr_of_mut!(cell) as *mut u8;

            let buffer = f.output.as_mut_ptr() as *mut CgCodegenBuffer;
            let label = cg_label_create(f.codegen_ptr());
            f.output[CG_CODEGEN_OUTPUT_OFFSET] = 0x40;
            cg_label_add_fixup(f.codegen_ptr(), label, 0);

            // Forward: label at fixup + 0x18, existing imm12 0x18.
            bind_label(label, 0x58);
            cg_codegen_resolve_label_fixups(f.codegen_ptr());
            assert_eq!(cell, 0xe59f_f030, "imm12 = 0x18 + 0x18, top 20 bits kept");
            assert_eq!(
                PAGE_POINTER_CALLS.as_slice(),
                &[(buffer, 0x40), (buffer, 0x40)],
                "read then write, both at the fixup offset VERBATIM"
            );

            // Backward: label BEFORE the fixup — the byte delta wraps.
            cell = 0xe59f_f010;
            PAGE_POINTER_CALLS.clear();
            bind_label(label, 0x20); // delta = -0x20
            cg_codegen_resolve_label_fixups(f.codegen_ptr());

            *core::ptr::addr_of_mut!(CG_BUFFER_PAGE_POINTER) = saved;

            assert_eq!(
                cell, 0xe59f_fff0,
                "imm12 = (0x10 - 0x20) & 0xfff, wrapping like the target"
            );
            assert_eq!(
                PAGE_POINTER_CALLS.as_slice(),
                &[(buffer, 0x40), (buffer, 0x40)],
                "the re-resolve reads and writes the same word again"
            );
        }
        drop(f);
        teardown();
    }

    #[test]
    fn resolve_fixups_walks_every_label_and_full_fixup_chains() {
        let _g = setup();
        let mut f = Fixture::new(4096);

        unsafe {
            let saved = hook(core::ptr::addr_of!(CG_BUFFER_PAGE_POINTER));
            *core::ptr::addr_of_mut!(CG_BUFFER_PAGE_POINTER) = cooperating_page_pointer;
            core::ptr::write_bytes(core::ptr::addr_of_mut!(COOP_ARENA) as *mut u8, 0, 64);
            let arena = core::ptr::addr_of_mut!(COOP_ARENA) as *mut u32;

            // Two labels on the codegen's list; label_a carries a
            // three-fixup chain (newest first: 0x18, 0x08, 0x00 — the
            // middle one tagged with an encoding the resolver skips).
            let label_a = cg_label_create(f.codegen_ptr());
            let label_b = cg_label_create(f.codegen_ptr());
            f.output[CG_CODEGEN_OUTPUT_OFFSET] = 0x00;
            cg_label_add_fixup(f.codegen_ptr(), label_a, 1);
            f.output[CG_CODEGEN_OUTPUT_OFFSET] = 0x08;
            cg_label_add_fixup(f.codegen_ptr(), label_a, 1);
            f.output[CG_CODEGEN_OUTPUT_OFFSET] = 0x18;
            cg_label_add_fixup(f.codegen_ptr(), label_a, 9); // unknown tag
            f.output[CG_CODEGEN_OUTPUT_OFFSET] = 0x10;
            cg_label_add_fixup(f.codegen_ptr(), label_b, 0);
            f.output[CG_CODEGEN_OUTPUT_OFFSET] = 0x14;
            cg_label_add_fixup(f.codegen_ptr(), label_b, 1);

            arena.add(0x00 / 4).write(0xea00_0000); // b .
            arena.add(0x08 / 4).write(0x5a00_0001); // bpl .+4 (imm 1)
            arena.add(0x10 / 4).write(0xe59f_f000); // ldr r0, [pc, #0]
            arena.add(0x14 / 4).write(0x0a00_0000); // beq .
            arena.add(0x18 / 4).write(0xdead_beef); // unknown-tag word

            bind_label(label_a, 0x20);
            bind_label(label_b, 0x04);
            cg_codegen_resolve_label_fixups(f.codegen_ptr());

            *core::ptr::addr_of_mut!(CG_BUFFER_PAGE_POINTER) = saved;

            assert_eq!(arena.add(0x00 / 4).read(), 0xea00_0008, "+0x20 bytes = 8 words");
            assert_eq!(arena.add(0x08 / 4).read(), 0x5a00_0007, "imm 1 + 6, cond kept");
            assert_eq!(arena.add(0x10 / 4).read(), 0xe59f_fff4, "imm12 = (0 - 0xc) & 0xfff");
            assert_eq!(arena.add(0x14 / 4).read(), 0x0aff_fffc, "-0x10 bytes = -4 words");
            assert_eq!(arena.add(0x18 / 4).read(), 0xdead_beef, "tag 9 is skipped mid-chain");
        }
        drop(f);
        teardown();
    }

    #[test]
    fn resolve_fixups_end_to_end_emits_and_patches_across_a_page_boundary() {
        let _g = setup();
        let mut f = Fixture::new(4096);

        unsafe {
            let saved_alloc = hook(core::ptr::addr_of!(CG_BUFFER_ALLOC));
            *core::ptr::addr_of_mut!(CG_BUFFER_ALLOC) = poisoning_alloc;

            let buffer = f.output.as_mut_ptr() as *mut CgCodegenBuffer;
            let codegen = f.codegen_ptr();
            // Both buffer seams stay at their wired defaults (ported
            // accessor + exact-body page-slot model). Start the run at
            // 0xff8 so the fixup positions straddle the 0x1000 page
            // boundary: two forward branches live in page 0 with their
            // targets in page 1, one backward branch lives in page 1
            // with its target in page 0.
            f.output[CG_CODEGEN_OUTPUT_OFFSET] = 0xff8;

            let forward_a = cg_label_create(codegen);
            cg_label_add_fixup(codegen, forward_a, 1); // fixup @ 0xff8
            cg_buffer_emit_word(buffer, 0xea00_0000); // b . @ 0xff8

            let forward_b = cg_label_create(codegen);
            cg_label_add_fixup(codegen, forward_b, 1); // fixup @ 0xffc
            cg_buffer_emit_word(buffer, 0xea00_0000); // b . @ 0xffc

            let backward = cg_label_create(codegen);
            cg_label_add_fixup(codegen, backward, 1); // fixup @ 0x1000
            cg_buffer_emit_word(buffer, 0xea00_0000); // b . @ 0x1000

            cg_buffer_emit_word(buffer, 0xe3a0_0001); // mov r0, #1 @ 0x1004
            cg_buffer_emit_word(buffer, 0xe3a0_0002); // mov r0, #2 @ 0x1008
            cg_buffer_emit_word(buffer, 0xe3a0_0003); // mov r0, #3 @ 0x100c

            bind_label(forward_a, 0x1010); // +0x18 bytes from 0xff8
            bind_label(forward_b, 0x1004); // +0x08 bytes from 0xffc
            bind_label(backward, 0x0ff8); // -0x08 bytes from 0x1000
            cg_codegen_resolve_label_fixups(codegen);

            assert_eq!(cg_buffer_read_word(buffer, 0x0ff8), 0xea00_0006, "fwd: +6 words");
            assert_eq!(cg_buffer_read_word(buffer, 0x0ffc), 0xea00_0002, "fwd: +2 words");
            assert_eq!(cg_buffer_read_word(buffer, 0x1000), 0xeaff_fffe, "back: -2 words");
            assert_eq!(cg_buffer_read_word(buffer, 0x1004), 0xe3a0_0001, "non-fixup word kept");
            assert_eq!(cg_buffer_read_word(buffer, 0x1008), 0xe3a0_0002, "non-fixup word kept");
            assert_eq!(cg_buffer_read_word(buffer, 0x100c), 0xe3a0_0003, "non-fixup word kept");
            assert_eq!(
                cg_buffer_current_offset(buffer),
                0x1010,
                "the resolver never moves the emit offset"
            );

            *core::ptr::addr_of_mut!(CG_BUFFER_ALLOC) = saved_alloc;
            let record = f.output.as_mut_ptr() as *mut u8;
            for index in 0..=(0x1010usize >> CG_BUFFER_PAGE_SHIFT) {
                let page = slot(record, CG_BUFFER_PAGES + index).read();
                if !page.is_null() {
                    poisoning_free(page);
                }
            }
        }
        drop(f);
        teardown();
    }

    #[test]
    fn proc_create_allocates_from_module_heap_and_prepends() {
        let _g = setup();
        let mut f = Fixture::new(4096);
        assert_eq!(f.module[CG_MODULE_PROCS], 0, "the list starts empty");

        unsafe {
            let block = (*f.heap).current;
            let expected = (*block).base.add((*block).current);
            let before = (*block).current;
            let proc = cg_proc_create(f.module_ptr()) as *mut u8;

            assert_eq!(proc, expected, "the 52-byte record comes from module->heap");
            assert_eq!(
                (*block).current,
                before + stride(CG_PROC_BYTES),
                "cg_heap_alloc advances by its eight-byte-rounded request"
            );
            assert_eq!(
                slot(proc, CG_PROC_NEXT).read(),
                core::ptr::null_mut(),
                "the first procedure's next is the NULL old head"
            );
            assert_eq!(
                f.module[CG_MODULE_PROCS], proc as usize,
                "the new record becomes the module's procedure head"
            );
            assert_eq!(
                slot(proc, CG_PROC_MODULE).read(),
                f.module.as_mut_ptr() as *mut u8,
                "the record back-points to the owning module"
            );
            assert_eq!(
                word(proc, CG_PROC_REGISTERS).read(),
                0,
                "the register list head stays NULL by the arena's zero-fill"
            );
            assert_eq!(
                word(proc, CG_PROC_LAST_REGISTER).read(),
                0,
                "the register list tail stays NULL by the arena's zero-fill"
            );
            assert_eq!(
                word(proc, CG_PROC_NUM_REGISTERS).read(),
                0,
                "the register counter starts at zero"
            );
        }
        drop(f);
        teardown();
    }

    #[test]
    fn proc_create_chains_procedures_newest_first() {
        let _g = setup();
        let mut f = Fixture::new(4096);
        unsafe {
            let first = cg_proc_create(f.module_ptr()) as *mut u8;
            let second = cg_proc_create(f.module_ptr()) as *mut u8;

            assert_eq!(f.module[CG_MODULE_PROCS], second as usize, "head is the newest");
            assert_eq!(
                slot(second, CG_PROC_NEXT).read(),
                first,
                "the second procedure links to the first"
            );
            assert_eq!(
                slot(first, CG_PROC_NEXT).read(),
                core::ptr::null_mut(),
                "the first procedure terminates the list"
            );
            assert_eq!(
                slot(first, CG_PROC_MODULE).read(),
                f.module.as_mut_ptr() as *mut u8,
                "prepending does not disturb an existing record"
            );
        }
        drop(f);
        teardown();
    }

    #[test]
    fn created_proc_accepts_virtual_registers_through_the_matching_layout() {
        // Cross-check against cg_virtual_reg_create: the freshly created
        // procedure must be a legal proc — module back-pointer at +0x04,
        // zeroed register list at +0x10/+0x14, zeroed counter at +0x20.
        let _g = setup();
        let mut f = Fixture::new(4096);
        unsafe {
            let proc = cg_proc_create(f.module_ptr());
            let reg = cg_virtual_reg_create(proc, 7) as *mut u8;

            assert_eq!(
                slot(proc as *mut u8, CG_PROC_REGISTERS).read(),
                reg,
                "the first register becomes the head"
            );
            assert_eq!(
                slot(proc as *mut u8, CG_PROC_LAST_REGISTER).read(),
                reg,
                "...and the tail"
            );
            assert_eq!(
                word(proc as *mut u8, CG_PROC_NUM_REGISTERS).read(),
                1,
                "the counter advanced from its zero-filled start"
            );
            assert_eq!(reg_no(reg as *mut CgVirtualReg), 0, "first number is 0");
            assert_eq!(reg_type(reg as *mut CgVirtualReg), 7);
        }
        drop(f);
        teardown();
    }

    #[test]
    fn the_first_register_becomes_both_head_and_tail() {
        let _g = setup();
        let mut f = Fixture::new(4096);
        unsafe {
            let reg = cg_virtual_reg_create(f.proc_ptr(), 3);
            assert_eq!(f.proc[CG_PROC_REGISTERS], reg as usize, "head");
            assert_eq!(f.proc[CG_PROC_LAST_REGISTER], reg as usize, "tail");
            assert_eq!(f.proc[CG_PROC_NUM_REGISTERS], 1);
            assert_eq!(reg_no(reg), 0, "numbers are handed out pre-increment");
            assert_eq!(reg_type(reg), 3);
            assert!(reg_next(reg).is_null(), "arena zero-fill terminates the list");
        }
        drop(f);
        teardown();
    }

    #[test]
    fn registers_append_in_order_with_ascending_numbers() {
        let _g = setup();
        let mut f = Fixture::new(4096);
        unsafe {
            let mut regs = std::vec::Vec::new();
            for i in 0..5u32 {
                regs.push(cg_virtual_reg_create(f.proc_ptr(), i));
            }
            assert_eq!(f.proc[CG_PROC_NUM_REGISTERS], 5);
            assert_eq!(f.proc[CG_PROC_REGISTERS], regs[0] as usize);
            assert_eq!(f.proc[CG_PROC_LAST_REGISTER], regs[4] as usize);
            for (i, &reg) in regs.iter().enumerate() {
                assert_eq!(reg_no(reg), i, "reg {i} number");
                assert_eq!(reg_type(reg), i as u8, "reg {i} type");
                let expected = regs.get(i + 1).copied().unwrap_or(core::ptr::null_mut());
                assert_eq!(reg_next(reg), expected, "reg {i} link");
            }
        }
        drop(f);
        teardown();
    }

    #[test]
    fn only_the_low_byte_of_the_type_survives() {
        let _g = setup();
        let mut f = Fixture::new(4096);
        unsafe {
            // `strb r5, [r0, #32]`: the argument is truncated.
            let reg = cg_virtual_reg_create(f.proc_ptr(), 0x1234_5678);
            assert_eq!(reg_type(reg), 0x78);
            // ...and it must not have spilled into the neighbouring word.
            assert_eq!(word(reg as *mut u8, CG_VREG_TYPE).read(), 0x78);
        }
        drop(f);
        teardown();
    }

    #[test]
    fn the_register_counter_survives_an_arena_block_boundary() {
        let _g = setup();
        // 40-byte records out of an 80-byte block: every third register
        // forces cg_heap_alloc to push a new block.
        let mut f = Fixture::new(record_size(CG_VREG_BYTES) * 2);
        unsafe {
            let mut regs = std::vec::Vec::new();
            for _ in 0..7 {
                regs.push(cg_virtual_reg_create(f.proc_ptr(), 1));
            }
            assert_eq!(f.proc[CG_PROC_NUM_REGISTERS], 7);
            for (i, &reg) in regs.iter().enumerate() {
                assert_eq!(reg_no(reg), i);
                let expected = regs.get(i + 1).copied().unwrap_or(core::ptr::null_mut());
                assert_eq!(reg_next(reg), expected, "reg {i} link across blocks");
            }
        }
        drop(f);
        teardown();
    }

    #[test]
    fn instructions_append_to_the_block_and_carry_kind_and_opcode() {
        let _g = setup();
        let mut f = Fixture::new(4096);
        unsafe {
            let a = cg_inst_create_base(f.block_ptr(), record_size(20), 6, 0x28);
            let b = cg_inst_create_base(f.block_ptr(), record_size(36), 2, 0x0f);
            assert_eq!(f.block[CG_BLOCK_INSTS], a as usize, "head");
            assert_eq!(f.block[CG_BLOCK_LAST_INST], b as usize, "tail");
            assert_eq!(inst_next(a), b);
            assert!(inst_next(b).is_null());
            assert_eq!(inst_kind(a), 6);
            assert_eq!(inst_opcode(a), 0x28);
            assert_eq!(inst_kind(b), 2);
            assert_eq!(inst_opcode(b), 0x0f);
            for inst in [a, b] {
                assert_eq!(
                    slot(inst as *mut u8, CG_INST_BLOCK).read(),
                    f.block_ptr() as *mut u8,
                    "back-pointer to the owning block"
                );
            }
        }
        drop(f);
        teardown();
    }

    #[test]
    fn kind_and_opcode_are_bytes_that_do_not_disturb_the_block_pointer() {
        let _g = setup();
        let mut f = Fixture::new(4096);
        unsafe {
            let inst = cg_inst_create_base(f.block_ptr(), record_size(36), 0x1ff, 0x2aa);
            assert_eq!(inst_kind(inst), 0xff);
            assert_eq!(inst_opcode(inst), 0xaa);
            assert_eq!(
                slot(inst as *mut u8, CG_INST_BLOCK).read(),
                f.block_ptr() as *mut u8
            );
            assert!(inst_next(inst).is_null());
        }
        drop(f);
        teardown();
    }

    #[test]
    fn binary_stores_dest_and_both_sources_and_leaves_dest_flags_null() {
        let _g = setup();
        let mut f = Fixture::new(4096);
        unsafe {
            let dest = cg_virtual_reg_create(f.proc_ptr(), 1);
            let s0 = cg_virtual_reg_create(f.proc_ptr(), 1);
            let s1 = cg_virtual_reg_create(f.proc_ptr(), 1);
            let inst = cg_create_inst_binary(f.block_ptr(), 0x0f, dest, s0, s1);
            let raw = inst as *mut u8;
            assert_eq!(inst_kind(inst), CG_INST_KIND_BINARY as u8);
            assert_eq!(inst_opcode(inst), 0x0f);
            assert_eq!(slot(raw, CG_INST_BINARY_DEST).read(), dest as *mut u8);
            assert_eq!(slot(raw, CG_INST_BINARY_SOURCE0).read(), s0 as *mut u8);
            assert_eq!(slot(raw, CG_INST_BINARY_SOURCE1).read(), s1 as *mut u8);
            // +0x10 (dest_flags) is untouched, so the arena's zero shows.
            assert!(slot(raw, 4).read().is_null(), "dest_flags stays NULL");
            assert_eq!(f.block[CG_BLOCK_INSTS], inst as usize);
        }
        drop(f);
        teardown();
    }

    #[test]
    fn load_immed_stores_dest_and_value() {
        let _g = setup();
        let mut f = Fixture::new(4096);
        unsafe {
            let dest = cg_virtual_reg_create(f.proc_ptr(), 2);
            let inst = cg_create_inst_load_immed(f.block_ptr(), 0x28, dest, 0);
            let raw = inst as *mut u8;
            assert_eq!(inst_kind(inst), CG_INST_KIND_LOAD_IMMED as u8);
            assert_eq!(inst_opcode(inst), 0x28);
            assert_eq!(slot(raw, CG_INST_LOAD_IMMED_DEST).read(), dest as *mut u8);
            assert_eq!(word(raw, CG_INST_LOAD_IMMED_VALUE).read(), 0);

            let other = cg_create_inst_load_immed(f.block_ptr(), 0x28, dest, 0xdead_beef);
            assert_eq!(word(other as *mut u8, CG_INST_LOAD_IMMED_VALUE).read(), 0xdead_beef);
            assert_eq!(inst_next(inst), other);
        }
        drop(f);
        teardown();
    }

    #[test]
    fn unary_stores_dest_and_source_and_leaves_word4_null() {
        let _g = setup();
        let mut f = Fixture::new(4096);
        unsafe {
            let dest = cg_virtual_reg_create(f.proc_ptr(), 1);
            let source = cg_virtual_reg_create(f.proc_ptr(), 1);
            let inst = cg_create_inst_unary(f.block_ptr(), 0x1a, dest, source);
            let raw = inst as *mut u8;
            assert_eq!(inst_kind(inst), CG_INST_KIND_UNARY as u8);
            assert_eq!(inst_opcode(inst), 0x1a);
            assert_eq!(slot(raw, CG_INST_UNARY_DEST).read(), dest as *mut u8);
            assert_eq!(slot(raw, CG_INST_UNARY_SOURCE).read(), source as *mut u8);
            assert!(slot(raw, 4).read().is_null(), "+0x10 stays NULL");
            assert_eq!(f.block[CG_BLOCK_INSTS], inst as usize);
        }
        drop(f);
        teardown();
    }

    #[test]
    fn binary_s_fills_all_four_derived_fields() {
        let _g = setup();
        let mut f = Fixture::new(4096);
        unsafe {
            let dest = cg_virtual_reg_create(f.proc_ptr(), 1);
            let flags = cg_virtual_reg_create(f.proc_ptr(), 1);
            let s0 = cg_virtual_reg_create(f.proc_ptr(), 1);
            let s1 = cg_virtual_reg_create(f.proc_ptr(), 1);
            let inst = cg_create_inst_binary_s(f.block_ptr(), 0x0f, dest, flags, s0, s1);
            let raw = inst as *mut u8;
            assert_eq!(inst_kind(inst), CG_INST_KIND_BINARY_S as u8);
            assert_eq!(inst_opcode(inst), 0x0f);
            assert_eq!(slot(raw, CG_INST_BINARY_DEST).read(), dest as *mut u8);
            assert_eq!(slot(raw, CG_INST_BINARY_DEST_FLAGS).read(), flags as *mut u8);
            assert_eq!(slot(raw, CG_INST_BINARY_SOURCE0).read(), s0 as *mut u8);
            assert_eq!(slot(raw, CG_INST_BINARY_SOURCE1).read(), s1 as *mut u8);
        }
        drop(f);
        teardown();
    }

    #[test]
    fn compare_packs_dest_and_both_sources_one_word_earlier_than_binary() {
        let _g = setup();
        let mut f = Fixture::new(4096);
        unsafe {
            let dest = cg_virtual_reg_create(f.proc_ptr(), 1);
            let s0 = cg_virtual_reg_create(f.proc_ptr(), 1);
            let s1 = cg_virtual_reg_create(f.proc_ptr(), 1);
            let inst = cg_create_inst_compare(f.block_ptr(), 0x30, dest, s0, s1);
            let raw = inst as *mut u8;
            assert_eq!(inst_kind(inst), CG_INST_KIND_COMPARE as u8);
            assert_eq!(inst_opcode(inst), 0x30);
            assert_eq!(slot(raw, CG_INST_COMPARE_DEST).read(), dest as *mut u8);
            assert_eq!(slot(raw, CG_INST_COMPARE_SOURCE0).read(), s0 as *mut u8);
            assert_eq!(slot(raw, CG_INST_COMPARE_SOURCE1).read(), s1 as *mut u8);
            assert!(slot(raw, 6).read().is_null(), "+0x18 stays NULL");
        }
        drop(f);
        teardown();
    }

    #[test]
    fn load_stores_dest_and_address() {
        let _g = setup();
        let mut f = Fixture::new(4096);
        unsafe {
            let dest = cg_virtual_reg_create(f.proc_ptr(), 1);
            let address = cg_virtual_reg_create(f.proc_ptr(), 1);
            let inst = cg_create_inst_load(f.block_ptr(), 0x29, dest, address);
            let raw = inst as *mut u8;
            assert_eq!(inst_kind(inst), CG_INST_KIND_LOAD as u8);
            assert_eq!(inst_opcode(inst), 0x29);
            assert_eq!(slot(raw, CG_INST_LOAD_DEST).read(), dest as *mut u8);
            assert_eq!(slot(raw, CG_INST_LOAD_ADDRESS).read(), address as *mut u8);
            assert!(slot(raw, 5).read().is_null(), "+0x14 stays NULL");
        }
        drop(f);
        teardown();
    }

    #[test]
    fn store_stores_value_and_address() {
        let _g = setup();
        let mut f = Fixture::new(4096);
        unsafe {
            let value = cg_virtual_reg_create(f.proc_ptr(), 1);
            let address = cg_virtual_reg_create(f.proc_ptr(), 1);
            let inst = cg_create_inst_store(f.block_ptr(), 0x2b, value, address);
            let raw = inst as *mut u8;
            assert_eq!(inst_kind(inst), CG_INST_KIND_STORE as u8);
            assert_eq!(inst_opcode(inst), 0x2b);
            assert_eq!(slot(raw, CG_INST_STORE_VALUE).read(), value as *mut u8);
            assert_eq!(slot(raw, CG_INST_STORE_ADDRESS).read(), address as *mut u8);
            assert!(slot(raw, 5).read().is_null(), "+0x14 stays NULL");
        }
        drop(f);
        teardown();
    }

    #[test]
    fn branch_label_stores_only_the_target() {
        let _g = setup();
        let mut f = Fixture::new(4096);
        unsafe {
            let inst = cg_create_inst_branch_label(f.block_ptr(), 0x40, f.block_ptr());
            let raw = inst as *mut u8;
            assert_eq!(inst_kind(inst), CG_INST_KIND_BRANCH_LABEL as u8);
            assert_eq!(inst_opcode(inst), 0x40);
            assert_eq!(slot(raw, CG_INST_BRANCH_LABEL_TARGET).read(), f.block_ptr() as *mut u8);
            assert!(slot(raw, 4).read().is_null(), "+0x10 stays NULL");
        }
        drop(f);
        teardown();
    }

    #[test]
    fn branch_cond_swaps_its_two_derived_fields() {
        // The original stores the THIRD argument at +0x10 and the
        // FOURTH at +0xc — the opposite of every sibling factory.
        let _g = setup();
        let mut f = Fixture::new(4096);
        unsafe {
            let condition = cg_virtual_reg_create(f.proc_ptr(), 1);
            let inst = cg_create_inst_branch_cond(f.block_ptr(), 0x41, condition, f.block_ptr());
            let raw = inst as *mut u8;
            assert_eq!(inst_kind(inst), CG_INST_KIND_BRANCH_COND as u8);
            assert_eq!(inst_opcode(inst), 0x41);
            assert_eq!(slot(raw, CG_INST_BRANCH_COND_CONDITION).read(), condition as *mut u8);
            assert_eq!(slot(raw, CG_INST_BRANCH_COND_TARGET).read(), f.block_ptr() as *mut u8);
        }
        drop(f);
        teardown();
    }

    #[test]
    fn phi_stores_dest_and_the_register_list() {
        let _g = setup();
        let mut f = Fixture::new(4096);
        unsafe {
            let dest = cg_virtual_reg_create(f.proc_ptr(), 1);
            let list = [0usize; 2];
            let inst = cg_create_inst_phi(
                f.block_ptr(),
                0x50,
                dest,
                list.as_ptr() as *mut CgVirtualRegList,
            );
            let raw = inst as *mut u8;
            assert_eq!(inst_kind(inst), CG_INST_KIND_PHI as u8);
            assert_eq!(inst_opcode(inst), 0x50);
            assert_eq!(slot(raw, CG_INST_PHI_DEST).read(), dest as *mut u8);
            assert_eq!(slot(raw, CG_INST_PHI_REGS).read(), list.as_ptr() as *mut u8);
        }
        drop(f);
        teardown();
    }

    #[test]
    fn ret_carries_no_derived_fields() {
        let _g = setup();
        let mut f = Fixture::new(4096);
        unsafe {
            let inst = cg_create_inst_ret(f.block_ptr(), 0x60);
            let raw = inst as *mut u8;
            assert_eq!(inst_kind(inst), CG_INST_KIND_RET as u8);
            assert_eq!(inst_opcode(inst), 0x60);
            assert!(slot(raw, 3).read().is_null(), "+0x0c stays NULL");
            assert_eq!(f.block[CG_BLOCK_INSTS], inst as usize);
        }
        drop(f);
        teardown();
    }

    #[test]
    fn ret_value_stores_the_returned_register() {
        let _g = setup();
        let mut f = Fixture::new(4096);
        unsafe {
            let value = cg_virtual_reg_create(f.proc_ptr(), 1);
            let inst = cg_create_inst_ret_value(f.block_ptr(), 0x60, value);
            let raw = inst as *mut u8;
            assert_eq!(inst_kind(inst), CG_INST_KIND_RET as u8);
            assert_eq!(inst_opcode(inst), 0x60);
            assert_eq!(slot(raw, CG_INST_RET_VALUE_VALUE).read(), value as *mut u8);
        }
        drop(f);
        teardown();
    }

    #[test]
    fn the_whole_family_appends_in_call_order() {
        let _g = setup();
        let mut f = Fixture::new(4096);
        unsafe {
            let r0 = cg_virtual_reg_create(f.proc_ptr(), 1);
            let r1 = cg_virtual_reg_create(f.proc_ptr(), 1);
            let insts = [
                cg_create_inst_unary(f.block_ptr(), 0x1a, r0, r1),
                cg_create_inst_binary_s(f.block_ptr(), 0x0f, r0, r1, r0, r1),
                cg_create_inst_compare(f.block_ptr(), 0x30, r0, r1, r0),
                cg_create_inst_load(f.block_ptr(), 0x29, r0, r1),
                cg_create_inst_store(f.block_ptr(), 0x2b, r0, r1),
                cg_create_inst_branch_label(f.block_ptr(), 0x40, f.block_ptr()),
                cg_create_inst_branch_cond(f.block_ptr(), 0x41, r0, f.block_ptr()),
                cg_create_inst_phi(f.block_ptr(), 0x50, r0, core::ptr::null_mut()),
                cg_create_inst_ret(f.block_ptr(), 0x60),
                cg_create_inst_ret_value(f.block_ptr(), 0x60, r0),
            ];
            assert_eq!(f.block[CG_BLOCK_INSTS], insts[0] as usize, "head");
            assert_eq!(f.block[CG_BLOCK_LAST_INST], insts[9] as usize, "tail");
            for pair in insts.windows(2) {
                assert_eq!(inst_next(pair[0]), pair[1]);
            }
            assert!(inst_next(insts[9]).is_null());
        }
        drop(f);
        teardown();
    }

    #[test]
    fn reg_list_of_no_registers_is_null() {
        let _g = setup();
        let mut f = Fixture::new(4096);
        unsafe {
            let args = [core::ptr::null_mut::<CgVirtualReg>()];
            let list = cg_virtual_reg_list_create(f.heap, args.as_ptr());
            assert!(list.is_null(), "first entry NULL -> NULL head");
        }
        drop(f);
        teardown();
    }

    #[test]
    fn reg_list_chains_cells_in_argument_order_and_null_terminates() {
        let _g = setup();
        let mut f = Fixture::new(4096);
        unsafe {
            let r0 = cg_virtual_reg_create(f.proc_ptr(), 1);
            let r1 = cg_virtual_reg_create(f.proc_ptr(), 1);
            let r2 = cg_virtual_reg_create(f.proc_ptr(), 1);
            let args = [r0, r1, r2, core::ptr::null_mut()];
            let head = cg_virtual_reg_list_create(f.heap, args.as_ptr()) as *mut u8;
            assert!(!head.is_null());

            let regs = [r0, r1, r2];
            let mut cell = head;
            for (i, &reg) in regs.iter().enumerate() {
                assert_eq!(
                    slot(cell, CG_VREG_LIST_REG).read(),
                    reg as *mut u8,
                    "cell {i} holds argument {i}"
                );
                let next = slot(cell, CG_VREG_LIST_NEXT).read();
                if i + 1 < regs.len() {
                    assert!(!next.is_null(), "cell {i} links onward");
                    // Cells are contiguous 8-byte arena carvings.
                    assert_eq!(
                        next as usize - cell as usize,
                        stride(CG_VREG_LIST_BYTES),
                        "cell {i} stride"
                    );
                    cell = next;
                } else {
                    assert!(next.is_null(), "last cell's next is NULL by zero-fill");
                }
            }
        }
        drop(f);
        teardown();
    }

    #[test]
    fn reg_list_single_register_is_a_single_unlinked_cell() {
        let _g = setup();
        let mut f = Fixture::new(4096);
        unsafe {
            let r0 = cg_virtual_reg_create(f.proc_ptr(), 1);
            let args = [r0, core::ptr::null_mut()];
            let cell = cg_virtual_reg_list_create(f.heap, args.as_ptr()) as *mut u8;
            assert!(!cell.is_null());
            assert_eq!(slot(cell, CG_VREG_LIST_REG).read(), r0 as *mut u8);
            assert!(slot(cell, CG_VREG_LIST_NEXT).read().is_null());
        }
        drop(f);
        teardown();
    }

    #[test]
    fn reg_list_stops_at_the_first_null_entry() {
        let _g = setup();
        let mut f = Fixture::new(4096);
        unsafe {
            let r0 = cg_virtual_reg_create(f.proc_ptr(), 1);
            let r1 = cg_virtual_reg_create(f.proc_ptr(), 1);
            // The NULL at index 1 ends the walk; r1 must never be read.
            let args = [r0, core::ptr::null_mut(), r1];
            let head = cg_virtual_reg_list_create(f.heap, args.as_ptr()) as *mut u8;
            assert_eq!(slot(head, CG_VREG_LIST_REG).read(), r0 as *mut u8);
            assert!(slot(head, CG_VREG_LIST_NEXT).read().is_null());
        }
        drop(f);
        teardown();
    }

    #[test]
    fn reg_list_feeds_a_phi_instruction() {
        let _g = setup();
        let mut f = Fixture::new(4096);
        unsafe {
            let dest = cg_virtual_reg_create(f.proc_ptr(), 1);
            let r0 = cg_virtual_reg_create(f.proc_ptr(), 1);
            let r1 = cg_virtual_reg_create(f.proc_ptr(), 1);
            let args = [r0, r1, core::ptr::null_mut()];
            let list = cg_virtual_reg_list_create(f.heap, args.as_ptr());
            let inst = cg_create_inst_phi(f.block_ptr(), 0x2f, dest, list);
            assert_eq!(
                slot(inst as *mut u8, CG_INST_PHI_REGS).read(),
                list as *mut u8,
                "the phi records the list head, as at every stock call site"
            );
            assert_eq!(slot(list as *mut u8, CG_VREG_LIST_REG).read(), r0 as *mut u8);
        }
        drop(f);
        teardown();
    }

    /// The emission sequence of the pipeline generator @ 0x0823a6ac,
    /// transcribed from its disassembly: two fresh registers, a
    /// load-immediate of 0 into the first, then two binary instructions.
    #[test]
    fn reproduces_the_emission_sequence_of_the_generator_at_0x0823a6ac() {
        let _g = setup();
        let mut f = Fixture::new(4096);
        unsafe {
            let zero = cg_virtual_reg_create(f.proc_ptr(), 0);
            let tmp = cg_virtual_reg_create(f.proc_ptr(), 0);
            let a = cg_virtual_reg_create(f.proc_ptr(), 0);
            let b = cg_virtual_reg_create(f.proc_ptr(), 0);
            let c = cg_virtual_reg_create(f.proc_ptr(), 0);

            let i0 = cg_create_inst_load_immed(f.block_ptr(), 0x28, zero, 0);
            let i1 = cg_create_inst_binary(f.block_ptr(), 0x0f, tmp, a, c);
            let i2 = cg_create_inst_binary(f.block_ptr(), 0x10, b, tmp, zero);

            assert_eq!(f.proc[CG_PROC_NUM_REGISTERS], 5);
            assert_eq!(reg_no(zero), 0);
            assert_eq!(reg_no(c), 4);
            assert_eq!(f.block[CG_BLOCK_INSTS], i0 as usize);
            assert_eq!(f.block[CG_BLOCK_LAST_INST], i2 as usize);
            assert_eq!(inst_next(i0), i1);
            assert_eq!(inst_next(i1), i2);
            assert!(inst_next(i2).is_null());
            // The records are distinct, contiguous arena carvings, each
            // taking its record size rounded up to 8.
            assert_eq!(
                i1 as usize - i0 as usize,
                stride(CG_INST_LOAD_IMMED_BYTES),
                "load_immed record stride"
            );
            assert_eq!(
                i2 as usize - i1 as usize,
                stride(CG_INST_BINARY_BYTES),
                "binary record stride"
            );
        }
        drop(f);
        teardown();
    }

    // --- cg_inst_visit_by_kind ------------------------------------------

    /// Fabricates a raw instruction record with the given kind byte and
    /// +0xc/+0x10/+0x14 words — for the kinds no factory emits (0, 10,
    /// 12-22 and out-of-range values).
    fn raw_inst(kind: u8, def0: usize, def1: usize, kind10_def: usize) -> [usize; 6] {
        let mut record = [0usize; 6];
        record[CG_INST_DEF0] = def0;
        record[CG_INST_DEF1] = def1;
        record[CG_INST_KIND10_DEF] = kind10_def;
        unsafe {
            (record.as_mut_ptr() as *mut u8)
                .add(CG_INST_KIND * WORD)
                .write(kind);
        }
        record
    }

    /// Runs the visitor over `inst` into a 4-slot output array; returns
    /// the array and how many slots the returned cursor covers.
    unsafe fn visit4(inst: *mut CgInst) -> ([*mut CgVirtualReg; 4], usize) {
        let mut out = [core::ptr::null_mut::<CgVirtualReg>(); 4];
        let base = out.as_mut_ptr();
        let cursor = cg_inst_visit_by_kind(inst, base, base.add(4));
        (out, cursor.offset_from(base) as usize)
    }

    /// Runs the used-register collector over `inst` into a 4-slot output
    /// array; returns the array and how many slots the returned cursor covers.
    unsafe fn collect4(inst: *mut CgInst) -> ([*mut CgVirtualReg; 4], usize) {
        let mut out = [core::ptr::null_mut::<CgVirtualReg>(); 4];
        let base = out.as_mut_ptr();
        let cursor = cg_inst_collect_used_regs(inst, base, base.add(4));
        (out, cursor.offset_from(base) as usize)
    }

    /// Builds the eight words needed by the largest recovered input layout:
    /// kind plus the five candidate source slots at +0xc through +0x1c.
    unsafe fn collect_raw_used(
        kind: u8,
        source_words: [usize; 5],
    ) -> ([*mut CgVirtualReg; 4], usize) {
        let mut record = [0usize; 8];
        record[CG_INST_DEF0..=CG_INST_KIND16_SOURCE2].copy_from_slice(&source_words);
        (record.as_mut_ptr() as *mut u8)
            .add(CG_INST_KIND * WORD)
            .write(kind);
        collect4(record.as_mut_ptr() as *mut CgInst)
    }

    #[test]
    fn unary_and_binary_visit_their_dest_and_skip_the_null_dest_flags() {
        let _g = setup();
        let mut f = Fixture::new(4096);
        unsafe {
            let dest = cg_virtual_reg_create(f.proc_ptr(), 1);
            let source = cg_virtual_reg_create(f.proc_ptr(), 1);
            let unary = cg_create_inst_unary(f.block_ptr(), 0x1a, dest, source);
            let (out, count) = visit4(unary);
            assert_eq!(count, 1, "unary defines one register");
            assert_eq!(out[0], dest);

            let s1 = cg_virtual_reg_create(f.proc_ptr(), 1);
            let binary = cg_create_inst_binary(f.block_ptr(), 0x0f, dest, source, s1);
            let (out, count) = visit4(binary);
            assert_eq!(count, 1, "binary's dest_flags slot is NULL by zero-fill");
            assert_eq!(out[0], dest);
        }
        drop(f);
        teardown();
    }

    #[test]
    fn binary_s_visits_dest_then_dest_flags() {
        let _g = setup();
        let mut f = Fixture::new(4096);
        unsafe {
            let dest = cg_virtual_reg_create(f.proc_ptr(), 1);
            let flags = cg_virtual_reg_create(f.proc_ptr(), 1);
            let s0 = cg_virtual_reg_create(f.proc_ptr(), 1);
            let s1 = cg_virtual_reg_create(f.proc_ptr(), 1);
            let inst = cg_create_inst_binary_s(f.block_ptr(), 0x0f, dest, flags, s0, s1);
            let (out, count) = visit4(inst);
            assert_eq!(count, 2);
            assert_eq!(out[0], dest, "+0xc first");
            assert_eq!(out[1], flags, "+0x10 second");
        }
        drop(f);
        teardown();
    }

    #[test]
    fn compare_load_load_immed_and_phi_visit_their_dest() {
        let _g = setup();
        let mut f = Fixture::new(4096);
        unsafe {
            let dest = cg_virtual_reg_create(f.proc_ptr(), 1);
            let src = cg_virtual_reg_create(f.proc_ptr(), 1);
            let insts = [
                cg_create_inst_compare(f.block_ptr(), 0x30, dest, src, src),
                cg_create_inst_load(f.block_ptr(), 0x29, dest, src),
                cg_create_inst_load_immed(f.block_ptr(), 0x28, dest, 42),
                cg_create_inst_phi(f.block_ptr(), 0x50, dest, core::ptr::null_mut()),
            ];
            for (i, &inst) in insts.iter().enumerate() {
                let (out, count) = visit4(inst);
                assert_eq!(count, 1, "inst {i} defines one register");
                assert_eq!(out[0], dest, "inst {i} dest");
            }
        }
        drop(f);
        teardown();
    }

    #[test]
    fn store_branches_and_rets_define_no_register() {
        let _g = setup();
        let mut f = Fixture::new(4096);
        unsafe {
            let reg = cg_virtual_reg_create(f.proc_ptr(), 1);
            let insts = [
                cg_create_inst_store(f.block_ptr(), 0x2b, reg, reg),
                cg_create_inst_branch_label(f.block_ptr(), 0x40, f.block_ptr()),
                cg_create_inst_branch_cond(f.block_ptr(), 0x41, reg, f.block_ptr()),
                cg_create_inst_ret(f.block_ptr(), 0x60),
                cg_create_inst_ret_value(f.block_ptr(), 0x60, reg),
            ];
            for (i, &inst) in insts.iter().enumerate() {
                let (_, count) = visit4(inst);
                assert_eq!(count, 0, "inst {i} defines nothing");
            }
        }
        drop(f);
        teardown();
    }

    #[test]
    fn kind_zero_and_kinds_past_22_visit_nothing() {
        // Distinct sentinels in every slot the visitor could read.
        for kind in [0u8, 23, 100, 255] {
            let mut record = raw_inst(kind, 0xaaaa, 0xbbbb, 0xcccc);
            unsafe {
                let (_, count) = visit4(record.as_mut_ptr() as *mut CgInst);
                assert_eq!(count, 0, "kind {kind} defines nothing");
            }
        }
    }

    #[test]
    fn kind_10_visits_word_0x14_only_when_non_null() {
        let _g = setup();
        let mut f = Fixture::new(4096);
        unsafe {
            let reg = cg_virtual_reg_create(f.proc_ptr(), 1);
            // +0x14 NULL: nothing, even with garbage in +0xc/+0x10.
            let mut null_case = raw_inst(10, 0xaaaa, 0xbbbb, 0);
            let (_, count) = visit4(null_case.as_mut_ptr() as *mut CgInst);
            assert_eq!(count, 0, "+0x14 NULL -> no append");
            // +0x14 set: appended; +0xc/+0x10 are never touched.
            let mut set_case = raw_inst(10, 0xaaaa, 0xbbbb, reg as usize);
            let (out, count) = visit4(set_case.as_mut_ptr() as *mut CgInst);
            assert_eq!(count, 1);
            assert_eq!(out[0], reg);
        }
        drop(f);
        teardown();
    }

    #[test]
    fn kinds_12_to_17_visit_reg0_then_reg1_when_non_null() {
        let _g = setup();
        let mut f = Fixture::new(4096);
        unsafe {
            let r0 = cg_virtual_reg_create(f.proc_ptr(), 1);
            let r1 = cg_virtual_reg_create(f.proc_ptr(), 1);
            for kind in 12..=17u8 {
                let mut one = raw_inst(kind, r0 as usize, 0, 0xcccc);
                let (out, count) = visit4(one.as_mut_ptr() as *mut CgInst);
                assert_eq!(count, 1, "kind {kind} with NULL +0x10");
                assert_eq!(out[0], r0);

                let mut two = raw_inst(kind, r0 as usize, r1 as usize, 0xcccc);
                let (out, count) = visit4(two.as_mut_ptr() as *mut CgInst);
                assert_eq!(count, 2, "kind {kind} with +0x10 set");
                assert_eq!(out[0], r0);
                assert_eq!(out[1], r1);
            }
        }
        drop(f);
        teardown();
    }

    #[test]
    fn kinds_18_to_22_visit_only_reg0() {
        let _g = setup();
        let mut f = Fixture::new(4096);
        unsafe {
            let r0 = cg_virtual_reg_create(f.proc_ptr(), 1);
            for kind in 18..=22u8 {
                // +0x10 and +0x14 deliberately non-NULL: not read.
                let mut record = raw_inst(kind, r0 as usize, 0xbbbb, 0xcccc);
                let (out, count) = visit4(record.as_mut_ptr() as *mut CgInst);
                assert_eq!(count, 1, "kind {kind}");
                assert_eq!(out[0], r0);
            }
        }
        drop(f);
        teardown();
    }

    #[test]
    fn the_reg0_store_is_not_null_checked() {
        // `strne r0, [r1], #4` stores whatever +0xc holds — even NULL.
        let mut record = raw_inst(CG_INST_KIND_COMPARE as u8, 0, 0xbbbb, 0xcccc);
        unsafe {
            let (out, count) = visit4(record.as_mut_ptr() as *mut CgInst);
            assert_eq!(count, 1);
            assert!(out[0].is_null(), "a NULL +0xc lands in the array as-is");
        }
    }

    // --- cg_inst_collect_used_regs -------------------------------------

    #[test]
    fn used_collector_reads_factory_inputs_and_preserves_their_order() {
        let _g = setup();
        let mut f = Fixture::new(4096);
        unsafe {
            let dest = cg_virtual_reg_create(f.proc_ptr(), 1);
            let r0 = cg_virtual_reg_create(f.proc_ptr(), 1);
            let r1 = cg_virtual_reg_create(f.proc_ptr(), 1);
            let r2 = cg_virtual_reg_create(f.proc_ptr(), 1);
            let regs = [r0, r1, core::ptr::null_mut()];
            let list = cg_virtual_reg_list_create(f.heap, regs.as_ptr());
            let insts: [(*mut CgInst, &[*mut CgVirtualReg]); 10] = [
                (cg_create_inst_unary(f.block_ptr(), 0x1a, dest, r0), &[r0]),
                (cg_create_inst_binary(f.block_ptr(), 0x0f, dest, r0, r1), &[r0, r1]),
                (cg_create_inst_compare(f.block_ptr(), 0x30, dest, r0, r1), &[r0, r1]),
                (cg_create_inst_load(f.block_ptr(), 0x29, dest, r0), &[r0]),
                (cg_create_inst_store(f.block_ptr(), 0x2b, r0, r1), &[r0, r1]),
                (cg_create_inst_load_immed(f.block_ptr(), 0x28, dest, 42), &[]),
                (cg_create_inst_branch_label(f.block_ptr(), 0x40, f.block_ptr()), &[]),
                (cg_create_inst_branch_cond(f.block_ptr(), 0x41, r0, f.block_ptr()), &[r0]),
                (cg_create_inst_phi(f.block_ptr(), 0x50, dest, list), &[r0, r1]),
                (cg_create_inst_ret_value(f.block_ptr(), 0x60, r2), &[r2]),
            ];
            for (i, &(inst, expected)) in insts.iter().enumerate() {
                let (out, count) = collect4(inst);
                assert_eq!(count, expected.len(), "factory kind class {i}");
                assert_eq!(&out[..count], expected, "factory kind class {i}");
            }
            let (out, count) = collect4(cg_create_inst_ret(f.block_ptr(), 0x60));
            assert_eq!(count, 0, "ret without a value is optional");
            assert!(out[0].is_null());
        }
        drop(f);
        teardown();
    }

    #[test]
    fn used_collector_dispatches_every_unrecovered_kind_class() {
        let _g = setup();
        let mut f = Fixture::new(4096);
        unsafe {
            let r0 = cg_virtual_reg_create(f.proc_ptr(), 1);
            let r1 = cg_virtual_reg_create(f.proc_ptr(), 1);
            let r2 = cg_virtual_reg_create(f.proc_ptr(), 1);
            let r3 = cg_virtual_reg_create(f.proc_ptr(), 1);
            for kind in [1, 14, 15] {
                let (out, count) = collect_raw_used(kind, [0, 0, r0 as usize, r1 as usize, r2 as usize]);
                assert_eq!((&out[..count], count), (&[r0][..], 1), "kind {kind}");
            }
            for kind in [2, 13, 17] {
                let (out, count) = collect_raw_used(kind, [0, 0, r0 as usize, r1 as usize, r2 as usize]);
                assert_eq!((&out[..count], count), (&[r0, r1][..], 2), "kind {kind}");
            }
            for kind in [3, 20, 22] {
                let (out, count) = collect_raw_used(kind, [0, r0 as usize, r1 as usize, r2 as usize, 0]);
                assert_eq!((&out[..count], count), (&[r0, r1][..], 2), "kind {kind}");
            }
            for kind in [4, 8, 18, 21] {
                let (out, count) = collect_raw_used(kind, [r3 as usize, r0 as usize, r1 as usize, 0, 0]);
                assert_eq!((&out[..count], count), (&[r0][..], 1), "kind {kind}");
            }
            for kind in [5, 19, 23] {
                let (out, count) = collect_raw_used(kind, [r0 as usize, r1 as usize, r2 as usize, 0, 0]);
                assert_eq!((&out[..count], count), (&[r0, r1][..], 2), "kind {kind}");
            }
            let (out, count) = collect_raw_used(16, [0, 0, r0 as usize, r1 as usize, r2 as usize]);
            assert_eq!((&out[..count], count), (&[r0, r1, r2][..], 3));
            let (out, count) = collect_raw_used(24, [r0 as usize, r1 as usize, r2 as usize, r3 as usize, 0]);
            assert_eq!((&out[..count], count), (&[r0, r1, r2][..], 3));
        }
        drop(f);
        teardown();
    }

    #[test]
    fn used_collector_handles_list_empty_and_out_of_range_kinds() {
        let _g = setup();
        let mut f = Fixture::new(4096);
        unsafe {
            let r0 = cg_virtual_reg_create(f.proc_ptr(), 1);
            let r1 = cg_virtual_reg_create(f.proc_ptr(), 1);
            let cells = [r0, r1, core::ptr::null_mut()];
            let list = cg_virtual_reg_list_create(f.heap, cells.as_ptr()) as usize;
            for kind in [9, 10] {
                let (out, count) = collect_raw_used(kind, [0, list, 0, 0, 0]);
                assert_eq!((&out[..count], count), (&[r0, r1][..], 2), "kind {kind} list");
            }
            for kind in [9, 10] {
                let (out, count) = collect_raw_used(kind, [0, 0, r0 as usize, r1 as usize, 0]);
                assert_eq!(count, 0, "kind {kind} NULL list is empty");
                assert!(out[0].is_null());
            }
            for kind in [0, 6, 7, 12, 25, 100, 255] {
                let (out, count) =
                    collect_raw_used(kind, [r0 as usize, r1 as usize, r0 as usize, r1 as usize, r0 as usize]);
                assert_eq!(count, 0, "kind {kind} has no input");
                assert!(out[0].is_null());
            }
            let (out, count) = collect_raw_used(11, [0, r0 as usize, r1 as usize, 0, 0]);
            assert_eq!(count, 0, "NULL return-value slot is not appended");
            assert!(out[0].is_null());
        }
        drop(f);
        teardown();
    }

    #[test]
    fn used_collector_stores_selected_nulls_and_stops_at_the_bound() {
        let mut record = [0usize; 8];
        record[CG_INST_DEF0] = 0xaaaa;
        record[CG_INST_DEF1] = 0xbbbb;
        record[CG_INST_KIND10_DEF] = 0xcccc;
        unsafe {
            (record.as_mut_ptr() as *mut u8)
                .add(CG_INST_KIND * WORD)
                .write(24);
            let mut out = [0x5cusize as *mut CgVirtualReg; 3];
            let base = out.as_mut_ptr();
            let cursor = cg_inst_collect_used_regs(record.as_mut_ptr() as *mut CgInst, base, base);
            assert_eq!(cursor, base);
            assert_eq!(out, [0x5cusize as *mut CgVirtualReg; 3], "full output remains untouched");

            let cursor =
                cg_inst_collect_used_regs(record.as_mut_ptr() as *mut CgInst, base, base.add(1));
            assert_eq!(cursor, base.add(1));
            assert_eq!(out[0], 0xaaaa as *mut CgVirtualReg, "first source wins");
            assert_eq!(out[1], 0x5c as *mut CgVirtualReg, "later sources are dropped");

            let (out, count) = collect_raw_used(1, [0, 0, 0, 0, 0]);
            assert_eq!(count, 1, "selected NULL still consumes bounded capacity");
            assert!(out[0].is_null());
        }
    }

    // --- cg_reg_append_bounded ----------------------------------------

    #[test]
    fn append_bounded_stores_and_advances_while_room_remains() {
        let mut out = [core::ptr::null_mut::<CgVirtualReg>(); 3];
        let base = out.as_mut_ptr();
        let values = [1usize as *mut CgVirtualReg, 2 as *mut CgVirtualReg];
        unsafe {
            let cursor = cg_reg_append_bounded(values[0], base, base.add(3));
            assert_eq!(cursor, base.add(1), "cursor advanced one slot");
            assert_eq!(out[0], values[0], "value stored at the old cursor");
            let cursor = cg_reg_append_bounded(values[1], cursor, base.add(3));
            assert_eq!(cursor, base.add(2));
            assert_eq!(out[1], values[1]);
            assert!(out[2].is_null(), "the untouched slot is undisturbed");
        }
    }

    #[test]
    fn append_bounded_at_end_stores_nothing_and_returns_the_cursor() {
        let mut out = [0x5cusize as *mut CgVirtualReg; 1];
        let base = out.as_mut_ptr();
        unsafe {
            // cursor == end: `cmp r1, r2` is equal, the strne never fires.
            let cursor = cg_reg_append_bounded(1 as *mut CgVirtualReg, base, base);
            assert_eq!(cursor, base, "cursor returned unchanged");
            assert_eq!(out[0], 0x5c as *mut CgVirtualReg, "nothing stored");
            // Same one slot before end: the store fills the slot, and the
            // advanced cursor IS end.
            let cursor = cg_reg_append_bounded(7 as *mut CgVirtualReg, base, base.add(1));
            assert_eq!(cursor, base.add(1));
            assert_eq!(out[0], 7 as *mut CgVirtualReg);
        }
    }

    #[test]
    fn append_bounded_stores_a_null_value_unchecked() {
        // The original has no NULL test on the value: `strne r0, [r1], #4`
        // stores whatever r0 holds.
        let mut out = [0x5cusize as *mut CgVirtualReg; 1];
        let base = out.as_mut_ptr();
        unsafe {
            let cursor =
                cg_reg_append_bounded(core::ptr::null_mut(), base, base.add(1));
            assert_eq!(cursor, base.add(1), "a NULL value still advances");
            assert!(out[0].is_null(), "NULL lands in the array as-is");
        }
    }

    #[test]
    fn a_full_output_array_suppresses_the_store() {
        let _g = setup();
        let mut f = Fixture::new(4096);
        unsafe {
            let dest = cg_virtual_reg_create(f.proc_ptr(), 1);
            let flags = cg_virtual_reg_create(f.proc_ptr(), 1);
            let s0 = cg_virtual_reg_create(f.proc_ptr(), 1);
            let s1 = cg_virtual_reg_create(f.proc_ptr(), 1);
            let inst = cg_create_inst_binary_s(f.block_ptr(), 0x0f, dest, flags, s0, s1);

            let mut out = [core::ptr::null_mut::<CgVirtualReg>(); 2];
            let base = out.as_mut_ptr();
            // cursor == end: no store at all, cursor returned unchanged.
            let cursor = cg_inst_visit_by_kind(inst, base, base);
            assert_eq!(cursor, base);
            assert!(out[0].is_null(), "nothing was stored");
            // Room for exactly one: the dest lands, dest_flags is dropped.
            let cursor = cg_inst_visit_by_kind(inst, base, base.add(1));
            assert_eq!(cursor, base.add(1));
            assert_eq!(out[0], dest);
            assert!(out[1].is_null(), "the second append hit the bound");
        }
        drop(f);
        teardown();
    }
}
