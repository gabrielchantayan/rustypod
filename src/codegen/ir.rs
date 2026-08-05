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
//! - `cg_label_create` — original: `FUN_082c0dec` @ 0x082c0dec
//!   (52 bytes; 4 `bl` call sites). Allocates and initializes a label
//!   record and prepends it to the codegen's label list.
//! - `cg_label_add_fixup` — original: `FUN_082c17ac` @ 0x082c17ac
//!   (64 bytes; 4 `bl` call sites). Prepends the current output position
//!   to a label's fixup list.
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
//! cg_module_t                 cg_proc_t                    cg_block_t
//!   +0x00 heap                  +0x04 module                 +0x04 proc
//!                               +0x10 registers (head)       +0x0c insts (head)
//!                               +0x14 last_register (tail)   +0x10 last_inst (tail)
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

use super::heap::{cg_heap_alloc, CgHeap};

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

/// `cg_proc_t + 0x04` — owning module.
pub const CG_PROC_MODULE: usize = 1;
/// `cg_proc_t + 0x10` — first virtual register.
pub const CG_PROC_REGISTERS: usize = 4;
/// `cg_proc_t + 0x14` — last virtual register.
pub const CG_PROC_LAST_REGISTER: usize = 5;
/// `cg_proc_t + 0x20` — number of registers created so far.
pub const CG_PROC_NUM_REGISTERS: usize = 8;

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
        module: [usize; 1],
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
                module: [0; 1],
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
