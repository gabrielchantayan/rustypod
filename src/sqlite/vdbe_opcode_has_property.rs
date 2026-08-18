//! Opcode-property probe — how the engine asks whether a VDBE opcode
//! carries one of the `OPFLG_*` property bits (jump target in P2, P1/
//! P2/P3 input/output roles).
//!
//! - `vdbe_opcode_has_property` — original: `FUN_0838c7d4` @
//!   0x0838c7d4 (20 bytes of code, 0x0838c7d4..0x0838c7e8; **2 `bl`
//!   call sites**, binary-scanned from osos.dec — no predicated or
//!   tail branches). Upstream SQLite 3.5.9's
//!   `sqlite3VdbeOpcodeHasProperty` (`int
//!   sqlite3VdbeOpcodeHasProperty(int opcode, int mask)` in vdbe.c),
//!   identified by exact structural match of both callers against the
//!   public 3.5.9 source: `resolveP2Values` (FUN_08368038, vdbeaux.c)
//!   and `sqlite3VdbeAddOpList` (FUN_0838690c, vdbeaux.c) each gate
//!   their negative-P2 label fixup on `…(opcode, OPFLG_JUMP)`.
//!
//! ### Extent and literal pool
//!
//! Confirmed from raw words: five instructions 0x0838c7d4..0x0838c7e8,
//! then the function's only literal-pool word @ 0x0838c7e8 holding the
//! table pointer 0x08a0994c; 0x0838c7ec is the next function's
//! `stmdb sp!,{r2,r3,r4,r5,r6,lr}`.
//!
//! ### Listing
//!
//! ```text
//! 0838c7d4  ldr  r2,[0x838c7e8]   @ opcodeProperty base (0x08a0994c)
//! 0838c7d8  ldrb r0,[r2,r0]       @ opcodeProperty[opcode]
//! 0838c7dc  ands r0,r0,r1         @ & mask, full register
//! 0838c7e0  movne r0,#0x1         @ normalize to 0/1
//! 0838c7e4  bx   lr
//! ```
//!
//! ### The table (144 bytes, recovered)
//!
//! `opcodeProperty` is a `static unsigned char[]` initialized by the
//! build-host-generated `OPFLG_INITIALIZER` (tool/mkopcodeh.awk). That
//! script numbers the non-`TK_`-matched opcodes by iterating an awk
//! associative array, whose order is unspecified — so this build's
//! opcode numbering cannot be regenerated from the public 3.5.9
//! source; the table itself is recovered from the image instead.
//! Applying the +0xaed8 image/runtime skew documented in
//! `sqlite/mod.rs` to the runtime base 0x08a0994c gives image address
//! 0x08a14824, which holds exactly 144 flag bytes (max opcode 143,
//! every value drawn from the six `OPFLG_*` bits 0x01..0x20) followed
//! by unrelated pointer/ASCII data. Recovery is cross-checked against
//! vdbe.c's per-opcode property comments through the opcode numbers
//! recovered from the two callers' decompiles:
//!
//! | opcode | name (from caller structure) | comment in vdbe.c | byte |
//! |--------|------------------------------|-------------------|------|
//! | 0x15   | OP_Function                  | (none)            | 0x00 |
//! | 0x17   | OP_Noop                      | (synthesized)     | 0x00 |
//! | 0x1d   | OP_VRename                   | (none)            | 0x00 |
//! | 0x26   | OP_Halt                      | (none)            | 0x00 |
//! | 0x2a   | OP_Statement                 | (none)            | 0x00 |
//! | 0x61   | OP_AggStep                   | (none)            | 0x00 |
//! | 0x64   | OP_VFilter                   | /* jump */        | 0x01 |
//! | 0x6a   | OP_Destroy                   | /* out2-prerelease */ | 0x02 |
//! | 0x77   | OP_VUpdate                   | (none)            | 0x00 |
//!
//! plus the 0x2c (`IN1|IN2|OUT3`) arithmetic run at opcodes 74..=83
//! (the `same as TK_*` expression operators). All consistent.
//!
//! ### Algorithm
//!
//! A single byte load: index the table by `opcode`, AND with `mask`
//! (the full `r1` register — callers pass `OPFLG_JUMP`), and return
//! exactly 0 or 1. Upstream's `assert(0 < opcode && opcode <
//! sizeof(opcodeProperty))` is compiled out; the machine would index
//! the ROM for any `opcode`, and the port mirrors that with a
//! `wrapping_offset` byte read.
//!
//! Call sites (binary-scanned):
//!
//! - `bl` @ 0x083680e8 — inside `resolveP2Values` (FUN_08368038):
//!   `pOp->p2 = aLabel[-1-pOp->p2]` only when the property probe says
//!   the opcode jumps.
//! - `bl` @ 0x0838699c — inside `sqlite3VdbeAddOpList`
//!   (FUN_0838690c): negative template P2 becomes
//!   `addr + ADDR(p2)` under the same gate.
//!
//! ### Deviations
//!
//! - The ROM table is modeled as the crate static
//!   [`OPCODE_PROPERTY`]; out-of-range `opcode` values read whatever
//!   the linker placed beside it (the firmware equivalent reads
//!   neighboring image bytes) — no caller can do this, per the
//!   upstream assert.
//! - `mask` is `i32`, matching the full-register `ands` (the
//!   decompile's `byte param_2` is just Ghidra narrowing the type).

/// Runtime address of the `opcodeProperty` table the original indexes,
/// from the literal-pool word @ 0x0838c7e8. Its contents live at
/// `OPCODE_PROPERTY_ADDRESS + 0xaed8` in the decrypted image (the skew
/// `sqlite/mod.rs` documents) — image 0x08a14824.
pub const OPCODE_PROPERTY_ADDRESS: u32 = 0x08a0994c;

/// jump: P2 holds a jump target (vdbeaux.c resolves negative label
/// references only for these opcodes).
pub const OPFLG_JUMP: i32 = 0x01;
/// out2-prerelease: P2 is an output; release its old value first.
pub const OPFLG_OUT2_PRERELEASE: i32 = 0x02;
/// in1: P1 is an input.
pub const OPFLG_IN1: i32 = 0x04;
/// in2: P2 is an input.
pub const OPFLG_IN2: i32 = 0x08;
/// in3: P3 is an input.
pub const OPFLG_IN3: i32 = 0x10;
/// out3: P3 is an output.
pub const OPFLG_OUT3: i32 = 0x20;

/// The number of table entries (max opcode 143): 144 flag bytes sit at
/// image 0x08a14824 before unrelated pointer data begins.
pub const NUM_OPCODES: usize = 144;

/// The `opcodeProperty[]` table, verbatim from the image @ 0x08a14824
/// (runtime 0x08a0994c). A ROM address a host cannot reproduce, so the
/// port models it as a crate static — the `blob_to_hex.rs` precedent.
/// Annotated rows name the opcodes recovered from the callers.
#[rustfmt::skip]
pub static OPCODE_PROPERTY: [u8; NUM_OPCODES] = [
    0x00, 0x01, 0x00, 0x00, 0x10, 0x02, 0x11, 0x00, 0x00, 0x00, 0x05, 0x02, 0x00, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x02, 0x02, 0x02, 0x04, 0x00, 0x00, 0x00,
    0x00, 0x02, 0x11, 0x11, 0x02, 0x05, 0x00, 0x02, 0x11, 0x04, 0x00, 0x00, 0x0c, 0x11, 0x01, 0x02,
    0x01, 0x00, 0x02, 0x01, 0x01, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x11, 0x2c, 0x2c, 0x00, 0x00,
    0x11, 0x05, 0x05, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x05, 0x2c, 0x2c, 0x2c, 0x2c, 0x2c, 0x2c,
    0x2c, 0x2c, 0x2c, 0x2c, 0x00, 0x00, 0x00, 0x04, 0x02, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x11,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x08, 0x00, 0x02, 0x02, 0x05, 0x00, 0x00, 0x00,
    0x00, 0x02, 0x00, 0x02, 0x01, 0x11, 0x00, 0x00, 0x05, 0x00, 0x11, 0x05, 0x00, 0x02, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x04, 0x04, 0x04, 0x04, 0x00,
];

/// vdbe_opcode_has_property — original: `FUN_0838c7d4` @ 0x0838c7d4
/// (20 bytes; 2 `bl` call sites).
///
/// `sqlite3VdbeOpcodeHasProperty`: report 1 when
/// `opcodeProperty[opcode] & mask` is nonzero, 0 otherwise — the gate
/// `resolveP2Values` and `sqlite3VdbeAddOpList` run with
/// `mask == OPFLG_JUMP` before resolving negative label references in
/// P2. The return is always exactly 0 or 1 (`movne r0,#0x1`), never
/// the raw AND result.
///
/// # Safety
/// `opcode` must be a valid opcode index `0..NUM_OPCODES` (upstream:
/// `assert(opcode > 0 && opcode < sizeof(opcodeProperty))`, compiled
/// out). Other values read outside the recovered table, mirroring the
/// original's unconditional ROM index.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vdbe_opcode_has_property(opcode: i32, mask: i32) -> i32 {
    // ldrb r0,[r2,r0] — r0 is a raw byte index into the ROM table.
    let property = core::ptr::read_volatile(
        OPCODE_PROPERTY.as_ptr().wrapping_offset(opcode as isize)
    );
    // ands r0,r0,r1 / movne r0,#0x1 — full-register AND, normalized.
    ((property as i32 & mask) != 0) as i32
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Independent copy of the 144 recovered image bytes @ 0x08a14824,
    /// so a corrupted `OPCODE_PROPERTY` static fails loudly instead of
    /// being compared against itself.
    const EXPECTED_TABLE: [u8; NUM_OPCODES] = [
        0x00, 0x01, 0x00, 0x00, 0x10, 0x02, 0x11, 0x00, 0x00, 0x00, 0x05, 0x02, 0x00, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x02, 0x02, 0x02, 0x04, 0x00, 0x00, 0x00,
        0x00, 0x02, 0x11, 0x11, 0x02, 0x05, 0x00, 0x02, 0x11, 0x04, 0x00, 0x00, 0x0c, 0x11, 0x01, 0x02,
        0x01, 0x00, 0x02, 0x01, 0x01, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x11, 0x2c, 0x2c, 0x00, 0x00,
        0x11, 0x05, 0x05, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x05, 0x2c, 0x2c, 0x2c, 0x2c, 0x2c, 0x2c,
        0x2c, 0x2c, 0x2c, 0x2c, 0x00, 0x00, 0x00, 0x04, 0x02, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x11,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x08, 0x00, 0x02, 0x02, 0x05, 0x00, 0x00, 0x00,
        0x00, 0x02, 0x00, 0x02, 0x01, 0x11, 0x00, 0x00, 0x05, 0x00, 0x11, 0x05, 0x00, 0x02, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x04, 0x04, 0x04, 0x04, 0x00,
    ];

    /// The literal-pool pointer plus the sqlite subsystem's +0xaed8
    /// skew lands on the recovered table bytes in the decrypted image.
    #[test]
    fn skewed_address_points_into_image_table() {
        assert_eq!(OPCODE_PROPERTY_ADDRESS + 0xaed8, 0x08a1_4824);
    }

    #[test]
    fn table_is_the_recovered_image_bytes() {
        assert_eq!(OPCODE_PROPERTY, EXPECTED_TABLE);
        // Recovery sanity: every entry is drawn from the six OPFLG bits.
        assert!(OPCODE_PROPERTY.iter().all(|&b| b & !0x3f == 0));
    }

    /// The engine's one observable contract, exhaustively: every valid
    /// opcode against every byte mask, checked against the reference
    /// table semantics `(property & mask) != 0`.
    #[test]
    fn exhaustive_opcode_by_byte_mask() {
        for opcode in 0..NUM_OPCODES as i32 {
            for mask in 0..=0xff {
                let expected = (EXPECTED_TABLE[opcode as usize] as i32 & mask != 0) as i32;
                assert_eq!(
                    unsafe { vdbe_opcode_has_property(opcode, mask) },
                    expected,
                    "opcode {opcode}, mask {mask:#04x}"
                );
            }
        }
    }

    /// `ands r0,r0,r1` uses the whole register: mask bits above the
    /// six property bits can never match, and the sign bit does not
    /// change the verdict.
    #[test]
    fn mask_is_full_register() {
        // 0x11 = JUMP|IN3 @ opcode 6.
        assert_eq!(unsafe { vdbe_opcode_has_property(6, 0x100) }, 0);
        assert_eq!(unsafe { vdbe_opcode_has_property(6, i32::MIN | OPFLG_JUMP) }, 1);
        assert_eq!(unsafe { vdbe_opcode_has_property(6, -1) }, 1);
        // Mask 0 never matches, even for a property-rich opcode.
        assert_eq!(unsafe { vdbe_opcode_has_property(74, 0) }, 0);
    }

    /// The return is normalized to exactly 0/1 even when the AND has
    /// several bits set (`movne r0,#0x1`, not the raw mask result).
    #[test]
    fn result_is_normalized_zero_or_one() {
        // 0x2c = IN1|IN2|OUT3 @ opcode 74: raw AND with 0x0c is 0x0c.
        assert_eq!(unsafe { vdbe_opcode_has_property(74, 0x0c) }, 1);
        assert_eq!(unsafe { vdbe_opcode_has_property(74, OPFLG_IN1 | OPFLG_IN2) }, 1);
    }

    /// Boundary opcodes: index 0 and the last entry.
    #[test]
    fn boundary_opcodes() {
        // Opcode 0 is the unused padding slot: no properties.
        for mask in [OPFLG_JUMP, OPFLG_OUT2_PRERELEASE, OPFLG_IN1, OPFLG_IN2, OPFLG_IN3, OPFLG_OUT3] {
            assert_eq!(unsafe { vdbe_opcode_has_property(0, mask) }, 0);
        }
        // Opcode 143 (last) carries 0x00 too; opcode 138..142 are 0x04.
        assert_eq!(unsafe { vdbe_opcode_has_property(143, -1) }, 0);
        assert_eq!(unsafe { vdbe_opcode_has_property(142, OPFLG_IN1) }, 1);
        assert_eq!(unsafe { vdbe_opcode_has_property(142, OPFLG_JUMP) }, 0);
    }

    /// The opcode numbers recovered from the two callers' decompiles,
    /// cross-checked against vdbe.c's property comments — this is the
    /// evidence that ties the recovered table to upstream 3.5.9.
    #[test]
    fn recovered_opcode_numbers_match_vdbe_c_comments() {
        const OP_FUNCTION: i32 = 0x15;
        const OP_NOOP: i32 = 0x17;
        const OP_VRENAME: i32 = 0x1d;
        const OP_HALT: i32 = 0x26;
        const OP_STATEMENT: i32 = 0x2a;
        const OP_AGGSTEP: i32 = 0x61;
        const OP_VFILTER: i32 = 0x64;
        const OP_DESTROY: i32 = 0x6a;
        const OP_VUPDATE: i32 = 0x77;

        // `case OP_VFilter: /* jump */` — a resolveP2Values target.
        assert_eq!(unsafe { vdbe_opcode_has_property(OP_VFILTER, OPFLG_JUMP) }, 1);
        assert_eq!(unsafe { vdbe_opcode_has_property(OP_VFILTER, OPFLG_IN1 | OPFLG_IN2 | OPFLG_IN3) }, 0);
        // `case OP_Destroy: /* out2-prerelease */`.
        assert_eq!(unsafe { vdbe_opcode_has_property(OP_DESTROY, OPFLG_OUT2_PRERELEASE) }, 1);
        assert_eq!(unsafe { vdbe_opcode_has_property(OP_DESTROY, OPFLG_JUMP) }, 0);
        // The rest carry no property comment in vdbe.c.
        for op in [OP_FUNCTION, OP_NOOP, OP_VRENAME, OP_HALT, OP_STATEMENT, OP_AGGSTEP, OP_VUPDATE] {
            assert_eq!(unsafe { vdbe_opcode_has_property(op, -1) }, 0, "opcode {op:#x}");
        }
        // The `same as TK_*` arithmetic run: IN1|IN2|OUT3 @ 74..=83.
        for op in 74..=83 {
            assert_eq!(unsafe { vdbe_opcode_has_property(op, OPFLG_IN1) }, 1, "opcode {op}");
            assert_eq!(unsafe { vdbe_opcode_has_property(op, OPFLG_IN2) }, 1, "opcode {op}");
            assert_eq!(unsafe { vdbe_opcode_has_property(op, OPFLG_OUT3) }, 1, "opcode {op}");
            assert_eq!(unsafe { vdbe_opcode_has_property(op, OPFLG_JUMP) }, 0, "opcode {op}");
        }
    }
}
