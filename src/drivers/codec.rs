//! `codec_update_bits` — original: `FUN_080d5170` @ `0x080d5170`
//! (56 bytes, 14 instructions, 0x080d5170..0x080d51a8 — Ghidra's 56-byte
//! extent is CORRECT here: the next function opens at 0x080d51a8 with
//! `push {r4,r5,r6,lr}`; **36 `bl` call sites, 0 predicated**, verified by
//! decoding every B/BL word in osos.dec: 6 inside `FUN_0809393c` @
//! 0x0809393c (0x08093a1c..0x08093a78), 28 inside `FUN_080aa0a0` @
//! 0x080aa0a0, and 2 inside the sibling dispatcher `FUN_080d51a8` @
//! 0x080d51a8 immediately below).
//!
//! # Algorithm
//!
//! Read-modify-write of one byte-wide register on the I2C device at slave
//! address 0x4a — the 6G audio codec: every caller configures audio
//! (`FUN_080aa0a0` is a codec init/power-mode sequencer — register 0 reset
//! strobed 0x99 -> 0, a 0x2e..0x3f register dump, 75 ms delay, four output
//! channels powered via the bit-7 power-down of regs 0x1a..0x1d;
//! `FUN_0809393c` is a route/mute flag decoder — mute bits at regs
//! 0x10/0x11 bit 7). The body:
//!
//! ```text
//! 080d5170  push {r3, r4, r5, r6, r7, lr}   @ one 4-byte stack slot
//! 080d5174  mov  r4, r1                     @ r4 = mask
//! 080d5178  mov  r1, sp                     @ reader out-pointer
//! 080d517c  mov  r6, r0                     @ r6 = reg
//! 080d5180  mov  r5, r2                     @ r5 = value
//! 080d5184  bl   0x080aa060                 @ codec_read_reg(reg, &slot)
//! 080d5188  ldrh r0, [sp]                   @ old = slot (zero-extended)
//! 080d518c  and  r1, r5, r4                 @ value & mask
//! 080d5190  bic  r0, r0, r4                 @ old & ~mask
//! 080d5194  orr  r1, r0, r1                 @ merged
//! 080d5198  mov  r0, r6                     @ reg
//! 080d519c  str  r1, [sp]                   @ dead store (see notes)
//! 080d51a0  bl   0x080b2894                 @ codec_write_reg(reg, merged)
//! 080d51a4  pop  {r3, r4, r5, r6, r7, pc}
//! ```
//!
//! `merged = (old & !mask) | (value & mask)` in full 32-bit arithmetic;
//! `old` is the halfword the reader stored (`ldrh`, zero-extended). The
//! writer receives the merged word untruncated in r1 and itself keeps only
//! the low byte (`strb r1, [sp, #1]` in its body).
//!
//! The callees (neither ported):
//!
//! - `0x080aa060` — codec register read: writes the register index to I2C
//!   slave 0x4a (`FUN_0836bb84`, 1 byte), reads one byte back
//!   (`FUN_0836b950`), stores it to `*out` with `strh` (high byte 0). An
//!   RTXC semaphore pair (`0x0806a4a0` wait / `0x080645a8` signal)
//!   brackets the transaction.
//! - `0x080b2894` — codec register write: pushes {reg, value} as two bytes
//!   to slave 0x4a (`FUN_0836bb84`, 2 bytes), same semaphore bracket.
//!
//! # Deliberate deviations
//!
//! - The `str r1, [sp]` before the write call is dead: the writer takes
//!   the value in r1 and never reads the slot. The port drops it (the slot
//!   itself is kept as the reader's out-parameter, matching the `strh`/
//!   `ldrh` halfword protocol).
//! - Both callees dispatch through installable volatile slots
//!   ([`CODEC_READ_REG`] / [`CODEC_WRITE_REG`], the house foreign-service
//!   pattern): the target defaults transmute the retail addresses
//!   0x080aa060 / 0x080b2894, so the port is hook-ready on device; host
//!   tests install recording mocks. `bl` becomes `blx` through the slot.
//! - Ghidra's C drops the third argument at several call sites
//!   (`FUN_080d5170(3,0xff)` in `FUN_080aa0a0` is really
//!   `codec_update_bits(3, 0xff, r2)` with r2 live from the caller's
//!   frame); the signature here follows the ARM, which always reads r2.

/// ABI of the retail codec register read @ `0x080aa060`: fetches register
/// `reg` of I2C slave 0x4a and stores the byte to `*out` as a u16
/// (`strh`, high byte zero).
pub type CodecReadRegFn = unsafe extern "C" fn(reg: u32, out: *mut u16);

/// ABI of the retail codec register write @ `0x080b2894`: writes the low
/// byte of `value` to register `reg` of I2C slave 0x4a.
pub type CodecWriteRegFn = unsafe extern "C" fn(reg: u32, value: u32);

/// RetailOS load address of the codec register read.
pub const CODEC_READ_REG_ADDRESS: usize = 0x080a_a060;

/// RetailOS load address of the codec register write.
pub const CODEC_WRITE_REG_ADDRESS: usize = 0x080b_2894;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_codec_read_reg(reg: u32, out: *mut u16) {
    let read: CodecReadRegFn = core::mem::transmute(CODEC_READ_REG_ADDRESS);
    read(reg, out)
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_codec_write_reg(reg: u32, value: u32) {
    let write: CodecWriteRegFn = core::mem::transmute(CODEC_WRITE_REG_ADDRESS);
    write(reg, value)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_codec_read_reg(_reg: u32, _out: *mut u16) {
    panic!("codec_update_bits requires codec read 0x080aa060")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_codec_write_reg(_reg: u32, _value: u32) {
    panic!("codec_update_bits requires codec write 0x080b2894")
}

/// Active boundary for the unported codec register read (0x080aa060). On
/// the target it calls directly into retailOS; host tests replace it with
/// a recording implementation.
#[cfg(target_os = "none")]
pub static mut CODEC_READ_REG: CodecReadRegFn = retail_codec_read_reg;

/// Active host boundary for the unported codec register read.
#[cfg(not(target_os = "none"))]
pub static mut CODEC_READ_REG: CodecReadRegFn = missing_codec_read_reg;

/// Active boundary for the unported codec register write (0x080b2894). On
/// the target it calls directly into retailOS; host tests replace it with
/// a recording implementation.
#[cfg(target_os = "none")]
pub static mut CODEC_WRITE_REG: CodecWriteRegFn = retail_codec_write_reg;

/// Active host boundary for the unported codec register write.
#[cfg(not(target_os = "none"))]
pub static mut CODEC_WRITE_REG: CodecWriteRegFn = missing_codec_write_reg;

#[inline(always)]
unsafe fn codec_read_reg() -> CodecReadRegFn {
    core::ptr::read_volatile(core::ptr::addr_of!(CODEC_READ_REG))
}

#[inline(always)]
unsafe fn codec_write_reg() -> CodecWriteRegFn {
    core::ptr::read_volatile(core::ptr::addr_of!(CODEC_WRITE_REG))
}

/// codec_update_bits — original: `FUN_080d5170` @ `0x080d5170` (56 bytes).
///
/// Reads codec register `reg`, replaces the bits selected by `mask` with
/// the corresponding bits of `value`, and writes the register back:
/// `(old & !mask) | (value & mask)`, computed in 32 bits with `old` the
/// zero-extended halfword the reader returned. The merged word reaches the
/// writer untruncated; the writer keeps its low byte.
///
/// # Safety
///
/// `reg` must name a readable/writable register of the on-board codec;
/// with the shipped target defaults this performs two real I2C
/// transactions against slave 0x4a.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn codec_update_bits(reg: u32, mask: u32, value: u32) {
    let mut old: u16 = 0;
    codec_read_reg()(reg, &mut old);
    let merged = ((old as u32) & !mask) | (value & mask);
    codec_write_reg()(reg, merged);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::Mutex;
    use std::vec::Vec;

    static SEAM_LOCK: Mutex<()> = Mutex::new(());

    #[derive(Clone, Copy, PartialEq, Debug)]
    enum Op {
        Read { reg: u32 },
        Write { reg: u32, value: u32 },
    }

    static mut OPS: Vec<Op> = Vec::new();
    static mut READ_RESULT: u16 = 0;

    unsafe extern "C" fn recording_read(reg: u32, out: *mut u16) {
        OPS.push(Op::Read { reg });
        *out = READ_RESULT;
    }

    unsafe extern "C" fn recording_write(reg: u32, value: u32) {
        OPS.push(Op::Write { reg, value });
    }

    struct Reset;

    impl Reset {
        fn install() -> Self {
            unsafe {
                CODEC_READ_REG = recording_read;
                CODEC_WRITE_REG = recording_write;
                OPS.clear();
            }
            Reset
        }
    }

    impl Drop for Reset {
        fn drop(&mut self) {
            unsafe {
                CODEC_READ_REG = missing_codec_read_reg;
                CODEC_WRITE_REG = missing_codec_write_reg;
                OPS.clear();
                READ_RESULT = 0;
            }
        }
    }

    /// One mocked transaction; returns the word the writer saw.
    fn run(old: u16, reg: u32, mask: u32, value: u32) -> Vec<Op> {
        unsafe {
            OPS.clear();
            READ_RESULT = old;
            codec_update_bits(reg, mask, value);
            OPS.clone()
        }
    }

    #[test]
    fn read_precedes_write_and_reg_is_forwarded_to_both() {
        let _lock = SEAM_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _reset = Reset::install();
        let ops = run(0xa5, 0x1b, 0x80, 0x80);
        assert_eq!(
            ops,
            [
                Op::Read { reg: 0x1b },
                Op::Write {
                    reg: 0x1b,
                    value: 0xa5
                }
            ],
            "one read then one write, register unchanged on both edges"
        );
    }

    #[test]
    fn merge_formula_matches_the_arm_bit_ops() {
        let _lock = SEAM_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _reset = Reset::install();
        // old, mask, value — covers: mask 0 (keep old), mask 0xff (replace),
        // partial masks, value bits outside the mask dropped, old bits
        // outside the mask kept, and a mask wider than a byte.
        let cases: [(u16, u32, u32); 12] = [
            (0x00, 0x00, 0xff),
            (0xa5, 0x00, 0xff),
            (0xa5, 0xff, 0x5a),
            (0xff, 0x0f, 0x3c),
            (0x0f, 0xf0, 0xa0),
            (0xa5, 0x80, 0x80),
            (0xa5, 0x80, 0x00),
            (0x55, 0x1c, 0x14),
            (0xff, 0x1ff, 0x1ff), // mask wider than a byte: merged keeps bit 8
            (0x00, 0xffff_ffff, 0xdead_beef),
            (0x7f, 0xaa, 0x55),
            (0x1ab, 0x0f, 0x05), // reader halfword above 0xff: ldrh sees it all
        ];
        for (old, mask, value) in cases {
            let ops = run(old, 7, mask, value);
            let expected = ((old as u32) & !mask) | (value & mask);
            match ops[1] {
                Op::Write { reg, value: written } => {
                    assert_eq!(reg, 7);
                    assert_eq!(
                        written, expected,
                        "old={old:#06x} mask={mask:#010x} value={value:#010x}"
                    );
                }
                other => panic!("expected a write, saw {other:?}"),
            }
        }
    }

    #[test]
    fn writer_receives_the_merged_word_untruncated() {
        let _lock = SEAM_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _reset = Reset::install();
        // mask 0x100 selects a bit above the byte the codec owns; the
        // original still hands the full merged word to the writer in r1
        // (the writer's own strb keeps only the low byte).
        let ops = run(0x12, 2, 0x1f0, 0x1a0);
        assert_eq!(
            ops[1],
            Op::Write {
                reg: 2,
                value: 0x1a2
            }
        );
    }
}
