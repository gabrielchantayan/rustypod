//! `wmcodec_update_bits` — original: `FUN_080e3318` @ `0x080e3318`
//! (28 bytes, 7 instructions, 0x080e3318..0x080e3334, plus the literal
//! pool word 0x08ad9de4 at 0x080e3334 — Ghidra's 28-byte extent is
//! CORRECT here: the next function opens at 0x080e3338 with
//! `push {r4, r5, r6, lr}`; **24 `bl` call sites, 0 predicated, 0 `b`**,
//! verified by decoding every B/BL word in osos.dec: 9 inside
//! `FUN_0808f894` @ 0x0808f894 (0x0808f8c0..0x0808f9b8), 5 inside
//! `FUN_080a7c60` (0x080a7cbc..0x080a7dac), 2 inside `FUN_080ad3d4`
//! (0x080ad40c, 0x080ad450), 4 inside `FUN_080b5248` (0x080b5278..
//! 0x080b52c4), 4 inside `FUN_080d35f8` (0x080d3660..0x080d36c0). No
//! data word in osos references 0x080e3318 — it is never dispatched
//! virtually.
//!
//! # Algorithm
//!
//! Shadow-cached read-modify-write of one 9-bit register on the I2C
//! device at slave address 0x1a — a Wolfson-format audio codec (the
//! 2-wire control word `(reg << 1) | (value >> 8) & 1`, `value & 0xff`
//! written by the callee is the Wolfson Microelectronics 2-wire
//! interface, 7-bit register address + 9-bit data; distinct from the
//! byte-register codec at slave 0x4a in `codec.rs`). Every caller
//! configures audio routing/power: `FUN_0808f894` latches volume
//! registers 0/1 (bit 8 = both-channel update) and drives the
//! route/mute bits of registers 0x18/0x19/0x1a from a mode word;
//! `FUN_080d35f8` / `FUN_080b5248` do per-route power-up/down
//! (register 0 reset values 0x17 / 0x1c = 0 dB volume latch).
//!
//! The body:
//!
//! ```text
//! 080e3318  ldr  r3, [pc, #0x14]   @ r3 = 0x08ad9de4 (shadow table)
//! 080e331c  add  r3, r3, r0, lsl #1
//! 080e3320  ldrh r3, [r3]          @ old = shadow[reg] (zero-extended)
//! 080e3324  bic  r3, r3, r1        @ old & ~mask
//! 080e3328  and  r1, r2, r1        @ value & mask
//! 080e332c  orr  r1, r3, r1        @ merged
//! 080e3330  b    0x080da15c        @ tail: wmcodec_write_reg(reg, merged)
//! ```
//!
//! `merged = (old & !mask) | (value & mask)` in full 32-bit arithmetic;
//! `old` is the zero-extended halfword in the shadow. The register index
//! is not bounds-checked. The merged word reaches the writer untruncated
//! in r1 — the writer itself keeps only bit 8 (folded into the address
//! byte) and the low byte. This function does NOT update the shadow
//! itself; the `strh` back into `shadow[reg]` is the tail callee's last
//! instruction, so a failed or mocked write leaves the shadow untouched
//! here exactly as in the original when the callee is interposed.
//!
//! The shadow table @ 0x08ad9de4 is 68 `u16` entries (0x88 bytes) in
//! osos BSS — it lies past the end of osos.dec (the file ends at
//! 0x08a1b9e8), so it is zero-filled RAM at boot. Entry count verified
//! from the dump loop at 0x080a9824 (`cmp r0, #0x44` @ 0x080a9834)
//! which copies all 68 halfwords out to a caller buffer; the only
//! other references are this function's literal, the writer's literal
//! (0x080da1a4), and a register-store helper at 0x080a7ddc.
//!
//! The tail callee (not ported):
//!
//! - `0x080da15c` — codec register write: builds the 2-byte Wolfson
//!   control word `{ (reg << 1) | ((value >> 8) & 1), value & 0xff }` on
//!   the stack, brackets the I2C write to slave 0x1a
//!   (`FUN_0836bb84(slave=0x1a, len=2, buf)`) with the RTXC
//!   semaphore-5 pair (`kernel_sem5_wait` @ 0x0806a4a0 /
//!   `rom_sem_signal(5)` @ 0x080645a8), then stores the new value into
//!   `shadow[reg]` (`strh r4, [table + reg*2]`).
//!
//! # Deliberate deviations
//!
//! - The tail branch `b 0x080da15c` becomes a call through the
//!   installable volatile slot [`WMCODEC_WRITE_REG`] (the house
//!   foreign-service pattern, `blx` in place of `b`): on target the
//!   default transmutes the retail address 0x080da15c so the port is
//!   hook-ready and behaviorally identical; host tests install a
//!   recording mock, and the host default panics like `codec.rs`'s
//!   `missing_codec_write_reg`.
//! - The shadow table is addressed through [`shadow_table()`]: the
//!   retail BSS address on target, a module-owned 68-entry buffer on
//!   host (the table is pure RAM — it exists in no host fixture).
//! - Ghidra's C is faithful here; the only liberty is the name
//!   (`DAT_080e3334`/`DAT_080da1a4` are the same shadow-table literal).

/// ABI of the retail codec register write @ `0x080da15c`: writes the
/// low 9 bits of `value` to register `reg` of I2C slave 0x1a (bit 8
/// rides in the low bit of the address byte) and caches `value` in the
/// shadow table.
pub type WmcodecWriteRegFn = unsafe extern "C" fn(reg: u32, value: u32);

/// RetailOS load address of the codec register write.
pub const WMCODEC_WRITE_REG_ADDRESS: usize = 0x080d_a15c;

/// RetailOS load address of the 68-entry `u16` register shadow table
/// (osos BSS — past the end of osos.dec, zero-filled at boot).
pub const WMCODEC_SHADOW_ADDRESS: usize = 0x08ad_9de4;

/// Number of shadowed registers (the dump loop at 0x080a9824 counts
/// `cmp r0, #0x44`).
pub const WMCODEC_REG_COUNT: usize = 0x44;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_wmcodec_write_reg(reg: u32, value: u32) {
    let write: WmcodecWriteRegFn = core::mem::transmute(WMCODEC_WRITE_REG_ADDRESS);
    write(reg, value)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_wmcodec_write_reg(_reg: u32, _value: u32) {
    panic!("wmcodec_update_bits requires codec write 0x080da15c")
}

/// Active boundary for the unported codec register write (0x080da15c).
/// On the target it calls directly into retailOS; host tests replace it
/// with a recording implementation.
#[cfg(target_os = "none")]
pub static mut WMCODEC_WRITE_REG: WmcodecWriteRegFn = retail_wmcodec_write_reg;

/// Active host boundary for the unported codec register write.
#[cfg(not(target_os = "none"))]
pub static mut WMCODEC_WRITE_REG: WmcodecWriteRegFn = missing_wmcodec_write_reg;

#[inline(always)]
unsafe fn wmcodec_write_reg() -> WmcodecWriteRegFn {
    core::ptr::read_volatile(core::ptr::addr_of!(WMCODEC_WRITE_REG))
}

/// The register shadow table: the retail BSS address on target, a
/// module-owned replica on host (the table is pure RAM, present in no
/// host fixture). Returns the base of [`WMCODEC_REG_COUNT`] `u16`s.
#[cfg(target_os = "none")]
#[inline(always)]
fn shadow_table() -> *mut u16 {
    WMCODEC_SHADOW_ADDRESS as *mut u16
}

/// Host replica of the retail shadow table.
#[cfg(not(target_os = "none"))]
static mut HOST_SHADOW: [u16; WMCODEC_REG_COUNT] = [0; WMCODEC_REG_COUNT];

#[cfg(not(target_os = "none"))]
#[inline(always)]
fn shadow_table() -> *mut u16 {
    unsafe { core::ptr::addr_of_mut!(HOST_SHADOW).cast() }
}

/// wmcodec_update_bits — original: `FUN_080e3318` @ `0x080e3318` (28
/// bytes).
///
/// Reads codec register `reg`'s cached value from the shadow table,
/// replaces the bits selected by `mask` with the corresponding bits of
/// `value` — `(old & !mask) | (value & mask)` in 32 bits with `old`
/// the zero-extended shadow halfword — and hands the merged word,
/// untruncated, to the register write (which keeps bit 8 and the low
/// byte and updates the shadow itself). `reg` is not bounds-checked.
///
/// # Safety
///
/// `reg` must be below [`WMCODEC_REG_COUNT`] on host; on target any
/// index reads osos RAM at `0x08ad9de4 + reg * 2` exactly as the
/// original's unchecked `ldrh` does. With the shipped target default
/// this performs a real semaphore-bracketed I2C transaction against
/// slave 0x1a.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn wmcodec_update_bits(reg: u32, mask: u32, value: u32) {
    let old = shadow_table().add(reg as usize).read() as u32;
    let merged = (old & !mask) | (value & mask);
    wmcodec_write_reg()(reg, merged);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::Mutex;
    use std::vec::Vec;

    static SEAM_LOCK: Mutex<()> = Mutex::new(());

    static mut WRITES: Vec<(u32, u32)> = Vec::new();

    unsafe extern "C" fn recording_write(reg: u32, value: u32) {
        WRITES.push((reg, value));
    }

    struct Reset;

    impl Reset {
        fn install() -> Self {
            unsafe {
                WMCODEC_WRITE_REG = recording_write;
                WRITES.clear();
                core::ptr::addr_of_mut!(HOST_SHADOW)
                    .cast::<[u16; WMCODEC_REG_COUNT]>()
                    .write([0; WMCODEC_REG_COUNT]);
            }
            Reset
        }
    }

    impl Drop for Reset {
        fn drop(&mut self) {
            unsafe {
                WMCODEC_WRITE_REG = missing_wmcodec_write_reg;
                WRITES.clear();
            }
        }
    }

    unsafe fn set_shadow(reg: usize, value: u16) {
        shadow_table().add(reg).write(value);
    }

    unsafe fn get_shadow(reg: usize) -> u16 {
        shadow_table().add(reg).read()
    }

    /// One mocked update; returns the (reg, value) pairs the writer saw.
    fn run(old: u16, reg: u32, mask: u32, value: u32) -> Vec<(u32, u32)> {
        unsafe {
            WRITES.clear();
            set_shadow(reg as usize, old);
            wmcodec_update_bits(reg, mask, value);
            WRITES.clone()
        }
    }

    #[test]
    fn merge_formula_matches_the_arm_bit_ops() {
        let _lock = SEAM_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _reset = Reset::install();
        // old, mask, value — covers: mask 0 (keep old), full 9-bit
        // replace, partial masks, value bits outside the mask dropped,
        // old bits outside the mask kept, and the bit-8 address-fold
        // boundary the writer consumes.
        let cases: [(u16, u32, u32); 12] = [
            (0x000, 0x000, 0x1ff),
            (0x1a5, 0x000, 0x1ff),
            (0x1a5, 0x1ff, 0x05a),
            (0x1ff, 0x0f, 0x3c),
            (0x00f, 0x1f0, 0x0a0),
            (0x1a5, 0x80, 0x80), // the FUN_0808f894(0, 0x80, 0x80) case
            (0x1a5, 0x80, 0x00),
            (0x055, 0x1c, 0x14),
            (0x000, 0x1fc, 0x1e0), // the (0x1a, 0x1fc, uVar3) route write
            (0x17, 0x100, 0x100),  // volume update bit only
            (0x1ab, 0x0f, 0x05),   // shadow bits above the mask kept
            (0x123, 0x18, 0x10),
        ];
        for (old, mask, value) in cases {
            let writes = run(old, 7, mask, value);
            let expect = ((old as u32) & !mask) | (value & mask);
            assert_eq!(
                writes,
                [(7, expect)],
                "old={old:#x} mask={mask:#x} value={value:#x}"
            );
        }
    }

    #[test]
    fn merged_word_reaches_the_writer_untruncated() {
        let _lock = SEAM_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _reset = Reset::install();
        // The original computes in 32 bits and never masks to 9 bits:
        // with a full-word mask the writer sees every value bit (it
        // keeps only bit 8 and the low byte itself).
        let writes = run(0x1ff, 3, 0xffff_ffff, 0xdead_beef);
        assert_eq!(writes, [(3, 0xdead_beef)]);
    }

    #[test]
    fn shadow_is_read_but_not_written_by_this_function() {
        let _lock = SEAM_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _reset = Reset::install();
        // The strh back into the shadow is the tail callee's job; an
        // interposed write leaves the shadow exactly as it was.
        let writes = run(0x1a5, 0x19, 0x3c, 0x14);
        assert_eq!(writes, [(0x19, ((0x1a5 & !0x3c) | (0x14 & 0x3c)) as u32)]);
        unsafe {
            assert_eq!(get_shadow(0x19), 0x1a5, "shadow untouched here");
        }
    }

    #[test]
    fn only_the_indexed_shadow_entry_is_read() {
        let _lock = SEAM_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _reset = Reset::install();
        unsafe {
            set_shadow(0, 0x080);
            set_shadow(1, 0x180);
            set_shadow(0x43, 0x1ff); // last entry of the 68
        }
        let writes = run(0x1ff, 0x43, 0x100, 0x100);
        assert_eq!(writes, [(0x43, 0x1ff)]);
        unsafe {
            assert_eq!(get_shadow(0), 0x080);
            assert_eq!(get_shadow(1), 0x180);
            assert_eq!(get_shadow(0x43), 0x1ff);
        }
    }

    #[test]
    fn register_index_is_forwarded_unchanged() {
        let _lock = SEAM_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _reset = Reset::install();
        for reg in [0u32, 1, 0x1a, 0x43] {
            let writes = run(0, reg, 0xff, 0xa5);
            assert_eq!(writes, [(reg, 0xa5)]);
        }
    }
}
