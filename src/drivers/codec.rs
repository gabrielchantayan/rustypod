//! Audio-codec register access.
//!
//! # Ported functions
//!
//! - `codec_write_reg` — original: `FUN_080b2894` @ `0x080b2894` (40 bytes,
//!   10 instructions). Raw bytes put its final `pop {ip,pc}` at
//!   `0x080b28b8`; the distinct sibling function begins with
//!   `push {r4,r5,r6,r7,r8,lr}` at `0x080b28bc`, confirming Ghidra's extent.
//!   Decoding every ARM B/BL word in osos.dec finds **19 plain,
//!   unconditional `bl` callers and zero predicated forms**: one in
//!   `FUN_0809393c`, 16 in the codec-init sequence `FUN_080aa0a0`, one at
//!   raw caller address `0x080b2820`, and one in `codec_update_bits`.
//! - `codec_update_bits` — original: `FUN_080d5170` @ `0x080d5170` (56
//!   bytes, 14 instructions, `0x080d5170..0x080d51a8`; Ghidra's extent is
//!   correct). It has 36 plain `bl` call sites and no predicated forms.
//!
//! # Algorithms
//!
//! `codec_write_reg` puts the low bytes of `(reg, value)` into a two-byte
//! stack buffer, acquires RTXC semaphore 5, writes the buffer to I2C slave
//! `0x4a`, then releases semaphore 5. It ignores the transfer status and
//! returns the release's r0 word. `codec_update_bits` reads one byte-wide
//! register then writes `(old & !mask) | (value & mask)` in full 32-bit
//! arithmetic. The writer truncates that merged word to its low byte.
//!
//! # Deliberate deviations
//!
//! - Raw S5L8702 I2C write `FUN_0836bb84` remains unported. This module
//!   reaches it through a typed fixed-address call on target and a volatile
//!   recording seam on host; that turns the original direct `bl` into `blx`.
//! - The semaphore wrappers are the existing
//!   [`crate::kernel::task_lock::kernel_sem5_wait`] and
//!   [`crate::kernel::task_lock::kernel_sem5_signal`] ports, inheriting their
//!   documented ROM-hook deviation.
//! - Codec register read `FUN_080aa060` remains behind its existing
//!   [`CODEC_READ_REG`] seam. The newly ported writer is called directly;
//!   its former `CODEC_WRITE_REG` seam is removed.
//! - `codec_update_bits` drops the ARM's dead `str r1, [sp]` before its
//!   writer call. Ghidra also drops r2 at several call sites; ARM reads it.

use crate::kernel::task_lock::{kernel_sem5_signal, kernel_sem5_wait};

/// ABI of the retail codec register read @ `0x080aa060`: fetches register
/// `reg` of I2C slave 0x4a and stores the byte to `*out` as a u16
/// (`strh`, high byte zero).
pub type CodecReadRegFn = unsafe extern "C" fn(reg: u32, out: *mut u16);

/// RetailOS load address of the codec register read.
pub const CODEC_READ_REG_ADDRESS: usize = 0x080a_a060;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_codec_read_reg(reg: u32, out: *mut u16) {
    let read: CodecReadRegFn = core::mem::transmute(CODEC_READ_REG_ADDRESS);
    read(reg, out)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_codec_read_reg(_reg: u32, _out: *mut u16) {
    panic!("codec_update_bits requires codec read 0x080aa060")
}

/// Active boundary for the unported codec register read (0x080aa060). On
/// target it calls retailOS; host tests replace it with a recorder.
#[cfg(target_os = "none")]
pub static mut CODEC_READ_REG: CodecReadRegFn = retail_codec_read_reg;

/// Active host boundary for the unported codec register read.
#[cfg(not(target_os = "none"))]
pub static mut CODEC_READ_REG: CodecReadRegFn = missing_codec_read_reg;

/// ABI of raw S5L8702 I2C transfer `FUN_0836bb84`: write `len` bytes from
/// `buf` to `slave`, returning its status word.
type I2cWriteFn = unsafe extern "C" fn(slave: u32, len: u32, buf: *const u8) -> u32;

/// RetailOS load address of the raw S5L8702 I2C write transfer.
const I2C_WRITE_ADDRESS: usize = 0x0836_bb84;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn i2c_write(slave: u32, len: u32, buf: *const u8) -> u32 {
    let write: I2cWriteFn = core::mem::transmute(I2C_WRITE_ADDRESS);
    write(slave, len, buf)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_i2c_write(_slave: u32, _len: u32, _buf: *const u8) -> u32 {
    panic!("codec_write_reg requires I2C write 0x0836bb84")
}

/// Active host boundary for the unported raw I2C write transfer.
#[cfg(not(target_os = "none"))]
static mut I2C_WRITE: I2cWriteFn = missing_i2c_write;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn i2c_write(slave: u32, len: u32, buf: *const u8) -> u32 {
    core::ptr::read_volatile(core::ptr::addr_of!(I2C_WRITE))(slave, len, buf)
}

#[inline(always)]
unsafe fn codec_read_reg() -> CodecReadRegFn {
    core::ptr::read_volatile(core::ptr::addr_of!(CODEC_READ_REG))
}

/// codec_write_reg — original: `FUN_080b2894` @ `0x080b2894` (40 bytes).
///
/// Stores the low byte of `reg` and `value` in order, acquires semaphore 5,
/// sends those two bytes to I2C slave 0x4a, then releases semaphore 5. The
/// raw transfer result is deliberately discarded; the semaphore release's r0
/// word returns to the caller, exactly as the final `pop {ip,pc}` preserves it.
///
/// # Safety
///
/// On target this performs a synchronous write to the audio codec. The raw
/// hardware transfer is not ported and must be callable at `0x0836bb84`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn codec_write_reg(reg: u32, value: u32) -> usize {
    let bytes = [reg as u8, value as u8];
    kernel_sem5_wait();
    i2c_write(0x4a, 2, bytes.as_ptr());
    kernel_sem5_signal()
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
    codec_write_reg(reg, merged);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::kernel::task_lock::{self, RomThunkOps};
    use std::sync::Mutex;
    use std::vec;
    use std::vec::Vec;

    static SEAM_LOCK: Mutex<()> = Mutex::new(());

    #[derive(Clone, Copy, PartialEq, Debug)]
    enum Op {
        Read { reg: u32 },
        Wait(usize),
        Transfer { slave: u32, bytes: [u8; 2] },
        Signal(usize),
    }

    static mut OPS: Vec<Op> = Vec::new();
    static mut READ_RESULT: u16 = 0;
    static mut I2C_STATUS: u32 = 0;
    static mut SIGNAL_RESULT: usize = 0;

    unsafe extern "C" fn recording_read(reg: u32, out: *mut u16) {
        OPS.push(Op::Read { reg });
        *out = READ_RESULT;
    }

    unsafe extern "C" fn recording_wait(sem: usize) -> usize {
        OPS.push(Op::Wait(sem));
        0
    }

    unsafe extern "C" fn recording_transfer(slave: u32, len: u32, buf: *const u8) -> u32 {
        assert_eq!(len, 2, "codec_write_reg always sends two bytes");
        OPS.push(Op::Transfer {
            slave,
            bytes: [buf.read(), buf.add(1).read()],
        });
        I2C_STATUS
    }

    unsafe extern "C" fn recording_signal(sem: usize) -> usize {
        OPS.push(Op::Signal(sem));
        SIGNAL_RESULT
    }

    struct Reset {
        original_kernel: RomThunkOps,
    }

    impl Reset {
        fn install() -> Self {
            unsafe {
                let original_kernel = task_lock::ROM_KERNEL;
                let mut kernel = original_kernel;
                kernel.rom_sem_wait = recording_wait;
                kernel.rom_sem_signal = recording_signal;
                task_lock::ROM_KERNEL = kernel;
                CODEC_READ_REG = recording_read;
                I2C_WRITE = recording_transfer;
                OPS.clear();
                READ_RESULT = 0;
                I2C_STATUS = 0;
                SIGNAL_RESULT = 0;
                Reset { original_kernel }
            }
        }
    }

    impl Drop for Reset {
        fn drop(&mut self) {
            unsafe {
                task_lock::ROM_KERNEL = self.original_kernel;
                CODEC_READ_REG = missing_codec_read_reg;
                I2C_WRITE = missing_i2c_write;
                OPS.clear();
                READ_RESULT = 0;
                I2C_STATUS = 0;
                SIGNAL_RESULT = 0;
            }
        }
    }

    fn writer_ops(reg: u32, value: u32, i2c_status: u32, signal_result: usize) -> (usize, Vec<Op>) {
        unsafe {
            OPS.clear();
            I2C_STATUS = i2c_status;
            SIGNAL_RESULT = signal_result;
            let result = codec_write_reg(reg, value);
            (result, OPS.clone())
        }
    }

    fn update_ops(old: u16, reg: u32, mask: u32, value: u32) -> Vec<Op> {
        unsafe {
            OPS.clear();
            READ_RESULT = old;
            codec_update_bits(reg, mask, value);
            OPS.clone()
        }
    }

    #[test]
    fn writer_truncates_inputs_and_brackets_two_byte_transfer() {
        let _kernel_lock = task_lock::tests::OPS_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _seam_lock = SEAM_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _reset = Reset::install();
        for (reg, value) in [(0, 0), (0x123, 0x1ff), (0xffff_ffff, 0xdead_beef)] {
            assert_eq!(
                writer_ops(reg, value, 0, 0),
                (
                    0,
                    vec![
                        Op::Wait(5),
                        Op::Transfer {
                            slave: 0x4a,
                            bytes: [reg as u8, value as u8],
                        },
                        Op::Signal(5),
                    ],
                ),
                "reg={reg:#x} value={value:#x}"
            );
        }
    }

    #[test]
    fn writer_ignores_transfer_status_but_returns_release_word() {
        let _kernel_lock = task_lock::tests::OPS_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _seam_lock = SEAM_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _reset = Reset::install();
        assert_eq!(
            writer_ops(0x1a, 0x1e0, 9, 0xfeed),
            (
                0xfeed,
                vec![
                    Op::Wait(5),
                    Op::Transfer {
                        slave: 0x4a,
                        bytes: [0x1a, 0xe0],
                    },
                    Op::Signal(5),
                ],
            ),
            "release remains unconditional after I2C failure and its r0 survives"
        );
    }

    #[test]
    fn update_reads_then_writes_merged_low_byte() {
        let _kernel_lock = task_lock::tests::OPS_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _seam_lock = SEAM_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _reset = Reset::install();
        let cases: [(u16, u32, u32); 12] = [
            (0x00, 0x00, 0xff),
            (0xa5, 0x00, 0xff),
            (0xa5, 0xff, 0x5a),
            (0xff, 0x0f, 0x3c),
            (0x0f, 0xf0, 0xa0),
            (0xa5, 0x80, 0x80),
            (0xa5, 0x80, 0x00),
            (0x55, 0x1c, 0x14),
            (0xff, 0x1ff, 0x1ff),
            (0x00, 0xffff_ffff, 0xdead_beef),
            (0x7f, 0xaa, 0x55),
            (0x1ab, 0x0f, 0x05),
        ];
        for (old, mask, value) in cases {
            let merged = ((old as u32) & !mask) | (value & mask);
            assert_eq!(
                update_ops(old, 7, mask, value),
                vec![
                    Op::Read { reg: 7 },
                    Op::Wait(5),
                    Op::Transfer {
                        slave: 0x4a,
                        bytes: [7, merged as u8],
                    },
                    Op::Signal(5),
                ],
                "old={old:#06x} mask={mask:#010x} value={value:#010x}"
            );
        }
    }
}
