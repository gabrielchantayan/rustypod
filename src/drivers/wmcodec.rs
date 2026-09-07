//! Wolfson two-wire audio codec register access.
//!
//! # Ported functions
//!
//! - `wmcodec_write_reg` — original: `FUN_080da15c` @ `0x080da15c` (72
//!   bytes including the literal pool at `0x080da1a4`; the next function
//!   starts at `0x080da1a8`). It has **21 direct, unconditional `bl` call
//!   sites, 0 predicated forms**, verified by decoding every ARM B/BL word
//!   in osos.dec; its only other branch reach is the `b` tail at
//!   `0x080e3330` from [`wmcodec_update_bits`]. No data word references its
//!   address, so it is never virtually dispatched.
//! - `wmcodec_update_bits` — original: `FUN_080e3318` @ `0x080e3318` (28
//!   bytes, plus the shadow-table literal at `0x080e3334`), a tail caller
//!   which merges a mask into one cached value before writing it.
//!
//! # Algorithm
//!
//! `wmcodec_write_reg` sends the two-byte Wolfson control word
//! `{ (reg << 1) | ((value >> 8) & 1), value }` to I2C slave `0x1a`,
//! bracketed by RTXC semaphore 5. It ignores the raw transfer status,
//! signals the semaphore unconditionally, then stores the low 16 bits of
//! the original value in `shadow[reg]`. The wire retains only value bit 8
//! and bits 0..7; the cache deliberately retains bits 0..15. The unchecked
//! register index and ordering are both literal ARM behavior.
//!
//! The shared shadow table @ `0x08ad9de4` is 68 `u16` entries (0x88 bytes)
//! in osos BSS, past the end of osos.dec and thus zero-filled at boot. The
//! dump loop at `0x080a9824` verifies its `0x44` entry count.
//!
//! # Deliberate deviations
//!
//! - The raw S5L8702 I2C transfer `FUN_0836bb84` is unported. On target,
//!   [`i2c_write`] calls its fixed address through a typed function pointer;
//!   host tests replace it with a recorder. This produces an indirect
//!   `blx` rather than retail's direct `bl`, while preserving the transfer
//!   ABI and all observable effects.
//! - The semaphore wrappers are the existing ports
//!   [`crate::kernel::task_lock::kernel_sem5_wait`] and
//!   [`crate::kernel::task_lock::kernel_sem5_signal`], whose documented ROM
//!   hook deviations are inherited here.
//! - [`shadow_table()`] uses the retail BSS address on target and a
//!   module-owned replica on host; the BSS object exists in no host fixture.

use crate::kernel::task_lock::{kernel_sem5_signal, kernel_sem5_wait};

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
    panic!("wmcodec_write_reg requires I2C write 0x0836bb84")
}

/// Active host boundary for the unported raw I2C write transfer.
#[cfg(not(target_os = "none"))]
static mut I2C_WRITE: I2cWriteFn = missing_i2c_write;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn i2c_write(slave: u32, len: u32, buf: *const u8) -> u32 {
    core::ptr::read_volatile(core::ptr::addr_of!(I2C_WRITE))(slave, len, buf)
}

/// RetailOS load address of the 68-entry `u16` register shadow table
/// (osos BSS — past the end of osos.dec, zero-filled at boot).
pub const WMCODEC_SHADOW_ADDRESS: usize = 0x08ad_9de4;

/// Number of shadowed registers (the dump loop at 0x080a9824 counts
/// `cmp r0, #0x44`).
pub const WMCODEC_REG_COUNT: usize = 0x44;

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

/// wmcodec_write_reg — original: `FUN_080da15c` @ `0x080da15c` (72 bytes,
/// including its literal-pool word at `0x080da1a4`).
///
/// Encodes `reg` and the low 9 bits of `value` as the two-byte Wolfson
/// control word, waits on semaphore 5, writes it to I2C slave `0x1a`,
/// signals semaphore 5 regardless of the transfer status, then caches the
/// low 16 bits of `value` in the unchecked shadow entry `reg`.
///
/// # Safety
///
/// `reg` must be below [`WMCODEC_REG_COUNT`] on host. On target, any index
/// writes osos RAM at `0x08ad9de4 + reg * 2`, exactly as the ARM `strh`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn wmcodec_write_reg(reg: u32, value: u32) {
    let control = [
        ((reg << 1) | ((value & 0x100) >> 8)) as u8,
        value as u8,
    ];
    kernel_sem5_wait();
    i2c_write(0x1a, 2, control.as_ptr());
    kernel_sem5_signal();
    shadow_table().add(reg as usize).write(value as u16);
}

/// wmcodec_update_bits — original: `FUN_080e3318` @ `0x080e3318` (28
/// bytes).
///
/// Reads codec register `reg`'s cached value from the shadow table,
/// replaces the bits selected by `mask` with the corresponding bits of
/// `value` — `(old & !mask) | (value & mask)` in 32 bits with `old` the
/// zero-extended shadow halfword — then tail-calls [`wmcodec_write_reg`].
///
/// # Safety
///
/// `reg` has the same unchecked shadow-table requirement as
/// [`wmcodec_write_reg`].
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn wmcodec_update_bits(reg: u32, mask: u32, value: u32) {
    let old = shadow_table().add(reg as usize).read() as u32;
    let merged = (old & !mask) | (value & mask);
    wmcodec_write_reg(reg, merged);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::kernel::task_lock::{self, RomThunkOps};
    use std::sync::Mutex;
    use std::vec::Vec;

    static SEAM_LOCK: Mutex<()> = Mutex::new(());

    #[derive(Clone, Debug, PartialEq)]
    enum Op {
        Wait(usize),
        Transfer { slave: u32, bytes: [u8; 2] },
        Signal(usize),
    }

    static mut OPS: Vec<Op> = Vec::new();
    static mut TRANSFER_STATUS: u32 = 0;

    unsafe extern "C" fn recording_wait(sem: usize) -> usize {
        OPS.push(Op::Wait(sem));
        0
    }

    unsafe extern "C" fn recording_transfer(slave: u32, len: u32, buf: *const u8) -> u32 {
        assert_eq!(len, 2, "wmcodec_write_reg always sends two bytes");
        OPS.push(Op::Transfer {
            slave,
            bytes: [buf.read(), buf.add(1).read()],
        });
        TRANSFER_STATUS
    }

    unsafe extern "C" fn recording_signal(sem: usize) -> usize {
        OPS.push(Op::Signal(sem));
        0
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
                I2C_WRITE = recording_transfer;
                OPS.clear();
                TRANSFER_STATUS = 0;
                core::ptr::addr_of_mut!(HOST_SHADOW)
                    .cast::<[u16; WMCODEC_REG_COUNT]>()
                    .write([0; WMCODEC_REG_COUNT]);
                Reset { original_kernel }
            }
        }
    }

    impl Drop for Reset {
        fn drop(&mut self) {
            unsafe {
                task_lock::ROM_KERNEL = self.original_kernel;
                I2C_WRITE = missing_i2c_write;
                OPS.clear();
                TRANSFER_STATUS = 0;
            }
        }
    }

    unsafe fn set_shadow(reg: usize, value: u16) {
        shadow_table().add(reg).write(value);
    }

    unsafe fn get_shadow(reg: usize) -> u16 {
        shadow_table().add(reg).read()
    }

    fn writer_ops(reg: u32, value: u32, transfer_status: u32) -> Vec<Op> {
        unsafe {
            OPS.clear();
            TRANSFER_STATUS = transfer_status;
            wmcodec_write_reg(reg, value);
            OPS.clone()
        }
    }

    #[test]
    fn writer_encodes_wire_word_and_brackets_transfer() {
        let _kernel_lock = task_lock::tests::OPS_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _seam_lock = SEAM_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _reset = Reset::install();
        for (reg, value) in [
            (0u32, 0x000),
            (0x12, 0x0ab),
            (0x12, 0x1ab),
            (0x43, 0x3ff),
            (3, 0xdead_beef),
        ] {
            let control = [
                ((reg << 1) | ((value & 0x100) >> 8)) as u8,
                value as u8,
            ];
            assert_eq!(
                writer_ops(reg, value, 0),
                [
                    Op::Wait(5),
                    Op::Transfer {
                        slave: 0x1a,
                        bytes: control,
                    },
                    Op::Signal(5),
                ],
                "reg={reg:#x} value={value:#x}"
            );
            unsafe {
                assert_eq!(get_shadow(reg as usize), value as u16);
            }
        }
    }

    #[test]
    fn writer_signals_and_caches_after_transfer_failure() {
        let _kernel_lock = task_lock::tests::OPS_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _seam_lock = SEAM_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _reset = Reset::install();
        assert_eq!(
            writer_ops(0x1a, 0x1e0, 9),
            [
                Op::Wait(5),
                Op::Transfer {
                    slave: 0x1a,
                    bytes: [0x35, 0xe0],
                },
                Op::Signal(5),
            ]
        );
        unsafe {
            assert_eq!(get_shadow(0x1a), 0x1e0);
        }
    }

    #[test]
    fn update_bits_merges_before_calling_writer() {
        let _kernel_lock = task_lock::tests::OPS_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _seam_lock = SEAM_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _reset = Reset::install();
        for (old, mask, value) in [
            (0x1a5u16, 0x000, 0x1ff),
            (0x1a5, 0x1ff, 0x05a),
            (0x00f, 0x1f0, 0x0a0),
            (0x000, 0xffff_ffff, 0xdead_beef),
        ] {
            let merged = ((old as u32) & !mask) | (value & mask);
            unsafe {
                OPS.clear();
                set_shadow(7, old);
                wmcodec_update_bits(7, mask, value);
            }
            assert_eq!(
                unsafe { OPS.clone() },
                [
                    Op::Wait(5),
                    Op::Transfer {
                        slave: 0x1a,
                        bytes: [
                            ((7 << 1) | ((merged & 0x100) >> 8)) as u8,
                            merged as u8,
                        ],
                    },
                    Op::Signal(5),
                ],
                "old={old:#x} mask={mask:#x} value={value:#x}"
            );
            unsafe {
                assert_eq!(get_shadow(7), merged as u16);
            }
        }
    }
}
