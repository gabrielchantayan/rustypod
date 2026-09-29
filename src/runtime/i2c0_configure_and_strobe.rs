//! I2C0 configure-and-strobe @ 0x0836b77c.
//!
//! The S5L8702 I2C0 controller is at 0x3c60_0000. The routine waits for
//! `IICCON` (+0x10) to read zero, sets bits 8..13 in `IICSTA2` (+0x20),
//! waits for `IICCON` to return zero again, then writes the current base
//! register word back to itself. The final volatile write is a hardware
//! strobe, so it must not be optimized away.

use crate::runtime::i2c0_idle::I2C0_REGISTER_BASE;

const I2C0_CON_OFFSET: usize = 0x10;
const I2C0_STA2_OFFSET: usize = 0x20;
const I2C0_ENABLE_BITS: u32 = 0x3f00;
const I2C0_CON: *const u32 = (I2C0_REGISTER_BASE + I2C0_CON_OFFSET) as *const u32;
const I2C0_STA2: *mut u32 = (I2C0_REGISTER_BASE + I2C0_STA2_OFFSET) as *mut u32;
const I2C0_BASE: *mut u32 = I2C0_REGISTER_BASE as *mut u32;

#[cfg(target_os = "none")]
unsafe extern "C" fn default_con_read() -> u32 {
    core::ptr::read_volatile(I2C0_CON)
}

#[cfg(not(target_os = "none"))]
static HOST_I2C0_CON: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn default_con_read() -> u32 {
    HOST_I2C0_CON.load(core::sync::atomic::Ordering::Relaxed)
}

#[cfg(target_os = "none")]
unsafe extern "C" fn default_sta2_read() -> u32 {
    core::ptr::read_volatile(I2C0_STA2)
}

#[cfg(not(target_os = "none"))]
static HOST_I2C0_STA2: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn default_sta2_read() -> u32 {
    HOST_I2C0_STA2.load(core::sync::atomic::Ordering::Relaxed)
}

#[cfg(target_os = "none")]
unsafe extern "C" fn default_sta2_write(value: u32) {
    core::ptr::write_volatile(I2C0_STA2, value);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn default_sta2_write(value: u32) {
    HOST_I2C0_STA2.store(value, core::sync::atomic::Ordering::Relaxed);
}

#[cfg(target_os = "none")]
unsafe extern "C" fn default_base_read() -> u32 {
    core::ptr::read_volatile(I2C0_BASE)
}

#[cfg(not(target_os = "none"))]
static HOST_I2C0_BASE: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn default_base_read() -> u32 {
    HOST_I2C0_BASE.load(core::sync::atomic::Ordering::Relaxed)
}

#[cfg(target_os = "none")]
unsafe extern "C" fn default_base_write(value: u32) {
    core::ptr::write_volatile(I2C0_BASE, value);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn default_base_write(value: u32) {
    HOST_I2C0_BASE.store(value, core::sync::atomic::Ordering::Relaxed);
}

#[derive(Clone, Copy)]
pub struct I2c0ConfigureAndStrobeOps {
    pub con_read: unsafe extern "C" fn() -> u32,
    pub sta2_read: unsafe extern "C" fn() -> u32,
    pub sta2_write: unsafe extern "C" fn(u32),
    pub base_read: unsafe extern "C" fn() -> u32,
    pub base_write: unsafe extern "C" fn(u32),
}

pub static mut I2C0_CONFIGURE_AND_STROBE_OPS: I2c0ConfigureAndStrobeOps = I2c0ConfigureAndStrobeOps {
    con_read: default_con_read,
    sta2_read: default_sta2_read,
    sta2_write: default_sta2_write,
    base_read: default_base_read,
    base_write: default_base_write,
};

#[inline(always)]
fn i2c0_configure_and_strobe_ops() -> I2c0ConfigureAndStrobeOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(I2C0_CONFIGURE_AND_STROBE_OPS)) }
}

/// i2c0_configure_and_strobe — original: `FUN_0836b77c` @ 0x0836b77c
/// (52 bytes, including the 0x3c60_0000 literal at 0x0836b7b0).
///
/// Verified from `osos.dec`: 48 bytes of code followed by the literal; the
/// next function begins with `push {r4-r8, lr}` at 0x0836b7b4. It contains
/// zero BL instructions (plain or predicated). It polls `IICCON` before and
/// after the `IICSTA2 |= 0x3f00` update, then performs the base-register
/// read-back strobe described in the module header.
///
/// # Deviation
///
/// The five MMIO accesses dispatch through an ops slot so host tests can
/// observe the two polling phases. Shipped target defaults preserve volatile
/// accesses in the stock order; host defaults use private atomics because the
/// physical controller is unmapped.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn i2c0_configure_and_strobe() {
    let ops = i2c0_configure_and_strobe_ops();
    while (ops.con_read)() != 0 {}
    (ops.sta2_write)((ops.sta2_read)() | I2C0_ENABLE_BITS);
    while (ops.con_read)() != 0 {}
    (ops.base_write)((ops.base_read)());
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut CON_READS: u32 = 0;
    static mut CON_BUSY_THROUGH: u32 = 0;
    static mut STA2_WORD: u32 = 0;
    static mut STA2_WRITES: u32 = 0;
    static mut BASE_WORD: u32 = 0;
    static mut BASE_WRITES: u32 = 0;

    unsafe extern "C" fn mock_con_read() -> u32 {
        CON_READS += 1;
        u32::from(CON_READS <= CON_BUSY_THROUGH)
    }
    unsafe extern "C" fn mock_sta2_read() -> u32 { STA2_WORD }
    unsafe extern "C" fn mock_sta2_write(value: u32) { STA2_WORD = value; STA2_WRITES += 1; }
    unsafe extern "C" fn mock_base_read() -> u32 { BASE_WORD }
    unsafe extern "C" fn mock_base_write(value: u32) { assert_eq!(value, BASE_WORD); BASE_WRITES += 1; }

    struct OpsGuard { _lock: MutexGuard<'static, ()> }
    impl Drop for OpsGuard {
        fn drop(&mut self) {
            unsafe {
                I2C0_CONFIGURE_AND_STROBE_OPS = I2c0ConfigureAndStrobeOps {
                    con_read: default_con_read, sta2_read: default_sta2_read,
                    sta2_write: default_sta2_write, base_read: default_base_read,
                    base_write: default_base_write,
                };
            }
        }
    }

    fn install_mocks(busy_through: u32, sta2_word: u32, base_word: u32) -> OpsGuard {
        let lock = OPS_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            CON_READS = 0; CON_BUSY_THROUGH = busy_through; STA2_WORD = sta2_word;
            STA2_WRITES = 0; BASE_WORD = base_word; BASE_WRITES = 0;
            I2C0_CONFIGURE_AND_STROBE_OPS = I2c0ConfigureAndStrobeOps {
                con_read: mock_con_read, sta2_read: mock_sta2_read, sta2_write: mock_sta2_write,
                base_read: mock_base_read, base_write: mock_base_write,
            };
        }
        OpsGuard { _lock: lock }
    }

    #[test]
    fn waits_on_both_sides_of_sta2_update_then_strobes_base() {
        let _guard = install_mocks(3, 0x8000_0041, 0xa5a5_5a5a);
        unsafe { i2c0_configure_and_strobe(); }
        unsafe {
            assert_eq!(CON_READS, 5, "two zero reads delimit the STA2 write");
            assert_eq!(STA2_WORD, 0x8000_3f41);
            assert_eq!(STA2_WRITES, 1);
            assert_eq!(BASE_WRITES, 1);
        }
    }

    #[test]
    fn idle_controller_still_writes_sta2_once_and_strobes_base() {
        let _guard = install_mocks(0, 0, 0x1234_5678);
        unsafe { i2c0_configure_and_strobe(); }
        unsafe {
            assert_eq!(CON_READS, 2);
            assert_eq!(STA2_WORD, I2C0_ENABLE_BITS);
            assert_eq!(STA2_WRITES, 1);
            assert_eq!(BASE_WRITES, 1);
        }
    }
}
