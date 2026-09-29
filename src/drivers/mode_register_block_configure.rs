//! Mode register-block setup — original: `FUN_0836dff8` @ `0x0836dff8`.
//!
//! Raw `osos.dec` establishes the exact 136-byte A32 extent
//! `0x0836dff8..0x0836e07f`: 33 instruction words through `pop {pc}`, followed
//! by the two-word literal pool at `0x0836e080`; `0x0836e088` is the next real
//! function. The body contains no `bl` instructions; whole-image decoding
//! finds two inbound plain `bl` sites and no predicated `bl` sites. It selects
//! one of four 16 KiB-spaced register blocks, then writes its mode, format,
//! dimensions, stride, and control words. Deliberate deviation: host builds
//! replace the fixed MMIO base with an installable test pointer.

const MODE_REGISTER_BLOCK_ADDRESS: usize = 0x3cc0_0000;
const MODE_REGISTER_BLOCK_STRIDE: usize = 0x4000;
const MODE_FORMAT: u32 = 0x405;

#[cfg(not(target_os = "none"))]
static mut MODE_REGISTER_BLOCKS: *mut u8 = MODE_REGISTER_BLOCK_ADDRESS as *mut u8;

#[inline(always)]
unsafe fn mode_register_blocks() -> *mut u8 {
    #[cfg(target_os = "none")]
    { MODE_REGISTER_BLOCK_ADDRESS as *mut u8 }
    #[cfg(not(target_os = "none"))]
    { core::ptr::read_volatile(core::ptr::addr_of!(MODE_REGISTER_BLOCKS)) }
}

#[inline(always)]
unsafe fn mode_register_block(mode: u32) -> *mut u8 {
    let bank = match mode {
        0 => 0,
        1 => 1,
        2 => 2,
        _ => 3,
    };
    mode_register_blocks().add(bank * MODE_REGISTER_BLOCK_STRIDE)
}

/// Configures the mode-selected 16 KiB register block.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn mode_register_block_configure(mode: u32) {
    let registers = mode_register_block(mode);
    registers.add(4).cast::<u32>().write_volatile(MODE_FORMAT);
    registers.cast::<u32>().write_volatile(3);
    registers.add(12).cast::<u32>().write_volatile(1);
    registers.add(16).cast::<u32>().write_volatile(0x170);
    registers.add(40).cast::<u32>().write_volatile(12);
    registers.add(8).cast::<u32>().write_volatile(7);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use core::ptr;
    use std::sync::{Mutex, MutexGuard};

    use super::*;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    struct Restore {
        blocks: *mut u8,
        _lock: MutexGuard<'static, ()>,
    }

    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe { MODE_REGISTER_BLOCKS = self.blocks; }
        }
    }

    fn install(blocks: *mut u8) -> Restore {
        let lock = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            let old_blocks = MODE_REGISTER_BLOCKS;
            MODE_REGISTER_BLOCKS = blocks;
            Restore { blocks: old_blocks, _lock: lock }
        }
    }

    #[test]
    fn configures_each_mode_bank_and_maps_other_modes_to_the_fourth() {
        let mut blocks = [0xa5a5_a5a5u32; (MODE_REGISTER_BLOCK_STRIDE * 4 + 44) / 4];
        let _restore = install(blocks.as_mut_ptr().cast());

        for (mode, bank) in [(0, 0), (1, 1), (2, 2), (3, 3), (u32::MAX, 3)] {
            unsafe { mode_register_block_configure(mode) };
            let registers = unsafe { blocks.as_ptr().cast::<u8>().add(bank * MODE_REGISTER_BLOCK_STRIDE) };
            unsafe {
                assert_eq!(ptr::read(registers.cast::<u32>()), 3);
                assert_eq!(ptr::read(registers.add(4).cast::<u32>()), MODE_FORMAT);
                assert_eq!(ptr::read(registers.add(8).cast::<u32>()), 7);
                assert_eq!(ptr::read(registers.add(12).cast::<u32>()), 1);
                assert_eq!(ptr::read(registers.add(16).cast::<u32>()), 0x170);
                assert_eq!(ptr::read(registers.add(40).cast::<u32>()), 12);
            }
        }
    }
}
