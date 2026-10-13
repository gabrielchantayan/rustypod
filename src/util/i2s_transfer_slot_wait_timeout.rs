//! I2S transfer-slot timeout wait.
//!
//! `thunk_EXT_FUN_220086c4` @ 0x08038000: true size 8 bytes, ending at
//! 0x08038008. Raw words e51ff004/220086c4 dispatch to the IRAM mirror
//! of 0x080086c4. Two plain inbound BLs (0x0836b05c, 0x0836b0c4), zero
//! predicated inbound BLs, and zero outgoing BLs in the veneer. The mirrored
//! body has 56 instruction bytes plus its four-byte table literal, ending at
//! 0x08008700; its single outgoing plain BL at 0x080086e8 reaches 0x08003a00.
//!
//! Select the word at table + controller*32 + channel*4 - 32. An empty cell
//! returns 0x11. Otherwise pass its handle and timeout to the unidentified
//! firmware boundary, returning zero on success or 0x1f for any nonzero result.
//! The boundary's literal is 0x0804ba84; no callee identity is assumed.
//! Deliberate deviation: implement the mirrored lookup/status algorithm here
//! rather than retaining an IRAM jump; LLVM calls the resolved firmware
//! boundary indirectly. Hosts inject that boundary and table for testing.

pub type TransferTimeoutCore = unsafe extern "C" fn(u32, u32) -> u32;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_timeout_core(handle: u32, timeout: u32) -> u32 {
    let call: TransferTimeoutCore = core::mem::transmute(0x0804_ba84usize);
    call(handle, timeout)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_timeout_core(_: u32, _: u32) -> u32 {
    panic!("transfer timeout requires retailOS boundary 0x0804ba84")
}

pub static mut I2S_TRANSFER_TIMEOUT_TABLE_BASE: *const u32 = 0x2200_ae7cusize as *const u32;
#[cfg(target_os = "none")]
pub static mut I2S_TRANSFER_TIMEOUT_CORE: TransferTimeoutCore = firmware_timeout_core;
#[cfg(not(target_os = "none"))]
pub static mut I2S_TRANSFER_TIMEOUT_CORE: TransferTimeoutCore = unavailable_timeout_core;

/// # Safety
/// The selected table cell must be readable and its handle valid for the
/// installed timeout core. No controller/channel bounds checks are added.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn i2s_transfer_slot_wait_timeout(
    controller: i32, channel: i32, timeout: u32,
) -> u32 {
    wait_at(I2S_TRANSFER_TIMEOUT_TABLE_BASE, I2S_TRANSFER_TIMEOUT_CORE,
        controller, channel, timeout)
}

unsafe fn wait_at(table: *const u32, wait: TransferTimeoutCore,
    controller: i32, channel: i32, timeout: u32) -> u32 {
    let index = controller.wrapping_mul(8).wrapping_add(channel).wrapping_sub(8);
    let handle = table.offset(index as isize).read_volatile();
    if handle == 0 { return 0x11; }
    if wait(handle, timeout) == 0 { 0 } else { 0x1f }
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn must_not_wait(_: u32, _: u32) -> u32 {
        panic!("empty slot must not enter firmware")
    }

    // A consumable handle model: bit 31 means completion, low bits give the
    // remaining ticks. Exercise the port's status normalization independently
    // of the unported firmware implementation.
    unsafe extern "C" fn completion_model(handle: u32, timeout: u32) -> u32 {
        if handle & 0x8000_0000 != 0 || timeout >= handle { 0 } else { u32::MAX }
    }

    #[test]
    fn empty_cells_do_not_wait_even_with_extreme_timeout() {
        let cells = [0u32; 24];
        for (controller, channel) in [(0, 0), (1, -1), (2, 7)] {
            for timeout in [0, 1, u32::MAX] {
                assert_eq!(unsafe { wait_at(cells.as_ptr().add(8), must_not_wait,
                    controller, channel, timeout) }, 0x11);
            }
        }
    }

    #[test]
    fn selected_handle_completion_and_timeout_map_to_retail_status() {
        let mut cells = [0u32; 24];
        cells[7] = 3;
        cells[23] = 0x8000_0001;
        for (controller, channel, timeout, expected) in [
            (1, -1, 0, 0x1f), (1, -1, 2, 0x1f), (1, -1, 3, 0),
            (1, -1, u32::MAX, 0), (2, 7, 0, 0), (1, 0, 99, 0x11),
        ] {
            assert_eq!(unsafe { wait_at(cells.as_ptr().add(8), completion_model,
                controller, channel, timeout) }, expected);
        }
    }
}
