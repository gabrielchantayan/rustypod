//! FAT directory cursor block advance — `FUN_082e36c8` @ `0x082e36c8`.
//!
//! Raw `osos.dec` words establish the 36-byte extent
//! `0x082e36c8..0x082e36eb`; `0x082e36ec` starts the next independently
//! entered function with `mov r3, r0`. Whole-image ARM B/BL decoding finds
//! three inbound plain `bl` calls (0x082e1340, 0x082e208c, and 0x082e2918) and
//! no predicated BL calls.
//!
//! # Algorithm
//!
//! Passes the FAT volume at cursor word zero and its current cache-block index
//! at word three to resident `FUN_082e2b34`. A nonzero next index replaces
//! cursor word three; zero leaves it unchanged. The returned status is one
//! exactly when that next index is nonzero.
//!
//! # Deliberate deviations
//!
//! `FUN_082e2b34` is not ported. Target builds dispatch to its exact resident
//! address; host tests install a recording seam for that boundary.

/// ABI of resident FAT cache-block advancement helper `FUN_082e2b34`.
type FatCursorNextBlock = unsafe extern "C" fn(*mut u8, u32) -> u32;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn fat_cursor_next_block(volume: *mut u8, block: u32) -> u32 {
    let function: FatCursorNextBlock = core::mem::transmute(0x082e2b34usize);
    function(volume, block)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_next_block(_volume: *mut u8, _block: u32) -> u32 {
    panic!("fat_cursor_advance_block called without a host next-block seam")
}

#[cfg(not(target_os = "none"))]
static mut FAT_CURSOR_NEXT_BLOCK: FatCursorNextBlock = unavailable_next_block;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn fat_cursor_next_block(volume: *mut u8, block: u32) -> u32 {
    (core::ptr::addr_of!(FAT_CURSOR_NEXT_BLOCK).read_volatile())(volume, block)
}

/// Advances a FAT directory cursor to its next cache block.
///
/// Original: `FUN_082e36c8` at `0x082e36c8`, 36 bytes, with three verified
/// plain `bl` callers and zero predicated BL callers.
///
/// # Safety
///
/// `cursor` must point to at least four target-width words. Its first word is
/// the FAT volume pointer and word three is the current cache-block index.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn fat_cursor_advance_block(cursor: *mut u32) -> u32 {
    let next_block = fat_cursor_next_block((*cursor) as usize as *mut u8, *cursor.add(3));
    if next_block != 0 {
        cursor.add(3).write(next_block);
    }
    u32::from(next_block != 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut NEXT_BLOCK_RESULT: u32 = 0;
    static mut NEXT_BLOCK_CALL: Option<(*mut u8, u32)> = None;

    unsafe extern "C" fn record_next_block(volume: *mut u8, block: u32) -> u32 {
        NEXT_BLOCK_CALL = Some((volume, block));
        NEXT_BLOCK_RESULT
    }

    struct NextBlockReset(FatCursorNextBlock);

    impl Drop for NextBlockReset {
        fn drop(&mut self) {
            unsafe { core::ptr::addr_of_mut!(FAT_CURSOR_NEXT_BLOCK).write_volatile(self.0) };
        }
    }

    unsafe fn install_next_block(result: u32) -> NextBlockReset {
        NEXT_BLOCK_RESULT = result;
        NEXT_BLOCK_CALL = None;
        let prior = core::ptr::addr_of!(FAT_CURSOR_NEXT_BLOCK).read_volatile();
        core::ptr::addr_of_mut!(FAT_CURSOR_NEXT_BLOCK).write_volatile(record_next_block);
        NextBlockReset(prior)
    }

    #[test]
    fn updates_the_cursor_only_for_a_nonzero_next_block() {
        let _lock = TEST_LOCK.lock();
        let _reset = unsafe { install_next_block(0x2345) };
        let mut cursor = [0u32; 4];
        cursor[0] = 0x1234_5000;
        cursor[3] = 0x1234;

        assert_eq!(unsafe { fat_cursor_advance_block(cursor.as_mut_ptr()) }, 1);
        assert_eq!(cursor[3], 0x2345);
        assert_eq!(unsafe { NEXT_BLOCK_CALL }, Some((cursor[0] as *mut u8, 0x1234)));
    }

    #[test]
    fn preserves_the_cursor_block_when_the_resident_helper_fails() {
        let _lock = TEST_LOCK.lock();
        let _reset = unsafe { install_next_block(0) };
        let mut cursor = [0u32; 4];
        cursor[0] = 0xabcd_0000;
        cursor[3] = 0x7654;

        assert_eq!(unsafe { fat_cursor_advance_block(cursor.as_mut_ptr()) }, 0);
        assert_eq!(cursor[3], 0x7654);
        assert_eq!(unsafe { NEXT_BLOCK_CALL }, Some((cursor[0] as *mut u8, 0x7654)));
    }
}
