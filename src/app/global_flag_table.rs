//! Global flag-byte table writer.
//!
//! Original: `FUN_0819c9d0` @ 0x0819c9d0 (16 bytes exactly:
//! three instructions plus the 0x08a77a8f literal-pool word at
//! 0x0819c9dc; the next function starts at 0x0819c9e0). A complete
//! ARM B/BL-word scan of osos.dec finds 32 direct call sites: all are
//! unconditional `bl` instructions.
//!
//! # Algorithm
//!
//! Store `value` into the global flag-byte table at 0x08a77a8f plus the
//! unguarded `index`. The literal base is deliberately odd; the original
//! uses byte addressing and neither aligns nor bounds-checks the index.
//!
//! # Deliberate deviation
//!
//! Host builds use a 0x78-byte local table so tests can observe the stores;
//! target builds write the retailOS table at its literal address.

#[cfg(target_os = "none")]
const GLOBAL_FLAG_TABLE: *mut u8 = 0x08a7_7a8f as *mut u8;

#[cfg(not(target_os = "none"))]
static mut HOST_GLOBAL_FLAG_TABLE: [u8; 0x78] = [0; 0x78];

#[inline(always)]
unsafe fn global_flag_table() -> *mut u8 {
    #[cfg(target_os = "none")]
    {
        GLOBAL_FLAG_TABLE
    }

    #[cfg(not(target_os = "none"))]
    {
        core::ptr::addr_of_mut!(HOST_GLOBAL_FLAG_TABLE).cast()
    }
}

/// set_global_flag_byte — original: `FUN_0819c9d0` @ 0x0819c9d0
/// (16 bytes including the literal pool; 32 unconditional `bl` callers).
///
/// Writes `value` to global flag-table byte `index`, without a NULL, alignment,
/// or bounds guard, exactly as `ldr r2, [pc, #4]; strb r1, [r2, r0]; bx lr`.
///
/// # Safety
///
/// The retailOS table must cover `index`; the original has no bounds check.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn set_global_flag_byte(index: u32, value: u8) {
    unsafe { global_flag_table().add(index as usize).write_volatile(value) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static TABLE_LOCK: Mutex<()> = Mutex::new(());

    unsafe fn reset_table() -> *mut u8 {
        let table = unsafe { global_flag_table() };
        unsafe { core::ptr::write_bytes(table, 0, 0x78) };
        table
    }

    #[test]
    fn writes_values_at_observed_flag_indices() {
        let _guard = TABLE_LOCK.lock();
        let table = unsafe { reset_table() };

        for (index, value) in [(0x00, 0xa5), (0x1d, 0x01), (0x5a, 0x02), (0x6f, 0xfe), (0x77, 0x3c)] {
            unsafe { set_global_flag_byte(index, value) };
            assert_eq!(unsafe { table.add(index as usize).read_volatile() }, value);
        }
    }

    #[test]
    fn overwrites_only_the_selected_byte() {
        let _guard = TABLE_LOCK.lock();
        let table = unsafe { reset_table() };
        unsafe {
            table.add(0x58).write_volatile(0x11);
            table.add(0x59).write_volatile(0x22);
            table.add(0x5a).write_volatile(0x33);
            set_global_flag_byte(0x59, 0xe4);
        }

        assert_eq!(unsafe { table.add(0x58).read_volatile() }, 0x11);
        assert_eq!(unsafe { table.add(0x59).read_volatile() }, 0xe4);
        assert_eq!(unsafe { table.add(0x5a).read_volatile() }, 0x33);
    }
}
