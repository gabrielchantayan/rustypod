//! Lazy slot-table entry accessor.
//!
//! `lazy_slot_table_entry` — original: `FUN_081cda64` @ `0x081cda64`
//! (24 bytes, `0x081cda64..0x081cda7c`; Ghidra reports 32 bytes). The true
//! boundary is the `push` beginning `FUN_081cda7c`, immediately after the
//! final tail branch.
//!
//! Raw ARM decoding finds exactly 9 direct call sites, all unconditional `bl`
//! (at `0x0829c874`, `0x0829c944`, `0x0829da30`, `0x0829da44`, `0x0829da78`,
//! `0x0829da8c`, `0x0829ee8c`, `0x0829eeb4`, and `0x0829eecc`); there are no
//! predicated calls or plain branches to this entry.
//!
//! # Algorithm
//!
//! Saves the requested slot, calls the lazy table getter at `0x081cda30`, then
//! tail-calls the two-instruction `ldr r0, [r0, r1, lsl #2]; bx lr` helper at
//! `0x081cd9b8`. Thus it returns the requested word from the table and does no
//! bounds or NULL checking. `FUN_081cda30` allocates a 15-word table and fills
//! it with 0x2000-byte-buffer records, but no surviving call-site evidence
//! establishes a concrete class identity for those records.
//!
//! # Deliberate deviations
//!
//! On target this invokes the fixed retail getter address; host tests install
//! a getter seam. The tail call is expressed as an indexed Rust load rather
//! than a distinct call to `0x081cd9b8`; its observable result is identical.

#[cfg(not(target_os = "none"))]
use core::ptr::addr_of;

/// Address of the unported lazy slot-table getter (`FUN_081cda30`).
const RETAIL_LAZY_SLOT_TABLE_GETTER: usize = 0x081c_da30;

/// ABI of the unported lazy table getter.
pub type LazySlotTableGetter = unsafe extern "C" fn() -> *mut *mut u8;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn retail_lazy_slot_table() -> *mut *mut u8 {
    let getter: LazySlotTableGetter = core::mem::transmute(RETAIL_LAZY_SLOT_TABLE_GETTER);
    getter()
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_lazy_slot_table() -> *mut *mut u8 {
    panic!("install lazy slot-table host operations before accessing an entry")
}

/// Host default before a test installs the retail-table equivalent.
#[cfg(not(target_os = "none"))]
pub const DEFAULT_LAZY_SLOT_TABLE_GETTER: LazySlotTableGetter = missing_lazy_slot_table;

/// Host-side seam for the unported retail table getter.
#[cfg(not(target_os = "none"))]
pub static mut LAZY_SLOT_TABLE_GETTER: LazySlotTableGetter = DEFAULT_LAZY_SLOT_TABLE_GETTER;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn host_lazy_slot_table() -> *mut *mut u8 {
    let getter = core::ptr::read_volatile(addr_of!(LAZY_SLOT_TABLE_GETTER));
    getter()
}

/// lazy_slot_table_entry — original: `FUN_081cda64` @ `0x081cda64` (24 bytes;
/// **9 unconditional direct `bl` sites and no predicated forms**).
///
/// Returns `table[slot]` after forcing the table's lazy initialization. The
/// original has no bounds or NULL guard: `slot` must name a readable table word
/// and the getter must return a valid table pointer.
///
/// # Safety
///
/// The retail getter must return a table containing a readable entry at `slot`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn lazy_slot_table_entry(slot: u32) -> *mut u8 {
    #[cfg(target_os = "none")]
    let table = retail_lazy_slot_table();
    #[cfg(not(target_os = "none"))]
    let table = host_lazy_slot_table();
    table.add(slot as usize).read()
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr::addr_of_mut;
    use parking_lot::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut GETTER_CALLS: u32 = 0;
    static mut SLOTS: [*mut u8; 16] = [core::ptr::null_mut(); 16];

    unsafe extern "C" fn test_slot_table() -> *mut *mut u8 {
        GETTER_CALLS += 1;
        addr_of_mut!(SLOTS).cast::<*mut u8>()
    }

    fn install_table() -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock();
        unsafe {
            GETTER_CALLS = 0;
            for slot in 0..16 {
                addr_of_mut!(SLOTS).cast::<*mut u8>().add(slot).write(core::ptr::null_mut());
            }
            LAZY_SLOT_TABLE_GETTER = test_slot_table;
        }
        guard
    }

    #[test]
    fn returns_requested_known_slot_after_getter() {
        let _guard = install_table();
        unsafe {
            let table = addr_of_mut!(SLOTS).cast::<*mut u8>();
            table.add(0).write(0x1000usize as *mut u8);
            table.add(1).write(0x2000usize as *mut u8);
            table.add(5).write(0x6000usize as *mut u8);
            table.add(13).write(0xe000usize as *mut u8);

            assert_eq!(lazy_slot_table_entry(0), 0x1000usize as *mut u8);
            assert_eq!(lazy_slot_table_entry(1), 0x2000usize as *mut u8);
            assert_eq!(lazy_slot_table_entry(5), 0x6000usize as *mut u8);
            assert_eq!(lazy_slot_table_entry(13), 0xe000usize as *mut u8);
            assert_eq!(GETTER_CALLS, 4);
        }
    }

    #[test]
    fn preserves_null_slot_without_a_guard() {
        let _guard = install_table();
        unsafe {
            assert!(lazy_slot_table_entry(15).is_null());
            assert_eq!(GETTER_CALLS, 1);
        }
    }
}
