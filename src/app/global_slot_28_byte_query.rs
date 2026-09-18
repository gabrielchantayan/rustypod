//! Runtime-global byte query.
//!
//! `global_slot_28_byte_query` — original: `FUN_081a99a8` @ **0x081a99a8**.
//! Raw ARM establishes the exact 56-byte extent, `0x081a99a8..0x081a99e0`:
//! `pop {r4, pc}` ends the body and its literal-pool word follows at
//! `0x081a99e0`; the next separately linked function starts at `0x081a99e4`.
//! Decoding every A32 `B`/`BL` immediate in `osos.dec` finds four inbound
//! plain unconditional `BL` calls (`0x0818de7c`, `0x0818ded4`, `0x0818df54`,
//! and `0x081a9044`) and zero predicated forms. The one outbound `BLX` is a
//! vtable-data dispatch, not an identified callee.
//!
//! # Algorithm
//!
//! Volatile-load the runtime-global pointer at `0x089ccb68`, then its target
//! word at `+0x28`. A NULL target returns `0x0b` and leaves `out` untouched.
//! Otherwise invoke the target's vtable word at `+0x24`, preserving the target
//! in `r0`; store its low return byte through `out`, then return zero.
//!
//! # Deliberate deviation
//!
//! Firmware pointers and vtable words are 32 bits. Host fixtures use
//! native-width typed pointers/function pointers, so their physical offsets
//! differ while the target-only compile-time assertions preserve ARM offsets.

use core::ptr::{addr_of, read_volatile};

/// Runtime-global pointer loaded by the stock literal pool.
pub const GLOBAL_SLOT_28_BYTE_QUERY_ADDRESS: usize = 0x089c_cb68;

/// Callback ABI stored in the target vtable's word at `+0x24`.
pub type GlobalSlot28ByteQuery = unsafe extern "C" fn(*mut GlobalSlot28ByteQueryTarget) -> u8;

/// Prefix of the runtime global used by this query.
#[repr(C)]
pub struct GlobalSlot28ByteQueryRoot {
    pub unresolved_00: [usize; 10],
    pub target: *mut GlobalSlot28ByteQueryTarget,
}

/// Vtable prefix consumed by this query.
#[repr(C)]
pub struct GlobalSlot28ByteQueryVtable {
    pub unresolved_00: [usize; 9],
    pub query_byte: GlobalSlot28ByteQuery,
}

/// Target object consumed by this query.
#[repr(C)]
pub struct GlobalSlot28ByteQueryTarget {
    pub vtable: *const GlobalSlot28ByteQueryVtable,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x28] = [0; core::mem::offset_of!(GlobalSlot28ByteQueryRoot, target)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x24] = [0; core::mem::offset_of!(GlobalSlot28ByteQueryVtable, query_byte)];

/// Host representation of the runtime-global query root.
#[cfg(not(target_os = "none"))]
pub static mut GLOBAL_SLOT_28_BYTE_QUERY_ROOT: *mut GlobalSlot28ByteQueryRoot = core::ptr::null_mut();

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn global_slot_28_byte_query_root() -> *mut GlobalSlot28ByteQueryRoot {
    read_volatile(GLOBAL_SLOT_28_BYTE_QUERY_ADDRESS as *const *mut GlobalSlot28ByteQueryRoot)
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn global_slot_28_byte_query_root() -> *mut GlobalSlot28ByteQueryRoot {
    read_volatile(addr_of!(GLOBAL_SLOT_28_BYTE_QUERY_ROOT))
}

/// Queries the runtime-global target's vtable and writes its returned byte.
///
/// # Safety
///
/// `out` must be writable. The firmware global must be NULL or point to a root
/// and target with readable fields and a callable vtable slot at `+0x24`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn global_slot_28_byte_query(out: *mut u8) -> u32 {
    let root = global_slot_28_byte_query_root();
    let target = read_volatile(addr_of!((*root).target));
    if target.is_null() {
        return 0x0b;
    }

    let vtable = read_volatile(addr_of!((*target).vtable));
    let query_byte = read_volatile(addr_of!((*vtable).query_byte));
    *out = query_byte(target);
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr::{addr_of, addr_of_mut, read_volatile, write_volatile};

    static TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    static mut SEEN_TARGET: *mut GlobalSlot28ByteQueryTarget = core::ptr::null_mut();

    unsafe extern "C" fn return_a5(target: *mut GlobalSlot28ByteQueryTarget) -> u8 {
        SEEN_TARGET = target;
        0xa5
    }

    struct RootRestore(*mut GlobalSlot28ByteQueryRoot);

    impl Drop for RootRestore {
        fn drop(&mut self) {
            unsafe { write_volatile(addr_of_mut!(GLOBAL_SLOT_28_BYTE_QUERY_ROOT), self.0) };
        }
    }

    #[test]
    fn null_target_returns_0b_without_writing_output() {
        let _lock = TEST_LOCK.lock();
        let mut root = GlobalSlot28ByteQueryRoot { unresolved_00: [0; 10], target: core::ptr::null_mut() };
        let restore = unsafe {
            let prior = read_volatile(addr_of!(GLOBAL_SLOT_28_BYTE_QUERY_ROOT));
            write_volatile(addr_of_mut!(GLOBAL_SLOT_28_BYTE_QUERY_ROOT), addr_of_mut!(root));
            RootRestore(prior)
        };
        let mut out = 0x5a;

        assert_eq!(unsafe { global_slot_28_byte_query(addr_of_mut!(out)) }, 0x0b);
        assert_eq!(out, 0x5a);
        drop(restore);
    }

    #[test]
    fn writes_callback_low_byte_and_returns_zero() {
        let _lock = TEST_LOCK.lock();
        let vtable = GlobalSlot28ByteQueryVtable { unresolved_00: [0; 9], query_byte: return_a5 };
        let mut target = GlobalSlot28ByteQueryTarget { vtable: addr_of!(vtable) };
        let mut root = GlobalSlot28ByteQueryRoot { unresolved_00: [0; 10], target: addr_of_mut!(target) };
        let restore = unsafe {
            let prior = read_volatile(addr_of!(GLOBAL_SLOT_28_BYTE_QUERY_ROOT));
            write_volatile(addr_of_mut!(GLOBAL_SLOT_28_BYTE_QUERY_ROOT), addr_of_mut!(root));
            SEEN_TARGET = core::ptr::null_mut();
            RootRestore(prior)
        };
        let mut out = 0;

        assert_eq!(unsafe { global_slot_28_byte_query(addr_of_mut!(out)) }, 0);
        assert_eq!(out, 0xa5);
        assert_eq!(unsafe { SEEN_TARGET }, addr_of_mut!(target));
        drop(restore);
    }
}
