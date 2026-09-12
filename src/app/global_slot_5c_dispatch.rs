//! `global_slot_5c_dispatch` — original: `FUN_081b0ad8` @ `0x081b0ad8`
//! (24 instruction bytes, `0x081b0ad8..0x081b0af0`, plus its 4-byte literal
//! pool at `0x081b0af0`; the next separately linked function starts at
//! `0x081b0af4`, for a 28-byte true extent).
//!
//! Raw ARM moves the incoming payload from `r0` to `r1`, loads the target from
//! the word at `0x089cb234` (the `+4` word of the literal `0x089cb230`), then
//! tail-dispatches that target's vtable slot `+0x5c`. The slot's concrete
//! identity is not established, so this port names only the verified forwarding
//! role. Full-image decoding finds **8 direct `bl` callers**, all unconditional
//! and none predicated: `0x08179260`, `0x08179c40`, `0x0817a380`,
//! `0x0817b5b8`, `0x0817bc8c`, `0x0817bcc4`, `0x0817d108`, and `0x0817d3f4`.
//! Three additional unconditional `b` tail entries (`0x081792f4`, `0x0817a7cc`,
//! `0x0817d68c`) reach this wrapper. There are no aligned data-word references
//! to its entry.
//!
//! Deliberate host deviation: the physical target-global word is represented by
//! [`GLOBAL_SLOT_5C_TARGET`], while the host vtable uses native-width function
//! pointers. Target builds volatile-read the original global and its 32-bit
//! vtable slot exactly. The slot return is preserved because the raw tail branch
//! returns its `r0` unchanged even though every recovered plain caller ignores it.

use core::ptr::{addr_of, read_volatile};

/// Address of the literal-designated global holder. The wrapper reads its +4
/// word; the bytes in the decrypted file currently hold stale string data, so
/// no concrete singleton identity is claimed.
pub const GLOBAL_SLOT_5C_HOLDER_ADDRESS: usize = 0x089c_b230;
const GLOBAL_SLOT_5C_TARGET_ADDRESS: usize = GLOBAL_SLOT_5C_HOLDER_ADDRESS + 4;
const GLOBAL_SLOT_5C_VTABLE_WORD: usize = 0x5c / 4;

/// The target object as far as this forwarding wrapper observes it.
#[repr(C)]
pub struct GlobalSlot5cTarget {
    /// +0x00: vtable pointer.
    pub vtable: *const GlobalSlot5cVtable,
}

/// ABI of the unresolved vtable slot at target `+0x5c`.
pub type GlobalSlot5cDispatch = unsafe extern "C" fn(*mut GlobalSlot5cTarget, u32) -> u32;

/// The observed prefix of the target's vtable.
///
/// The native-width host representation preserves the slot's ordinal role;
/// only the target build has the physical `+0x5c` byte offset.
#[repr(C)]
pub struct GlobalSlot5cVtable {
    /// Slots +0x00 through +0x58, not decoded by this wrapper.
    pub unresolved_00_58: [usize; GLOBAL_SLOT_5C_VTABLE_WORD],
    /// +0x5c: receives the target and forwarded payload.
    pub dispatch: GlobalSlot5cDispatch,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x5c] = [0; core::mem::offset_of!(GlobalSlot5cVtable, dispatch)];

/// Host representation of the target-global word at `0x089cb234`.
///
/// Tests and host callers must install a valid vtable-bearing target before
/// dispatching, just as the retailOS wrapper requires the runtime global.
#[cfg(not(target_os = "none"))]
pub static mut GLOBAL_SLOT_5C_TARGET: *mut GlobalSlot5cTarget = core::ptr::null_mut();

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn global_slot_5c_target() -> *mut GlobalSlot5cTarget {
    read_volatile(GLOBAL_SLOT_5C_TARGET_ADDRESS as *const *mut GlobalSlot5cTarget)
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn global_slot_5c_target() -> *mut GlobalSlot5cTarget {
    read_volatile(addr_of!(GLOBAL_SLOT_5C_TARGET))
}

/// Forwards `payload` to the runtime global target's vtable slot +0x5c.
///
/// # Safety
///
/// The global word at `0x089cb234` on target (or [`GLOBAL_SLOT_5C_TARGET`] on
/// host) must name an object with a valid vtable and callable +0x5c slot. The
/// payload follows the unresolved slot's unvalidated retailOS ABI.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn global_slot_5c_dispatch(payload: u32) -> u32 {
    let target = global_slot_5c_target();
    let vtable = read_volatile(addr_of!((*target).vtable));
    let dispatch = read_volatile(addr_of!((*vtable).dispatch));
    dispatch(target, payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr::{addr_of, addr_of_mut, read_volatile, write_volatile};

    static TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    static mut SEEN_TARGET: *mut GlobalSlot5cTarget = core::ptr::null_mut();
    static mut SEEN_PAYLOAD: u32 = 0;
    const DISPATCH_RESULT: u32 = 0x7e57_1ead;

    unsafe extern "C" fn record_dispatch(target: *mut GlobalSlot5cTarget, payload: u32) -> u32 {
        SEEN_TARGET = target;
        SEEN_PAYLOAD = payload;
        DISPATCH_RESULT
    }

    static VTABLE: GlobalSlot5cVtable = GlobalSlot5cVtable {
        unresolved_00_58: [0; GLOBAL_SLOT_5C_VTABLE_WORD],
        dispatch: record_dispatch,
    };

    struct TargetRestore(*mut GlobalSlot5cTarget);

    impl Drop for TargetRestore {
        fn drop(&mut self) {
            unsafe { write_volatile(addr_of_mut!(GLOBAL_SLOT_5C_TARGET), self.0) };
        }
    }

    #[test]
    fn forwards_payload_to_global_target_slot_5c_and_preserves_return() {
        let _lock = TEST_LOCK.lock();
        let mut target = GlobalSlot5cTarget { vtable: &VTABLE };
        let target = addr_of_mut!(target);
        let restore = unsafe {
            let prior = read_volatile(addr_of!(GLOBAL_SLOT_5C_TARGET));
            write_volatile(addr_of_mut!(GLOBAL_SLOT_5C_TARGET), target);
            SEEN_TARGET = core::ptr::null_mut();
            SEEN_PAYLOAD = 0;
            TargetRestore(prior)
        };

        let payload = 0xa5a5_5a5a;
        let result = unsafe { global_slot_5c_dispatch(payload) };

        assert_eq!(result, DISPATCH_RESULT);
        assert_eq!(unsafe { SEEN_TARGET }, target);
        assert_eq!(unsafe { SEEN_PAYLOAD }, payload);
        drop(restore);
    }
}
