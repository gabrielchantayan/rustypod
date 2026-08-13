//! Address-distinct eight-slot byte identity-table initialization alias.
//!
//! `initialize_eight_byte_identity_slots_alias` — original: `FUN_08028490` @
//! `0x08028490` (36 bytes). Reference:
//! `/home/gabe/Programming/ipod-decomp/decomp/c/001/08028490_FUN_08028490.c`;
//! raw ARM is `0x08028490..0x080284b4`.
//!
//! This is a separately hookable, byte-identical alias of
//! [`super::eight_slot_identity_init::initialize_eight_byte_identity_slots`]
//! at 0x08028460. It invokes the retail byte identity-table initializer at
//! `0x0802b9ec` exactly eight times, once for every consecutive 0x100-byte
//! slot beginning at its argument. Each initialized slot maps byte `n` to `n`.

/// Width of one byte identity-table slot.
const BYTE_IDENTITY_SLOT_BYTES: usize = 0x100;
/// Number of consecutive slots initialized by the retail wrapper.
const BYTE_IDENTITY_SLOT_COUNT: usize = 8;

/// ABI of the retail byte identity-table initializer at 0x0802b9ec.
type ByteIdentitySlotInitializer = unsafe extern "C" fn(slot: *mut u8);

/// Target/host boundary for the unported byte identity-table initializer.
#[derive(Clone, Copy)]
struct ByteIdentitySlotInitOps {
    initialize_slot: ByteIdentitySlotInitializer,
}

unsafe extern "C" fn firmware_initialize_byte_identity_slot(slot: *mut u8) {
    #[cfg(target_os = "none")]
    {
        let initialize_slot: ByteIdentitySlotInitializer =
            core::mem::transmute(0x0802_b9ecusize);
        initialize_slot(slot);
    }

    #[cfg(not(target_os = "none"))]
    {
        let _ = slot;
    }
}

/// Default target/host boundary: calls retailOS on target and is inert on host.
const DEFAULT_BYTE_IDENTITY_SLOT_INIT_OPS: ByteIdentitySlotInitOps = ByteIdentitySlotInitOps {
    initialize_slot: firmware_initialize_byte_identity_slot,
};

/// Active byte identity-table initialization boundary. Host tests replace this
/// with a recorder; target builds retain the retailOS call at 0x0802b9ec.
static mut BYTE_IDENTITY_SLOT_INIT_OPS: ByteIdentitySlotInitOps =
    DEFAULT_BYTE_IDENTITY_SLOT_INIT_OPS;

#[inline(always)]
fn byte_identity_slot_init_ops() -> ByteIdentitySlotInitOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(BYTE_IDENTITY_SLOT_INIT_OPS)) }
}

/// initialize_eight_byte_identity_slots_alias — original: `FUN_08028490` @
/// `0x08028490` (36 bytes).
///
/// Address-distinct alias of
/// [`super::eight_slot_identity_init::initialize_eight_byte_identity_slots`]
/// at 0x08028460. Calls the byte identity-table initializer at
/// `base + i * 0x100` for every `i` from zero through seven, in ascending slot
/// order.
///
/// # Deviations
///
/// The callee at 0x0802b9ec remains retailOS. The private target/host boundary
/// preserves that target call and provides a deterministic host seam without
/// changing the wrapper's eight calls, offsets, or order.
///
/// # Safety
///
/// `base` must designate the first byte of at least eight contiguous
/// 0x100-byte slots, each valid for the retail initializer to write.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn initialize_eight_byte_identity_slots_alias(base: *mut u8) {
    let ops = byte_identity_slot_init_ops();
    for index in 0..BYTE_IDENTITY_SLOT_COUNT {
        (ops.initialize_slot)(base.add(index * BYTE_IDENTITY_SLOT_BYTES));
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: Vec<usize> = Vec::new();

    unsafe extern "C" fn record_initialize_slot(slot: *mut u8) {
        (*addr_of_mut!(CALLS)).push(slot as usize);
    }

    struct SlotInitBench {
        _lock: MutexGuard<'static, ()>,
        previous: ByteIdentitySlotInitOps,
    }

    impl Drop for SlotInitBench {
        fn drop(&mut self) {
            unsafe { addr_of_mut!(BYTE_IDENTITY_SLOT_INIT_OPS).write(self.previous) };
        }
    }

    fn install_recorder() -> SlotInitBench {
        let lock = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            let previous = core::ptr::read_volatile(addr_of!(BYTE_IDENTITY_SLOT_INIT_OPS));
            (*addr_of_mut!(CALLS)).clear();
            addr_of_mut!(BYTE_IDENTITY_SLOT_INIT_OPS).write(ByteIdentitySlotInitOps {
                initialize_slot: record_initialize_slot,
            });
            SlotInitBench {
                _lock: lock,
                previous,
            }
        }
    }

    #[test]
    fn alias_initializes_all_eight_slots_in_ascending_256_byte_order() {
        let _bench = install_recorder();
        let mut slots = [0u8; BYTE_IDENTITY_SLOT_COUNT * BYTE_IDENTITY_SLOT_BYTES];
        unsafe { initialize_eight_byte_identity_slots_alias(slots.as_mut_ptr()) };

        let base = slots.as_ptr() as usize;
        let expected: Vec<usize> = (0..BYTE_IDENTITY_SLOT_COUNT)
            .map(|index| base + index * BYTE_IDENTITY_SLOT_BYTES)
            .collect();
        assert_eq!(unsafe { &*addr_of!(CALLS) }, &expected);
    }
}
