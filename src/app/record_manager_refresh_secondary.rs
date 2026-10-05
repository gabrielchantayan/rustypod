//! Secondary registration refresh — FUN_081c88b8 at 0x081c88b8.
//!
//! True extent: [0x081c88b8, 0x081c88d0), 24 bytes; the next function
//! begins with push {r4,r5,r6,lr}. Raw A32 words verify two inbound plain
//! BLs (0x08235c30, 0x08237198), one outbound plain BL (0x081c88c4),
//! and zero predicated BLs. Add 0xa0c to the manager, refresh its secondary
//! registration slots via 0x081d9810, ignore the result, and return zero.
//!
//! Deliberate deviations: host fixtures use a repr(C) embedded manager
//! with native pointer alignment rather than target byte offsets. Firmware
//! retains the retail registration_slots_refresh call: its lock-service
//! failure behavior differs from the existing Rust mutex-based port.

#[cfg(not(target_os = "none"))]
use super::registration_slot_release::RegistrationSlotManager;

#[repr(C)]
pub struct RecordManagerSecondary {
    #[cfg(not(target_os = "none"))]
    pub prefix: [u32; 0xa0c / 4],
    #[cfg(not(target_os = "none"))]
    pub secondary: RegistrationSlotManager,
    #[cfg(target_os = "none")]
    _opaque: [u8; 0],
}

/// Refresh the secondary registrations and always return success.
///
/// # Safety
/// `manager` must contain a live secondary registration manager at target
/// offset +0xa0c (or the native-width `secondary` field on host), including
/// initialized locks and callable vtables for non-NULL state-two objects.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn record_manager_refresh_secondary(manager: *mut RecordManagerSecondary) -> u32 {
    #[cfg(target_os = "none")]
    {
        let refresh: unsafe extern "C" fn(*mut u8) -> u32 =
            core::mem::transmute(0x081d_9810usize);
        refresh(manager.cast::<u8>().add(0xa0c));
    }
    #[cfg(not(target_os = "none"))]
    super::registration_slots_refresh::registration_slots_refresh(
        core::ptr::addr_of_mut!((*manager).secondary));
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refreshes_boundary_slots_without_touching_primary_storage() {
        let mut manager: RecordManagerSecondary = unsafe { core::mem::zeroed() };
        manager.prefix.fill(0xa5a5_5a5a);
        manager.secondary.slots[0].state = 2;
        manager.secondary.slots[31].state = 2;
        manager.secondary.slots[15].state = 3;
        manager.secondary.slots[15].opaque = 0x1234_5678;
        assert_eq!(unsafe { record_manager_refresh_secondary(&mut manager) }, 0);
        assert_eq!(manager.secondary.slots[0].state, 0);
        assert_eq!(manager.secondary.slots[31].state, 0);
        assert_eq!(manager.secondary.slots[15].state, 3);
        assert_eq!(manager.secondary.slots[15].opaque, 0x1234_5678);
        assert!(manager.prefix.iter().all(|&word| word == 0xa5a5_5a5a));
        assert_eq!(unsafe { record_manager_refresh_secondary(&mut manager) }, 0);
        assert_eq!(manager.secondary.slots[15].state, 3);
    }
}
