//! Fixed-capacity tracked-object registration.
//!
//! `tracked_object_register` — original: `FUN_0807fd9c` @ `0x0807fd9c`
//! (160 bytes). Raw ARM is `0x0807fd9c..0x0807fe3c`; it has four inbound
//! plain `bl` call sites, two plain internal `bl` instructions, and no
//! predicated `bl` instructions.
//!
//! The mode word at `0x089cc8a4` controls a 30-record table at `0x08a79d94`.
//! Mode 2 clears all `{object, token}` pairs. The function then finds the
//! first pair with both words zero, calls the unported activation target with
//! `(object, 1)`, records object and its +0x12c token, and increments the
//! registry count at `0x089cc8a8`. A partially occupied pair is terminal.

const TRACKED_OBJECT_REGISTRY_STATE: usize = 0x089c_c8a0;
const TRACKED_OBJECT_RECORDS: usize = 0x08a7_9d94;
const TRACKED_OBJECT_CAPACITY: usize = 30;
const OBJECT_TOKEN_OFFSET: usize = 0x12c;

/// Boundary for the unported `FUN_0808ccc8` activation call.
#[derive(Clone, Copy)]
pub struct TrackedObjectRegisterOps {
    pub activate: unsafe extern "C" fn(u32, u32),
}

unsafe extern "C" fn firmware_activate_tracked_object(object: u32, active: u32) {
    #[cfg(target_os = "none")]
    {
        let activate: unsafe extern "C" fn(u32, u32) = core::mem::transmute(0x0808_ccc8usize);
        activate(object, active);
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = (object, active);
    }
}

pub const DEFAULT_TRACKED_OBJECT_REGISTER_OPS: TrackedObjectRegisterOps = TrackedObjectRegisterOps {
    activate: firmware_activate_tracked_object,
};
pub static mut TRACKED_OBJECT_REGISTER_OPS: TrackedObjectRegisterOps = DEFAULT_TRACKED_OBJECT_REGISTER_OPS;

#[cfg(not(target_os = "none"))]
static mut HOST_TRACKED_OBJECT_REGISTRY_STATE: [u32; 3] = [0; 3];
#[cfg(not(target_os = "none"))]
static mut HOST_TRACKED_OBJECT_RECORDS: [u32; TRACKED_OBJECT_CAPACITY * 2] = [0; TRACKED_OBJECT_CAPACITY * 2];

#[inline(always)]
fn register_ops() -> TrackedObjectRegisterOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(TRACKED_OBJECT_REGISTER_OPS)) }
}

#[inline(always)]
unsafe fn registry_state() -> *mut u32 {
    #[cfg(target_os = "none")]
    { TRACKED_OBJECT_REGISTRY_STATE as *mut u32 }
    #[cfg(not(target_os = "none"))]
    { core::ptr::addr_of_mut!(HOST_TRACKED_OBJECT_REGISTRY_STATE).cast() }
}

#[inline(always)]
unsafe fn tracked_object_records() -> *mut u32 {
    #[cfg(target_os = "none")]
    { TRACKED_OBJECT_RECORDS as *mut u32 }
    #[cfg(not(target_os = "none"))]
    { core::ptr::addr_of_mut!(HOST_TRACKED_OBJECT_RECORDS).cast() }
}

/// Registers an object in the fixed tracked-object table.
///
/// # Deviations
///
/// `FUN_0808ccc8` has no established semantic identity or existing Rust port,
/// so it remains an explicit typed boundary. Target builds call it at its
/// verified address; host tests replace the boundary. The fixed retail RAM
/// state and record table use same-shaped module-owned storage on host.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn tracked_object_register(object: u32) {
    let state = registry_state();
    let records = tracked_object_records();
    if core::ptr::read_volatile(state.add(1)) == 2 {
        for index in 0..TRACKED_OBJECT_CAPACITY * 2 {
            core::ptr::write_volatile(records.add(index), 0);
        }
    }
    for index in 0..TRACKED_OBJECT_CAPACITY {
        let record = records.add(index * 2);
        if core::ptr::read_volatile(record) == 0 {
            if core::ptr::read_volatile(record.add(1)) != 0 {
                crate::heap::veneers::heap_panic();
            }
            (register_ops().activate)(object, 1);
            core::ptr::write_volatile(record, object);
            core::ptr::write_volatile(record.add(1), core::ptr::read_volatile((object as usize + OBJECT_TOKEN_OFFSET) as *const u32));
            core::ptr::write_volatile(state.add(2), core::ptr::read_volatile(state.add(2)).wrapping_add(1));
            return;
        }
    }
    crate::heap::veneers::heap_panic();
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    static LOCK: Mutex<()> = Mutex::new(());
    static OBJECT: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::TRACKED_OBJECT_REGISTER, 0x1000).map(|pointer| pointer as usize)
    });
    static mut ACTIVATION: (u32, u32, u32) = (0, 0, 0);

    unsafe extern "C" fn record_activation(object: u32, active: u32) {
        ACTIVATION = (ACTIVATION.0.wrapping_add(1), object, active);
    }

    unsafe fn reset() {
        HOST_TRACKED_OBJECT_REGISTRY_STATE = [0; 3];
        HOST_TRACKED_OBJECT_RECORDS = [0; TRACKED_OBJECT_CAPACITY * 2];
        TRACKED_OBJECT_REGISTER_OPS = TrackedObjectRegisterOps { activate: record_activation };
        ACTIVATION = (0, 0, 0);
    }

    #[test]
    fn registers_first_empty_pair_and_preserves_pair_order() {
        let _lock = LOCK.lock();
        let Some(object) = *OBJECT else {
            assert!(note_missing_u32_fixture("ui/tracked_object_register"));
            return;
        };
        unsafe {
            reset();
            ((object as *mut u32).add(OBJECT_TOKEN_OFFSET / 4)).write(0x4433_2211);
            tracked_object_register(object as u32);
            assert_eq!(HOST_TRACKED_OBJECT_RECORDS[0..2], [object as u32, 0x4433_2211]);
            assert_eq!(HOST_TRACKED_OBJECT_REGISTRY_STATE[2], 1);
            assert_eq!(ACTIVATION, (1, object as u32, 1));
        }
    }

    #[test]
    fn mode_two_clears_existing_pairs_before_registering() {
        let _lock = LOCK.lock();
        let Some(object) = *OBJECT else {
            assert!(note_missing_u32_fixture("ui/tracked_object_register"));
            return;
        };
        unsafe {
            reset();
            HOST_TRACKED_OBJECT_REGISTRY_STATE[1] = 2;
            HOST_TRACKED_OBJECT_RECORDS = [0xffff_ffff; TRACKED_OBJECT_CAPACITY * 2];
            ((object as *mut u32).add(OBJECT_TOKEN_OFFSET / 4)).write(9);
            tracked_object_register(object as u32);
            assert_eq!(HOST_TRACKED_OBJECT_RECORDS[0..2], [object as u32, 9]);
            assert!(HOST_TRACKED_OBJECT_RECORDS[2..].iter().all(|word| *word == 0));
            assert_eq!(HOST_TRACKED_OBJECT_REGISTRY_STATE[2], 1);
        }
    }
}
