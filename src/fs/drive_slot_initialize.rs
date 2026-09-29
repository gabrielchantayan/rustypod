//! Drive-slot initialization wrapper.
//!
//! `drive_slot_initialize` is retailOS `FUN_082e2458` at `0x082e2458` (72
//! bytes; true extent `0x082e2458..0x082e249c`, with the next independently
//! entered function at `0x082e24a0`). The body has four unconditional `bl`
//! instructions and no predicated `bl`: `0x082e07a4`, `0x082e06f4`,
//! `0x082d0a14`, and `0x082c62bc`.
//!
//! It first invokes the opaque slot-creation phase. Only when that returns a
//! nonzero status and a subsequent lookup finds the slot does it initialize
//! the slot's data fields at byte offsets 8 and 4, then run the final
//! slot-specific phase with the field at byte offset 22. It returns the first
//! phase's status unchanged.
//!
//! Deliberate deviation: three callees have no established identities and are
//! address-verified direct-call seams on device; host tests install recording
//! seams. The lookup is the existing `drive_slot_lookup` port on device and a
//! host seam, avoiding its private target-width table model in these tests.

#[cfg(not(target_os = "none"))]
use core::ptr;

type DriveSlotCreate = unsafe extern "C" fn(u32) -> u32;
type DriveSlotLookup = unsafe extern "C" fn(u32) -> *mut u8;
type DriveSlotInitializeData = unsafe extern "C" fn(u32, *mut u8, *mut u8);
type DriveSlotFinalize = unsafe extern "C" fn(u32, *mut u8);

#[cfg(target_os = "none")]
const DRIVE_SLOT_CREATE_ADDRESS: usize = 0x082e_07a4;
#[cfg(target_os = "none")]
const DRIVE_SLOT_INITIALIZE_DATA_ADDRESS: usize = 0x082d_0a14;
#[cfg(target_os = "none")]
const DRIVE_SLOT_FINALIZE_ADDRESS: usize = 0x082c_62bc;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn create_drive_slot(index: u32) -> u32 {
    core::mem::transmute::<usize, DriveSlotCreate>(DRIVE_SLOT_CREATE_ADDRESS)(index)
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn lookup_drive_slot(index: u32) -> *mut u8 {
    crate::fs::drive_slot::drive_slot_lookup(index)
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn initialize_slot_data(index: u32, data_out: *mut u8, result_out: *mut u8) {
    core::mem::transmute::<usize, DriveSlotInitializeData>(DRIVE_SLOT_INITIALIZE_DATA_ADDRESS)(
        index, data_out, result_out,
    )
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn finalize_drive_slot(index: u32, slot_field: *mut u8) {
    core::mem::transmute::<usize, DriveSlotFinalize>(DRIVE_SLOT_FINALIZE_ADDRESS)(index, slot_field)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_create(_index: u32) -> u32 {
    panic!("drive_slot_initialize called without a host create seam")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_lookup(_index: u32) -> *mut u8 {
    panic!("drive_slot_initialize called without a host lookup seam")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_initialize(_index: u32, _data_out: *mut u8, _result_out: *mut u8) {
    panic!("drive_slot_initialize called without a host initialization seam")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_finalize(_index: u32, _slot_field: *mut u8) {
    panic!("drive_slot_initialize called without a host finalization seam")
}

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
struct DriveSlotInitializeHostOps {
    create: DriveSlotCreate,
    lookup: DriveSlotLookup,
    initialize: DriveSlotInitializeData,
    finalize: DriveSlotFinalize,
}

#[cfg(not(target_os = "none"))]
const DEFAULT_HOST_OPS: DriveSlotInitializeHostOps = DriveSlotInitializeHostOps {
    create: unavailable_create,
    lookup: unavailable_lookup,
    initialize: unavailable_initialize,
    finalize: unavailable_finalize,
};

#[cfg(not(target_os = "none"))]
static mut HOST_OPS: DriveSlotInitializeHostOps = DEFAULT_HOST_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn host_ops() -> DriveSlotInitializeHostOps {
    ptr::read_volatile(ptr::addr_of!(HOST_OPS))
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn create_drive_slot(index: u32) -> u32 {
    (host_ops().create)(index)
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn lookup_drive_slot(index: u32) -> *mut u8 {
    (host_ops().lookup)(index)
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn initialize_slot_data(index: u32, data_out: *mut u8, result_out: *mut u8) {
    (host_ops().initialize)(index, data_out, result_out)
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn finalize_drive_slot(index: u32, slot_field: *mut u8) {
    (host_ops().finalize)(index, slot_field)
}

/// Initializes a drive slot and returns the creation phase's status.
///
/// # Safety
/// When creation succeeds, the lookup must return either NULL or a slot with
/// writable fields at byte offsets 4, 8, and 22 for the opaque callees.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.drive_slot_initialize")]
#[inline(never)]
pub unsafe extern "C" fn drive_slot_initialize(index: u32) -> u32 {
    let status = create_drive_slot(index);
    if status != 0 {
        let slot = lookup_drive_slot(index);
        if !slot.is_null() {
            initialize_slot_data(index, slot.add(8), slot.add(4));
            finalize_drive_slot(index, slot.add(22));
        }
    }
    status
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut CREATE_RESULT: u32 = 0;
    static mut SLOT: *mut u8 = core::ptr::null_mut();
    static mut CREATE_CALL: Option<u32> = None;
    static mut LOOKUP_CALL: Option<u32> = None;
    static mut INITIALIZE_CALL: Option<(u32, *mut u8, *mut u8)> = None;
    static mut FINALIZE_CALL: Option<(u32, *mut u8)> = None;

    unsafe extern "C" fn record_create(index: u32) -> u32 {
        CREATE_CALL = Some(index);
        CREATE_RESULT
    }

    unsafe extern "C" fn record_lookup(index: u32) -> *mut u8 {
        LOOKUP_CALL = Some(index);
        SLOT
    }

    unsafe extern "C" fn record_initialize(index: u32, data_out: *mut u8, result_out: *mut u8) {
        INITIALIZE_CALL = Some((index, data_out, result_out));
    }

    unsafe extern "C" fn record_finalize(index: u32, slot_field: *mut u8) {
        FINALIZE_CALL = Some((index, slot_field));
    }

    struct Fixture {
        _guard: parking_lot::MutexGuard<'static, ()>,
        old_ops: DriveSlotInitializeHostOps,
    }

    impl Fixture {
        unsafe fn new() -> Fixture {
            let guard = TEST_LOCK.lock();
            let old_ops = ptr::read_volatile(ptr::addr_of!(HOST_OPS));
            ptr::write_volatile(
                ptr::addr_of_mut!(HOST_OPS),
                DriveSlotInitializeHostOps {
                    create: record_create,
                    lookup: record_lookup,
                    initialize: record_initialize,
                    finalize: record_finalize,
                },
            );
            CREATE_RESULT = 0;
            SLOT = core::ptr::null_mut();
            CREATE_CALL = None;
            LOOKUP_CALL = None;
            INITIALIZE_CALL = None;
            FINALIZE_CALL = None;
            Fixture { _guard: guard, old_ops }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            unsafe { ptr::write_volatile(ptr::addr_of_mut!(HOST_OPS), self.old_ops) }
        }
    }

    #[test]
    fn zero_status_returns_without_lookup() {
        unsafe {
            let _fixture = Fixture::new();
            CREATE_RESULT = 0;
            assert_eq!(drive_slot_initialize(3), 0);
            assert_eq!(CREATE_CALL, Some(3));
            assert_eq!(LOOKUP_CALL, None);
            assert_eq!(INITIALIZE_CALL, None);
            assert_eq!(FINALIZE_CALL, None);
        }
    }

    #[test]
    fn missing_slot_returns_success_without_later_phases() {
        unsafe {
            let _fixture = Fixture::new();
            CREATE_RESULT = 1;
            assert_eq!(drive_slot_initialize(2), 1);
            assert_eq!(CREATE_CALL, Some(2));
            assert_eq!(LOOKUP_CALL, Some(2));
            assert_eq!(INITIALIZE_CALL, None);
            assert_eq!(FINALIZE_CALL, None);
        }
    }

    #[test]
    fn initializes_live_slot_with_exact_byte_offsets() {
        unsafe {
            let _fixture = Fixture::new();
            let mut slot = [0u8; 32];
            CREATE_RESULT = u32::MAX;
            SLOT = slot.as_mut_ptr();
            assert_eq!(drive_slot_initialize(1), u32::MAX);
            assert_eq!(CREATE_CALL, Some(1));
            assert_eq!(LOOKUP_CALL, Some(1));
            assert_eq!(INITIALIZE_CALL, Some((1, SLOT.add(8), SLOT.add(4))));
            assert_eq!(FINALIZE_CALL, Some((1, SLOT.add(22))));
        }
    }
}
