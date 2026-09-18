//! `owner_callback_dispatch` — original: `FUN_08178e9c` @ `0x08178e9c` (92
//! bytes; four direct unconditional call sites: two plain `bl` and two `blx`;
//! no predicated `bl` call sites).
//!
//! Raw ARM covers exactly 23 instruction words from `0x08178e9c` through the
//! `pop {r3,r4,r5,pc}` at `0x08178ef4`; `ldr r0,[pc,#4]` at `0x08178ef8`
//! starts the separately linked next function. It first dispatches the owner
//! object's vtable `+0x1c` slot for the embedded receiver at `owner + 0x24`.
//! If the still-retail predicate at `0x082a2084` reports that `object + 4` is
//! zero, it allocates four bytes, stores `object`, and dispatches the same slot
//! for the receiver at `owner + 0x50`.
//!
//! Deliberate deviations: stack spills are Rust locals, and the unrecovered
//! predicate and virtual slots are explicit device-address/host-test seams.

use core::ptr::addr_of;

/// Firmware load address of the still-retail `FUN_082a2084` predicate.
pub const OBJECT_WORD4_IS_ZERO_ADDRESS: usize = 0x082a_2084;

type ObjectWord4IsZero = unsafe extern "C" fn(*mut u8) -> u32;
type OwnerSlotDispatch = unsafe extern "C" fn(*mut u8, *mut *mut u8);
type AllocateWord = unsafe extern "C" fn(usize) -> *mut u8;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_object_word4_is_zero(object: *mut u8) -> u32 {
    let predicate: ObjectWord4IsZero = core::mem::transmute(OBJECT_WORD4_IS_ZERO_ADDRESS);
    predicate(object)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_object_word4_is_zero(_object: *mut u8) -> u32 {
    panic!("owner_callback_dispatch requires predicate 0x082a2084")
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_owner_slot_dispatch(receiver: *mut u8, object: *mut *mut u8) {
    type OwnerSlot = unsafe extern "C" fn(*mut u8, *mut *mut u8, usize);
    let vtable = receiver.cast::<u32>().read() as usize as *const u32;
    let slot = vtable.add(0x1c / 4).read() as usize;
    let callback: OwnerSlot = core::mem::transmute(slot);
    callback(receiver, object, slot);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_owner_slot_dispatch(_receiver: *mut u8, _object: *mut *mut u8) {
    panic!("owner_callback_dispatch requires host dispatch seam")
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_allocate_word(size: usize) -> *mut u8 {
    crate::heap::veneers::operator_new(size)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_allocate_word(_size: usize) -> *mut u8 {
    panic!("owner_callback_dispatch requires host allocation seam")
}

#[cfg(target_os = "none")]
pub static mut OBJECT_WORD4_IS_ZERO: ObjectWord4IsZero = firmware_object_word4_is_zero;
#[cfg(not(target_os = "none"))]
pub static mut OBJECT_WORD4_IS_ZERO: ObjectWord4IsZero = missing_object_word4_is_zero;
#[cfg(target_os = "none")]
pub static mut OWNER_SLOT_DISPATCH: OwnerSlotDispatch = firmware_owner_slot_dispatch;
#[cfg(not(target_os = "none"))]
pub static mut OWNER_SLOT_DISPATCH: OwnerSlotDispatch = missing_owner_slot_dispatch;
#[cfg(target_os = "none")]
pub static mut ALLOCATE_WORD: AllocateWord = firmware_allocate_word;
#[cfg(not(target_os = "none"))]
pub static mut ALLOCATE_WORD: AllocateWord = missing_allocate_word;

/// Dispatches an object to the owner's primary callback and, when its word-4
/// predicate succeeds, queues a four-byte owned copy through the secondary callback.
///
/// # Safety
/// `owner` must contain valid callback receivers at target offsets `+0x24` and
/// `+0x50`; `object` must meet the predicate and callback contracts.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn owner_callback_dispatch(owner: *mut u8, object: *mut u8) {
    let mut first_object = object;
    let dispatch = core::ptr::read_volatile(addr_of!(OWNER_SLOT_DISPATCH));
    dispatch(owner.add(0x24), &mut first_object);

    let predicate = core::ptr::read_volatile(addr_of!(OBJECT_WORD4_IS_ZERO));
    if predicate(object) != 0 {
        let allocate = core::ptr::read_volatile(addr_of!(ALLOCATE_WORD));
        let copied_object = allocate(core::mem::size_of::<u32>()).cast::<*mut u8>();
        copied_object.write(object);
        let mut copied_object = copied_object.cast::<u8>();
        dispatch(owner.add(0x50), &mut copied_object);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    const FIXTURE_LEN: usize = 0x1000;
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::OWNER_CALLBACK_DISPATCH, FIXTURE_LEN).map(|pointer| pointer as usize)
    });
    static SEAM_LOCK: Mutex<()> = Mutex::new(());
    static mut DISPATCHES: [(usize, usize); 2] = [(0, 0); 2];
    static mut DISPATCH_COUNT: usize = 0;
    static mut PREDICATE_RESULT: u32 = 0;
    static mut ALLOCATION: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn record_dispatch(receiver: *mut u8, object: *mut *mut u8) {
        DISPATCHES[DISPATCH_COUNT] = (receiver as usize, object.read() as usize);
        DISPATCH_COUNT += 1;
    }
    unsafe extern "C" fn predicate(_object: *mut u8) -> u32 { PREDICATE_RESULT }
    unsafe extern "C" fn allocate(size: usize) -> *mut u8 {
        assert_eq!(size, 4);
        ALLOCATION
    }

    #[test]
    fn always_dispatches_primary_receiver_without_copying() {
        let _lock = SEAM_LOCK.lock();
        let Some(base) = *SLAB else { return };
        unsafe {
            DISPATCH_COUNT = 0;
            PREDICATE_RESULT = 0;
            OWNER_SLOT_DISPATCH = record_dispatch;
            OBJECT_WORD4_IS_ZERO = predicate;
            ALLOCATE_WORD = allocate;
            let owner = base as *mut u8;
            let object = owner.add(0x100);
            owner_callback_dispatch(owner, object);
            assert_eq!(DISPATCH_COUNT, 1);
            assert_eq!(DISPATCHES[0], (owner.add(0x24) as usize, object as usize));
        }
    }

    #[test]
    fn predicate_success_queues_a_target_word_copy_to_secondary_receiver() {
        let _lock = SEAM_LOCK.lock();
        let Some(base) = *SLAB else { return };
        unsafe {
            DISPATCH_COUNT = 0;
            PREDICATE_RESULT = 1;
            let owner = base as *mut u8;
            ALLOCATION = owner.add(0x200);
            OWNER_SLOT_DISPATCH = record_dispatch;
            OBJECT_WORD4_IS_ZERO = predicate;
            ALLOCATE_WORD = allocate;
            let object = owner.add(0x100);
            owner_callback_dispatch(owner, object);
            assert_eq!(DISPATCH_COUNT, 2);
            assert_eq!(DISPATCHES[1], (owner.add(0x50) as usize, ALLOCATION as usize));
            assert_eq!(ALLOCATION.cast::<*mut u8>().read(), object);
        }
    }
}
