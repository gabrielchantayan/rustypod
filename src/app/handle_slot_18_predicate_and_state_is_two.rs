//! `handle_slot_18_predicate_and_state_is_two` — original: `FUN_08298064` @
//! `0x08298064` (60 bytes).
//!
//! Raw `osos.dec` disassembly fixes the extent at `0x08298064..0x0829809c`:
//! `push {r4,lr}; mov r4,r0; ldr r0,[r0]; ldr r1,[r0,#0x18]; mov r0,r4;
//! blx r1; cmp r0,#0; beq false; ldr r0,[r4,#0xc]; ldrb r0,[r0]; cmp r0,#2;
//! moveq r0,#1; popeq {r4,pc}; mov r0,#0; pop {r4,pc}`. The separately
//! linked next function begins at `0x082980a0`. Complete aligned ARM
//! `B`/`BL`-immediate decoding finds seven direct inbound calls, all plain,
//! unconditional `bl` instructions at `0x08110718`, `0x081111d4`,
//! `0x0826cad4`, `0x0826f028`, `0x08288374`, `0x08288384`, and `0x0828839c`;
//! there are no predicated calls or direct tail branches.
//!
//! The handle's vtable slot +0x18 is invoked with the handle itself. Only a
//! nonzero result permits reading the first byte through the handle's +0x0c
//! target-width pointer; the function returns one exactly when that byte is
//! two. The concrete vtable method and the pointed-to state object have not
//! been recovered, so no identity is invented. On firmware the indirect call
//! is performed directly. Host tests replace it with a recording seam because
//! a firmware 32-bit vtable function pointer cannot represent a host function
//! pointer; this is the sole deliberate host-only deviation.

/// Target-byte offset of the state pointer in the opaque handle.
const STATE_POINTER_OFFSET: usize = 0x0c;
/// Target-byte offset of the predicate method in the opaque vtable.
const VTABLE_SLOT_18_OFFSET: usize = 0x18;

type VtableSlot18Predicate = unsafe extern "C" fn(*mut u8) -> u32;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn invoke_vtable_slot_18_predicate(handle: *mut u8) -> u32 {
    let vtable = unsafe { handle.cast::<*const u8>().read() };
    let predicate = unsafe {
        vtable
            .add(VTABLE_SLOT_18_OFFSET)
            .cast::<VtableSlot18Predicate>()
            .read()
    };
    unsafe { predicate(handle) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_host_vtable_slot_18_predicate(_: *mut u8) -> u32 {
    panic!("host tests must install the slot +0x18 predicate seam")
}

/// Host-only adapter for the target-width virtual call. Firmware builds use
/// [`invoke_vtable_slot_18_predicate`]'s exact raw-vtable dispatch instead.
#[cfg(not(target_os = "none"))]
static mut HOST_VTABLE_SLOT_18_PREDICATE: VtableSlot18Predicate =
    unavailable_host_vtable_slot_18_predicate;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn invoke_vtable_slot_18_predicate(handle: *mut u8) -> u32 {
    unsafe { HOST_VTABLE_SLOT_18_PREDICATE(handle) }
}

/// `handle_slot_18_predicate_and_state_is_two` — original: `FUN_08298064` @
/// `0x08298064` (60 bytes; seven unconditional `bl` call sites).
///
/// Calls `handle`'s vtable slot +0x18. If that predicate is nonzero, returns
/// whether the byte pointed to by the target-width word at `handle+0x0c` is
/// exactly two; otherwise returns zero.
///
/// # Safety
///
/// `handle` must be non-NULL, four-byte aligned, and readable through its
/// +0x0c target-width pointer field. Its vtable and slot +0x18 method must be
/// valid. When that method returns nonzero, the state pointer must designate a
/// readable byte. These unchecked preconditions match the original ARM code.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn handle_slot_18_predicate_and_state_is_two(handle: *mut u8) -> u32 {
    if unsafe { invoke_vtable_slot_18_predicate(handle) } == 0 {
        return 0;
    }

    let state_address = unsafe { handle.add(STATE_POINTER_OFFSET).cast::<u32>().read() };
    let state = state_address as usize as *const u8;
    u32::from(unsafe { state.read() } == 2)
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr;
    use std::sync::{LazyLock, Mutex};

    const FIXTURE_LEN: usize = 0x100;
    const STATE_AT: usize = 0x40;
    const STATE_WORD_INDEX: usize = STATE_POINTER_OFFSET / core::mem::size_of::<u32>();
    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::HANDLE_SLOT_18_PREDICATE_AND_STATE, FIXTURE_LEN)
            .map(|pointer| pointer as usize)
    });
    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLBACK_RESULT: u32 = 0;
    static mut CALLBACK_HANDLE: *mut u8 = ptr::null_mut();
    static mut CALLBACK_COUNT: u32 = 0;

    unsafe extern "C" fn recording_predicate(handle: *mut u8) -> u32 {
        unsafe {
            CALLBACK_HANDLE = handle;
            CALLBACK_COUNT += 1;
            CALLBACK_RESULT
        }
    }

    struct PredicateRestore(VtableSlot18Predicate);

    impl Drop for PredicateRestore {
        fn drop(&mut self) {
            unsafe { HOST_VTABLE_SLOT_18_PREDICATE = self.0 };
        }
    }

    unsafe fn install_recording_predicate(result: u32) -> PredicateRestore {
        unsafe {
            let previous = HOST_VTABLE_SLOT_18_PREDICATE;
            HOST_VTABLE_SLOT_18_PREDICATE = recording_predicate;
            CALLBACK_RESULT = result;
            CALLBACK_HANDLE = ptr::null_mut();
            CALLBACK_COUNT = 0;
            PredicateRestore(previous)
        }
    }

    unsafe fn handle_with_state(base: *mut u8, state: u8) -> *mut u8 {
        unsafe {
            ptr::write_bytes(base, 0, FIXTURE_LEN);
            base.add(STATE_AT).write(state);
            base.cast::<u32>().add(STATE_WORD_INDEX).write((base.add(STATE_AT)) as u32);
            base
        }
    }

    #[test]
    fn zero_predicate_short_circuits_before_state_pointer_dereference() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some(base) = *FIXTURE else {
            assert!(note_missing_u32_fixture("app/handle_slot_18_predicate_and_state_is_two"));
            return;
        };
        let _restore = unsafe { install_recording_predicate(0) };
        let handle = unsafe { handle_with_state(base as *mut u8, 0) };

        assert_eq!(unsafe { handle_slot_18_predicate_and_state_is_two(handle) }, 0);
        assert_eq!(unsafe { CALLBACK_HANDLE }, handle);
        assert_eq!(unsafe { CALLBACK_COUNT }, 1);
    }

    #[test]
    fn accepts_only_state_byte_two_after_nonzero_predicate() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some(base) = *FIXTURE else {
            assert!(note_missing_u32_fixture("app/handle_slot_18_predicate_and_state_is_two"));
            return;
        };
        let _restore = unsafe { install_recording_predicate(0xffff_ffff) };

        for (state, expected) in [(0, 0), (1, 0), (2, 1), (3, 0), (u8::MAX, 0)] {
            let handle = unsafe { handle_with_state(base as *mut u8, state) };
            let before = unsafe { core::slice::from_raw_parts(handle, FIXTURE_LEN) }.to_vec();

            assert_eq!(unsafe { handle_slot_18_predicate_and_state_is_two(handle) }, expected);
            assert_eq!(unsafe { core::slice::from_raw_parts(handle, FIXTURE_LEN) }, before);
            assert_eq!(unsafe { CALLBACK_HANDLE }, handle);
        }
        assert_eq!(unsafe { CALLBACK_COUNT }, 5);
    }
}
