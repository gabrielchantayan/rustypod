//! `opaque_context_dispatch_forever` — `FUN_0825782c` @ **0x0825782c**.
//! True extent: **96 bytes**, 0x0825782c..0x0825788c (exclusive); the next
//! constructor starts at 0x0825788c. Full-image A32 decoding verifies two
//! incoming plain BLs (0x0839e864, 0x0839e9d0), zero predicated incoming BLs.
//! The body has two plain BLs, one BLEQ to heap_panic, and two virtual BLXs.
//!
//! Retry mode-one record acquisition until status zero, reject a null payload,
//! dispatch through owner vtable slot zero, release the acquisition record,
//! then finalize the saved payload through its freshly loaded vtable slot one.
//! Repeat forever. The second ABI argument is unused; incoming r2/r3 initialize
//! record/payload spill slots, although successful acquisition normally replaces
//! them. There is no return path, despite the callers' unreachable epilogues.
//!
//! Deviations: reuse the existing mode-one Rust port; record release remains a
//! fixed-address seam at 0x082617ec. Host pointer fields widen structurally,
//! preserving target word layout. Host-only Rust-ABI seams allow finite tests
//! of this non-returning loop; target code calls the real fatal implementation.

use core::ptr::{addr_of, read_volatile};
use crate::cxx::opaque_context_take_mode_one::opaque_context_take_mode_one;

#[repr(C)]
pub struct DispatchOwner {
    pub vtable: *const DispatchOwnerVtable,
    pub context: [u8; 0xa0],
}

#[repr(C)]
pub struct DispatchOwnerVtable {
    pub dispatch: unsafe extern "C" fn(*mut DispatchOwner, *mut DispatchPayload),
}

#[repr(C)]
pub struct DispatchPayload {
    pub vtable: *const DispatchPayloadVtable,
}

#[repr(C)]
pub struct DispatchPayloadVtable {
    pub unresolved_slot_zero: usize,
    pub finalize: unsafe extern "C" fn(*mut DispatchPayload),
}

pub type RecordRelease = unsafe extern "C" fn(*mut u8, *mut *mut u8) -> u32;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn release_record(context: *mut u8, record: *mut *mut u8) {
    let release: RecordRelease = core::mem::transmute(0x0826_17ecusize);
    release(context, record);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_release(_context: *mut u8, _record: *mut *mut u8) -> u32 {
    panic!("install opaque context record release before host dispatch")
}

#[cfg(not(target_os = "none"))]
pub static mut OPAQUE_DISPATCH_RECORD_RELEASE: RecordRelease = missing_release;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn release_record(context: *mut u8, record: *mut *mut u8) {
    read_volatile(addr_of!(OPAQUE_DISPATCH_RECORD_RELEASE))(context, record);
}

#[cfg(test)]
type Take = unsafe fn(*mut u8, *mut *mut u8, *mut *mut u8) -> u32;
#[cfg(test)]
unsafe fn default_take(context: *mut u8, payload: *mut *mut u8, record: *mut *mut u8) -> u32 {
    opaque_context_take_mode_one(context, payload, record)
}
#[cfg(test)]
static mut TAKE: Take = default_take;

#[inline(always)]
unsafe fn dispatch_loop(owner: *mut DispatchOwner, mut record: *mut u8, mut payload: *mut u8) -> ! {
    let context = addr_of!((*owner).context) as *mut u8;
    loop {
        #[cfg(not(test))]
        let status = opaque_context_take_mode_one(context, &mut payload, &mut record);
        #[cfg(test)]
        let status = read_volatile(addr_of!(TAKE))(context, &mut payload, &mut record);
        if status != 0 {
            continue;
        }
        let saved_payload = payload as *mut DispatchPayload;
        if saved_payload.is_null() {
            #[cfg(not(test))]
            crate::heap::veneers::heap_panic();
            #[cfg(test)]
            panic!("null dispatch payload");
        }
        let owner_vtable = read_volatile(addr_of!((*owner).vtable));
        ((*owner_vtable).dispatch)(owner, saved_payload);
        release_record(context, &mut record);
        let payload_vtable = read_volatile(addr_of!((*saved_payload).vtable));
        ((*payload_vtable).finalize)(saved_payload);
    }
}

/// # Safety
/// Owner, acquired payloads, vtables and context must satisfy the retail
/// acquisition/release ABIs. Callbacks must leave the payload valid until its
/// finalizer runs. This function never returns.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn opaque_context_dispatch_forever(
    owner: *mut DispatchOwner,
    _unused: u32,
    initial_record: *mut u8,
    initial_payload: *mut u8,
) -> ! {
    dispatch_loop(owner, initial_record, initial_payload)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::ptr::{addr_of_mut, null_mut};
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut STEP: usize = 0;
    static mut NULL_PAYLOAD: bool = false;
    static mut PAYLOAD: *mut DispatchPayload = null_mut();
    static mut EVENTS: std::vec::Vec<u8> = std::vec::Vec::new();

    unsafe fn take(_context: *mut u8, payload: *mut *mut u8, record: *mut *mut u8) -> u32 {
        STEP += 1;
        match STEP {
            1 => { EVENTS.push(1); 0x27 }
            2 => { EVENTS.push(2); 0x1a }
            3 | 4 => {
                EVENTS.push(3);
                *payload = if NULL_PAYLOAD { null_mut() } else { PAYLOAD.cast() };
                *record = if STEP == 3 { 0x1234usize as *mut u8 } else { null_mut() };
                0
            }
            _ => panic!("finite fixture exhausted"),
        }
    }
    unsafe extern "C" fn dispatch(_owner: *mut DispatchOwner, payload: *mut DispatchPayload) {
        EVENTS.push(4);
        // Dispatch may replace the payload vtable; finalization must reload it.
        (*payload).vtable = &FINAL;
    }
    unsafe extern "C" fn release(_context: *mut u8, record: *mut *mut u8) -> u32 {
        EVENTS.push(if (*record).is_null() { 6 } else { 5 });
        *record = null_mut();
        0x99 // Ignored: finalization must still run on release errors.
    }
    unsafe extern "C" fn finalize(_payload: *mut DispatchPayload) { EVENTS.push(7); }
    unsafe extern "C" fn stale_finalize(_payload: *mut DispatchPayload) { EVENTS.push(8); }
    static OWNER: DispatchOwnerVtable = DispatchOwnerVtable { dispatch };
    static INITIAL: DispatchPayloadVtable = DispatchPayloadVtable { unresolved_slot_zero: 0, finalize: stale_finalize };
    static FINAL: DispatchPayloadVtable = DispatchPayloadVtable { unresolved_slot_zero: 0, finalize };

    struct Restore(Take, RecordRelease);
    impl Drop for Restore {
        fn drop(&mut self) { unsafe {
            addr_of_mut!(TAKE).write(self.0);
            addr_of_mut!(OPAQUE_DISPATCH_RECORD_RELEASE).write(self.1);
        } }
    }

    unsafe fn exercise(null_payload: bool) -> std::vec::Vec<u8> {
        let _restore = Restore(read_volatile(addr_of!(TAKE)), read_volatile(addr_of!(OPAQUE_DISPATCH_RECORD_RELEASE)));
        addr_of_mut!(TAKE).write(take);
        addr_of_mut!(OPAQUE_DISPATCH_RECORD_RELEASE).write(release);
        STEP = 0;
        NULL_PAYLOAD = null_payload;
        EVENTS = std::vec::Vec::new();
        let mut owner = DispatchOwner { vtable: &OWNER, context: [0; 0xa0] };
        let mut payload = DispatchPayload { vtable: &INITIAL };
        PAYLOAD = &mut payload;
        let failure = catch_unwind(AssertUnwindSafe(|| dispatch_loop(&mut owner, null_mut(), null_mut())));
        assert!(failure.is_err());
        core::mem::take(&mut *addr_of_mut!(EVENTS))
    }

    #[test]
    fn retries_then_dispatches_releases_and_finalizes_each_payload() {
        let _lock = LOCK.lock();
        assert_eq!(unsafe { exercise(false) }, [1, 2, 3, 4, 5, 7, 3, 4, 6, 7]);
    }

    #[test]
    fn successful_null_payload_is_fatal_before_any_callback() {
        let _lock = LOCK.lock();
        assert_eq!(unsafe { exercise(true) }, [1, 2, 3]);
    }
}
