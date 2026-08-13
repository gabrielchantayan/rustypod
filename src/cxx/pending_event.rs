//! Pending-event virtual forwarding.
//!
//! `pending_event_dispatch` — original: `FUN_08005e4c` @ 0x08005e4c (16 bytes).
//! Reference: `decomp/c/000/08005e4c_FUN_08005e4c.c`; definitive sequence:
//! raw ARM `ldr r0, [r0]; ldr r1, [r0]; ldr r1, [r1, #0x20]; bx r1`.
//!
//! Algorithm: load the pending-event object from the caller-owned slot, load
//! its vtable from object offset +0x00, then tail-dispatch vtable entry +0x20
//! with that object in `r0`. No null checks exist at either dereference or
//! before `bx`; malformed slots therefore retain the firmware's fault or
//! invalid-branch behavior.
//!
//! On the 32-bit ARM target, vtable entry 8 is exactly byte offset +0x20.
//! Tests use pointer-width vtable cells so their native callbacks form the
//! host dispatch seam without fabricating an unported event target.
//!
//! Deviation: Rust expresses the terminal indirect transfer as a final call.
//! The original's `void` ABI exposes no return value, and neither form has
//! observable work after the virtual dispatch.

/// Word index of the pending-event handler: +0x20 on ARMv5TE.
const PENDING_EVENT_VTABLE_INDEX: usize = 0x20 / 4;

/// ABI of the unported pending-event virtual handler.
type PendingEventHandler = unsafe extern "C" fn(*mut u8);

/// pending_event_dispatch — original: `FUN_08005e4c` @ 0x08005e4c (16 bytes).
///
/// Forwards the pending-event object in `*event_slot` to its vtable's +0x20
/// method. This has the original's deliberately unchecked pointer behavior.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn pending_event_dispatch(event_slot: *mut *mut u8) {
    let event = unsafe { event_slot.read() };
    let vtable = unsafe { (event as *const *const usize).read() };
    let entry = unsafe { vtable.add(PENDING_EVENT_VTABLE_INDEX).read() };
    let handler: PendingEventHandler = unsafe { core::mem::transmute(entry) };
    unsafe { handler(event) }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static DISPATCH_LOCK: Mutex<()> = Mutex::new(());
    static mut FORWARDED_EVENT: usize = 0;
    static mut WRONG_SLOT_CALLS: usize = 0;

    unsafe extern "C" fn wrong_slot(_event: *mut u8) {
        unsafe { WRONG_SLOT_CALLS += 1 };
    }

    unsafe extern "C" fn recording_handler(event: *mut u8) {
        unsafe { FORWARDED_EVENT = event as usize };
    }

    /// An object with exactly the wrapper's only required field: its vtable.
    #[repr(C)]
    struct VtableObject {
        vtable: *const usize,
    }

    struct Bench {
        _lock: MutexGuard<'static, ()>,
    }

    fn bench() -> Bench {
        let lock = DISPATCH_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            FORWARDED_EVENT = 0;
            WRONG_SLOT_CALLS = 0;
        }
        Bench { _lock: lock }
    }

    #[test]
    fn dispatches_pending_event_vtable_slot_0x20() {
        let _bench = bench();
        let mut vtable = [wrong_slot as usize; PENDING_EVENT_VTABLE_INDEX + 1];
        vtable[PENDING_EVENT_VTABLE_INDEX] = recording_handler as usize;
        let mut object = VtableObject { vtable: vtable.as_ptr() };
        let mut event_slot = (&mut object as *mut VtableObject).cast::<u8>();

        unsafe { pending_event_dispatch(&mut event_slot) };

        assert_eq!(unsafe { FORWARDED_EVENT }, event_slot as usize);
        assert_eq!(unsafe { WRONG_SLOT_CALLS }, 0, "only slot +0x20 dispatches");
    }

    #[test]
    fn dispatch_reads_the_event_from_the_caller_owned_slot() {
        let _bench = bench();
        let first_vtable = [wrong_slot as usize; PENDING_EVENT_VTABLE_INDEX + 1];
        let mut second_vtable = [wrong_slot as usize; PENDING_EVENT_VTABLE_INDEX + 1];
        second_vtable[PENDING_EVENT_VTABLE_INDEX] = recording_handler as usize;
        let mut first = VtableObject { vtable: first_vtable.as_ptr() };
        let mut second = VtableObject { vtable: second_vtable.as_ptr() };
        let mut event_slot = (&mut first as *mut VtableObject).cast::<u8>();
        event_slot = (&mut second as *mut VtableObject).cast::<u8>();

        unsafe { pending_event_dispatch(&mut event_slot) };

        assert_eq!(unsafe { FORWARDED_EVENT }, event_slot as usize);
    }
}
