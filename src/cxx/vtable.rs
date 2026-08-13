//! Virtual completion dispatch for a queued media-decoder event.
//!
//! `decoder_complete_event` — original: `FUN_08005e98` @ 0x08005e98
//! (16 bytes). Reference: `decomp/c/000/08005e98_FUN_08005e98.c`; definitive
//! sequence: `decomp/osos.asm:4651-4654`.
//!
//! Algorithm: load the active media-decoder object from the caller-owned slot,
//! load its vtable from object offset +0x00, then tail-dispatch vtable entry
//! +0x38 with that object preserved in `r0`. Its only recovered caller runs
//! this after a pending-event dispatch at +0x20 has returned zero and after
//! the scheduler's global event work, so this is the event-completion lifecycle
//! operation. No null checks exist at either dereference or before `bx`;
//! malformed slots therefore retain the firmware's fault/invalid-branch
//! behavior.
//!
//! On the 32-bit ARM target, vtable entry 14 is exactly byte offset +0x38.
//! Tests use pointer-width vtable cells so their native callbacks form the
//! established host dispatch seam without fabricating an unported decoder
//! target.
//!
//! Deviation: Rust expresses the terminal indirect transfer as a final call
//! whose return is immediately propagated; it has no observable work after
//! the dispatch, preserving the binary tail-call contract.

/// Word index of the event-completion virtual method: +0x38 on ARMv5TE.
const COMPLETE_EVENT_VTABLE_INDEX: usize = 0x38 / 4;

/// ABI of the unported media decoder's event-completion method.
type DecoderCompleteEvent = unsafe extern "C" fn(*mut u8) -> usize;

/// decoder_complete_event — original: `FUN_08005e98` @ 0x08005e98 (16 bytes).
///
/// Forwards the decoder object in `*decoder_slot` to its vtable's +0x38
/// method. The returned register value is passed through unchanged. This has
/// the original's deliberately unchecked pointer behavior.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn decoder_complete_event(decoder_slot: *mut *mut u8) -> usize {
    let decoder = unsafe { decoder_slot.read() };
    let vtable = unsafe { (decoder as *const *const usize).read() };
    let entry = unsafe { vtable.add(COMPLETE_EVENT_VTABLE_INDEX).read() };
    let complete_event: DecoderCompleteEvent = unsafe { core::mem::transmute(entry) };
    unsafe { complete_event(decoder) }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static DISPATCH_LOCK: Mutex<()> = Mutex::new(());
    static mut FORWARDED_DECODER: usize = 0;
    static mut WRONG_SLOT_CALLS: usize = 0;
    const RETURN_MARKER: usize = 0x5a5a_5a5a;

    unsafe extern "C" fn wrong_slot(_decoder: *mut u8) -> usize {
        unsafe { WRONG_SLOT_CALLS += 1 };
        0
    }

    unsafe extern "C" fn recording_complete_event(decoder: *mut u8) -> usize {
        unsafe { FORWARDED_DECODER = decoder as usize };
        RETURN_MARKER
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
            FORWARDED_DECODER = 0;
            WRONG_SLOT_CALLS = 0;
        }
        Bench { _lock: lock }
    }

    #[test]
    fn forwards_decoder_to_vtable_slot_0x38_and_propagates_return() {
        let _bench = bench();
        let mut vtable = [wrong_slot as usize; COMPLETE_EVENT_VTABLE_INDEX + 1];
        vtable[COMPLETE_EVENT_VTABLE_INDEX] = recording_complete_event as usize;
        let mut object = VtableObject { vtable: vtable.as_ptr() };
        let mut decoder_slot = (&mut object as *mut VtableObject).cast::<u8>();

        let result = unsafe { decoder_complete_event(&mut decoder_slot) };

        assert_eq!(unsafe { FORWARDED_DECODER }, decoder_slot as usize);
        assert_eq!(result, RETURN_MARKER, "the virtual tail return propagates");
        assert_eq!(unsafe { WRONG_SLOT_CALLS }, 0, "only slot +0x38 dispatches");
    }

    #[test]
    fn reads_the_decoder_from_the_caller_owned_slot() {
        let _bench = bench();
        let mut vtable = [0usize; COMPLETE_EVENT_VTABLE_INDEX + 1];
        vtable[COMPLETE_EVENT_VTABLE_INDEX] = recording_complete_event as usize;
        let mut first = VtableObject { vtable: vtable.as_ptr() };
        let mut second = VtableObject { vtable: vtable.as_ptr() };
        let mut decoder_slot = (&mut first as *mut VtableObject).cast::<u8>();
        decoder_slot = (&mut second as *mut VtableObject).cast::<u8>();

        unsafe { decoder_complete_event(&mut decoder_slot) };

        assert_eq!(unsafe { FORWARDED_DECODER }, decoder_slot as usize);
    }
}
