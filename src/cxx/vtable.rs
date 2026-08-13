//! Virtual readiness/status dispatch for a media decoder.
//!
//! `decoder_poll` — original: `FUN_08005ea8` @ 0x08005ea8 (16 bytes).
//! Reference: `decomp/c/000/08005ea8_FUN_08005ea8.c`; definitive sequence:
//! raw ARM `ldr r0, [r0]; ldr r1, [r0]; ldr r1, [r1, #0x1c]; bx r1`.
//!
//! Algorithm: load the media-decoder object from the caller-owned slot, load
//! its vtable from object offset +0x00, then tail-dispatch vtable entry +0x1c
//! with that object in `r0`. No null checks exist at either dereference or
//! before `bx`; malformed slots therefore retain the firmware's fault or
//! invalid-branch behavior.
//!
//! On the 32-bit ARM target, vtable entry 7 is exactly byte offset +0x1c.
//! Tests use pointer-width vtable cells so their native callbacks form the
//! host dispatch seam without fabricating an unported decoder target.
//!
//! Deviation: Rust expresses the terminal indirect transfer as a final call
//! whose return is immediately propagated; it has no observable work after
//! the dispatch, preserving the binary tail-call contract.




/// Word index of the decoder readiness/status poll: +0x1c on ARMv5TE.
const POLL_VTABLE_INDEX: usize = 0x1c / 4;

/// ABI of the unported media decoder's readiness/status poll method.
type DecoderPoll = unsafe extern "C" fn(*mut u8) -> usize;


/// decoder_poll — original: `FUN_08005ea8` @ 0x08005ea8 (16 bytes).
///
/// Forwards the decoder object in `*decoder_slot` to its vtable's +0x1c
/// method. The returned register value is passed through unchanged. This has
/// the original's deliberately unchecked pointer behavior.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn decoder_poll(decoder_slot: *mut *mut u8) -> usize {
    let decoder = unsafe { decoder_slot.read() };
    let vtable = unsafe { (decoder as *const *const usize).read() };
    let entry = unsafe { vtable.add(POLL_VTABLE_INDEX).read() };
    let poll: DecoderPoll = unsafe { core::mem::transmute(entry) };
    unsafe { poll(decoder) }
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

    unsafe extern "C" fn recording_poll(decoder: *mut u8) -> usize {
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
    fn polls_decoder_vtable_slot_0x1c_and_propagates_return() {
        let _bench = bench();
        let mut vtable = [wrong_slot as usize; POLL_VTABLE_INDEX + 1];
        vtable[POLL_VTABLE_INDEX] = recording_poll as usize;
        let mut object = VtableObject { vtable: vtable.as_ptr() };
        let mut decoder_slot = (&mut object as *mut VtableObject).cast::<u8>();

        let result = unsafe { decoder_poll(&mut decoder_slot) };

        assert_eq!(unsafe { FORWARDED_DECODER }, decoder_slot as usize);
        assert_eq!(result, RETURN_MARKER, "the virtual tail return propagates");
        assert_eq!(unsafe { WRONG_SLOT_CALLS }, 0, "only slot +0x1c dispatches");
    }

    #[test]
    fn poll_reads_the_decoder_from_the_caller_owned_slot() {
        let _bench = bench();
        let first_vtable = [wrong_slot as usize; POLL_VTABLE_INDEX + 1];
        let mut second_vtable = [wrong_slot as usize; POLL_VTABLE_INDEX + 1];
        second_vtable[POLL_VTABLE_INDEX] = recording_poll as usize;
        let mut first = VtableObject { vtable: first_vtable.as_ptr() };
        let mut second = VtableObject { vtable: second_vtable.as_ptr() };
        let mut decoder_slot = (&mut first as *mut VtableObject).cast::<u8>();
        decoder_slot = (&mut second as *mut VtableObject).cast::<u8>();

        unsafe { decoder_poll(&mut decoder_slot) };

        assert_eq!(unsafe { FORWARDED_DECODER }, decoder_slot as usize);
    }
}
