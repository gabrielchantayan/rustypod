//! Virtual cleanup dispatch for the media decoder lifecycle.
//!
//! `decoder_cleanup` — original: `FUN_08005ef0` @ 0x08005ef0 (16 bytes).
//! Reference: `decomp/c/000/08005ef0_FUN_08005ef0.c`; definitive sequence:
//! `decomp/osos.asm:4673-4676`.
//!
//! Algorithm: load the active media decoder object from the caller-owned slot,
//! load its vtable from object offset +0x00, and tail-dispatch vtable entry
//! +0x0c with that object preserved in `r0`. The two direct callers invoke it
//! only while their pending-cleanup byte is set, then clear that byte after a
//! UI notification, making this the decoder cleanup lifecycle operation. No
//! null check exists at either dereference or before `bx`; malformed slots
//! retain the firmware's fault/invalid-branch behavior.
//!
//! On the 32-bit ARM target, vtable entry 3 is exactly byte offset +0x0c.
//! Tests use pointer-width vtable cells so their native callbacks form the
//! local dispatch seam without fabricating an unported decoder target.
//!
//! Deviation: Rust expresses the terminal indirect transfer as a final call
//! whose return is immediately propagated; it has no observable work after
//! the dispatch, preserving the binary tail-call contract.

/// Word index of the cleanup virtual method: +0x0c on ARMv5TE.
const CLEANUP_VTABLE_INDEX: usize = 0x0c / 4;

/// ABI of the unported media decoder cleanup method.
type DecoderCleanup = unsafe extern "C" fn(*mut u8) -> usize;

/// decoder_cleanup — original: `FUN_08005ef0` @ 0x08005ef0 (16 bytes).
///
/// Forwards the decoder object in `*decoder_slot` to its vtable's +0x0c
/// method. The returned register value is passed through unchanged. This has
/// the original's deliberately unchecked pointer behavior.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn decoder_cleanup(decoder_slot: *mut *mut u8) -> usize {
    let decoder = unsafe { decoder_slot.read() };
    let vtable = unsafe { (decoder as *const *const usize).read() };
    let entry = unsafe { vtable.add(CLEANUP_VTABLE_INDEX).read() };
    let cleanup: DecoderCleanup = unsafe { core::mem::transmute(entry) };
    unsafe { cleanup(decoder) }
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

    unsafe extern "C" fn recording_cleanup(decoder: *mut u8) -> usize {
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
    fn forwards_decoder_to_vtable_slot_0x0c_and_propagates_return() {
        let _bench = bench();
        let mut vtable = [wrong_slot as usize; CLEANUP_VTABLE_INDEX + 1];
        vtable[CLEANUP_VTABLE_INDEX] = recording_cleanup as usize;
        let mut object = VtableObject { vtable: vtable.as_ptr() };
        let mut decoder_slot = (&mut object as *mut VtableObject).cast::<u8>();

        let result = unsafe { decoder_cleanup(&mut decoder_slot) };

        assert_eq!(unsafe { FORWARDED_DECODER }, decoder_slot as usize);
        assert_eq!(unsafe { WRONG_SLOT_CALLS }, 0, "only vtable slot +0x0c dispatches");
        assert_eq!(result, RETURN_MARKER, "the virtual tail return propagates");
    }
}
