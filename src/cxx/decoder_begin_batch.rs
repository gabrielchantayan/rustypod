//! Virtual begin-of-batch dispatch for the media decoder lifecycle.
//!
//! `decoder_begin_batch` — original: `FUN_08005e04` @ 0x08005e04
//! (16 bytes). Reference: `decomp/c/000/08005e04_FUN_08005e04.c`; definitive
//! sequence: `decomp/osos.asm:4620-4623`.
//!
//! Algorithm: the caller owns a slot whose first word is the active media
//! decoder object. The wrapper loads that object, loads its vtable from offset
//! +0x00, and tail-dispatches the vtable's +0x30 entry with the decoder object
//! still in `r0`. Its sole direct caller invokes it after ensuring the decoder
//! is active and before the paired `decoder_end_batch` call, so this is the
//! begin-of-batch lifecycle operation. No null check exists at either
//! dereference or before `bx`; malformed slots therefore retain the firmware's
//! fault/invalid-branch behavior.
//!
//! On the 32-bit ARM target, vtable entry 12 is exactly byte offset +0x30.
//! Tests use pointer-width vtable cells so their native callbacks form the
//! local dispatch seam without fabricating an unported decoder target.
//!
//! Deviation: Rust expresses the terminal indirect transfer as a final call
//! whose return is immediately propagated; it has no observable work after
//! the dispatch, preserving the binary tail-call contract.

/// Word index of the begin-of-batch virtual method: +0x30 on ARMv5TE.
const BEGIN_BATCH_VTABLE_INDEX: usize = 0x30 / 4;

/// ABI of the unported media decoder's begin-of-batch method.
type DecoderBeginBatch = unsafe extern "C" fn(*mut u8) -> usize;

/// decoder_begin_batch — original: `FUN_08005e04` @ 0x08005e04 (16 bytes).
///
/// Forwards the decoder object in `*decoder_slot` to its vtable's +0x30
/// method. The returned register value is passed through unchanged. This has
/// the original's deliberately unchecked pointer behavior.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn decoder_begin_batch(decoder_slot: *mut *mut u8) -> usize {
    let decoder = unsafe { decoder_slot.read() };
    let vtable = unsafe { (decoder as *const *const usize).read() };
    let entry = unsafe { vtable.add(BEGIN_BATCH_VTABLE_INDEX).read() };
    let begin_batch: DecoderBeginBatch = unsafe { core::mem::transmute(entry) };
    unsafe { begin_batch(decoder) }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static DISPATCH_LOCK: Mutex<()> = Mutex::new(());
    static mut FORWARDED_DECODER: usize = 0;
    const RETURN_MARKER: usize = 0x5a5a_5a5a;

    unsafe extern "C" fn recording_begin_batch(decoder: *mut u8) -> usize {
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
        unsafe { FORWARDED_DECODER = 0 };
        Bench { _lock: lock }
    }

    #[test]
    fn forwards_the_decoder_to_vtable_slot_0x30_and_propagates_its_return() {
        let _bench = bench();
        let mut vtable = [0usize; BEGIN_BATCH_VTABLE_INDEX + 1];
        vtable[BEGIN_BATCH_VTABLE_INDEX] = recording_begin_batch as usize;
        let mut object = VtableObject { vtable: vtable.as_ptr() };
        let mut decoder_slot = (&mut object as *mut VtableObject).cast::<u8>();

        let result = unsafe { decoder_begin_batch(&mut decoder_slot) };

        assert_eq!(unsafe { FORWARDED_DECODER }, decoder_slot as usize);
        assert_eq!(result, RETURN_MARKER, "the virtual tail return propagates");
    }
}
