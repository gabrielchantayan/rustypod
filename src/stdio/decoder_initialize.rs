//! Media decoder initialization virtual dispatch.
//!
//! `decoder_initialize` — original: `FUN_08005f00` @ 0x08005f00 (16 bytes).
//! Reference: `decomp/c/000/08005f00_FUN_08005f00.c`; definitive sequence:
//! `ldr r0,[r0]; ldr r1,[r0]; ldr r1,[r1,#8]; bx r1`.
//!
//! Algorithm: load the media decoder object from the caller-owned slot, load
//! its vtable from object offset +0x00, then tail-dispatch entry +0x08 with
//! that object in `r0`. The sole recovered call path guards this dispatch with
//! a byte at decoder-owner +0x06 and sets that byte afterward, identifying this
//! as decoder initialization. No null check exists at either dereference or
//! before the terminal branch; malformed slots retain the firmware's
//! fault/invalid-branch behavior.
//!
//! Target vtable cells are four-byte ARM words. Host tests instead use
//! pointer-width cells, the established target/host seam for direct virtual
//! forwarding, so native callbacks can inhabit fake vtables without pointer
//! truncation. Rust models the terminal `bx` as a final call which propagates
//! its return value unchanged.

/// Word index of the decoder initialization method: +0x08 on ARMv5TE.
const INITIALIZE_VTABLE_INDEX: usize = 0x08 / 4;

/// ABI of the unported decoder initialization virtual method.
type DecoderInitialize = unsafe extern "C" fn(*mut u8) -> usize;

/// Initialize the decoder held by `*decoder_slot` through vtable slot +0x08.
///
/// The virtual method receives the decoder object and its returned register
/// value is propagated unchanged. The firmware deliberately does not validate
/// either pointer before loading or branching.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn decoder_initialize(decoder_slot: *mut *mut u8) -> usize {
    let decoder = decoder_slot.read();
    let vtable = (decoder as *const *const usize).read();
    let entry = vtable.add(INITIALIZE_VTABLE_INDEX).read();
    let initialize: DecoderInitialize = core::mem::transmute(entry);
    initialize(decoder)
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
        WRONG_SLOT_CALLS += 1;
        0
    }

    unsafe extern "C" fn recording_initialize(decoder: *mut u8) -> usize {
        FORWARDED_DECODER = decoder as usize;
        RETURN_MARKER
    }

    /// Only the object vtable word is required by this forwarding thunk.
    #[repr(C)]
    struct VtableObject {
        vtable: *const usize,
    }

    struct Bench {
        _lock: MutexGuard<'static, ()>,
    }

    fn bench() -> Bench {
        let lock = DISPATCH_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            FORWARDED_DECODER = 0;
            WRONG_SLOT_CALLS = 0;
        }
        Bench { _lock: lock }
    }

    #[test]
    fn forwards_decoder_to_vtable_slot_0x08_and_propagates_return() {
        let _bench = bench();
        let vtable = [
            wrong_slot as usize,
            wrong_slot as usize,
            recording_initialize as usize,
            wrong_slot as usize,
        ];
        let mut object = VtableObject {
            vtable: vtable.as_ptr(),
        };
        let mut decoder_slot = (&mut object as *mut VtableObject).cast::<u8>();

        let result = unsafe { decoder_initialize(&mut decoder_slot) };

        assert_eq!(result, RETURN_MARKER);
        unsafe {
            assert_eq!(FORWARDED_DECODER, (&mut object as *mut VtableObject) as usize);
            assert_eq!(WRONG_SLOT_CALLS, 0, "only vtable slot +0x08 may run");
        }
    }
}
