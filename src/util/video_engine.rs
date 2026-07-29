//! Port of the video-engine instance getter `FUN_08252bec` @ 0x08252bec
//! (12 bytes; 146 `bl` + 1 tail `b` call sites in osos, plus the alias
//! thunk `b 0x08252bec` @ 0x082cafbc).
//!
//! Original:
//!
//! ```text
//! ldr r0, [0x8252bf8]      ; literal 0x089ca8a8 — instance slot
//! ldr r0, [r0, #0x0]       ; return *slot
//! bx  lr
//! ```
//!
//! A bare singleton getter: `return *(void **)0x089ca8a8`. Unlike the
//! lazily-constructed framework singletons (`app/singletons.rs`) this
//! one never allocates — the instance is created elsewhere and
//! installed through the setter @ 0x08252d4c (which releases the old
//! instance with flag 0 and retains the new one with flag 1 via
//! 0x0824ddf0), so a NULL return simply means "no video session" and
//! every one of the 146 callers checks for it.
//!
//! What the singleton is: the **video playback engine** instance.
//! The evidence, all from its own methods and installers:
//!
//! - Its only installer (0x082cb038, called from the media view
//!   controller's setup @ 0x08295ae0) is invoked while that view builds
//!   a **320x240 (0x140 x 0xf0)** display-layer-backed output path —
//!   the iPod Classic's screen size.
//! - The frame-advance method @ 0x08252aXX keeps a **ring of three
//!   frame slots** (index @ +0xab4, advanced mod 3): it picks the
//!   current, `(cur-1) mod 3` and `(cur-2) mod 3` slots (stride @
//!   +0xac8-derived), and feeds all three to the 1304-byte three-plane
//!   fixed-point (20.12) scaler/compositor @ 0x08251894 — the classic
//!   previous/current/next cadence of **temporal deinterlacing** of
//!   planar video.
//! - It carries a property bag keyed by 16-bit ids (0x8892 -> +0xad8,
//!   0x8893 -> +0xadc in the dispatcher @ 0x0825360c; 0x88e4/0x88e8 in
//!   0x0824ce14; 0x3059/0x305a -> +0xae0/+0xae4 in the query @
//!   0x082cafc8) with 0x500 as the unknown-property error code
//!   (0x0824f388), plus a byte flag word @ +0x14c and an "active" flag
//!   @ +0xb50 whose clearing tears down the frame buffer
//!   (0x0824ddf0 -> heap free of the block 0x0825642c returns).
//! - The public C wrappers @ 0x082d0c68..0x082d23ec are all
//!   `if (video_engine_get()) method(instance, ...)` thunks, which is
//!   where the bulk of the call sites come from.
//!
//! # Deviation
//!
//! On target the slot is read straight from the original firmware
//! address 0x089ca8a8 (the `kernel/control_state.rs` precedent): the
//! setter that owns the slot is unported, so the port must not keep its
//! own copy. Host builds substitute a mock pointer
//! (`set_mock_instance`) so the read-through behavior is testable.
//! Codegen on ARM is the same two-load leaf as the original.

#[cfg(not(target_arch = "arm"))]
use core::ptr::{addr_of, addr_of_mut};

/// Firmware address of the instance slot: the literal-pool word the
/// original's first `ldr` fetches (0x089ca8a8).
#[cfg(target_arch = "arm")]
const INSTANCE_SLOT_ADDR: u32 = 0x089c_a8a8;

/// Host-test stand-in for the firmware instance slot @ 0x089ca8a8.
#[cfg(not(target_arch = "arm"))]
static mut MOCK_INSTANCE: *mut u8 = core::ptr::null_mut();

/// Host only: install the pointer the getter will return.
#[cfg(not(target_arch = "arm"))]
pub unsafe fn set_mock_instance(instance: *mut u8) {
    *addr_of_mut!(MOCK_INSTANCE) = instance;
}

#[inline]
fn instance() -> *mut u8 {
    #[cfg(target_arch = "arm")]
    unsafe {
        (INSTANCE_SLOT_ADDR as *const *mut u8).read_volatile()
    }
    #[cfg(not(target_arch = "arm"))]
    unsafe {
        *addr_of!(MOCK_INSTANCE)
    }
}

/// video_engine_get — original: `FUN_08252bec` @ 0x08252bec (12 bytes).
///
/// Returns the video-engine instance @ *0x089ca8a8, or NULL when no
/// video session is installed (the case every caller checks for).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn video_engine_get() -> *mut u8 {
    instance()
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;

    #[test]
    fn returns_null_before_any_instance_is_installed() {
        unsafe {
            set_mock_instance(ptr::null_mut());
            assert!(video_engine_get().is_null());
        }
    }

    #[test]
    fn returns_the_installed_instance_exactly() {
        let mut object = [0xa5u8; 16];
        unsafe {
            set_mock_instance(object.as_mut_ptr());
            assert_eq!(video_engine_get(), object.as_mut_ptr());
        }
    }

    #[test]
    fn every_call_re_reads_the_slot() {
        // The setter swaps the instance at runtime (release old /
        // retain new), so the getter must not cache: a second call
        // after a swap sees the new pointer, and NULL after teardown.
        let mut first = [0xa5u8; 16];
        let mut second = [0x5au8; 16];
        unsafe {
            set_mock_instance(first.as_mut_ptr());
            assert_eq!(video_engine_get(), first.as_mut_ptr());
            set_mock_instance(second.as_mut_ptr());
            assert_eq!(video_engine_get(), second.as_mut_ptr());
            set_mock_instance(ptr::null_mut());
            assert!(video_engine_get().is_null());
        }
    }

    #[test]
    fn the_returned_pointer_is_not_dereferenced() {
        // A bare getter: the object's contents are irrelevant to it.
        let mut object = [0u8; 16];
        unsafe {
            set_mock_instance(object.as_mut_ptr());
            assert_eq!(video_engine_get(), object.as_mut_ptr());
            assert_eq!(object, [0u8; 16], "the object is untouched");
        }
    }
}
