//! Port of the video-engine instance getter `FUN_08252bec` @ 0x08252bec
//! (12 bytes; 146 `bl` + 1 tail `b` call sites in osos, plus the alias
//! thunk `b 0x08252bec` @ 0x082cafbc) and of the public property-set
//! wrapper `FUN_082d2314` @ 0x082d2314 (48 bytes, 12 `bl` sites).
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

/// Firmware address of the property dispatcher the wrapper tail-calls
/// (`FUN_08250498` @ 0x08250498, unported).
#[cfg(target_arch = "arm")]
const PROPERTY_DISPATCH_ADDR: usize = 0x0825_0498;

/// Host-test stand-in for the property dispatcher @ 0x08250498. `None`
/// panics if reached — the wrapper must never dispatch without an
/// instance, and tests assert that.
#[cfg(not(target_arch = "arm"))]
static mut MOCK_DISPATCH: Option<unsafe extern "C" fn(*mut u8, u32, u32, u32)> = None;

/// Host only: install the mock the wrapper dispatches to.
#[cfg(not(target_arch = "arm"))]
pub unsafe fn set_mock_dispatch(
    dispatch: Option<unsafe extern "C" fn(*mut u8, u32, u32, u32)>,
) {
    *addr_of_mut!(MOCK_DISPATCH) = dispatch;
}

/// Tail dispatch into the (unported) property dispatcher @ 0x08250498.
fn property_dispatch(engine: *mut u8, command: u32, key: u32, value: u32) {
    #[cfg(target_arch = "arm")]
    unsafe {
        let dispatch: unsafe extern "C" fn(*mut u8, u32, u32, u32) =
            core::mem::transmute(PROPERTY_DISPATCH_ADDR);
        dispatch(engine, command, key, value)
    }
    #[cfg(not(target_arch = "arm"))]
    unsafe {
        match *addr_of!(MOCK_DISPATCH) {
            Some(dispatch) => dispatch(engine, command, key, value),
            None => panic!("video_engine_set_property requires dispatcher 0x08250498"),
        }
    }
}

/// video_engine_set_property — original: `FUN_082d2314` @ 0x082d2314
/// (48 bytes; 12 `bl` call sites in osos, all plain `bl`, none
/// predicated — verified by a B/BL scan of osos.dec).
///
/// Public C wrapper that submits a property-set command to the video
/// engine when a session is installed:
///
/// ```text
/// push {r4, r5, r6, lr}
/// mov   r6, r2               ; value
/// mov   r5, r1               ; key
/// mov   r4, r0               ; command
/// bl    0x08252bec           ; video_engine_get
/// cmp   r0, #0
/// movne r3, r6
/// movne r2, r5
/// movne r1, r4
/// popne {r4, r5, r6, lr}
/// bne   0x08250498           ; tail: dispatch(instance, command, key, value)
/// pop   {r4, r5, r6, pc}     ; NULL instance: silent no-op
/// ```
///
/// `if (video_engine_get()) dispatch(instance, command, key, value)` —
/// no session, no error, no latch: a NULL instance is simply ignored.
///
/// The tail target `FUN_08250498` @ 0x08250498 is the engine's property
/// dispatcher: it rejects any `command != 0xde1` by latching the
/// unknown-property error code 0x500 through `latch_first_error`
/// (0x0824f388, ported in util/error_latch). For `command == 0xde1` it
/// resolves the current frame slot (0x08252bfc: `slot =
/// instance->table[instance->index]`, table @ +0xa8c, index @ +0x24c)
/// and writes one parameter byte keyed by `key`: 0x2800 -> slot+0x105
/// (1 for value 0x2600, 2 for 0x2601), 0x2801 -> slot+0x104 and
/// slot+0x106 (maps values 0x2600/0x2601/0x2700/0x2701/0x2702),
/// 0x2802 -> slot+0x107 and 0x2803 -> slot+0x108 (via the resolver
/// 0x08260448), 0x8191 -> the instance bool @ +0x90a; unknown
/// key/value pairs also latch 0x500. All 12 call sites pass command
/// 0xde1: six in the engine setup @ 0x0825bd98 (as 0x201 + 0xbe0; keys
/// 0x2800/0x2801/0x2802/0x2803 with values 0x2600/0x2601/0x812f — the
/// 0x2802/0x2803 keys computed as `0x2801 ^| 0xde1 >> 10`), six in the
/// 0x08281030 cluster (literal 0xde1).
///
/// # Deviation
///
/// The dispatcher @ 0x08250498 is unported: on target the wrapper calls
/// the original firmware body through its address (the
/// `core::mem::transmute` seam of app/command_dispatch.rs); host tests
/// install a recording mock via `set_mock_dispatch`. The NULL-instance
/// no-op path never touches the seam.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn video_engine_set_property(command: u32, key: u32, value: u32) {
    let engine = video_engine_get();
    if engine.is_null() {
        return;
    }
    property_dispatch(engine, command, key, value);
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

    // --- video_engine_set_property (FUN_082d2314) ---

    /// Serializes the set_property tests: MOCK_INSTANCE is shared with
    /// the getter tests above and MOCK_DISPATCH/RECORDED are shared
    /// between these tests.
    static LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    static mut RECORDED: Option<(*mut u8, u32, u32, u32)> = None;

    unsafe extern "C" fn recording_dispatch(
        engine: *mut u8,
        command: u32,
        key: u32,
        value: u32,
    ) {
        *addr_of_mut!(RECORDED) = Some((engine, command, key, value));
    }

    unsafe fn recorded() -> Option<(*mut u8, u32, u32, u32)> {
        *addr_of!(RECORDED)
    }

    #[test]
    fn null_instance_is_a_silent_no_op() {
        let _guard = LOCK.lock();
        unsafe {
            *addr_of_mut!(RECORDED) = None;
            set_mock_dispatch(Some(recording_dispatch));
            set_mock_instance(ptr::null_mut());
            // Must not dispatch, must not error, must not panic.
            video_engine_set_property(0xde1, 0x2801, 0x2600);
            assert_eq!(recorded(), None, "no dispatch without a session");
        }
    }

    #[test]
    fn dispatches_with_instance_prepended_and_args_verbatim() {
        let _guard = LOCK.lock();
        let mut engine = [0u8; 16];
        unsafe {
            *addr_of_mut!(RECORDED) = None;
            set_mock_dispatch(Some(recording_dispatch));
            set_mock_instance(engine.as_mut_ptr());
            video_engine_set_property(0xde1, 0x2801, 0x2600);
            assert_eq!(
                recorded(),
                Some((engine.as_mut_ptr(), 0xde1, 0x2801, 0x2600)),
                "instance first, command/key/value unchanged"
            );
        }
    }

    #[test]
    fn edge_values_pass_through_unmodified() {
        let _guard = LOCK.lock();
        let mut engine = [0u8; 16];
        unsafe {
            set_mock_dispatch(Some(recording_dispatch));
            set_mock_instance(engine.as_mut_ptr());
            for &(command, key, value) in &[
                (0, 0, 0),
                (0xde1, 0x8191, 1),
                (0xffff_ffff, 0xffff_ffff, 0xffff_ffff),
                (0xde1, 0x2803, 0x812f),
            ] {
                *addr_of_mut!(RECORDED) = None;
                video_engine_set_property(command, key, value);
                assert_eq!(
                    recorded(),
                    Some((engine.as_mut_ptr(), command, key, value)),
                    "the wrapper is a pure pass-through; validation is the dispatcher's job"
                );
            }
        }
    }

    #[test]
    fn the_instance_is_re_read_for_every_call() {
        let _guard = LOCK.lock();
        let mut first = [0u8; 16];
        let mut second = [0u8; 16];
        unsafe {
            set_mock_dispatch(Some(recording_dispatch));
            set_mock_instance(first.as_mut_ptr());
            *addr_of_mut!(RECORDED) = None;
            video_engine_set_property(0xde1, 0x2800, 0x2600);
            assert_eq!(recorded().map(|r| r.0), Some(first.as_mut_ptr()));
            // The setter can swap or tear down the session at runtime.
            set_mock_instance(second.as_mut_ptr());
            *addr_of_mut!(RECORDED) = None;
            video_engine_set_property(0xde1, 0x2800, 0x2601);
            assert_eq!(recorded().map(|r| r.0), Some(second.as_mut_ptr()));
            set_mock_instance(ptr::null_mut());
            *addr_of_mut!(RECORDED) = None;
            video_engine_set_property(0xde1, 0x2800, 0x2601);
            assert_eq!(recorded(), None, "teardown stops the dispatch");
        }
    }
}
