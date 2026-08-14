//! The **display object** — the per-panel compositor root that owns the six
//! display layers `drivers/display_layer.rs` ports, and the lazy accessor
//! every caller in the image uses to reach one of them.
//!
//! `display_layer.rs` already names `FUN_081d9064` @ 0x081d9064 as "the
//! layer is obtained with `FUN_081d9064(display, index)`". This module is
//! the other side of that sentence: the display class itself.
//!
//! # Why this lives under `drivers/`
//!
//! The address (0x081dxxxx) sits in the app/Silver band, but the class is
//! pure display driver. Its constructor `FUN_081d92a4` @ 0x081d92a4 is
//! decisive:
//!
//! ```text
//! FUN_080744a4(display + 0x28)           @ mutex_create on the embedded mutex
//! for (i = 0; i < 6; i++) {
//!     *(u32 *)(display + i * 4)  = 0;    @ six layer slots, +0x00..+0x17
//!     *(u8  *)(display + i + 0x18) = 0;  @ six per-layer bytes, +0x18..+0x1d
//! }
//! *(u8  *)(display + 0x90) = param_2;    @ the display id, 0 or 1
//! *(u32 *)(display + 0x94) = 0;
//! if (param_2 == 0) *(display + 0x94) = FUN_0814ece0();  @ panel driver
//! else if (param_2 == 1) *(display + 0x94) = FUN_08169018();
//! ```
//!
//! and the singleton getter `FUN_081d8870` @ 0x081d8870 hands out exactly
//! two of them, id 0 and id 1 — the internal LCD and the secondary output.
//! Every field this module touches feeds the layer object, so it belongs
//! beside the layer, not in `app/`.
//!
//! # Recovered field map (only the fields this port reads)
//!
//! ```text
//! +0x00  ptr[6]  layer slots, NULL until first use — what this accessor
//!                fills in; the index is the layer id 0..5 (the only
//!                immediates any of the 63 call sites passes)
//! +0x18  u8[6]   per-layer bytes, zeroed by the constructor
//! +0x28  Mutex   the display's own mutex (kernel::sync_mutex::Mutex),
//!                created by the constructor, held across the whole
//!                lazy-construction window
//! +0x90  u8      display id — 0 = internal LCD, 1 = secondary output
//! +0x94  ptr     the panel driver object, handed to every layer this
//!                accessor builds and landing at the layer's +0x04
//!                ("display driver object" in display_layer.rs)
//! ```
//!
//! The layer constructor's fifth argument, `display_id == 1`, is what the
//! layer keeps at its +0x09 — the byte `display_layer.rs` could only call
//! "(opaque)". It is the "this layer is on the secondary display" flag.

use crate::kernel::sync_mutex::{mutex_lock, mutex_unlock, Mutex};

/// Layer slots a display owns (`i < 6` in the constructor's clearing loop;
/// the accessor's call sites use exactly the immediates 0..5).
pub const LAYER_SLOT_COUNT: usize = 6;

/// Allocation size of one layer object — the `mov r0, #0x1d8` feeding
/// `operator_new` in [`display_get_layer`].
pub const LAYER_OBJECT_SIZE: usize = 0x1d8;

/// The display id the accessor tests for: id 1 is the secondary output, and
/// its layers are built with the "secondary display" byte set.
pub const SECONDARY_DISPLAY_ID: u8 = 1;

/// The display object, cut down to the fields [`display_get_layer`] reads.
///
/// Named `repr(C)` fields rather than literal byte offsets: `layers` and
/// `driver` are native-width pointers, so the target offsets in the header
/// hold on a 32-bit build while a 64-bit host test simply gets a larger,
/// self-consistent object.
#[repr(C)]
pub struct Display {
    /// +0x00: the six lazily constructed layer objects.
    pub layers: [*mut u8; LAYER_SLOT_COUNT],
    /// +0x18..+0x27: the six per-layer bytes and the flags beside them.
    pub reserved_18: [u8; 0x10],
    /// +0x28: the display's mutex, created by `FUN_081d92a4`.
    pub mutex: Mutex,
    /// +0x30..+0x8f: geometry and state this port does not touch.
    pub reserved_30: [u8; 0x60],
    /// +0x90: display id — 0 internal LCD, 1 secondary output.
    pub display_id: u8,
    /// +0x91..+0x93: padding ahead of the driver word.
    pub reserved_91: [u8; 3],
    /// +0x94: the panel driver object every layer is bound to.
    pub driver: *mut u8,
}

// The header's offsets are only claims about the 32-bit target layout, so
// assert them there and nowhere else.
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x18] = [0; core::mem::offset_of!(Display, reserved_18)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x28] = [0; core::mem::offset_of!(Display, mutex)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x90] = [0; core::mem::offset_of!(Display, display_id)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x94] = [0; core::mem::offset_of!(Display, driver)];

/// Indirect dispatch for this cluster's unported callee (the house pattern
/// — see `drivers/display_layer.rs` and `heap/alloc_core.rs`).
#[derive(Clone, Copy)]
pub struct DisplayHooks {
    /// `FUN_08120b10` @ 0x08120b10 (1 `bl` call site, [`display_get_layer`]):
    /// the layer constructor. Zero-initializes the 0x1d8-byte layer, plants
    /// `display` at +0x00, `driver` at +0x04, `layer_index` at +0x08,
    /// `on_secondary_display` at +0x09, 0xff at +0x48, then creates the
    /// layer's own mutex (+0x78) and its two event objects, and returns the
    /// layer. Default: identity — it returns `storage` untouched, which
    /// reproduces exactly the one thing the accessor observes (the original
    /// leaves r0 alone on the path that matters, so the NULL check below
    /// still sees an `operator_new` failure).
    pub layer_construct: unsafe extern "C" fn(
        storage: *mut u8,
        display: *mut Display,
        driver: *mut u8,
        layer_index: u8,
        on_secondary_display: u8,
    ) -> *mut u8,
}

unsafe extern "C" fn layer_construct_stub(
    storage: *mut u8,
    _display: *mut Display,
    _driver: *mut u8,
    _layer_index: u8,
    _on_secondary_display: u8,
) -> *mut u8 {
    storage
}

/// Wired default: the documented identity stub for the unported layer
/// constructor.
pub(crate) const DEFAULT_DISPLAY_HOOKS: DisplayHooks = DisplayHooks {
    layer_construct: layer_construct_stub,
};

/// The active hooks. Host tests swap in a recording mock and restore.
pub static mut DISPLAY_HOOKS: DisplayHooks = DEFAULT_DISPLAY_HOOKS;

/// Volatile read so LLVM cannot fold the default stub in and delete the
/// dispatch (the `alloc_core.rs` rationale).
#[inline(always)]
unsafe fn display_hooks() -> DisplayHooks {
    core::ptr::read_volatile(core::ptr::addr_of!(DISPLAY_HOOKS))
}

/// The slot the original addresses with `ldr r0, [r4, r5, lsl #2]`.
///
/// Deliberately unchecked: the original has no bound on the index either,
/// and Rust slice indexing would introduce a panic path the firmware
/// does not have.
#[inline(always)]
unsafe fn layer_slot(display: *mut Display, index: u32) -> *mut *mut u8 {
    core::ptr::addr_of_mut!((*display).layers)
        .cast::<*mut u8>()
        .add(index as usize)
}

/// display_get_layer — original: `FUN_081d9064` @ 0x081d9064
/// (96 bytes, 0x081d9064..0x081d90c4 — 24 instructions with no literal
/// pool; the next function opens at 0x081d90c4 with `push {r4, lr}`, which
/// Ghidra's function table misses entirely, so its 96-byte extent is right
/// here by luck. **63 `bl` and 0 `b` call sites**, counted by decoding
/// every branch word in `osos.dec`.)
///
/// The display's lazy per-layer accessor: returns layer `index` of
/// `display`, constructing it on first request.
///
/// ```text
/// mutex_lock(&display->mutex);                    @ +0x28
/// if (display->layers[index] == NULL) {
///     on_secondary = (display->display_id == 1);  @ +0x90, ldrb + cmp #1
///     display->layers[index] =
///         layer_construct(operator_new(0x1d8),    @ tag-2 new
///                         display, display->driver, index, on_secondary);
/// }
/// mutex_unlock(&display->mutex);
/// return display->layers[index];                  @ re-loaded, not cached
/// ```
///
/// The slot is genuinely loaded three times in the original — once for the
/// test, once for the store, once for the return after the unlock — so the
/// port keeps them as volatile accesses rather than caching the value
/// across the constructor and the unlock.
///
/// # Deviations
///
/// - `mutex_lock`/`mutex_unlock` (0x0807f5c4 / 0x0807f6a0) and
///   `operator_new` (0x082aadd4) are ported and called directly.
/// - The layer constructor 0x08120b10 is not ported; it dispatches through
///   [`DISPLAY_HOOKS`].
/// - `operator_new`'s result is handed to the constructor unchecked, and
///   the constructor's result is stored unchecked — exactly as in the
///   original, which has no NULL test anywhere.
///
/// # Safety
///
/// `display` must point at a live display object and `index` must be a
/// valid layer id (0..[`LAYER_SLOT_COUNT`]), as the original requires.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn display_get_layer(display: *mut Display, index: u32) -> *mut u8 {
    let mutex = core::ptr::addr_of_mut!((*display).mutex) as *mut Mutex;
    let slot = layer_slot(display, index);

    mutex_lock(mutex);

    if slot.read_volatile().is_null() {
        let on_secondary_display =
            (core::ptr::addr_of!((*display).display_id).read_volatile() == SECONDARY_DISPLAY_ID)
                as u8;
        let storage = crate::heap::veneers::operator_new(LAYER_OBJECT_SIZE);
        let driver = core::ptr::addr_of!((*display).driver).read_volatile();
        let layer = (display_hooks().layer_construct)(
            storage,
            display,
            driver,
            index as u8,
            on_secondary_display,
        );
        slot.write_volatile(layer);
    }

    mutex_unlock(mutex);

    slot.read_volatile()
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::veneers::tests::{alloc_log, mock_heap, set_alloc_ret};
    use std::sync::{Mutex as HostMutex, MutexGuard};

    /// Serializes swaps of [`DISPLAY_HOOKS`].
    static HOOKS_LOCK: HostMutex<()> = HostMutex::new(());

    static mut CONSTRUCT_CALLS: usize = 0;
    static mut LAST_STORAGE: *mut u8 = core::ptr::null_mut();
    static mut LAST_DISPLAY: *mut Display = core::ptr::null_mut();
    static mut LAST_DRIVER: *mut u8 = core::ptr::null_mut();
    static mut LAST_INDEX: u8 = 0xff;
    static mut LAST_SECONDARY: u8 = 0xff;
    static mut CONSTRUCT_RESULT: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn recording_layer_construct(
        storage: *mut u8,
        display: *mut Display,
        driver: *mut u8,
        layer_index: u8,
        on_secondary_display: u8,
    ) -> *mut u8 {
        CONSTRUCT_CALLS += 1;
        LAST_STORAGE = storage;
        LAST_DISPLAY = display;
        LAST_DRIVER = driver;
        LAST_INDEX = layer_index;
        LAST_SECONDARY = on_secondary_display;
        CONSTRUCT_RESULT
    }

    /// Installs the recording constructor and the mock heap. The two guards
    /// are returned together so no test ever takes either lock twice.
    fn install_mocks() -> (MutexGuard<'static, ()>, MutexGuard<'static, ()>) {
        let hooks_guard = HOOKS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let heap_guard = mock_heap();
        unsafe {
            DISPLAY_HOOKS = DisplayHooks { layer_construct: recording_layer_construct };
            CONSTRUCT_CALLS = 0;
            LAST_STORAGE = core::ptr::null_mut();
            LAST_DISPLAY = core::ptr::null_mut();
            LAST_DRIVER = core::ptr::null_mut();
            LAST_INDEX = 0xff;
            LAST_SECONDARY = 0xff;
            CONSTRUCT_RESULT = core::ptr::null_mut();
        }
        (hooks_guard, heap_guard)
    }

    fn restore_mocks(guards: (MutexGuard<'static, ()>, MutexGuard<'static, ()>)) {
        unsafe { DISPLAY_HOOKS = DEFAULT_DISPLAY_HOOKS };
        drop(guards);
    }

    /// A display with a NULL mutex cell: `mutex_lock`/`mutex_unlock` take
    /// their NULL guard and never reach the ROM semaphore ops, which is the
    /// "mutex not created yet" state the kernel port models.
    fn display(display_id: u8, driver: *mut u8) -> Display {
        Display {
            layers: [core::ptr::null_mut(); LAYER_SLOT_COUNT],
            reserved_18: [0; 0x10],
            mutex: Mutex { sem_cell: core::ptr::null_mut(), unused: 0 },
            reserved_30: [0; 0x60],
            display_id,
            reserved_91: [0; 3],
            driver,
        }
    }

    #[test]
    fn builds_the_layer_on_first_request_and_caches_it() {
        let guards = install_mocks();
        let driver = 0x0814_ece0usize as *mut u8;
        let mut storage = [0u8; LAYER_OBJECT_SIZE];
        let built = 0x0BAD_F00Dusize as *mut u8;
        let mut d = display(0, driver);

        unsafe {
            set_alloc_ret(storage.as_mut_ptr());
            CONSTRUCT_RESULT = built;

            let first = display_get_layer(&mut d, 3);

            assert_eq!(first, built, "returns the constructed layer");
            assert_eq!(d.layers[3], built, "and caches it in slot 3");
            assert_eq!(CONSTRUCT_CALLS, 1);
            assert_eq!(LAST_STORAGE, storage.as_mut_ptr(), "operator_new block feeds the ctor");
            assert_eq!(LAST_DISPLAY, &mut d as *mut Display, "display is the ctor's r1");
            assert_eq!(LAST_DRIVER, driver, "+0x94 is the ctor's r2");
            assert_eq!(LAST_INDEX, 3, "the index is the ctor's r3");
            assert_eq!(
                alloc_log(),
                (1, LAYER_OBJECT_SIZE, 2),
                "exactly one tag-2 operator_new(0x1d8)"
            );

            // Second request must not allocate or construct again.
            let second = display_get_layer(&mut d, 3);
            assert_eq!(second, built);
            assert_eq!(CONSTRUCT_CALLS, 1, "cached slot short-circuits the ctor");
            assert_eq!(alloc_log().0, 1, "and the allocator");
        }
        restore_mocks(guards);
    }

    #[test]
    fn each_of_the_six_slots_is_independent() {
        let guards = install_mocks();
        let mut storage = [0u8; LAYER_OBJECT_SIZE];
        let mut d = display(0, core::ptr::null_mut());

        unsafe {
            set_alloc_ret(storage.as_mut_ptr());
            for index in 0..LAYER_SLOT_COUNT {
                CONSTRUCT_RESULT = (0x0100_0000usize + index * 0x100) as *mut u8;
                let layer = display_get_layer(&mut d, index as u32);
                assert_eq!(layer, CONSTRUCT_RESULT);
                assert_eq!(LAST_INDEX, index as u8, "index reaches the ctor as a byte");
            }
            assert_eq!(CONSTRUCT_CALLS, LAYER_SLOT_COUNT, "one construction per slot");
            for index in 0..LAYER_SLOT_COUNT {
                assert_eq!(
                    d.layers[index],
                    (0x0100_0000usize + index * 0x100) as *mut u8,
                    "slot {index} holds its own layer"
                );
            }
        }
        restore_mocks(guards);
    }

    #[test]
    fn secondary_display_flag_is_display_id_equal_one_only() {
        let guards = install_mocks();
        let mut storage = [0u8; LAYER_OBJECT_SIZE];

        // Only id 1 sets the byte: the original is `cmp r0, #1; moveq r6, #1`
        // over a zeroed r6, so 0 and every other value give 0.
        for (display_id, expected) in [(0u8, 0u8), (1, 1), (2, 0), (0xff, 0)] {
            let mut d = display(display_id, core::ptr::null_mut());
            unsafe {
                set_alloc_ret(storage.as_mut_ptr());
                CONSTRUCT_RESULT = 0x0DEF_ACEDusize as *mut u8;
                display_get_layer(&mut d, 0);
                assert_eq!(
                    LAST_SECONDARY, expected,
                    "display id {display_id} -> secondary flag {expected}"
                );
            }
        }
        restore_mocks(guards);
    }

    #[test]
    fn a_null_constructor_result_is_stored_and_returned_unchecked() {
        let guards = install_mocks();
        let mut storage = [0u8; LAYER_OBJECT_SIZE];
        let mut d = display(1, core::ptr::null_mut());

        unsafe {
            set_alloc_ret(storage.as_mut_ptr());
            CONSTRUCT_RESULT = core::ptr::null_mut();

            assert!(display_get_layer(&mut d, 5).is_null(), "no NULL check in the original");
            assert!(d.layers[5].is_null(), "the NULL is stored");
            assert_eq!(CONSTRUCT_CALLS, 1);

            // The slot is still NULL, so the next call retries — the
            // original's only "failure" behavior.
            CONSTRUCT_RESULT = 0x0C0F_FEE0usize as *mut u8;
            assert_eq!(display_get_layer(&mut d, 5), 0x0C0F_FEE0usize as *mut u8);
            assert_eq!(CONSTRUCT_CALLS, 2, "a NULL slot is retried on the next request");
        }
        restore_mocks(guards);
    }

    #[test]
    fn a_failed_allocation_still_reaches_the_constructor() {
        let guards = install_mocks();
        let mut d = display(0, core::ptr::null_mut());

        unsafe {
            set_alloc_ret(core::ptr::null_mut());
            CONSTRUCT_RESULT = core::ptr::null_mut();

            assert!(display_get_layer(&mut d, 2).is_null());
            assert_eq!(CONSTRUCT_CALLS, 1, "the original calls the ctor before testing anything");
            assert!(LAST_STORAGE.is_null(), "with the NULL block verbatim");
        }
        restore_mocks(guards);
    }
}
