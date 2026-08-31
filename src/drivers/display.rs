//! The **display object** — the per-panel compositor root that owns the six
//! display layers `drivers/display_layer.rs` ports, and the lazy accessor
//! every caller in the image uses to reach one of them.
//!
//! `display_layer.rs` already names `FUN_081d9064` @ 0x081d9064 as "the
//! layer is obtained with `FUN_081d9064(display, index)`". This module is
//! the other side of that sentence: the display class itself.
//!
//! Ports:
//! - [`display_get`] — original: `FUN_081d8870` @ 0x081d8870
//!   (188 bytes; **123 call sites, 118 `bl` + 5 `bleq`**). The two-panel
//!   singleton table: `display_get(0)` is the internal LCD,
//!   `display_get(1)` the secondary output, anything else is NULL.
//! - [`display_get_layer`] — original: `FUN_081d9064` @ 0x081d9064
//!   (96 bytes; **63 `bl` call sites**). The lazy per-layer accessor.
//! - [`display_set_clear_color`] — original: `FUN_081d8cfc` @ 0x081d8cfc
//!   (16 bytes; **28 `bl` call sites**). Arms the panel clear: the color
//!   word at +0x20 plus the pending byte at +0x1e, consumed by the flush
//!   loop @ 0x081d8b3c through the panel driver's vtable slot +0x10.
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
//! and the singleton getter [`display_get`] @ 0x081d8870 hands out exactly
//! two of them, id 0 and id 1 — the internal LCD and the secondary output.
//! Every field this module touches feeds the layer object, so it belongs
//! beside the layer, not in `app/`.
//!
//! # The two-panel singleton table (`display_get`)
//!
//! `FUN_081d8870` is a pair of ADS function-local statics selected by the
//! argument, the `app/media_command_facade.rs` idiom done twice in one
//! function. Binary-verified literal pool @ 0x081d8914..0x081d8928 — six
//! words Ghidra drops, which is why it reports 164 bytes instead of 188:
//!
//! ```text
//! 0x081d8914  0x089ca8b0   guard base / the SECONDARY display's guard
//! 0x081d8918  0x08a1b6cc   the SECONDARY display object
//! 0x081d891c  0x089ca09c   __dso_handle
//! 0x081d8920  0x081ce4d4   the registered "destructor"
//! 0x081d8924  0x089ca8b4   the INTERNAL display's guard (= base + 4)
//! 0x081d8928  0x08a1b624   the INTERNAL display object
//! ```
//!
//! The next function opens at 0x081d892c (`mov r3, r0; push {r4, lr}`), so
//! 0x081d8870..0x081d892c = 188 bytes is the true extent. The two objects
//! are 0x08a1b6cc − 0x08a1b624 = 0xa8 apart, and the constructor's last
//! store is `strb r5, [r4, #0xa5]` — two independent witnesses for
//! [`DISPLAY_OBJECT_SIZE`].
//!
//! ```text
//! movs r4, r0                       @ id; Z = (id == 0)
//! ldr  r0, =0x089ca8b0              @ the guard base, loaded for both arms
//! beq  internal                     @ id == 0
//! cmp  r4, #1
//! movne r0, #0; popne {r4, pc}      @ id > 1 -> NULL
//! ldr  r0, [r0]                     @ secondary guard, via the base word
//! tst  r0, #1; bne done             @ inlined fast path: bit 0
//! ldr  r0, =0x089ca8b0; bl cxa_guard_acquire
//! cmp  r0, #0; beq done
//! ldr  r0, =0x08a1b6cc              @ the object
//! mov  r1, r4                       @ the id itself, not an immediate
//! bl   0x081d92a4                   @ the constructor, returns `this`
//! ldr  r2, =0x089ca09c; ldr r1, =0x081ce4d4; bl cxa_atexit
//! ldr  r0, =0x089ca8b0; bl cxa_guard_release
//! done: ldr r0, =0x08a1b6cc; pop {r4, pc}   @ reloaded, not the ctor's r0
//! ```
//!
//! The `internal` arm is the same block over 0x089ca8b4 / 0x08a1b624,
//! except that its fast path reads the guard as `[base + 4]` while the
//! slow path loads 0x089ca8b4 as its own literal — one word, two ways of
//! naming it, a pure ADS pool artifact.
//!
//! **The 5 predicated sites are a real behavioural fact.** All five live
//! in one cluster (0x0828c528, 0x0828c5f4, 0x0828cc2c, 0x0828d0b0,
//! 0x0828d714) and all five have the shape
//!
//! ```text
//! cmp r0, #0; moveq r0, #1; bleq 0x081d8870
//! ```
//!
//! — "if the caller was handed a NULL display, default to display 1".
//! `display_get` itself has no NULL-related guard; the callers do the
//! test, and every predicated site asks for the secondary output.
//!
//! # Recovered field map (only the fields this port reads)
//!
//! ```text
//! +0x00  ptr[6]  layer slots, NULL until first use — what this accessor
//!                fills in; the index is the layer id 0..5 (the only
//!                immediates any of the 63 call sites passes)
//! +0x18  u8[6]   per-layer bytes, zeroed by the constructor
//! +0x1e  u8      clear-pending flag, armed by [`display_set_clear_color`]
//!                and cleared by the flush loop once the panel driver has
//!                cleared to the color word
//! +0x20  u32     the clear color, handed verbatim to the panel driver's
//!                vtable slot +0x10 by the flush loop @ 0x081d8bec
//! +0x28  Mutex   the display's own mutex (kernel::sync_mutex::Mutex),
//!                created by the constructor, held across the whole
//!                lazy-construction window
//! +0x90  u8      display id — 0 = internal LCD, 1 = secondary output
//! +0x94  ptr     the panel driver object, handed to every layer this
//!                accessor builds and landing at the layer's +0x04
//!                ("display driver object" in display_layer.rs)
//! +0x98  u8[16]  the constructor's byte block (+0x98..+0xa5: mostly
//!                zeroes, 1 at +0x9a and 3 at +0xa3), padded to the
//!                0xa8 object stride
//! ```
//!
//! The layer constructor's fifth argument, `display_id == 1`, is what the
//! layer keeps at its +0x09 — the byte `display_layer.rs` could only call
//! "(opaque)". It is the "this layer is on the secondary display" flag.
//!
//! The constructor also zeroes +0x1e (the clear-pending byte), so a fresh
//! display starts with no clear armed.

use core::ffi::c_void;

use crate::kernel::sync_mutex::{mutex_lock, mutex_unlock, Mutex};
use crate::runtime::cxa_guard::{cxa_guard_acquire, cxa_guard_release};
use crate::runtime::shutdown_chain::cxa_atexit;

/// Layer slots a display owns (`i < 6` in the constructor's clearing loop;
/// the accessor's call sites use exactly the immediates 0..5).
pub const LAYER_SLOT_COUNT: usize = 6;

/// Allocation size of one layer object — the `mov r0, #0x1d8` feeding
/// `operator_new` in [`display_get_layer`].
pub const LAYER_OBJECT_SIZE: usize = 0x1d8;

/// The display id the accessor tests for: id 1 is the secondary output, and
/// its layers are built with the "secondary display" byte set.
pub const SECONDARY_DISPLAY_ID: u8 = 1;

/// The internal LCD's id — [`display_get`]'s `movs r4, r0` / `beq` arm.
pub const INTERNAL_DISPLAY_ID: u32 = 0;

/// One display object's extent, agreed on by two independent witnesses:
/// the constructor's last store is `strb r5, [r4, #0xa5]`, and the two
/// static objects sit 0x08a1b6cc − 0x08a1b624 = 0xa8 apart.
pub const DISPLAY_OBJECT_SIZE: usize = 0xa8;

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
    /// +0x18..+0x1d: the six per-layer bytes, zeroed by the constructor.
    pub per_layer_bytes: [u8; 6],
    /// +0x1e: clear-pending flag — set by [`display_set_clear_color`],
    /// cleared by the flush loop @ 0x081d8bf0 once the panel driver has
    /// cleared to [`Display::clear_color`]. Zeroed by the constructor.
    pub clear_pending: u8,
    /// +0x1f: padding ahead of the color word.
    pub reserved_1f: u8,
    /// +0x20: the color the panel driver clears to on the next flush —
    /// handed verbatim to the driver's vtable slot +0x10 @ 0x081d8bec.
    pub clear_color: u32,
    /// +0x24..+0x27: the flags beside them (+0x24 is a second pending byte,
    /// armed by the sibling setter @ 0x081d8d0c; +0x25 is the flush loop's
    /// "changed" marker).
    pub reserved_24: [u8; 4],
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
    /// +0x98..+0xa7: the constructor's trailing byte block plus the pad
    /// that rounds the object up to [`DISPLAY_OBJECT_SIZE`].
    pub reserved_98: [u8; 0x10],
}

// The header's offsets are only claims about the 32-bit target layout, so
// assert them there and nowhere else.
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x18] = [0; core::mem::offset_of!(Display, per_layer_bytes)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x1e] = [0; core::mem::offset_of!(Display, clear_pending)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x20] = [0; core::mem::offset_of!(Display, clear_color)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x28] = [0; core::mem::offset_of!(Display, mutex)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x90] = [0; core::mem::offset_of!(Display, display_id)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x94] = [0; core::mem::offset_of!(Display, driver)];
#[cfg(target_pointer_width = "32")]
const _: [u8; DISPLAY_OBJECT_SIZE] = [0; core::mem::size_of::<Display>()];

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

    /// `FUN_081d92a4` @ 0x081d92a4 (2 `bl` call sites, both of them in
    /// [`display_get`]): the display constructor. Zeroes the flag bytes
    /// +0x1e/+0x24/+0x25 and the block +0x98..+0xa5 (1 at +0x9a, 3 at
    /// +0xa3), creates the display's mutex at +0x28, clears the six layer
    /// slots and their six bytes, writes the id at +0x90, then binds
    /// +0x94 to the panel driver — `FUN_0814ece0()` for id 0,
    /// `FUN_08169018()` for id 1 (plus a vtable +0x10 call and a second
    /// byte block for id 1) — and returns `this`.
    ///
    /// Default: the documented zeroing stub, which is why [`display_get`]
    /// is **not hook-ready** — a stock caller branched here would get a
    /// display with no mutex, no panel driver and a zero id.
    pub display_construct:
        unsafe extern "C" fn(storage: *mut Display, display_id: u32) -> *mut Display,
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

/// The default for the unported display constructor `FUN_081d92a4`:
/// zeroes the object and returns `this`.
///
/// A faithful *subset* — the original zeroes almost everything this does —
/// but it installs neither the mutex nor the panel driver nor the id,
/// which is what makes [`display_get`] not hook-ready. Volatile stores:
/// a plain loop is rewritten by LLVM into a call to `__aeabi_memclr`,
/// which does not exist in this build.
unsafe extern "C" fn display_construct_stub(
    storage: *mut Display,
    _display_id: u32,
) -> *mut Display {
    let bytes = storage.cast::<u8>();
    for offset in 0..DISPLAY_OBJECT_SIZE {
        bytes.add(offset).write_volatile(0);
    }
    storage
}

/// Wired default: the documented identity stub for the unported layer
/// constructor and the zeroing stub for the unported display constructor.
pub(crate) const DEFAULT_DISPLAY_HOOKS: DisplayHooks = DisplayHooks {
    layer_construct: layer_construct_stub,
    display_construct: display_construct_stub,
};

/// The active hooks. Host tests swap in a recording mock and restore.
pub static mut DISPLAY_HOOKS: DisplayHooks = DEFAULT_DISPLAY_HOOKS;

/// Volatile read so LLVM cannot fold the default stub in and delete the
/// dispatch (the `alloc_core.rs` rationale).
#[inline(always)]
unsafe fn display_hooks() -> DisplayHooks {
    core::ptr::read_volatile(core::ptr::addr_of!(DISPLAY_HOOKS))
}

/// `__dso_handle` — the pool word @ 0x081d891c (0x089ca09c), the key every
/// ADS static's `cxa_atexit` registration carries.
const DSO_HANDLE: i32 = 0x089ca09c;

/// The pre-construction state of a display object: all zero, exactly what
/// the .bss words at 0x08a1b624 / 0x08a1b6cc hold before the constructor
/// runs.
const ZEROED_DISPLAY: Display = Display {
    layers: [core::ptr::null_mut(); LAYER_SLOT_COUNT],
    per_layer_bytes: [0; 6],
    clear_pending: 0,
    reserved_1f: 0,
    clear_color: 0,
    reserved_24: [0; 4],
    mutex: Mutex { sem_cell: core::ptr::null_mut(), unused: 0 },
    reserved_30: [0; 0x60],
    display_id: 0,
    reserved_91: [0; 3],
    driver: core::ptr::null_mut(),
    reserved_98: [0; 0x10],
};

/// The internal LCD (original: the fixed object @ 0x08a1b624, pool word
/// @ 0x081d8928) and its one-time-initialization guard (@ 0x089ca8b4,
/// pool word @ 0x081d8924, reached on the fast path as `[0x089ca8b0 + 4]`).
///
/// Crate statics rather than the stock words: the 0x089cxxxx and
/// 0x08a1xxxx pages are runtime-initialized and the decrypted image holds
/// UI strings at those offsets (the `media_command_facade.rs` deviation).
/// Zero is the exact pre-init state either way.
pub static mut INTERNAL_DISPLAY_GUARD: u32 = 0;
/// The internal LCD object — see [`INTERNAL_DISPLAY_GUARD`].
pub static mut INTERNAL_DISPLAY: Display = ZEROED_DISPLAY;

/// The secondary output's guard (original: 0x089ca8b0, the pool word
/// @ 0x081d8914 that both arms load as their base).
pub static mut SECONDARY_DISPLAY_GUARD: u32 = 0;
/// The secondary output object (original: 0x08a1b6cc, pool word
/// @ 0x081d8918).
pub static mut SECONDARY_DISPLAY: Display = ZEROED_DISPLAY;

/// The destructor registered with `cxa_atexit` — original: the pool word
/// @ 0x081d8920, 0x081ce4d4.
///
/// That address is **not a function entry**: it sits inside a large
/// function, on the `mov r0, r7` at 0x081ce4d4 that feeds a
/// `bl 0x08391e38` string compare — run as a shutdown handler it would
/// execute with r4..r7 belonging to nobody and return through a frame it
/// never pushed, so the registration could never fire. retailOS never runs
/// `exit`'s chain anyway (`runtime/shutdown_chain.rs`). The same situation
/// as `media_command_facade_get`'s 0x0817f190 and `node_list_get`'s
/// 0x0810516c. A no-op matches every observable path.
unsafe extern "C" fn display_destructor(_object: *mut c_void) {}

/// One arm of [`display_get`]: the ADS function-local static over a fixed
/// object, `media_command_facade.rs`'s idiom.
///
/// `#[inline(always)]` because the original has both arms written out in
/// full — this is one source for two emitted blocks, not a shared callee.
#[inline(always)]
unsafe fn display_singleton(guard: *mut u32, object: *mut Display, display_id: u32) -> *mut Display {
    if (core::ptr::read_volatile(guard) & 1) == 0 && cxa_guard_acquire(guard) != 0 {
        let this = (display_hooks().display_construct)(object, display_id);
        cxa_atexit(this as *mut c_void, display_destructor, DSO_HANDLE);
        cxa_guard_release(guard);
    }
    object
}

/// display_get — original: `FUN_081d8870` @ 0x081d8870 (188 bytes,
/// 0x081d8870..0x081d892c: 164 of code plus the 6-word pool Ghidra drops;
/// the next function opens at 0x081d892c. **123 call sites — 118 `bl` and
/// 5 `bleq`** — counted by decoding every branch word in `osos.dec`.)
///
/// The image's whole display table: `display_get(0)` is the internal LCD,
/// `display_get(1)` the secondary output, each constructed once on first
/// request; every other id is NULL. See the module header for the stock
/// instruction sequence, the verified literal pool and the object layout.
///
/// Faithful details:
/// - The returned pointer is the object's address *reloaded* after the
///   init block, never the constructor's return; only the `cxa_atexit`
///   registration sees the constructor's value.
/// - The constructor's second argument is the caller's id in r4, not an
///   immediate — the two arms differ only in which pool words they use.
/// - The fast path tests bit 0 (`tst r0, #1`) while [`cxa_guard_acquire`]
///   tests the whole word, so a nonzero guard with bit 0 clear — a state
///   this pair never produces — takes the slow path and is still refused.
/// - A refused acquire skips construction and still hands out the object.
/// - There is no NULL check anywhere: the 5 predicated call sites test
///   *their own* display pointer and fall back to `display_get(1)`.
///
/// # Deviations
///
/// - The guard pair and `cxa_atexit` are ported and called directly; the
///   constructor 0x081d92a4 is not, so it rides
///   [`DisplayHooks::display_construct`] — whose zeroing default is why
///   this symbol is **not hook-ready**.
/// - Guards and objects are crate statics, not the stock .bss words.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn display_get(display_id: u32) -> *mut Display {
    match display_id {
        INTERNAL_DISPLAY_ID => display_singleton(
            core::ptr::addr_of_mut!(INTERNAL_DISPLAY_GUARD),
            core::ptr::addr_of_mut!(INTERNAL_DISPLAY),
            display_id,
        ),
        id if id == SECONDARY_DISPLAY_ID as u32 => display_singleton(
            core::ptr::addr_of_mut!(SECONDARY_DISPLAY_GUARD),
            core::ptr::addr_of_mut!(SECONDARY_DISPLAY),
            display_id,
        ),
        _ => core::ptr::null_mut(),
    }
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

/// display_set_clear_color — original: `FUN_081d8cfc` @ 0x081d8cfc
/// (16 bytes exactly, 0x081d8cfc..0x081d8d0c; the next function opens at
/// 0x081d8d0c with `cmp r2, #0`. **28 `bl` call sites, 0 predicated** —
/// counted by decoding every branch word in `osos.dec`; Ghidra's count
/// and extent are both right here.)
///
/// Arms the display's panel clear: stores `color` into the display's
/// +0x20 word and sets the +0x1e pending byte, in that order:
///
/// ```text
/// mov  r2, #1
/// strb r2, [r0, #0x1e]      @ clear_pending = 1
/// str  r1, [r0, #0x20]      @ clear_color = color
/// bx   lr
/// ```
///
/// The consumer is the flush loop @ 0x081d8b3c: when +0x1e is set it
/// calls the panel driver's vtable slot +0x10 as
/// `driver->vtable[0x10](driver, display->clear_color)` (0x081d8bdc..
/// 0x081d8bec) and then clears the pending byte (0x081d8bf0). The call
/// sites pass RGB colors — 0x00ff_ffff, 0x00ff_0000, 0xffff_ffff, 0 —
/// straight from `display_get`'s return, so this is the "clear the panel
/// to this color on the next flush" request.
///
/// Faithful details: the flag is stored *before* the color (the order a
/// racing flush observes them), there is no NULL guard on `display`, and
/// r0 passes through unmodified — the declared return is void and no
/// caller reads one.
///
/// # Safety
///
/// `display` must point at a live display object, as the original
/// requires.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn display_set_clear_color(display: *mut Display, color: u32) {
    core::ptr::addr_of_mut!((*display).clear_pending).write_volatile(1);
    core::ptr::addr_of_mut!((*display).clear_color).write_volatile(color);
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
            DISPLAY_HOOKS =
                DisplayHooks { layer_construct: recording_layer_construct, ..DEFAULT_DISPLAY_HOOKS };
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
            per_layer_bytes: [0; 6],
            clear_pending: 0,
            reserved_1f: 0,
            clear_color: 0,
            reserved_24: [0; 4],
            mutex: Mutex { sem_cell: core::ptr::null_mut(), unused: 0 },
            reserved_30: [0; 0x60],
            display_id,
            reserved_91: [0; 3],
            driver,
            reserved_98: [0; 0x10],
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

    // ---- display_get: the two-panel singleton table ----

    use crate::runtime::shutdown_chain::{
        lib_shutdown_chain, shutdown_chain_head, ShutdownNode, SHUTDOWN_ALLOC, SHUTDOWN_FREE,
    };
    use std::boxed::Box;
    use std::vec::Vec;

    /// (storage, display_id) of every display-constructor call, in order.
    static mut DISPLAY_CTOR_CALLS: Vec<(*mut Display, u32)> = Vec::new();
    /// What the recording display constructor hands back.
    static mut DISPLAY_CTOR_RESULT: *mut Display = core::ptr::null_mut();

    unsafe extern "C" fn recording_display_construct(
        storage: *mut Display,
        display_id: u32,
    ) -> *mut Display {
        (*core::ptr::addr_of_mut!(DISPLAY_CTOR_CALLS)).push((storage, display_id));
        if DISPLAY_CTOR_RESULT.is_null() {
            storage
        } else {
            DISPLAY_CTOR_RESULT
        }
    }

    /// Box-backed node allocator pair for the shutdown chain: the shipped
    /// defaults are the firmware malloc/free, wrong for host memory (the
    /// `media_command_facade.rs` test pattern).
    unsafe extern "C" fn box_alloc(size: usize) -> *mut u8 {
        assert_eq!(size, core::mem::size_of::<ShutdownNode>());
        Box::into_raw(Box::new(ShutdownNode {
            next: core::ptr::null_mut(),
            arg: core::ptr::null_mut(),
            handler: display_destructor,
            key: 0,
        })) as *mut u8
    }

    unsafe extern "C" fn box_free(block: *mut u8) {
        drop(Box::from_raw(block as *mut ShutdownNode));
    }

    fn internal() -> *mut Display {
        unsafe { core::ptr::addr_of_mut!(INTERNAL_DISPLAY) }
    }

    fn secondary() -> *mut Display {
        unsafe { core::ptr::addr_of_mut!(SECONDARY_DISPLAY) }
    }

    /// Returns both guards and objects to their pre-init state. Takes only
    /// [`HOOKS_LOCK`] — never the heap lock — so it can never self-deadlock
    /// against [`install_mocks`].
    fn install_singleton_mocks() -> MutexGuard<'static, ()> {
        let guard = HOOKS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            DISPLAY_HOOKS = DisplayHooks {
                display_construct: recording_display_construct,
                ..DEFAULT_DISPLAY_HOOKS
            };
            INTERNAL_DISPLAY_GUARD = 0;
            SECONDARY_DISPLAY_GUARD = 0;
            for object in [internal(), secondary()] {
                let bytes = object.cast::<u8>();
                for offset in 0..DISPLAY_OBJECT_SIZE {
                    bytes.add(offset).write(0xa5);
                }
            }
            (*core::ptr::addr_of_mut!(DISPLAY_CTOR_CALLS)).clear();
            DISPLAY_CTOR_RESULT = core::ptr::null_mut();
            SHUTDOWN_ALLOC = box_alloc;
            SHUTDOWN_FREE = box_free;
            *shutdown_chain_head() = core::ptr::null_mut();
        }
        guard
    }

    fn restore_singleton_mocks(guard: MutexGuard<'static, ()>) {
        unsafe {
            // Drain leftover registrations BEFORE restoring the firmware
            // allocator pair, so the nodes are freed by the allocator that
            // made them.
            lib_shutdown_chain(0);
            SHUTDOWN_ALLOC = crate::malloc_rt::malloc;
            SHUTDOWN_FREE = crate::malloc_rt::free;
            DISPLAY_HOOKS = DEFAULT_DISPLAY_HOOKS;
            INTERNAL_DISPLAY_GUARD = 0;
            SECONDARY_DISPLAY_GUARD = 0;
        }
        drop(guard);
    }

    #[test]
    fn each_id_constructs_its_own_object_with_its_own_id() {
        let guard = install_singleton_mocks();
        unsafe {
            assert_eq!(display_get(0), internal(), "id 0 is the internal LCD @ 0x08a1b624");
            assert_eq!(display_get(1), secondary(), "id 1 is the secondary @ 0x08a1b6cc");
            assert_eq!(
                *core::ptr::addr_of!(DISPLAY_CTOR_CALLS),
                std::vec![(internal(), 0u32), (secondary(), 1u32)],
                "`mov r1, r4` passes the caller's id, not an immediate"
            );
            assert_eq!(core::ptr::read_volatile(core::ptr::addr_of!(INTERNAL_DISPLAY_GUARD)), 1);
            assert_eq!(core::ptr::read_volatile(core::ptr::addr_of!(SECONDARY_DISPLAY_GUARD)), 1);
        }
        restore_singleton_mocks(guard);
    }

    #[test]
    fn the_two_guards_are_independent() {
        let guard = install_singleton_mocks();
        unsafe {
            display_get(1);
            assert_eq!(
                core::ptr::read_volatile(core::ptr::addr_of!(INTERNAL_DISPLAY_GUARD)),
                0,
                "the internal arm is untouched"
            );
            assert_eq!(internal().cast::<u8>().read(), 0xa5, "and so is its object");
            assert_eq!((*core::ptr::addr_of!(DISPLAY_CTOR_CALLS)).len(), 1);
        }
        restore_singleton_mocks(guard);
    }

    #[test]
    fn every_other_id_is_null_and_constructs_nothing() {
        let guard = install_singleton_mocks();
        unsafe {
            for id in [2u32, 3, 0xff, 0x8000_0000, u32::MAX] {
                assert!(display_get(id).is_null(), "id {id} -> `movne r0, #0; popne`");
            }
            assert!((*core::ptr::addr_of!(DISPLAY_CTOR_CALLS)).is_empty());
            assert!(shutdown_chain_head().read().is_null(), "no registration either");
        }
        restore_singleton_mocks(guard);
    }

    #[test]
    fn the_second_request_takes_the_bit0_fast_path() {
        let guard = install_singleton_mocks();
        unsafe {
            display_get(0);
            // A post-construction mutation must survive: the 123 call sites
            // after boot must not reconstruct the display.
            (*internal()).display_id = 0x7e;
            assert_eq!(display_get(0), internal());
            assert_eq!(display_get(0), internal());
            assert_eq!((*core::ptr::addr_of!(DISPLAY_CTOR_CALLS)).len(), 1, "constructed once");
            assert_eq!((*internal()).display_id, 0x7e, "no reconstruction");
            assert!((*shutdown_chain_head().read()).next.is_null(), "no second registration");
        }
        restore_singleton_mocks(guard);
    }

    #[test]
    fn a_guard_with_bit0_set_short_circuits_everything() {
        let guard = install_singleton_mocks();
        unsafe {
            SECONDARY_DISPLAY_GUARD = 3; // `tst r0, #1; bne done`
            assert_eq!(display_get(1), secondary());
            assert!((*core::ptr::addr_of!(DISPLAY_CTOR_CALLS)).is_empty(), "no construction");
            assert!(shutdown_chain_head().read().is_null(), "no registration");
            assert_eq!(core::ptr::read_volatile(core::ptr::addr_of!(SECONDARY_DISPLAY_GUARD)), 3);
            assert_eq!(secondary().cast::<u8>().read(), 0xa5, "handed out untouched");
        }
        restore_singleton_mocks(guard);
    }

    #[test]
    fn a_nonzero_guard_with_bit0_clear_is_still_turned_away_by_acquire() {
        // The fast path tests bit 0, cxa_guard_acquire the whole word. This
        // pair never produces the state; the original's two-level test is
        // what defines the behavior.
        let guard = install_singleton_mocks();
        unsafe {
            INTERNAL_DISPLAY_GUARD = 2;
            assert_eq!(display_get(0), internal());
            assert!((*core::ptr::addr_of!(DISPLAY_CTOR_CALLS)).is_empty(), "acquire refused");
            assert_eq!(
                core::ptr::read_volatile(core::ptr::addr_of!(INTERNAL_DISPLAY_GUARD)),
                2,
                "a refused acquire never writes"
            );
        }
        restore_singleton_mocks(guard);
    }

    #[test]
    fn the_object_literal_is_returned_but_the_registration_carries_the_ctors_value() {
        // The original reloads the pool word 0x081d8918; only the
        // cxa_atexit registration sees the constructor's r0.
        let guard = install_singleton_mocks();
        unsafe {
            DISPLAY_CTOR_RESULT = internal(); // deliberately the wrong object
            assert_eq!(display_get(1), secondary(), "the reloaded literal wins");

            let head = shutdown_chain_head().read();
            assert!(!head.is_null(), "registered with cxa_atexit");
            assert_eq!((*head).arg as *mut Display, internal(), "the ctor's return");
            assert_eq!((*head).handler as usize, display_destructor as usize);
            assert_eq!((*head).key, DSO_HANDLE, "__dso_handle @ 0x089ca09c");
        }
        restore_singleton_mocks(guard);
    }

    #[test]
    fn the_registration_is_real_and_the_chain_runs_the_noop_destructor() {
        let guard = install_singleton_mocks();
        unsafe {
            display_get(0);
            (*internal()).display_id = 0x3c;
            lib_shutdown_chain(0);
            assert!(shutdown_chain_head().read().is_null(), "the node ran and was freed");
            assert_eq!((*internal()).display_id, 0x3c, "the no-op destructor touched nothing");
        }
        restore_singleton_mocks(guard);
    }

    #[test]
    fn the_default_stub_zeroes_exactly_the_objects_extent() {
        let guard = install_singleton_mocks();
        unsafe {
            DISPLAY_HOOKS = DEFAULT_DISPLAY_HOOKS;
            assert_eq!(display_get(1), secondary());
            let bytes = secondary().cast::<u8>();
            assert!((0..DISPLAY_OBJECT_SIZE).all(|offset| bytes.add(offset).read() == 0));
        }
        restore_singleton_mocks(guard);
    }

    #[test]
    fn the_object_extent_and_pool_words_are_the_binary_verified_ones() {
        // ctor's last store `strb r5, [r4, #0xa5]`, and the two static
        // objects 0x08a1b6cc - 0x08a1b624 = 0xa8 apart.
        assert_eq!(DISPLAY_OBJECT_SIZE, 0xa8);
        assert_eq!(DSO_HANDLE, 0x089ca09c);
        assert_eq!(INTERNAL_DISPLAY_ID, 0);
        assert_eq!(SECONDARY_DISPLAY_ID, 1);
    }

    #[test]
    fn set_clear_color_arms_the_pending_byte_and_stores_the_color() {
        let mut d = display(0, core::ptr::null_mut());
        unsafe {
            // Every immediate any of the 28 call sites passes.
            for color in [0u32, 0x00ff_ffff, 0x00ff_0000, 0xffff_ffff] {
                d.clear_pending = 0;
                d.clear_color = 0xdead_beef;
                display_set_clear_color(&mut d, color);
                assert_eq!(d.clear_pending, 1, "the pending byte is armed for {color:#x}");
                assert_eq!(d.clear_color, color, "the color word is stored verbatim");
                assert_eq!(d.per_layer_bytes, [0; 6], "the per-layer bytes are untouched");
                assert_eq!(d.reserved_24, [0; 4], "the neighbouring flags are untouched");
                assert_eq!(d.reserved_1f, 0, "the pad byte is untouched");
            }
        }
    }

    #[test]
    fn set_clear_color_rearms_over_an_already_pending_clear() {
        let mut d = display(0, core::ptr::null_mut());
        unsafe {
            display_set_clear_color(&mut d, 0x00ff_ffff);
            display_set_clear_color(&mut d, 0);
            assert_eq!(d.clear_pending, 1, "the pending byte stays armed");
            assert_eq!(d.clear_color, 0, "the last color wins");
        }
    }
}
