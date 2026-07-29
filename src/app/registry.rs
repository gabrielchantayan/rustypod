//! The global **class registry** — retailOS's `class id -> singleton
//! instance` map — and the accessor family that reads and writes it.
//!
//! ## What the registry is
//!
//! One statically-allocated C++ associative container lives at
//! 0x08a79ca4 (constructed by `FUN_0810e64c`, run from the static-init
//! chain @ 0x082afb6c). Every framework class that has exactly one live
//! instance registers that instance into it from its own constructor:
//!
//! ```text
//! ...                                   ; build the object
//! ldr r1, =CLASS_ID                     ; the class's numeric id
//! mov r0, this
//! bl  0x081d23f8                        ; registry_register(this, id)
//! bl  0x0820b230                        ; the class-name factory
//! add r1, pc, #N                        ; "TCDemoMode"
//! blx [[factory]]                       ; factory->slot0(name, ctor, dtor)
//! ```
//!
//! 45 constructors do exactly this. The ids are 0x80-aligned 16-bit
//! numbers; the ones whose constructor also hands its class name to the
//! factory in the same basic block pin the id space down:
//!
//! ```text
//! 0x4180  TCNotesDispatcher   (ctor @ 0x0828bf6c, registers @ 0x0828c05c)
//! 0x5680  TCSportTimer        (registers @ 0x0815e978)
//! 0x5800  TRadioCntlr         (registers @ 0x0828e8d4)
//! 0x7600  TSearchCntlr        (registers @ 0x08103d2c)
//! 0x8080  TCDemoMode          (ctor @ 0x081889c0, registers @ 0x08188a28)
//! ```
//!
//! The same number is *also* the runtime type id: the framework's
//! `cast_to_class` implementations are of the textbook form
//! `return (id == MY_ID || id == BASE_ID) ? this : 0`, e.g.
//! `FUN_08275bcc` = `cmp r1,#0x5d00; cmpne r1,#1; movne r0,#0; bx lr`
//! (id 1 is the root class). So a class id names both the registry key
//! and the type, which is why every per-class accessor looks the id up
//! and then casts the result to the *same* id:
//!
//! ```text
//! void *TFoo_instance(void) {                 ; e.g. FUN_081883fc
//!     return object_cast_to_class(registry_lookup_by_id(ID), ID);
//! }
//! ```
//!
//! Thirteen of those accessors exist (all tail-branching into
//! [`object_cast_to_class`]); this module ports the three hottest.
//! `app/context.rs`'s `context_target_id` feeds the same lookup: its
//! 127 distinct callers resolve the pending target id through here.
//!
//! ## Ported here
//!
//! | address | name | size | sites |
//! |---|---|---|---|
//! | 0x0810e40c | [`registry_find`] | 84 | 3 `bl` |
//! | 0x0810e460 | [`registry_assign_at`] | 76 | 1 `bl` |
//! | 0x0810e4ac | [`registry_insert`] | 28 | 8 `bl` + 2 `b` |
//! | 0x0810e4c8 | [`registry_lookup`] | 40 | 15 `bl` + 1 `b` |
//! | 0x0810e4f0 | [`registry_assign`] | 60 | 2 `bl` + 1 `b` |
//! | 0x08134ff8 | [`observable_set_notify_enabled`] | 64 | 5 `bl` + 1 `b` |
//! | 0x08135038 | [`observable_set_changed`] | 8 | 1 `bl` |
//! | 0x081d2184 | [`registry_lookup_by_id`] | 36 | 60 `bl` + 2 `b` |
//! | 0x081d23f8 | [`registry_register`] | 16 | 45 `bl` |
//! | 0x08275b9c | [`object_cast_to_class`] | 20 | 414 `bl` + 17 `b` |
//! | 0x081883fc | [`demo_mode_instance`] | 28 | 328 `bl` |
//! | 0x08172124 | [`instance_of_class_6000`] | 24 | 72 `bl` |
//! | 0x08100b74 | [`instance_of_class_6600`] | 24 | 36 `bl` |
//!
//! All call-site counts are binary-scanned over osos.dec (every `bl`/`b`
//! whose computed target is the function), not read off osos.asm — the
//! scouting notes for 0x081883fc (312), 0x081d2184 (61+1),
//! 0x08172124 (63) and 0x08100b74 (38) are all slightly off.
//!
//! ## The container's virtual interface
//!
//! Everything the accessors do is dispatched through the registry
//! object's own vtable, so the container implementation itself stays
//! unported:
//!
//! ```text
//! vtable +0x1c  insert(this, const RegistryEntry *entry)
//! vtable +0x24  assign_at(this, index, const RegistryEntry *entry)
//! vtable +0x3c  entry_at(this, index, RegistryEntry *out) -> out
//! vtable +0x4c  index_of(this, const u32 *key) -> index, -1 if absent
//! vtable +0x64  notify_deferred(this)   \ the change-notification pair
//! vtable +0x68  notify_changed(this)    / (roles inferred, see below)
//! ```
//!
//! The entry is the container's `value_type`, a `(key, value)` pair —
//! `FUN_0810e4ac` builds one on the stack with `stm sp, {r1, r2}` and
//! `FUN_0810e4c8` reads the value back out of `[sp, #4]`.
//!
//! The registry is also an *observable*: it carries a "changed" byte at
//! +0x20 and a "notifications enabled" byte at +0x21, and
//! [`registry_assign`] brackets its write with them —
//! disable, write, mark changed, re-enable — so exactly one
//! notification fires per assignment. The +0x64 / +0x68 slot *names* are
//! inferred from that idiom (the +0x64 result short-circuits +0x68); the
//! slot offsets are exact.
//!
//! ## Deviations
//!
//! - The registry object lives in the crate static [`CLASS_REGISTRY`]
//!   instead of at 0x08a79ca4 (the `block_mgr.rs` / `context.rs`
//!   precedent: 0x08a79ca4 is past the end of the decrypted image, pure
//!   runtime RAM). It defaults to an all-zero object — exactly the
//!   pre-init state.
//! - **Not hook-ready.** Its constructor `FUN_0810e64c` is unported, so
//!   the static's vtable pointer is NULL and [`registry_lookup_by_id`]
//!   would fault on the first dispatch, precisely as the original would
//!   before static init. The original has no NULL-vtable guard and
//!   neither does this port; adding one would be a behavior change, not
//!   a fix. Host tests install a vtable first.
//! - Struct fields are typed members, never literal byte offsets, so the
//!   32-bit target layout is exact while a 64-bit host keeps every field
//!   disjoint (the `block_region.rs` word-index rule).
//! - `FUN_0810e4c8` / `FUN_0810e4f0` leave their stack entry
//!   uninitialized and only read it back on a hit; this port zeroes it,
//!   which is unobservable (nothing reads it on a miss) and keeps the
//!   host build free of `MaybeUninit` reads.

/// One entry of the registry: the class id and the instance registered
/// under it. This is the container's `value_type` — 8 bytes on the
/// 32-bit target, built on the stack by `FUN_0810e4ac`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RegistryEntry {
    /// +0x00: the class id (the map key).
    pub class_id: u32,
    /// +0x04: the registered instance (the map value).
    pub instance: *mut u8,
}

// Target-exact layout; on a 64-bit host the fields merely stay disjoint.
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x04] = [0; core::mem::offset_of!(RegistryEntry, instance)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x08] = [0; core::mem::size_of::<RegistryEntry>()];

/// An empty entry — what this port seeds the stack slots with (see the
/// module header's last deviation).
const EMPTY_ENTRY: RegistryEntry =
    RegistryEntry { class_id: 0, instance: core::ptr::null_mut() };

/// The registry container's vtable, modeled down to the six slots this
/// module dispatches. The filler arrays reproduce the original byte
/// offsets on the 32-bit target and keep the named slots disjoint on a
/// 64-bit host.
#[repr(C)]
pub struct RegistryVtable {
    /// Slots +0x00..+0x18: not dispatched here.
    pub unresolved_00: [usize; 7],
    /// +0x1c: `insert(this, entry)`.
    pub insert: unsafe extern "C" fn(this: *mut Registry, entry: *const RegistryEntry) -> usize,
    /// Slot +0x20: not dispatched here.
    pub unresolved_20: usize,
    /// +0x24: `assign_at(this, index, entry)` — overwrite the value of
    /// an existing entry.
    pub assign_at:
        unsafe extern "C" fn(this: *mut Registry, index: i32, entry: *const RegistryEntry) -> usize,
    /// Slots +0x28..+0x38: not dispatched here.
    pub unresolved_28: [usize; 5],
    /// +0x3c: `entry_at(this, index, out)` — copy entry `index` into
    /// `out` and return it.
    pub entry_at: unsafe extern "C" fn(
        this: *mut Registry,
        index: i32,
        out: *mut RegistryEntry,
    ) -> *mut RegistryEntry,
    /// Slots +0x40..+0x48: not dispatched here.
    pub unresolved_40: [usize; 3],
    /// +0x4c: `index_of(this, &key)` — the entry index, or -1.
    pub index_of: unsafe extern "C" fn(this: *mut Registry, key: *const u32) -> i32,
    /// Slots +0x50..+0x60: not dispatched here.
    pub unresolved_50: [usize; 5],
    /// +0x64: consulted when notifications are re-enabled; a nonzero
    /// result suppresses the +0x68 call (role inferred — see the module
    /// header).
    pub notify_deferred: unsafe extern "C" fn(this: *mut Registry) -> *mut u8,
    /// +0x68: the change notification itself (role inferred).
    pub notify_changed: unsafe extern "C" fn(this: *mut Registry) -> *mut u8,
}

/// The registry object's own layout, down to the observable state the
/// notification helpers touch. Everything between the vtable pointer
/// and +0x20 belongs to the unported container implementation.
#[repr(C)]
pub struct Registry {
    /// +0x00: the vtable.
    pub vtable: *const RegistryVtable,
    /// +0x04..+0x1c: the container's own state.
    pub container: [usize; 7],
    /// +0x20: raised by [`observable_set_changed`].
    pub changed: u8,
    /// +0x21: written by [`observable_set_notify_enabled`].
    pub notify_enabled: u8,
    /// +0x22..+0x23: never touched.
    pub reserved: [u8; 2],
    /// +0x24: the observer installed by `FUN_08135040`.
    pub observer: *mut u8,
}

// Target-exact layout (the observable fields are what the port reads).
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x20] = [0; core::mem::offset_of!(Registry, changed)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x21] = [0; core::mem::offset_of!(Registry, notify_enabled)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x24] = [0; core::mem::offset_of!(Registry, observer)];

/// The global class registry (original: the object @ 0x08a79ca4 — see
/// the module-header deviation). All-zero until its constructor
/// `FUN_0810e64c` runs.
pub static mut CLASS_REGISTRY: Registry = Registry {
    vtable: core::ptr::null(),
    container: [0; 7],
    changed: 0,
    notify_enabled: 0,
    reserved: [0; 2],
    observer: core::ptr::null_mut(),
};

/// Reads an object's vtable pointer. The original re-loads `[this]`
/// before every dispatch rather than caching it, so a callee that
/// swaps the vtable is honored; volatile keeps that re-read.
#[inline(always)]
unsafe fn vtable(this: *mut Registry) -> *const RegistryVtable {
    core::ptr::read_volatile(core::ptr::addr_of!((*this).vtable))
}

/// registry_find — original: `FUN_0810e40c` @ 0x0810e40c (84 bytes;
/// 3 `bl` call sites).
///
/// Looks `class_id` up and, on a hit, copies the whole entry into
/// `out`. Returns the entry index, or -1 when the id is not registered.
///
/// The key is passed to `index_of` by pointer to a *stack copy*, so a
/// container that rewrites it through that pointer cannot disturb the
/// caller's value. Reproduced.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn registry_find(
    registry: *mut Registry,
    class_id: u32,
    out: *mut RegistryEntry,
) -> i32 {
    let key = class_id;
    let index = ((*vtable(registry)).index_of)(registry, core::ptr::addr_of!(key));
    if index != -1 {
        ((*vtable(registry)).entry_at)(registry, index, out);
    }
    index
}

/// registry_lookup — original: `FUN_0810e4c8` @ 0x0810e4c8 (40 bytes;
/// 15 `bl` + 1 tail `b` call sites).
///
/// Writes the instance registered under `class_id` to `*out` and
/// returns 1; on a miss leaves `*out` alone and returns 0.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn registry_lookup(
    registry: *mut Registry,
    class_id: u32,
    out: *mut *mut u8,
) -> u32 {
    let mut entry = EMPTY_ENTRY;
    let found = registry_find(registry, class_id, &mut entry) != -1;
    if found {
        out.write(entry.instance);
    }
    found as u32
}

/// registry_insert — original: `FUN_0810e4ac` @ 0x0810e4ac (28 bytes;
/// 8 `bl` + 2 tail `b` call sites).
///
/// Builds the `(class_id, instance)` entry on the stack and hands it to
/// the container's `insert` slot, forwarding whatever that returns.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn registry_insert(
    registry: *mut Registry,
    class_id: u32,
    instance: *mut u8,
) -> usize {
    let entry = RegistryEntry { class_id, instance };
    ((*vtable(registry)).insert)(registry, &entry)
}

/// registry_assign — original: `FUN_0810e4f0` @ 0x0810e4f0 (60 bytes;
/// 2 `bl` + 1 tail `b` call sites).
///
/// Replaces the instance already registered under `class_id`. Returns 1
/// when the id was present (and the value replaced), 0 when it was not
/// — unlike [`registry_insert`], this never adds an entry.
///
/// The entry handed to [`registry_assign_at`] is the one
/// [`registry_find`] just read back, with only its value word
/// overwritten, so the container sees the *existing* key alongside the
/// new value. Reproduced (the original's `str r4, [sp, #4]` over the
/// pair it just filled).
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn registry_assign(
    registry: *mut Registry,
    class_id: u32,
    instance: *mut u8,
) -> u32 {
    let mut entry = EMPTY_ENTRY;
    let index = registry_find(registry, class_id, &mut entry);
    if index == -1 {
        return 0;
    }
    entry.instance = instance;
    registry_assign_at(registry, index, &entry);
    1
}

/// registry_assign_at — original: `FUN_0810e460` @ 0x0810e460
/// (76 bytes; 1 `bl` call site).
///
/// Writes one entry by index with the change notification batched:
/// notifications off, `assign_at`, mark changed, notifications back on
/// — so the write emits exactly one notification, at the end. Returns
/// what the final [`observable_set_notify_enabled`] returns (the
/// original tail-branches into it).
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn registry_assign_at(
    registry: *mut Registry,
    index: i32,
    entry: *const RegistryEntry,
) -> *mut u8 {
    observable_set_notify_enabled(registry, 0);
    ((*vtable(registry)).assign_at)(registry, index, entry);
    observable_set_changed(registry, 1);
    observable_set_notify_enabled(registry, 1)
}

/// observable_set_notify_enabled — original: `FUN_08134ff8` @
/// 0x08134ff8 (64 bytes; 5 `bl` + 1 tail `b` call sites).
///
/// Stores the low byte of `enabled` into the object's +0x21 flag.
/// Disabling stops there and returns the object; enabling asks the
/// +0x64 slot first and, only when that answers NULL, tail-calls the
/// +0x68 notification.
///
/// Faithful detail: the flag store is a *byte* store while the branch
/// tests the full word, so `enabled = 0x100` writes 0 and still takes
/// the notify path. Reproduced.
///
/// This is a base-class method on device — the registry is only one of
/// the observables that use it — but the layout it touches (+0x21 and
/// vtable +0x64/+0x68) is the base layout, which is what [`Registry`]
/// models.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn observable_set_notify_enabled(
    observable: *mut Registry,
    enabled: u32,
) -> *mut u8 {
    core::ptr::write_volatile(core::ptr::addr_of_mut!((*observable).notify_enabled), enabled as u8);
    if enabled == 0 {
        return observable as *mut u8;
    }
    let deferred = ((*vtable(observable)).notify_deferred)(observable);
    if !deferred.is_null() {
        return deferred;
    }
    ((*vtable(observable)).notify_changed)(observable)
}

/// observable_set_changed — original: `FUN_08135038` @ 0x08135038
/// (8 bytes; 1 `bl` call site).
///
/// `strb r1, [r0, #0x20]; bx lr` — raises (or clears) the object's
/// "changed" byte.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn observable_set_changed(observable: *mut Registry, changed: u32) {
    core::ptr::write_volatile(core::ptr::addr_of_mut!((*observable).changed), changed as u8);
}

/// registry_lookup_by_id — original: `FUN_081d2184` @ 0x081d2184
/// (36 bytes; 60 `bl` + 2 tail `b` call sites, 54 distinct callers).
///
/// The instance registered in the global registry under `class_id`, or
/// NULL when nothing is. This is the resolver `app/context.rs` names
/// for the pending target id.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn registry_lookup_by_id(class_id: u32) -> *mut u8 {
    let mut instance: *mut u8 = core::ptr::null_mut();
    registry_lookup(core::ptr::addr_of_mut!(CLASS_REGISTRY), class_id, &mut instance);
    instance
}

/// registry_register — original: `FUN_081d23f8` @ 0x081d23f8
/// (16 bytes; 45 `bl` call sites).
///
/// `registry_insert(&CLASS_REGISTRY, class_id, instance)` — the tail
/// call 45 framework constructors make to publish themselves.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn registry_register(instance: *mut u8, class_id: u32) -> usize {
    registry_insert(core::ptr::addr_of_mut!(CLASS_REGISTRY), class_id, instance)
}

/// A framework object's vtable, modeled down to the one slot
/// [`object_cast_to_class`] dispatches (+0x14).
#[repr(C)]
pub struct FrameworkObjectVtable {
    /// Slots +0x00..+0x10: not dispatched here.
    pub unresolved_00: [usize; 5],
    /// +0x14: `cast_to_class(this, class_id)` — `this` when the object
    /// is a `class_id` (or derives from it), NULL otherwise.
    pub cast_to_class:
        unsafe extern "C" fn(this: *mut FrameworkObject, class_id: u32) -> *mut u8,
}

/// Any framework object, modeled down to its vtable pointer.
#[repr(C)]
pub struct FrameworkObject {
    /// +0x00: the object's vtable.
    pub vtable: *const FrameworkObjectVtable,
}

/// object_cast_to_class — original: `FUN_08275b9c` @ 0x08275b9c
/// (20 bytes; **414 `bl` + 17 tail `b` call sites**, binary-scanned).
///
/// ```text
/// cmp r0, #0 ; ldrne r2, [r0] ; ldrne r2, [r2, #20] ; bxne r2 ; bx lr
/// ```
///
/// The framework's NULL-tolerant checked downcast: dispatches vtable
/// slot 5 (+0x14) with the wanted class id, and short-circuits a NULL
/// object to NULL (the `bx lr` leaves r0 = 0, the value that failed the
/// `cmp`).
///
/// Slot 5 is the `cast_to_class` operator. The evidence: the second
/// argument at the 414 `bl` sites is a 0x80-aligned constant from the
/// same numeric space as the registry class ids (0x6800 at 126 of them,
/// then 0x1700, 0x1180, 0x1100, 0x2b00, 0x6380, ...); the 13 per-class
/// accessors that tail-branch here pass the *same* id they just looked
/// up in the registry; and the two functions sitting immediately before
/// it in the image, `FUN_08275b90` (`cmp r1,#1; movne r0,#0; bx lr`)
/// and `FUN_08275bcc` (`cmp r1,#0x5d00; cmpne r1,#1; movne r0,#0;
/// bx lr`), are textbook `castTo` bodies for a class and the root class
/// id 1.
///
/// The dispatch goes through the object's own vtable pointer, not a
/// crate-level hook table, so subclass (and test) vtables work.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn object_cast_to_class(
    object: *mut FrameworkObject,
    class_id: u32,
) -> *mut u8 {
    if object.is_null() {
        return core::ptr::null_mut();
    }
    let vtable = core::ptr::read_volatile(core::ptr::addr_of!((*object).vtable));
    ((*vtable).cast_to_class)(object, class_id)
}

/// The body every per-class instance accessor shares: resolve the id
/// through the registry, then check the result really is that class.
#[inline(always)]
unsafe fn instance_of_class(class_id: u32) -> *mut u8 {
    let instance = registry_lookup_by_id(class_id) as *mut FrameworkObject;
    object_cast_to_class(instance, class_id)
}

/// The class id of `TCDemoMode` (the literal @ 0x08188b00).
pub const CLASS_ID_DEMO_MODE: u32 = 0x8080;

/// demo_mode_instance — original: `FUN_081883fc` @ 0x081883fc
/// (28 bytes; **328 `bl` call sites**, binary-scanned — the busiest
/// function in 0x08100000..0x081fffff).
///
/// The registered `TCDemoMode` singleton, or NULL when it has not been
/// constructed yet.
///
/// The class name comes from its constructor @ 0x081889c0: that
/// function registers its `this` under id 0x8080 and, in the same basic
/// block, hands the literal `"TCDemoMode"` to the class-name factory
/// singleton @ 0x0820b230 — the same `register-then-name` pairing that
/// identifies `TCNotesDispatcher` (0x4180), `TCSportTimer` (0x5680),
/// `TRadioCntlr` (0x5800) and `TSearchCntlr` (0x7600). Caveat: the
/// vtable pointer that constructor installs (0x08989718) lands inside
/// the C++ mangled-name blob in the decrypted image rather than in the
/// vtable region above 0x0898a000, so that one page of the image does
/// not match what the device runs; the identification rests on the code,
/// not on that pointer.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn demo_mode_instance() -> *mut u8 {
    instance_of_class(CLASS_ID_DEMO_MODE)
}

/// instance_of_class_6000 — original: `FUN_08172124` @ 0x08172124
/// (24 bytes; 72 `bl` call sites).
///
/// Same accessor for class id 0x6000. The class's own constructor
/// registers it @ 0x08173774 but never names it to the factory, so the
/// class is **not identified** — the id is the only handle the firmware
/// gives it, and inventing a name would be worse than none.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn instance_of_class_6000() -> *mut u8 {
    instance_of_class(0x6000)
}

/// instance_of_class_6600 — original: `FUN_08100b74` @ 0x08100b74
/// (24 bytes; 36 `bl` call sites).
///
/// Same accessor for class id 0x6600; registered @ 0x08101aa4 and, like
/// 0x6000, **not identified**.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn instance_of_class_6600() -> *mut u8 {
    instance_of_class(0x6600)
}

/// The class id of `TPhotosSettingsSlideshowPlaylistCntlr` (recovered
/// from the literal its constructor hands to the class-name factory @
/// 0x0820b230 next to its `bl 0x081d23f8`).
pub const CLASS_ID_PHOTOS_SLIDESHOW_PLAYLIST_CNTLR: u32 = 0x8300;

/// instance_of_class_8300 — original: `FUN_08103584` @ 0x08103584
/// (24 bytes; 6 `bl` call sites).
///
/// Same accessor for class id 0x8300, `TPhotosSettingsSlideshowPlaylistCntlr`:
/// `object_cast_to_class(registry_lookup_by_id(0x8300), 0x8300)` — resolve
/// the registered singleton through the global class registry, then let the
/// object's own vtable confirm it really is that class (NULL when either
/// step fails).
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn instance_of_class_8300() -> *mut u8 {
    instance_of_class(CLASS_ID_PHOTOS_SLIDESHOW_PLAYLIST_CNTLR)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::ptr;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes every test that touches the global registry.
    static REGISTRY_LOCK: Mutex<()> = Mutex::new(());

    // ---- a tiny array-backed container standing in for the C++ map ----

    /// Entries the mock container holds.
    static mut ENTRIES: Vec<RegistryEntry> = Vec::new();

    /// Ordered trace of the mock's virtual calls.
    static mut TRACE: Vec<&'static str> = Vec::new();

    /// What [`mock_notify_deferred`] hands back.
    static mut DEFERRED: *mut u8 = ptr::null_mut();

    fn entries() -> &'static mut Vec<RegistryEntry> {
        unsafe { &mut *ptr::addr_of_mut!(ENTRIES) }
    }

    fn trace() -> &'static mut Vec<&'static str> {
        unsafe { &mut *ptr::addr_of_mut!(TRACE) }
    }

    unsafe extern "C" fn mock_index_of(_this: *mut Registry, key: *const u32) -> i32 {
        trace().push("index_of");
        let key = key.read();
        entries().iter().position(|e| e.class_id == key).map_or(-1, |i| i as i32)
    }

    unsafe extern "C" fn mock_entry_at(
        _this: *mut Registry,
        index: i32,
        out: *mut RegistryEntry,
    ) -> *mut RegistryEntry {
        trace().push("entry_at");
        out.write(entries()[index as usize]);
        out
    }

    /// The sentinel `mock_insert` returns, so the forwarding of the
    /// container's result can be observed.
    const INSERT_MARKER: usize = 0xfeed_face;

    unsafe extern "C" fn mock_insert(_this: *mut Registry, entry: *const RegistryEntry) -> usize {
        trace().push("insert");
        entries().push(entry.read());
        INSERT_MARKER
    }

    unsafe extern "C" fn mock_assign_at(
        _this: *mut Registry,
        index: i32,
        entry: *const RegistryEntry,
    ) -> usize {
        trace().push("assign_at");
        entries()[index as usize] = entry.read();
        0
    }

    unsafe extern "C" fn mock_notify_deferred(_this: *mut Registry) -> *mut u8 {
        trace().push("notify_deferred");
        ptr::read_volatile(ptr::addr_of!(DEFERRED))
    }

    unsafe extern "C" fn mock_notify_changed(_this: *mut Registry) -> *mut u8 {
        trace().push("notify_changed");
        ptr::null_mut()
    }

    static MOCK_VTABLE: RegistryVtable = RegistryVtable {
        unresolved_00: [0; 7],
        insert: mock_insert,
        unresolved_20: 0,
        assign_at: mock_assign_at,
        unresolved_28: [0; 5],
        entry_at: mock_entry_at,
        unresolved_40: [0; 3],
        index_of: mock_index_of,
        unresolved_50: [0; 5],
        notify_deferred: mock_notify_deferred,
        notify_changed: mock_notify_changed,
    };

    /// Installs the mock container and clears every recorder.
    fn mock() -> MutexGuard<'static, ()> {
        let guard = REGISTRY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            entries().clear();
            trace().clear();
            DEFERRED = ptr::null_mut();
            CLASS_REGISTRY.vtable = &MOCK_VTABLE;
            CLASS_REGISTRY.changed = 0;
            CLASS_REGISTRY.notify_enabled = 0;
        }
        guard
    }

    /// Restores the pre-init state. Takes the guard by value so it
    /// cannot be re-locked while still held (the seek_core.rs rule).
    fn restore(guard: MutexGuard<'static, ()>) {
        unsafe {
            entries().clear();
            trace().clear();
            CLASS_REGISTRY.vtable = ptr::null();
            CLASS_REGISTRY.changed = 0;
            CLASS_REGISTRY.notify_enabled = 0;
        }
        drop(guard);
    }

    fn registry() -> *mut Registry {
        ptr::addr_of_mut!(CLASS_REGISTRY)
    }

    /// A distinct non-NULL instance pointer per id.
    fn instance(n: usize) -> *mut u8 {
        (0x1000 + n * 0x40) as *mut u8
    }

    // ---- the container accessors ----

    #[test]
    fn find_returns_the_index_and_fills_the_entry() {
        let guard = mock();
        unsafe {
            registry_insert(registry(), 0x8080, instance(1));
            registry_insert(registry(), 0x6000, instance(2));
            let mut entry = EMPTY_ENTRY;
            assert_eq!(registry_find(registry(), 0x6000, &mut entry), 1);
            assert_eq!(entry.class_id, 0x6000);
            assert_eq!(entry.instance, instance(2));
            assert_eq!(*trace(), std::vec!["insert", "insert", "index_of", "entry_at"]);
        }
        restore(guard);
    }

    #[test]
    fn a_miss_returns_minus_one_and_never_reads_an_entry() {
        let guard = mock();
        unsafe {
            registry_insert(registry(), 0x8080, instance(1));
            trace().clear();
            let mut entry = RegistryEntry { class_id: 0xdead, instance: instance(9) };
            assert_eq!(registry_find(registry(), 0x6600, &mut entry), -1);
            assert_eq!(entry.class_id, 0xdead, "the caller's entry is untouched");
            assert_eq!(*trace(), std::vec!["index_of"], "entry_at is not dispatched");
        }
        restore(guard);
    }

    #[test]
    fn lookup_reports_found_and_writes_only_on_a_hit() {
        let guard = mock();
        unsafe {
            registry_insert(registry(), 0x8080, instance(1));
            let mut out = instance(7);
            assert_eq!(registry_lookup(registry(), 0x8080, &mut out), 1);
            assert_eq!(out, instance(1));

            let mut untouched = instance(7);
            assert_eq!(registry_lookup(registry(), 0x1234, &mut untouched), 0);
            assert_eq!(untouched, instance(7), "a miss leaves the out slot alone");
        }
        restore(guard);
    }

    #[test]
    fn insert_forwards_the_containers_result() {
        let guard = mock();
        unsafe {
            assert_eq!(registry_insert(registry(), 0x8080, instance(1)), INSERT_MARKER);
            assert_eq!(entries().len(), 1);
            assert_eq!(entries()[0].class_id, 0x8080);
            assert_eq!(entries()[0].instance, instance(1));
        }
        restore(guard);
    }

    #[test]
    fn assign_replaces_an_existing_entry_and_keeps_its_key() {
        let guard = mock();
        unsafe {
            registry_insert(registry(), 0x8080, instance(1));
            trace().clear();
            assert_eq!(registry_assign(registry(), 0x8080, instance(5)), 1);
            assert_eq!(entries().len(), 1, "assign never adds");
            assert_eq!(entries()[0].class_id, 0x8080, "the existing key is preserved");
            assert_eq!(entries()[0].instance, instance(5));
        }
        restore(guard);
    }

    #[test]
    fn assign_to_an_absent_id_returns_zero_and_changes_nothing() {
        let guard = mock();
        unsafe {
            registry_insert(registry(), 0x8080, instance(1));
            trace().clear();
            assert_eq!(registry_assign(registry(), 0x6600, instance(5)), 0);
            assert_eq!(*trace(), std::vec!["index_of"]);
            assert_eq!(entries()[0].instance, instance(1));
        }
        restore(guard);
    }

    #[test]
    fn assign_brackets_the_write_with_one_notification() {
        let guard = mock();
        unsafe {
            registry_insert(registry(), 0x8080, instance(1));
            CLASS_REGISTRY.notify_enabled = 1;
            trace().clear();
            registry_assign(registry(), 0x8080, instance(5));
            assert_eq!(
                *trace(),
                std::vec![
                    "index_of",
                    "entry_at",
                    "assign_at",
                    "notify_deferred",
                    "notify_changed"
                ],
                "notifications are off across the write and fire once at the end"
            );
            assert_eq!(ptr::read_volatile(ptr::addr_of!(CLASS_REGISTRY.changed)), 1, "the changed byte is left raised");
            assert_eq!(ptr::read_volatile(ptr::addr_of!(CLASS_REGISTRY.notify_enabled)), 1);
        }
        restore(guard);
    }

    // ---- the observable pair ----

    #[test]
    fn disabling_notifications_returns_the_object_and_dispatches_nothing() {
        let guard = mock();
        unsafe {
            CLASS_REGISTRY.notify_enabled = 1;
            let result = observable_set_notify_enabled(registry(), 0);
            assert_eq!(result, registry() as *mut u8);
            assert_eq!(ptr::read_volatile(ptr::addr_of!(CLASS_REGISTRY.notify_enabled)), 0);
            assert!(trace().is_empty());
        }
        restore(guard);
    }

    #[test]
    fn a_nonnull_deferred_result_suppresses_the_notification() {
        let guard = mock();
        unsafe {
            DEFERRED = instance(3);
            assert_eq!(observable_set_notify_enabled(registry(), 1), instance(3));
            assert_eq!(*trace(), std::vec!["notify_deferred"], "notify_changed is skipped");
        }
        restore(guard);
    }

    #[test]
    fn the_enable_flag_is_stored_as_a_byte_but_tested_as_a_word() {
        let guard = mock();
        unsafe {
            // 0x100 has a zero low byte, so the flag lands 0 — yet the
            // word is nonzero, so the notify path still runs.
            assert!(observable_set_notify_enabled(registry(), 0x100).is_null());
            assert_eq!(ptr::read_volatile(ptr::addr_of!(CLASS_REGISTRY.notify_enabled)), 0, "only the low byte is stored");
            assert_eq!(*trace(), std::vec!["notify_deferred", "notify_changed"]);
        }
        restore(guard);
    }

    #[test]
    fn set_changed_writes_the_low_byte_of_its_argument() {
        let guard = mock();
        unsafe {
            observable_set_changed(registry(), 1);
            assert_eq!(ptr::read_volatile(ptr::addr_of!(CLASS_REGISTRY.changed)), 1);
            observable_set_changed(registry(), 0x1ff);
            assert_eq!(ptr::read_volatile(ptr::addr_of!(CLASS_REGISTRY.changed)), 0xff);
            observable_set_changed(registry(), 0x100);
            assert_eq!(ptr::read_volatile(ptr::addr_of!(CLASS_REGISTRY.changed)), 0);
        }
        restore(guard);
    }

    // ---- the global-registry wrappers ----

    #[test]
    fn register_then_lookup_round_trips_through_the_global_registry() {
        let guard = mock();
        unsafe {
            registry_register(instance(1), CLASS_ID_DEMO_MODE);
            assert_eq!(registry_lookup_by_id(CLASS_ID_DEMO_MODE), instance(1));
            assert!(registry_lookup_by_id(0x6000).is_null(), "an unregistered id is NULL");
        }
        restore(guard);
    }

    #[test]
    fn lookup_by_id_defaults_to_null_before_anything_registers() {
        let guard = mock();
        unsafe {
            assert!(registry_lookup_by_id(CLASS_ID_DEMO_MODE).is_null());
        }
        restore(guard);
    }

    // ---- the cast veneer and the per-class accessors ----

    /// A framework object whose cast accepts exactly one id.
    #[repr(C)]
    struct TestObject {
        vtable: *const FrameworkObjectVtable,
        accepts: u32,
    }

    unsafe extern "C" fn test_cast(this: *mut FrameworkObject, class_id: u32) -> *mut u8 {
        let object = this as *mut TestObject;
        if (*object).accepts == class_id {
            this as *mut u8
        } else {
            ptr::null_mut()
        }
    }

    static TEST_OBJECT_VTABLE: FrameworkObjectVtable =
        FrameworkObjectVtable { unresolved_00: [0; 5], cast_to_class: test_cast };

    fn object_accepting(id: u32) -> TestObject {
        TestObject { vtable: &TEST_OBJECT_VTABLE, accepts: id }
    }

    #[test]
    fn the_cast_veneer_short_circuits_a_null_object() {
        let guard = mock();
        unsafe {
            assert!(object_cast_to_class(ptr::null_mut(), 0x8080).is_null());
        }
        restore(guard);
    }

    #[test]
    fn the_cast_veneer_dispatches_the_objects_own_slot_five() {
        let guard = mock();
        unsafe {
            let mut object = object_accepting(0x8080);
            let this = ptr::addr_of_mut!(object) as *mut FrameworkObject;
            assert_eq!(object_cast_to_class(this, 0x8080), this as *mut u8);
            assert!(object_cast_to_class(this, 0x6000).is_null(), "a wrong id casts to NULL");
        }
        restore(guard);
    }

    #[test]
    fn the_demo_mode_accessor_looks_up_and_casts_the_same_id() {
        let guard = mock();
        unsafe {
            let mut object = object_accepting(CLASS_ID_DEMO_MODE);
            let this = ptr::addr_of_mut!(object) as *mut u8;
            registry_register(this, CLASS_ID_DEMO_MODE);
            assert_eq!(demo_mode_instance(), this);
        }
        restore(guard);
    }

    #[test]
    fn an_instance_of_the_wrong_class_reads_back_as_null() {
        let guard = mock();
        unsafe {
            // Registered under 0x8080 but refusing that id: the cast
            // filters it out, which is the whole point of the veneer.
            let mut object = object_accepting(0x1234);
            let this = ptr::addr_of_mut!(object) as *mut u8;
            registry_register(this, CLASS_ID_DEMO_MODE);
            assert_eq!(registry_lookup_by_id(CLASS_ID_DEMO_MODE), this);
            assert!(demo_mode_instance().is_null());
        }
        restore(guard);
    }

    #[test]
    fn each_accessor_resolves_only_its_own_class() {
        let guard = mock();
        unsafe {
            let mut demo = object_accepting(CLASS_ID_DEMO_MODE);
            let mut six_thousand = object_accepting(0x6000);
            let demo_ptr = ptr::addr_of_mut!(demo) as *mut u8;
            let six_ptr = ptr::addr_of_mut!(six_thousand) as *mut u8;
            registry_register(demo_ptr, CLASS_ID_DEMO_MODE);
            registry_register(six_ptr, 0x6000);
            assert_eq!(demo_mode_instance(), demo_ptr);
            assert_eq!(instance_of_class_6000(), six_ptr);
            assert!(instance_of_class_6600().is_null(), "0x6600 was never registered");
            assert!(
                instance_of_class_8300().is_null(),
                "0x8300 was never registered"
            );
        }
        restore(guard);
    }

    #[test]
    fn the_8300_accessor_looks_up_and_casts_its_own_id() {
        let guard = mock();
        unsafe {
            let mut object = object_accepting(CLASS_ID_PHOTOS_SLIDESHOW_PLAYLIST_CNTLR);
            let this = ptr::addr_of_mut!(object) as *mut u8;
            registry_register(this, CLASS_ID_PHOTOS_SLIDESHOW_PLAYLIST_CNTLR);
            assert_eq!(instance_of_class_8300(), this);
        }
        restore(guard);
    }

    #[test]
    fn the_pending_target_id_resolves_through_the_registry() {
        // The shape 127 distinct callers share: `id = context_target_id();
        // if (id) instance = registry_lookup_by_id(id);`. 0x7a88 is the
        // id the one writer @ 0x08202904 stores.
        let guard = mock();
        unsafe {
            registry_register(instance(1), 0x7a88);
            assert_eq!(registry_lookup_by_id(0x7a88), instance(1));
        }
        restore(guard);
    }
}
