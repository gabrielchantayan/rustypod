//! `class_6800_new` — original: `FUN_08177e84` @ 0x08177e84
//! (72 bytes of code + the 4-byte literal-pool word @ 0x08177ecc that
//! holds the vtable address, so 76 bytes of true extent; **128 `bl` and
//! 0 `b` call sites**, binary-scanned by decoding every B/BL word in
//! `work/firmware/osos.dec`).
//!
//! The constructor of the small framework object the **Silver** UI
//! framework hangs off a controller — the class whose runtime id is
//! **0x6800**.
//!
//! ```text
//! 08177e84  push {r4, lr}
//! 08177e88  mov  r2, #1
//! 08177e8c  mov  r1, #0
//! 08177e90  bl   0x081110d0        @ base_construct(storage, 0, 1)
//! 08177e94  ldr  r1, [pc, #48]     @ = 0x0898908c (pool word @ 0x08177ecc)
//! 08177e98  mov  r4, r0            @ this = the BASE CTOR'S RETURN
//! 08177e9c  str  r1, [r0]          @ this->vtable = 0x0898908c
//! 08177ea0  bl   0x081d2204        @ framework_root_instance()
//! 08177ea4  str  r0, [r4, #0x14]   @ this->default_target = it
//! 08177ea8  bl   0x081883fc        @ demo_mode_instance()   (ported)
//! 08177eac  str  r0, [r4, #0x18]   @ this->demo_mode = it
//! 08177eb0  ldr  r0, [r4]
//! 08177eb4  ldr  r1, [r4, #0x14]
//! 08177eb8  ldr  r2, [r0, #0x2c]
//! 08177ebc  mov  r0, r4
//! 08177ec0  blx  r2                @ this->vtable->set_target(this, default)
//! 08177ec4  mov  r0, r4
//! 08177ec8  pop  {r4, pc}
//! 08177ecc  .word 0x0898908c
//! ```
//!
//! # How the class was pinned down
//!
//! The class is **not named anywhere in the image**, so this module
//! calls it by its id, exactly as `app/registry.rs` does for
//! `instance_of_class_6000` / `_6600`. What *is* verified:
//!
//! - Its `cast_to_class` operator sits four functions earlier, at
//!   0x08177e08: `cmp r1, #0x6800 ; bne 0x08110640 ; bx lr` — the
//!   textbook body `return id == 0x6800 ? this : Base::castTo(id)`.
//!   The base it delegates to (0x08110640) answers ids 4, 3 and 1
//!   (1 is the root class id, per `app/registry.rs`).
//! - The immediate 0x6800 occurs at exactly **128 sites** in the whole
//!   image (scanned for the ARM data-processing encoding `#0x6800`,
//!   `...b1a`): the one `cmp` above, and 127 `mov r1, #0x6800` — one
//!   per `bl 0x08177e84`. Every call site is the same idiom:
//!
//!   ```text
//!   current = controller->vtable[0x1c](controller)      @ current addon
//!   if (current == NULL || object_cast_to_class(current, 0x6800) == NULL) {
//!       obj = class_6800_new(operator_new(28));         @ 0x082aadd4
//!       controller->vtable[0x2c](controller, obj);      @ install it
//!   }
//!   ```
//!
//!   i.e. "make sure this controller's addon is a 0x6800, and if it is
//!   not, build a fresh one". `app/registry.rs`'s note that 0x6800 is
//!   the dominant second argument at `object_cast_to_class`'s 414 call
//!   sites is the same population seen from the other end.
//! - 125 of the 128 callers live in 0x0839f6a0..0x083b43f4, the block of
//!   near-identical Silver controller bodies; the framework prefix is
//!   confirmed by the 159 distinct `TSilver*` mangled class names in the
//!   image (`TSilverCntlr`, `TSilverBridgeView`, 124
//!   `TSilverCntlrTransitionAddon<T>` instantiations, ...).
//! - The base constructor 0x081110d0 chains 0x08125234, plants its own
//!   vtable (0x08981958) and calls 0x081108b4, which allocates a 16-byte
//!   node and stores it at `this+0x0c` — the object's `base_link` word.
//!   The object is 28 bytes (`mov r0, #28` at every call site), so the
//!   base owns +0x04..+0x13 and this class owns +0x14 and +0x18.
//!
//! Four sibling methods of the same class surround the constructor and
//! corroborate the field meanings: 0x08177e14 re-dispatches slot +0x2c
//! with `this->default_target`; 0x08177e24 dispatches slot +0x2c with a
//! *live* object when one is available and `this->default_target`
//! otherwise; 0x08177e70 returns 0; 0x08177e78 tail-dispatches slot
//! +0x58. So slot +0x2c is the base's "adopt this target" operation and
//! +0x14 is the fallback it is seeded with.
//!
//! # Deviations
//!
//! - **The vtable literal 0x0898908c is not reproducible.** That address
//!   lands inside the C++ mangled-name blob in the decrypted image (the
//!   bytes there read `...ntlrTransitionAddonI16TPhotosMenuCntlrE`), not
//!   in the vtable region above 0x0898a000 — the same page mismatch
//!   `app/registry.rs` records for `TCDemoMode`'s 0x08989718. It is also
//!   the **only** reference to that word in the image, so nothing else
//!   pins it down. The port plants the modeled static
//!   [`CLASS_6800_VTABLE`] and keeps the original address in
//!   [`CLASS_6800_VTABLE_ADDRESS`]. The +0x2c dispatch still goes
//!   through `this->vtable`, so a test (or a later real vtable) is
//!   picked up without touching this function.
//! - `framework_base_construct` @ 0x081110d0 and
//!   `framework_root_instance` @ 0x081d2204 are ported directly. Its
//!   parent constructor @ 0x08125234 is likewise direct and chains the
//!   shared root constructor @ 0x08275bb8. The unported link/target
//!   initializer @ 0x081108b4 remains the sole [`CLASS_6800_OPS`]
//!   dispatch slot. The modeled [`FRAMEWORK_ROOT_HOLDER`] is the crate
//!   stand-in for the runtime global @ 0x089cc858 whose +4 slot the root
//!   getter returns, following `app/context.rs`'s modeled-global
//!   precedent. The wired child default preserves the modeled zero state
//!   but does not provide allocation or target-adoption behavior, so the
//!   complete construction chain is still not hook-ready.
//! - `demo_mode_instance` @ 0x081883fc **is** ported
//!   (`app/registry.rs`), so it is called directly rather than through a
//!   seam.
//! - `this` is taken from the base constructor's **return value**, not
//!   from the incoming storage (the original's `mov r4, r0` after the
//!   `bl`), so a base constructor that relocates its object is honoured.

use crate::app::registry::demo_mode_instance;

/// Runtime class id of the object built here. It is both the registry
/// key space value and the `cast_to_class` answer at 0x08177e08.
pub const CLASS_ID_6800: u32 = 0x6800;

/// Byte size every call site allocates before invoking the constructor
/// (`mov r0, #28` ahead of `bl 0x082aadd4`).
pub const CLASS_6800_SIZE: usize = 28;

/// The vtable address the original plants (literal-pool word @
/// 0x08177ecc). Unreadable in the decrypted image — see the module
/// deviations.
pub const CLASS_6800_VTABLE_ADDRESS: u32 = 0x0898_908c;

/// The vtable literal `FUN_081110d0` plants after its parent constructor
/// returns (pool word @ 0x08111104). The bytes at the target address are
/// runtime vtable data, so the port uses [`FRAMEWORK_BASE_VTABLE`] as its
/// dispatchable model.
pub const FRAMEWORK_BASE_VTABLE_ADDRESS: u32 = 0x0898_1958;

/// Address of the global whose +4 slot 0x081d2204 returns (pool word @
/// 0x081d2210). Modeled by [`FRAMEWORK_ROOT_HOLDER`].
pub const FRAMEWORK_ROOT_HOLDER_ADDRESS: u32 = 0x089c_c858;

/// The object's vtable, modeled down to the one slot the constructor
/// dispatches. The filler reproduces the original byte offsets on the
/// 32-bit target and keeps the named slot disjoint on a 64-bit host.
#[repr(C)]
pub struct Class6800Vtable {
    /// Slots +0x00..+0x28: not dispatched here.
    pub unresolved_00: [usize; 11],
    /// +0x2c: `set_target(this, target)` — the base operation the
    /// constructor seeds with `this->default_target`, and the same slot
    /// the sibling methods @ 0x08177e14 / 0x08177e24 re-dispatch. Its
    /// result is discarded.
    pub set_target:
        unsafe extern "C" fn(this: *mut Class6800, target: *mut u8) -> *mut u8,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x2c] = [0; core::mem::offset_of!(Class6800Vtable, set_target)];

/// The 28-byte class-0x6800 object.
///
/// +0x04..+0x13 belong to the base classes; only `base_link` among them
/// has a verified meaning (the 16-byte node `FUN_081108b4` allocates and
/// stores there). This constructor writes `vtable`, `default_target`
/// and `demo_mode` and nothing else.
#[repr(C)]
pub struct Class6800 {
    /// +0x00: the object's vtable.
    pub vtable: *const Class6800Vtable,
    /// +0x04: base-class word.
    pub base_04: u32,
    /// +0x08: base-class word.
    pub base_08: u32,
    /// +0x0c: the 16-byte node `FUN_081108b4` allocates for the base.
    pub base_link: *mut u8,
    /// +0x10: base-class word.
    pub base_10: u32,
    /// +0x14: the fallback target this object adopts on construction and
    /// falls back to in its sibling methods.
    pub default_target: *mut u8,
    /// +0x18: the registered `TCDemoMode` singleton (`0x081883fc`).
    pub demo_mode: *mut u8,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x0c] = [0; core::mem::offset_of!(Class6800, base_link)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x14] = [0; core::mem::offset_of!(Class6800, default_target)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x18] = [0; core::mem::offset_of!(Class6800, demo_mode)];
#[cfg(target_pointer_width = "32")]
const _: [u8; CLASS_6800_SIZE] = [0; core::mem::size_of::<Class6800>()];

/// The global @ 0x089cc858 that 0x081d2204 reads, modeled down to the
/// one slot it loads. That RW page is runtime-initialized, so the image
/// holds nothing usable there; zeroed = the pre-init state.
#[repr(C)]
pub struct FrameworkRootHolder {
    /// +0x00: not read by 0x081d2204.
    pub reserved_00: u32,
    /// +0x04: the instance the getter returns.
    pub instance: *mut u8,
}

/// Crate stand-in for the global @ [`FRAMEWORK_ROOT_HOLDER_ADDRESS`].
pub static mut FRAMEWORK_ROOT_HOLDER: FrameworkRootHolder = FrameworkRootHolder {
    reserved_00: 0,
    instance: core::ptr::null_mut(),
};

/// Injection point for the parent constructor @ 0x08125234. Host tests
/// may replace it to prove the outer constructor honours a relocated
/// return; the wired default is [`framework_linkage_parent_construct`].
pub type FrameworkBaseParentConstruct =
    unsafe extern "C" fn(storage: *mut Class6800) -> *mut Class6800;

/// Injection point for the link/target initializer @ 0x081108b4. Its
/// fourth argument is the literal zero `r3` that `FUN_081110d0` supplies.
pub type FrameworkBaseInitialize = unsafe extern "C" fn(
    this: *mut Class6800,
    initial_target: u32,
    create_link: u32,
    owner: u32,
);

/// The remaining unported retailOS dependency reached while constructing
/// this class family. [`framework_linkage_parent_construct`],
/// [`framework_base_construct`], and [`framework_root_instance`] are
/// direct code, not dispatch seams.
#[derive(Clone, Copy)]
pub struct Class6800Ops {
    /// `FUN_08125234` parent-constructor test seam. The wired default is
    /// [`framework_linkage_parent_construct`].
    pub parent_construct: FrameworkBaseParentConstruct,
    /// `FUN_081108b4` — allocates/initializes the base link and adopts
    /// the initial target.
    pub base_initialize: FrameworkBaseInitialize,
}

/// The vtable literal `FUN_08125234` plants after it chains the shared
/// framework root constructor (pool word @ 0x08125254). The outer
/// `framework_base_construct` overwrites this immediately, so only
/// pointer identity is modeled.
pub const FRAMEWORK_LINKAGE_PARENT_VTABLE_ADDRESS: u32 = 0x0898_30b8;

/// Crate stand-in for [`FRAMEWORK_LINKAGE_PARENT_VTABLE_ADDRESS`]. No
/// behavior is dispatched through this vtable before the direct child
/// constructor replaces it with [`FRAMEWORK_BASE_VTABLE`].
pub static FRAMEWORK_LINKAGE_PARENT_VTABLE: Class6800Vtable = Class6800Vtable {
    unresolved_00: [0; 11],
    set_target: unported_set_target,
};

/// framework_linkage_parent_construct — original: `FUN_08125234` @
/// 0x08125234 (32 bytes of code; literal-pool word at 0x08125254).
///
/// Constructs the unnamed parent of the class-0x6800 linkage base. It
/// first calls the shared root `framework_object_construct` @ 0x08275bb8,
/// replaces that root vtable with 0x089830b8, then clears its two words at
/// +0x04 and +0x08. It returns the root constructor's result in `r0`.
/// There is no NULL check: either the child or the first store faults for
/// NULL exactly as the ARM code does.
///
/// The physical vtable is runtime data; its modeled pointer is immediately
/// superseded by `framework_base_construct`, matching the only observed
/// behavior before any virtual dispatch.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn framework_linkage_parent_construct(
    storage: *mut Class6800,
) -> *mut Class6800 {
    let this = crate::cxx::observable_array::framework_object_construct(storage.cast())
        .cast::<Class6800>();
    core::ptr::addr_of_mut!((*this).vtable)
        .write_volatile(core::ptr::addr_of!(FRAMEWORK_LINKAGE_PARENT_VTABLE));
    core::ptr::addr_of_mut!((*this).base_04).write_volatile(0);
    core::ptr::addr_of_mut!((*this).base_08).write_volatile(0);
    this
}

/// Wired default for [`Class6800Ops::base_initialize`]. The real child
/// allocates a 16-byte node when `create_link != 0`, invokes vtable slot
/// +0x2c, and writes +0x10. Those effects remain intentionally unported;
/// the default only retains the old inert zero state.
unsafe extern "C" fn unported_base_initialize(
    this: *mut Class6800,
    _initial_target: u32,
    _create_link: u32,
    _owner: u32,
) {
    core::ptr::addr_of_mut!((*this).base_link).write_volatile(core::ptr::null_mut());
    core::ptr::addr_of_mut!((*this).base_10).write_volatile(0);
}

/// framework_root_instance — original: `FUN_081d2204` @ 0x081d2204
/// (12 bytes).
///
/// Returns the framework root object in the global holder at 0x089cc858
/// (`holder + 4`). The raw ARM body is `ldr r0, [pc] ; ldr r0, [r0, #4] ;
/// bx lr`, with the literal pool word at 0x081d2210. It takes no
/// arguments, writes no memory, and has no NULL branch: the holder itself
/// is always addressed, while its instance slot is returned verbatim,
/// including NULL before framework initialization.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn framework_root_instance() -> *mut u8 {
    core::ptr::read_volatile(core::ptr::addr_of!(FRAMEWORK_ROOT_HOLDER.instance))
}

/// Wired defaults for [`CLASS_6800_OPS`].
pub const DEFAULT_CLASS_6800_OPS: Class6800Ops = Class6800Ops {
    parent_construct: framework_linkage_parent_construct,
    base_initialize: unported_base_initialize,
};

/// Active model of the remaining unported child. Target integration
/// replaces its slot when ported; host tests install recording mocks.
pub static mut CLASS_6800_OPS: Class6800Ops = DEFAULT_CLASS_6800_OPS;

/// Wired default for [`CLASS_6800_VTABLE`]'s only modeled slot: the real
/// +0x2c body is not ported, so the constructor's seeding dispatch is a
/// no-op that reports "no target adopted".
unsafe extern "C" fn unported_set_target(
    _this: *mut Class6800,
    _target: *mut u8,
) -> *mut u8 {
    core::ptr::null_mut()
}

/// Crate stand-in for the vtable at [`CLASS_6800_VTABLE_ADDRESS`].
pub static mut CLASS_6800_VTABLE: Class6800Vtable = Class6800Vtable {
    unresolved_00: [0; 11],
    set_target: unported_set_target,
};

/// Crate stand-in for the base vtable at
/// [`FRAMEWORK_BASE_VTABLE_ADDRESS`]. Only its +0x2c operation is
/// represented; `FUN_081108b4` is still an operation seam.
pub static mut FRAMEWORK_BASE_VTABLE: Class6800Vtable = Class6800Vtable {
    unresolved_00: [0; 11],
    set_target: unported_set_target,
};

#[inline(always)]
unsafe fn class_6800_ops() -> Class6800Ops {
    core::ptr::read_volatile(core::ptr::addr_of!(CLASS_6800_OPS))
}

/// framework_base_construct — original: `FUN_081110d0` @ 0x081110d0
/// (52 bytes; two direct `bl` calls).
///
/// addon. It first chains to parent constructor `FUN_08125234`, plants
/// its vtable at +0x00 (`0x08981958`), then calls
/// `FUN_081108b4(this, initial_target, create_link, 0)`. The returned
/// pointer is exactly the parent constructor's return, forwarded after
/// the initializer; there are no NULL checks before either the vtable
/// store or child call. The link/target child remains a dispatch seam; no
/// deviations.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn framework_base_construct(
    storage: *mut Class6800,
    initial_target: u32,
    create_link: u32,
) -> *mut Class6800 {
    let ops = class_6800_ops();
    let this = (ops.parent_construct)(storage);
    core::ptr::addr_of_mut!((*this).vtable)
        .write_volatile(core::ptr::addr_of!(FRAMEWORK_BASE_VTABLE));
    (ops.base_initialize)(this, initial_target, create_link, 0);
    this
}

/// class_6800_new — original: `FUN_08177e84` @ 0x08177e84
/// (72 bytes of code + the 4-byte vtable literal @ 0x08177ecc;
/// **128 `bl` call sites**, binary-scanned).
///
/// Constructs the class-0x6800 controller addon in caller-owned storage
/// (`operator_new(28)` at every call site) and returns it:
///
/// 1. run the base constructor with the original's constants (0, 1) and
///    adopt **its** return as `this`;
/// 2. plant the class vtable;
/// 3. store the framework root instance in `default_target` and the
///    `TCDemoMode` singleton in `demo_mode`;
/// 4. dispatch vtable slot +0x2c with `default_target` re-read from the
///    object (the original's `ldr r1, [r4, #0x14]`, not the register it
///    just stored), discarding the result.
///
/// No NULL guard anywhere: the original dereferences the base
/// constructor's return unconditionally, and so does this.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn class_6800_new(storage: *mut Class6800) -> *mut Class6800 {
    let this = framework_base_construct(storage, 0, 1);

    core::ptr::addr_of_mut!((*this).vtable)
        .write_volatile(core::ptr::addr_of!(CLASS_6800_VTABLE));
    core::ptr::addr_of_mut!((*this).default_target)
        .write_volatile(framework_root_instance());
    core::ptr::addr_of_mut!((*this).demo_mode).write_volatile(demo_mode_instance());

    let vtable = core::ptr::read_volatile(core::ptr::addr_of!((*this).vtable));
    let target = core::ptr::read_volatile(core::ptr::addr_of!((*this).default_target));
    ((*vtable).set_target)(this, target);
    this
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::app::registry::{
        FrameworkObject, FrameworkObjectVtable, Registry, RegistryEntry, RegistryVtable,
        CLASS_ID_DEMO_MODE, CLASS_REGISTRY,
    };
    use crate::testing::CLASS_REGISTRY_TEST_LOCK as OPS_LOCK;
    use core::ptr;
    use std::sync::MutexGuard;

    // ---- the class registry `demo_mode_instance` resolves through ----

    /// The one entry the mock registry holds while a test runs.
    static mut REGISTERED: RegistryEntry =
        RegistryEntry { class_id: 0, instance: ptr::null_mut() };

    unsafe extern "C" fn mock_index_of(_this: *mut Registry, key: *const u32) -> i32 {
        let entry = ptr::read_volatile(ptr::addr_of!(REGISTERED));
        if entry.instance.is_null() || entry.class_id != key.read() {
            -1
        } else {
            0
        }
    }

    unsafe extern "C" fn mock_entry_at(
        _this: *mut Registry,
        _index: i32,
        out: *mut RegistryEntry,
    ) -> *mut RegistryEntry {
        out.write(ptr::read_volatile(ptr::addr_of!(REGISTERED)));
        out
    }

    /// Every registry slot `demo_mode_instance` must not touch.
    unsafe extern "C" fn unreachable_insert(
        _this: *mut Registry,
        _entry: *const RegistryEntry,
    ) -> usize {
        std::panic!("class_6800_new inserts nothing into the registry");
    }

    unsafe extern "C" fn unreachable_assign_at(
        _this: *mut Registry,
        _index: i32,
        _entry: *const RegistryEntry,
    ) -> usize {
        std::panic!("class_6800_new writes nothing to the registry");
    }

    unsafe extern "C" fn unreachable_notify(_this: *mut Registry) -> *mut u8 {
        std::panic!("class_6800_new fires no registry notification");
    }

    unsafe extern "C" fn mock_cast_to_class(
        this: *mut FrameworkObject,
        class_id: u32,
    ) -> *mut u8 {
        if class_id == CLASS_ID_DEMO_MODE { this.cast() } else { ptr::null_mut() }
    }

    static DEMO_MODE_VTABLE: FrameworkObjectVtable = FrameworkObjectVtable {
        unresolved_00: [0; 5],
        cast_to_class: mock_cast_to_class,
    };
    static mut DEMO_MODE_OBJECT: FrameworkObject =
        FrameworkObject { vtable: &DEMO_MODE_VTABLE };

    static REGISTRY_VTABLE: RegistryVtable = RegistryVtable {
        unresolved_00: [0; 7],
        insert: unreachable_insert,
        unresolved_20: 0,
        assign_at: unreachable_assign_at,
        unresolved_28: [0; 5],
        entry_at: mock_entry_at,
        unresolved_40: [0; 3],
        index_of: mock_index_of,
        unresolved_50: [0; 4],
        has_pending_changes: unreachable_notify,
        notify_deferred: unreachable_notify,
        notify_changed: unreachable_notify,
    };

    const PARENT_CALL: u8 = 1;
    const BASE_INITIALIZE_CALL: u8 = 2;
    const SET_TARGET_CALL: u8 = 3;

    static mut PARENT_CALLS: usize = 0;
    static mut PARENT_STORAGE: *mut Class6800 = ptr::null_mut();
    static mut PARENT_RESULT: *mut Class6800 = ptr::null_mut();
    static mut BASE_INITIALIZE_CALLS: usize = 0;
    static mut BASE_INITIALIZE_ARGS: (*mut Class6800, u32, u32, u32) =
        (ptr::null_mut(), 0xffff_ffff, 0xffff_ffff, 0xffff_ffff);
    static mut OBSERVED_BASE_VTABLE: *const Class6800Vtable = ptr::null();
    static mut SET_TARGET_CALLS: usize = 0;
    static mut SET_TARGET_ARGS: (*mut Class6800, *mut u8) =
        (ptr::null_mut(), ptr::null_mut());
    static mut OBSERVED_DEMO_MODE_AT_DISPATCH: *mut u8 = ptr::null_mut();
    static mut CALL_ORDER: [u8; 3] = [0; 3];
    static mut CALL_COUNT: usize = 0;

    unsafe fn record_call(kind: u8) {
        CALL_ORDER[CALL_COUNT] = kind;
        CALL_COUNT += 1;
    }

    fn call_order() -> [u8; 3] {
        unsafe { core::ptr::read_volatile(core::ptr::addr_of!(CALL_ORDER)) }
    }

    unsafe extern "C" fn record_parent_construct(storage: *mut Class6800) -> *mut Class6800 {
        record_call(PARENT_CALL);
        PARENT_CALLS += 1;
        PARENT_STORAGE = storage;
        if PARENT_RESULT.is_null() { storage } else { PARENT_RESULT }
    }

    unsafe extern "C" fn record_base_initialize(
        this: *mut Class6800,
        initial_target: u32,
        create_link: u32,
        owner: u32,
    ) {
        record_call(BASE_INITIALIZE_CALL);
        BASE_INITIALIZE_CALLS += 1;
        BASE_INITIALIZE_ARGS = (this, initial_target, create_link, owner);
        OBSERVED_BASE_VTABLE = ptr::read_volatile(ptr::addr_of!((*this).vtable));
    }


    unsafe extern "C" fn record_set_target(
        this: *mut Class6800,
        target: *mut u8,
    ) -> *mut u8 {
        record_call(SET_TARGET_CALL);
        SET_TARGET_CALLS += 1;
        SET_TARGET_ARGS = (this, target);
        // Both stores must already be visible when the seeding dispatch
        // runs: the original stores +0x14 and +0x18 before the blx.
        OBSERVED_DEMO_MODE_AT_DISPATCH =
            ptr::read_volatile(ptr::addr_of!((*this).demo_mode));
        0x5eed_0000usize as *mut u8
    }

    /// Stands the class registry up with `demo_mode` registered under
    /// 0x8080 (or nothing registered when it is NULL).
    unsafe fn install_registry(demo_mode: *mut FrameworkObject) {
        REGISTERED = RegistryEntry {
            class_id: CLASS_ID_DEMO_MODE,
            instance: demo_mode.cast(),
        };
        CLASS_REGISTRY.vtable = &REGISTRY_VTABLE;
    }

    unsafe fn install_mocks() -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        install_registry(ptr::addr_of_mut!(DEMO_MODE_OBJECT));
        PARENT_CALLS = 0;
        PARENT_STORAGE = ptr::null_mut();
        PARENT_RESULT = ptr::null_mut();
        BASE_INITIALIZE_CALLS = 0;
        BASE_INITIALIZE_ARGS = (ptr::null_mut(), 0xffff_ffff, 0xffff_ffff, 0xffff_ffff);
        OBSERVED_BASE_VTABLE = ptr::null();
        SET_TARGET_CALLS = 0;
        SET_TARGET_ARGS = (ptr::null_mut(), ptr::null_mut());
        OBSERVED_DEMO_MODE_AT_DISPATCH = ptr::null_mut();
        CALL_ORDER = [0; 3];
        CALL_COUNT = 0;
        CLASS_6800_OPS = Class6800Ops {
            parent_construct: record_parent_construct,
            base_initialize: record_base_initialize,
        };
        CLASS_6800_VTABLE.set_target = record_set_target;
        guard
    }

    unsafe fn restore() {
        CLASS_6800_OPS = DEFAULT_CLASS_6800_OPS;
        CLASS_6800_VTABLE.set_target = unported_set_target;
        FRAMEWORK_ROOT_HOLDER.instance = ptr::null_mut();
        REGISTERED = RegistryEntry { class_id: 0, instance: ptr::null_mut() };
        CLASS_REGISTRY.vtable = ptr::null();
    }

    fn poisoned() -> Class6800 {
        Class6800 {
            vtable: 0xa5a5_a5a5usize as *const Class6800Vtable,
            base_04: 0xa5a5_a5a5,
            base_08: 0xa5a5_a5a5,
            base_link: 0xa5a5_a5a5usize as *mut u8,
            base_10: 0xa5a5_a5a5,
            default_target: 0xa5a5_a5a5usize as *mut u8,
            demo_mode: 0xa5a5_a5a5usize as *mut u8,
        }
    }

    #[test]
    fn linkage_parent_construct_replaces_root_vtable_and_clears_its_two_words() {
        let mut object = poisoned();
        let storage = ptr::addr_of_mut!(object);

        unsafe {
            let this = framework_linkage_parent_construct(storage);

            assert_eq!(this, storage, "the root constructor's r0 is returned");
            assert_eq!(
                object.vtable,
                ptr::addr_of!(FRAMEWORK_LINKAGE_PARENT_VTABLE),
                "the derived parent overwrites the root vtable"
            );
            assert_eq!(object.base_04, 0, "exact store at +0x04");
            assert_eq!(object.base_08, 0, "exact store at +0x08");
            assert_eq!(
                object.base_link,
                0xa5a5_a5a5usize as *mut u8,
                "the parent leaves +0x0c for its child"
            );
            assert_eq!(
                object.base_10, 0xa5a5_a5a5,
                "the parent leaves +0x10 for its child"
            );
            assert_eq!(
                object.default_target,
                0xa5a5_a5a5usize as *mut u8,
                "the parent does not touch derived state"
            );
            assert_eq!(
                object.demo_mode,
                0xa5a5_a5a5usize as *mut u8,
                "the parent does not touch derived state"
            );
        }
    }

    #[test]
    fn a_null_storage_is_forwarded_to_the_parent_and_its_result_is_initialized() {
        // This wrapper itself has no NULL branch. A parent that handles a
        // NULL input and returns a real replacement therefore reaches both
        // the vtable store and the child initializer.
        let mut relocated = poisoned();
        let replacement = ptr::addr_of_mut!(relocated);

        unsafe {
            let guard = install_mocks();
            PARENT_RESULT = replacement;

            let result = framework_base_construct(ptr::null_mut(), 0x1234, 0);

            assert_eq!(result, replacement, "parent r0 is forwarded unchanged");
            assert_eq!(PARENT_CALLS, 1);
            assert!(PARENT_STORAGE.is_null(), "no wrapper NULL guard");
            assert_eq!(BASE_INITIALIZE_CALLS, 1);
            assert_eq!(BASE_INITIALIZE_ARGS, (replacement, 0x1234, 0, 0));
            assert_eq!(
                OBSERVED_BASE_VTABLE,
                ptr::addr_of!(FRAMEWORK_BASE_VTABLE),
                "the base vtable is planted between the two child calls"
            );
            assert_eq!(call_order()[..2], [PARENT_CALL, BASE_INITIALIZE_CALL]);
            restore();
            drop(guard);
        }
    }

    #[test]
    fn constructs_through_the_base_and_seeds_the_default_target() {
        let mut object = poisoned();
        let storage = ptr::addr_of_mut!(object);

        unsafe {
            let guard = install_mocks();
            FRAMEWORK_ROOT_HOLDER.instance = 0x1234_0000usize as *mut u8;

            let this = class_6800_new(storage);

            assert_eq!(this, storage, "the parent constructor's return is `this`");
            assert_eq!(PARENT_CALLS, 1);
            assert_eq!(PARENT_STORAGE, storage);
            assert_eq!(BASE_INITIALIZE_CALLS, 1);
            assert_eq!(
                BASE_INITIALIZE_ARGS,
                (storage, 0, 1, 0),
                "0x08177e84 supplies r1=0/r2=1; 0x081110d0 supplies r3=0"
            );
            assert_eq!(OBSERVED_BASE_VTABLE, ptr::addr_of!(FRAMEWORK_BASE_VTABLE));
            assert_eq!(object.vtable, ptr::addr_of!(CLASS_6800_VTABLE));
            assert_eq!(object.default_target, 0x1234_0000usize as *mut u8);
            assert_eq!(
                object.demo_mode,
                ptr::addr_of_mut!(DEMO_MODE_OBJECT).cast::<u8>(),
                "+0x18 is the registered TCDemoMode singleton"
            );
            assert_eq!(SET_TARGET_CALLS, 1, "slot +0x2c is dispatched exactly once");
            assert_eq!(SET_TARGET_ARGS, (storage, 0x1234_0000usize as *mut u8));
            assert_eq!(
                OBSERVED_DEMO_MODE_AT_DISPATCH, object.demo_mode,
                "+0x18 is stored before the seeding dispatch, not after"
            );
            assert_eq!(
                call_order(),
                [PARENT_CALL, BASE_INITIALIZE_CALL, SET_TARGET_CALL],
                "parent, base link initializer, then derived dispatch"
            );
            restore();
            drop(guard);
        }
    }

    #[test]
    fn a_relocating_parent_constructor_wins() {
        // `mov r4, r0` runs after the parent call: both constructors key
        // everything downstream off that return, never the input storage.
        let mut storage_object = poisoned();
        let mut relocated = poisoned();
        let storage = ptr::addr_of_mut!(storage_object);
        let elsewhere = ptr::addr_of_mut!(relocated);

        unsafe {
            let guard = install_mocks();
            PARENT_RESULT = elsewhere;
            FRAMEWORK_ROOT_HOLDER.instance = 0x2222_0000usize as *mut u8;

            let this = class_6800_new(storage);

            assert_eq!(this, elsewhere);
            assert_eq!(relocated.default_target, 0x2222_0000usize as *mut u8);
            assert_eq!(relocated.vtable, ptr::addr_of!(CLASS_6800_VTABLE));
            assert_eq!(
                storage_object.default_target, 0xa5a5_a5a5usize as *mut u8,
                "the abandoned storage is untouched after the base call"
            );
            assert_eq!(SET_TARGET_ARGS.0, elsewhere);
            restore();
            drop(guard);
        }
    }

    #[test]
    fn a_null_root_instance_is_stored_and_seeded_verbatim() {
        // 0x081d2204 returns the raw +4 slot; a pre-init NULL is not
        // special-cased anywhere in the original.
        let mut object = poisoned();
        let storage = ptr::addr_of_mut!(object);

        unsafe {
            let guard = install_mocks();
            FRAMEWORK_ROOT_HOLDER.instance = ptr::null_mut();

            class_6800_new(storage);

            assert!(object.default_target.is_null());
            assert_eq!(SET_TARGET_CALLS, 1, "NULL does not skip the dispatch");
            assert_eq!(SET_TARGET_ARGS.1, ptr::null_mut());
            restore();
            drop(guard);
        }
    }

    #[test]
    fn framework_root_instance_reads_the_holder_slot_verbatim() {
        unsafe {
            let guard = OPS_LOCK.lock().unwrap_or_else(|p| p.into_inner());
            FRAMEWORK_ROOT_HOLDER.reserved_00 = 0xa5a5_a5a5;
            FRAMEWORK_ROOT_HOLDER.instance = ptr::null_mut();
            assert!(
                framework_root_instance().is_null(),
                "a pre-initialization NULL is returned, not special-cased"
            );

            let mut root = [0u8; 1];
            FRAMEWORK_ROOT_HOLDER.instance = root.as_mut_ptr();
            assert_eq!(framework_root_instance(), root.as_mut_ptr());
            assert_eq!(
                FRAMEWORK_ROOT_HOLDER.reserved_00, 0xa5a5_a5a5,
                "the +0x00 word is not read or written"
            );

            FRAMEWORK_ROOT_HOLDER.reserved_00 = 0;
            FRAMEWORK_ROOT_HOLDER.instance = ptr::null_mut();
            drop(guard);
        }
    }

    #[test]
    fn the_wired_defaults_clear_the_base_and_read_the_modeled_global() {
        let mut object = poisoned();
        let storage = ptr::addr_of_mut!(object);

        unsafe {
            let guard = OPS_LOCK.lock().unwrap_or_else(|p| p.into_inner());
            install_registry(ptr::null_mut());
            CLASS_6800_OPS = DEFAULT_CLASS_6800_OPS;
            CLASS_6800_VTABLE.set_target = unported_set_target;
            FRAMEWORK_ROOT_HOLDER.instance = 0x7777_0000usize as *mut u8;

            let this = class_6800_new(storage);

            assert_eq!(this, storage);
            assert_eq!(object.base_04, 0);
            assert_eq!(object.base_08, 0);
            assert!(object.base_link.is_null(), "no link node without 0x081108b4");
            assert_eq!(object.base_10, 0);
            assert_eq!(object.default_target, 0x7777_0000usize as *mut u8);
            assert!(
                object.demo_mode.is_null(),
                "with nothing registered under 0x8080 the singleton is NULL"
            );
            restore();
            drop(guard);
        }
    }
}
