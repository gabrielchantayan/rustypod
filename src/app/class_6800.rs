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
//! - `framework_base_construct` @ 0x081110d0,
//!   `framework_base_initialize` @ 0x081108b4, and
//!   `framework_root_instance` @ 0x081d2204 are ported directly. The base
//!   initializer retains only its three unported direct callees as
//!   [`FRAMEWORK_BASE_INITIALIZE_OPS`] seams: the allocation diagnostic and
//!   the two context getters. The modeled [`FRAMEWORK_ROOT_HOLDER`] is the
//!   crate stand-in for the runtime global @ 0x089cc858 whose +4 slot the
//!   root getter returns, following `app/context.rs`'s modeled-global
//!   precedent. The complete chain remains unhookable only where those
//!   retained callees or the vtable implementation are unported.
//! - `demo_mode_instance` @ 0x081883fc **is** ported
//!   (`app/registry.rs`), so it is called directly rather than through a
//!   seam.
//! - `this` is taken from the base constructor's **return value**, not
//!   from the incoming storage (the original's `mov r4, r0` after the
//!   `bl`), so a base constructor that relocates its object is honoured.

use crate::heap::veneers::malloc_wrapper;
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
    /// +0x0c: the 16-byte link state `framework_base_initialize` allocates.
    pub base_link: *mut FrameworkBaseLink,
    /// +0x10: explicit link owner, or the active framework owner returned
    /// by `FUN_0809444c` when the caller supplies no owner.
    pub link_owner: *mut u8,
    /// +0x14: the fallback target this object adopts on construction and
    /// falls back to in its sibling methods.
    pub default_target: *mut u8,
    /// +0x18: the registered `TCDemoMode` singleton (`0x081883fc`).
    pub demo_mode: *mut u8,
}

/// The 16-byte state node stored in [`Class6800::base_link`].
///
/// `framework_base_initialize` writes the byte at +0x00 and the three
/// words at +0x04, +0x08, and +0x0c to zero, in that order. The later
/// unported routine @ 0x081109a0 reads the first byte as a state value and
/// the word at +0x08 as a collection handle; the remaining node semantics
/// are not recovered, so they intentionally remain unresolved.
#[repr(C)]
pub struct FrameworkBaseLink {
    /// +0x00: state byte; initialized to zero.
    pub state: u8,
    /// +0x01..+0x03: untouched by the initializer.
    pub unresolved_01: [u8; 3],
    /// +0x04: initialized to zero.
    pub unresolved_04: u32,
    /// +0x08: collection handle, initialized to zero.
    pub unresolved_08: u32,
    /// +0x0c: initialized to zero.
    pub unresolved_0c: u32,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 16] = [0; core::mem::size_of::<FrameworkBaseLink>()];

/// The explicit owner supplied in r3 to [`framework_base_initialize`].
/// Only its +0x0c context pointer is observed here.
#[repr(C)]
pub struct FrameworkBaseOwner {
    /// +0x00..+0x08: not read by this initializer.
    pub unresolved_00: [u32; 3],
    /// +0x0c: context holding the first linked base at +0x24.
    pub link_context: *mut FrameworkBaseLinkContext,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x0c] = [0; core::mem::offset_of!(FrameworkBaseOwner, link_context)];

/// Context reached through an explicit link owner. Its +0x24 slot is
/// populated only if it does not already point at a base object.
#[repr(C)]
pub struct FrameworkBaseLinkContext {
    /// +0x00..+0x20: not read by this initializer.
    pub unresolved_00: [u32; 9],
    /// +0x24: first linked framework base, if any.
    pub linked_base: *mut Class6800,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x24] = [0; core::mem::offset_of!(FrameworkBaseLinkContext, linked_base)];

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x0c] = [0; core::mem::offset_of!(Class6800, base_link)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x10] = [0; core::mem::offset_of!(Class6800, link_owner)];
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


/// The unported direct callees of [`framework_base_initialize`]. Allocation
/// and vtable dispatch are already-portable direct paths, so they are not
/// duplicated as seams.
#[derive(Clone, Copy)]
pub struct FrameworkBaseInitializeOps {
    /// `FUN_081b53e4(4, "nil")`, reached only after a failed 16-byte
    /// allocation. RetailOS then continues into the unconditional NULL
    /// stores if this diagnostic happens to return.
    pub report_allocation_failure: unsafe extern "C" fn(code: u32, message: *const u8),
    /// `FUN_080cb828()`: returns the implicit context whose +0x24 slot
    /// receives this base when r3 is NULL.
    pub implicit_link_context: unsafe extern "C" fn() -> *mut FrameworkBaseLinkContext,
    /// `FUN_0809444c()`: returns the active framework owner stored at
    /// `this + 0x10` whenever r3 is NULL.
    pub active_link_owner: unsafe extern "C" fn() -> *mut u8,
}

/// Injection point for the parent constructor @ 0x08125234. Host tests
/// may replace it to prove the outer constructor honours a relocated
/// return; the wired default is [`framework_linkage_parent_construct`].
pub type FrameworkBaseParentConstruct =
    unsafe extern "C" fn(storage: *mut Class6800) -> *mut Class6800;

/// Remaining unported dependency of `framework_base_construct`.
#[derive(Clone, Copy)]
pub struct Class6800Ops {
    /// `FUN_08125234` parent-constructor test seam. The wired default is
    /// [`framework_linkage_parent_construct`].
    pub parent_construct: FrameworkBaseParentConstruct,
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

/// The literal passed in r1 to `FUN_081b53e4` after a failed allocation.
/// The ARM instruction `addeq r1, pc, #136` computes 0x08110970, whose
/// bytes are `b"nil\0"`.
const BASE_LINK_ALLOCATION_FAILURE_MESSAGE: &[u8; 4] = b"nil\0";

/// Default diagnostic and context seams. These paths are separately
/// unported; returning from the diagnostic preserves the ARM fall-through
/// rather than adding a Rust-only recovery branch.
unsafe extern "C" fn unported_report_allocation_failure(_code: u32, _message: *const u8) {}

unsafe extern "C" fn unported_implicit_link_context() -> *mut FrameworkBaseLinkContext {
    core::ptr::null_mut()
}

unsafe extern "C" fn unported_active_link_owner() -> *mut u8 {
    core::ptr::null_mut()
}

/// Wired defaults for [`FRAMEWORK_BASE_INITIALIZE_OPS`].
pub const DEFAULT_FRAMEWORK_BASE_INITIALIZE_OPS: FrameworkBaseInitializeOps =
    FrameworkBaseInitializeOps {
        report_allocation_failure: unported_report_allocation_failure,
        implicit_link_context: unported_implicit_link_context,
        active_link_owner: unported_active_link_owner,
    };

/// Active seams for the unported direct callees of
/// [`framework_base_initialize`].
pub static mut FRAMEWORK_BASE_INITIALIZE_OPS: FrameworkBaseInitializeOps =
    DEFAULT_FRAMEWORK_BASE_INITIALIZE_OPS;

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
};

/// Active model of the parent constructor. Host tests install a recording
/// parent to prove return forwarding.
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
/// [`FRAMEWORK_BASE_VTABLE_ADDRESS`]. Its +0x2c operation is dispatched
/// directly by [`framework_base_initialize`].
pub static mut FRAMEWORK_BASE_VTABLE: Class6800Vtable = Class6800Vtable {
    unresolved_00: [0; 11],
    set_target: unported_set_target,
};

#[inline(always)]
unsafe fn class_6800_ops() -> Class6800Ops {
    core::ptr::read_volatile(core::ptr::addr_of!(CLASS_6800_OPS))
}

#[inline(always)]
unsafe fn framework_base_initialize_ops() -> FrameworkBaseInitializeOps {
    core::ptr::read_volatile(core::ptr::addr_of!(FRAMEWORK_BASE_INITIALIZE_OPS))
}

/// framework_base_initialize — original: `FUN_081108b4` @ 0x081108b4
/// (188 bytes).
///
/// Initializes the linkage portion of a framework base. When
/// `create_link != 0`, it allocates exactly 16 bytes through
/// `malloc_wrapper(16, 0)`, reports `FUN_081b53e4(4, "nil")` on failure
/// but deliberately falls through to the original's unconditional stores,
/// publishes the node at `this + 0x0c`, then zeros node +0x0c, +0x08,
/// +0x04, and +0x00 in that order. It dynamically dispatches vtable slot
/// +0x2c with `initial_target`; with an explicit `owner`, it fills that
/// owner's context +0x24 only when empty, while without one it overwrites
/// the implicit context +0x24. Finally it stores either the explicit owner
/// or the current active owner at `this + 0x10`. With `create_link == 0`,
/// it only clears +0x0c and performs that final owner selection.
///
/// There are no NULL guards: null `this`, a returning allocation-failure
/// handler, null vtable/context, and an invalid explicit owner all reach
/// the same subsequent dereference/store as the ARM body. The void ABI
/// returns with r0 dead.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn framework_base_initialize(
    this: *mut Class6800,
    initial_target: *mut u8,
    create_link: u32,
    owner: *mut FrameworkBaseOwner,
) {
    let ops = framework_base_initialize_ops();

    if create_link == 0 {
        core::ptr::addr_of_mut!((*this).base_link).write_volatile(core::ptr::null_mut());
    } else {
        let link = malloc_wrapper(core::mem::size_of::<FrameworkBaseLink>(), 0)
            .cast::<FrameworkBaseLink>();
        if link.is_null() {
            (ops.report_allocation_failure)(4, BASE_LINK_ALLOCATION_FAILURE_MESSAGE.as_ptr());
        }
        core::ptr::addr_of_mut!((*this).base_link).write_volatile(link);
        core::ptr::addr_of_mut!((*link).unresolved_0c).write_volatile(0);
        core::ptr::addr_of_mut!((*link).unresolved_08).write_volatile(0);
        core::ptr::addr_of_mut!((*link).unresolved_04).write_volatile(0);
        core::ptr::addr_of_mut!((*link).state).write_volatile(0);

        // ARM loads owner+0x0c before the virtual call (r5 is live across
        // blx), so a dispatch that mutates owner state cannot redirect the
        // later +0x24 test.
        let explicit_context = if owner.is_null() {
            core::ptr::null_mut()
        } else {
            core::ptr::read_volatile(core::ptr::addr_of!((*owner).link_context))
        };

        let vtable = core::ptr::read_volatile(core::ptr::addr_of!((*this).vtable));
        ((*vtable).set_target)(this, initial_target);

        if owner.is_null() {
            let context = (ops.implicit_link_context)();
            core::ptr::addr_of_mut!((*context).linked_base).write_volatile(this);
        } else {
            let context = explicit_context;
            if core::ptr::read_volatile(core::ptr::addr_of!((*context).linked_base)).is_null() {
                core::ptr::addr_of_mut!((*context).linked_base).write_volatile(this);
            }
        }
    }

    let link_owner = if owner.is_null() {
        (ops.active_link_owner)()
    } else {
        owner.cast()
    };
    core::ptr::addr_of_mut!((*this).link_owner).write_volatile(link_owner);
}

/// framework_base_construct — original: `FUN_081110d0` @ 0x081110d0
/// (52 bytes; two direct `bl` calls).
///
/// `framework_base_initialize(this, initial_target, create_link, NULL)`.
/// The returned pointer is exactly the parent constructor's return,
/// forwarded after the initializer; there are no NULL checks before either
/// the vtable store or child call. No deviations.
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
    framework_base_initialize(this, initial_target as usize as *mut u8, create_link, core::ptr::null_mut());
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
    const SET_TARGET_CALL: u8 = 2;

    static mut PARENT_CALLS: usize = 0;
    static mut PARENT_STORAGE: *mut Class6800 = ptr::null_mut();
    static mut PARENT_RESULT: *mut Class6800 = ptr::null_mut();
    static mut SET_TARGET_CALLS: usize = 0;
    static mut SET_TARGET_ARGS: [(*mut Class6800, *mut u8); 2] =
        [(ptr::null_mut(), ptr::null_mut()); 2];
    static mut OBSERVED_DEMO_MODE_AT_DISPATCH: *mut u8 = ptr::null_mut();
    static mut CALL_ORDER: [u8; 4] = [0; 4];
    static mut CALL_COUNT: usize = 0;
    static mut ALLOC_CALLS: usize = 0;
    static mut ALLOC_ARGS: (usize, usize) = (usize::MAX, usize::MAX);
    static mut TEST_HEAP: usize = 0;
    static mut TEST_LINK: FrameworkBaseLink = FrameworkBaseLink {
        state: 0xa5,
        unresolved_01: [0xa5; 3],
        unresolved_04: 0xa5a5_a5a5,
        unresolved_08: 0xa5a5_a5a5,
        unresolved_0c: 0xa5a5_a5a5,
    };
    static mut IMPLICIT_CONTEXT: FrameworkBaseLinkContext = FrameworkBaseLinkContext {
        unresolved_00: [0; 9],
        linked_base: ptr::null_mut(),
    };
    static mut ACTIVE_OWNER: u8 = 0;
    static mut IMPLICIT_CONTEXT_CALLS: usize = 0;
    static mut ACTIVE_OWNER_CALLS: usize = 0;

    unsafe fn record_call(kind: u8) {
        CALL_ORDER[CALL_COUNT] = kind;
        CALL_COUNT += 1;
    }

    fn call_order() -> [u8; 4] {
        unsafe { core::ptr::read_volatile(core::ptr::addr_of!(CALL_ORDER)) }
    }

    unsafe extern "C" fn record_parent_construct(storage: *mut Class6800) -> *mut Class6800 {
        record_call(PARENT_CALL);
        PARENT_CALLS += 1;
        PARENT_STORAGE = storage;
        if PARENT_RESULT.is_null() { storage } else { PARENT_RESULT }
    }

    unsafe extern "C" fn record_alloc(
        _heap: *mut crate::heap::types::HeapDescriptorDescriptor,
        size: usize,
        tag: usize,
    ) -> *mut u8 {
        ALLOC_CALLS += 1;
        ALLOC_ARGS = (size, tag);
        ptr::addr_of_mut!(TEST_LINK).cast()
    }

    unsafe extern "C" fn record_implicit_context() -> *mut FrameworkBaseLinkContext {
        IMPLICIT_CONTEXT_CALLS += 1;
        ptr::addr_of_mut!(IMPLICIT_CONTEXT)
    }

    unsafe extern "C" fn record_active_owner() -> *mut u8 {
        ACTIVE_OWNER_CALLS += 1;
        ptr::addr_of_mut!(ACTIVE_OWNER)
    }

    unsafe extern "C" fn record_set_target(
        this: *mut Class6800,
        target: *mut u8,
    ) -> *mut u8 {
        record_call(SET_TARGET_CALL);
        SET_TARGET_ARGS[SET_TARGET_CALLS] = (this, target);
        SET_TARGET_CALLS += 1;
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
        SET_TARGET_CALLS = 0;
        SET_TARGET_ARGS = [(ptr::null_mut(), ptr::null_mut()); 2];
        OBSERVED_DEMO_MODE_AT_DISPATCH = ptr::null_mut();
        CALL_ORDER = [0; 4];
        CALL_COUNT = 0;
        ALLOC_CALLS = 0;
        ALLOC_ARGS = (usize::MAX, usize::MAX);
        TEST_LINK = FrameworkBaseLink {
            state: 0xa5,
            unresolved_01: [0xa5; 3],
            unresolved_04: 0xa5a5_a5a5,
            unresolved_08: 0xa5a5_a5a5,
            unresolved_0c: 0xa5a5_a5a5,
        };
        IMPLICIT_CONTEXT.linked_base = ptr::null_mut();
        IMPLICIT_CONTEXT_CALLS = 0;
        ACTIVE_OWNER_CALLS = 0;
        CLASS_6800_OPS = Class6800Ops { parent_construct: record_parent_construct };
        FRAMEWORK_BASE_INITIALIZE_OPS = FrameworkBaseInitializeOps {
            report_allocation_failure: unported_report_allocation_failure,
            implicit_link_context: record_implicit_context,
            active_link_owner: record_active_owner,
        };
        let defaults = crate::heap::veneers::DEFAULT_HEAP_OPS;
        crate::heap::veneers::HEAP_OPS = crate::heap::veneers::HeapVeneerOps {
            alloc: record_alloc,
            ..defaults
        };
        crate::heap::types::DEFAULT_HEAP =
            ptr::addr_of_mut!(TEST_HEAP).cast::<crate::heap::types::HeapDescriptorDescriptor>();
        CLASS_6800_VTABLE.set_target = record_set_target;
        FRAMEWORK_BASE_VTABLE.set_target = record_set_target;
        guard
    }

    unsafe fn restore() {
        CLASS_6800_OPS = DEFAULT_CLASS_6800_OPS;
        FRAMEWORK_BASE_INITIALIZE_OPS = DEFAULT_FRAMEWORK_BASE_INITIALIZE_OPS;
        crate::heap::veneers::HEAP_OPS = crate::heap::veneers::DEFAULT_HEAP_OPS;
        crate::heap::types::DEFAULT_HEAP = ptr::null_mut();
        CLASS_6800_VTABLE.set_target = unported_set_target;
        FRAMEWORK_BASE_VTABLE.set_target = unported_set_target;
        FRAMEWORK_ROOT_HOLDER.instance = ptr::null_mut();
        REGISTERED = RegistryEntry { class_id: 0, instance: ptr::null_mut() };
        CLASS_REGISTRY.vtable = ptr::null();
    }

    fn poisoned() -> Class6800 {
        Class6800 {
            vtable: 0xa5a5_a5a5usize as *const Class6800Vtable,
            base_04: 0xa5a5_a5a5,
            base_08: 0xa5a5_a5a5,
            base_link: 0xa5a5_a5a5usize as *mut FrameworkBaseLink,
            link_owner: 0xa5a5_a5a5usize as *mut u8,
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
                0xa5a5_a5a5usize as *mut FrameworkBaseLink,
                "the parent leaves +0x0c for its child"
            );
            assert_eq!(
                object.link_owner, 0xa5a5_a5a5usize as *mut u8,
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
            assert!((*replacement).base_link.is_null(), "create_link=0 clears +0x0c");
            assert_eq!(
                (*replacement).link_owner,
                ptr::addr_of_mut!(ACTIVE_OWNER),
                "the NULL owner selects FUN_0809444c's result"
            );
            assert_eq!(
                (*replacement).vtable,
                ptr::addr_of!(FRAMEWORK_BASE_VTABLE),
                "the base vtable is planted before the direct initializer"
            );
            assert_eq!(call_order()[..1], [PARENT_CALL]);
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
            assert_eq!(ALLOC_CALLS, 1);
            assert_eq!(ALLOC_ARGS, (16, 0), "FUN_080eb67c(16, 0)");
            assert_eq!(object.base_link, ptr::addr_of_mut!(TEST_LINK));
            assert_eq!(TEST_LINK.state, 0);
            assert_eq!(TEST_LINK.unresolved_01, [0xa5; 3], "bytes +1..+3 are untouched");
            assert_eq!(TEST_LINK.unresolved_04, 0);
            assert_eq!(TEST_LINK.unresolved_08, 0);
            assert_eq!(TEST_LINK.unresolved_0c, 0);
            assert_eq!(IMPLICIT_CONTEXT_CALLS, 1);
            assert_eq!(IMPLICIT_CONTEXT.linked_base, storage);
            assert_eq!(ACTIVE_OWNER_CALLS, 1);
            assert_eq!(object.vtable, ptr::addr_of!(CLASS_6800_VTABLE));
            assert_eq!(object.default_target, 0x1234_0000usize as *mut u8);
            assert_eq!(
                object.demo_mode,
                ptr::addr_of_mut!(DEMO_MODE_OBJECT).cast::<u8>(),
                "+0x18 is the registered TCDemoMode singleton"
            );
            assert_eq!(SET_TARGET_CALLS, 2, "base and derived slots each dispatch once");
            assert_eq!(SET_TARGET_ARGS[0], (storage, ptr::null_mut()));
            assert_eq!(SET_TARGET_ARGS[1], (storage, 0x1234_0000usize as *mut u8));
            assert_eq!(
                OBSERVED_DEMO_MODE_AT_DISPATCH, object.demo_mode,
                "+0x18 is stored before the derived seeding dispatch"
            );
            assert_eq!(
                call_order(),
                [PARENT_CALL, SET_TARGET_CALL, SET_TARGET_CALL, 0],
                "parent, base-link dispatch, then derived dispatch"
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
            assert_eq!(SET_TARGET_ARGS[1].0, elsewhere);
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
            assert_eq!(SET_TARGET_CALLS, 2, "NULL does not skip either dispatch");
            assert_eq!(SET_TARGET_ARGS[1].1, ptr::null_mut());
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
    fn initialize_without_link_clears_only_the_link_and_selects_the_owner_path() {
        let mut implicit = poisoned();
        let mut explicit = poisoned();
        let mut context = FrameworkBaseLinkContext {
            unresolved_00: [0; 9],
            linked_base: 0x1usize as *mut Class6800,
        };
        let mut owner = FrameworkBaseOwner {
            unresolved_00: [0; 3],
            link_context: ptr::addr_of_mut!(context),
        };

        unsafe {
            let guard = install_mocks();
            framework_base_initialize(ptr::addr_of_mut!(implicit), 0x1234usize as *mut u8, 0, ptr::null_mut());
            framework_base_initialize(
                ptr::addr_of_mut!(explicit),
                0x5678usize as *mut u8,
                0,
                ptr::addr_of_mut!(owner),
            );

            assert!(implicit.base_link.is_null());
            assert_eq!(implicit.link_owner, ptr::addr_of_mut!(ACTIVE_OWNER));
            assert!(explicit.base_link.is_null());
            assert_eq!(explicit.link_owner, ptr::addr_of_mut!(owner).cast());
            assert_eq!(ALLOC_CALLS, 0);
            assert_eq!(SET_TARGET_CALLS, 0);
            assert_eq!(IMPLICIT_CONTEXT_CALLS, 0);
            assert_eq!(ACTIVE_OWNER_CALLS, 1, "only the NULL-owner path calls 0x0809444c");
            assert_eq!(context.linked_base, 0x1usize as *mut Class6800);
            restore();
            drop(guard);
        }
    }

    #[test]
    fn initialize_with_explicit_owner_allocates_dispatches_and_only_fills_an_empty_context() {
        let mut object = poisoned();
        let storage = ptr::addr_of_mut!(object);
        let mut context = FrameworkBaseLinkContext {
            unresolved_00: [0; 9],
            linked_base: ptr::null_mut(),
        };
        let mut owner = FrameworkBaseOwner {
            unresolved_00: [0; 3],
            link_context: ptr::addr_of_mut!(context),
        };

        unsafe {
            let guard = install_mocks();
            object.vtable = ptr::addr_of!(FRAMEWORK_BASE_VTABLE);
            framework_base_initialize(storage, 0x2468usize as *mut u8, 1, ptr::addr_of_mut!(owner));

            assert_eq!(ALLOC_CALLS, 1);
            assert_eq!(ALLOC_ARGS, (16, 0));
            assert_eq!(object.base_link, ptr::addr_of_mut!(TEST_LINK));
            assert_eq!(object.link_owner, ptr::addr_of_mut!(owner).cast());
            assert_eq!(SET_TARGET_ARGS[0], (storage, 0x2468usize as *mut u8));
            assert_eq!(context.linked_base, storage, "empty owner context is filled");
            assert_eq!(IMPLICIT_CONTEXT_CALLS, 0);
            assert_eq!(ACTIVE_OWNER_CALLS, 0);

            context.linked_base = 0x1usize as *mut Class6800;
            framework_base_initialize(storage, ptr::null_mut(), 1, ptr::addr_of_mut!(owner));
            assert_eq!(context.linked_base, 0x1usize as *mut Class6800, "occupied context is retained");
            assert_eq!(SET_TARGET_ARGS[1], (storage, ptr::null_mut()));
            restore();
            drop(guard);
        }
    }
}
