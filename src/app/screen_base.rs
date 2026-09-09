//! `screen_base_construct` — original: `FUN_082045ac` @ 0x082045ac
//! (**128 bytes of true extent**: Ghidra's 120 bytes of code plus the two
//! literal-pool words @ 0x08204624/0x08204628 holding the vtable address
//! and the root resource id; the separately linked next function — the
//! class's deleting destructor — begins at 0x0820462c, confirmed from raw
//! bytes. **16 `bl` call sites, 0 predicated `bl`, 0 tail `b`**,
//! binary-scanned by decoding every B/BL word in `work/firmware/osos.dec`,
//! matching Ghidra's count exactly).
//!
//! The shared base constructor of the Silver screen classes. Every one of
//! the 16 call sites is the same idiom — `mov r3, ...; mov r2, #1; bl
//! 0x082045ac` followed immediately by the caller re-planting its OWN
//! vtable over +0x00/+0x1c — i.e. each caller is a derived-class
//! constructor layering on top of this base. Two callers pin the family
//! down: 0x081d25ac builds the framework root object itself (it finishes
//! by storing the object into the `framework_root_instance` holder @
//! 0x089cc858) and passes r3 = 0x0dad0167, and 0x0815e934 registers the
//! `TCSportTimer*` screen classes.
//!
//! ```text
//! 082045ac  push {r4, r5, r6, lr}
//! 082045b0  mov  r6, r3             @ keep resource_id
//! 082045b4  mov  r5, r1             @ keep initial_target
//! 082045b8  bl   0x0812468c         @ this = <base ctor chain>(storage, target, link)
//! 082045bc  mov  r4, r0             @ this = the BASE CTOR'S RETURN
//! 082045c0  ldr  r0, [pc, #92]      @ = 0x089917d4 (pool word @ 0x08204624)
//! 082045c4  mov  r1, #0
//! 082045c8  str  r0, [r4]           @ this->vtable = 0x089917d4
//! 082045cc  add  r0, r0, #220       @ secondary vtable = primary + 0xdc
//! 082045d0  str  r0, [r4, #28]      @ this->secondary_vtable = 0x089918b0
//! 082045d4  str  r6, [r4, #32]      @ this->resource_id = arg4
//! 082045d8  str  r1, [r4, #36]      @ this->owned_object = NULL
//! 082045dc  bl   0x0827233c         @ task_ctx_field_0x30()  (ported)
//! 082045e0  mov  r1, r0             @ head of the task's provider chain
//! 082045e4  mov  r0, r4
//! 082045e8  bl   0x082722a0         @ this->set_next_link(head)  (refcounted)
//! 082045ec  cmp  r5, #0
//! 082045f0  bne  0x0820461c         @ explicit target: skip adoption
//! 082045f4  ldr  r0, [r4, #32]      @ re-read this->resource_id
//! 082045f8  ldr  r1, [pc, #40]      @ = 0x0dad0167 (pool word @ 0x08204628)
//! 082045fc  cmp  r0, r1
//! 08204600  beq  0x0820461c         @ constructing the root: skip adoption
//! 08204604  bl   0x081d2204         @ framework_root_instance()  (ported)
//! 08204608  mov  r1, r0
//! 0820460c  ldr  r0, [r4]           @ re-read this->vtable
//! 08204610  ldr  r2, [r0, #44]      @ vtable slot +0x2c ("adopt target")
//! 08204614  mov  r0, r4
//! 08204618  blx  r2                 @ this->adopt_target(root)
//! 0820461c  mov  r0, r4
//! 08204620  pop  {r4, r5, r6, pc}
//! 08204624  .word 0x089917d4
//! 08204628  .word 0x0dad0167
//! ```
//!
//! # What it does
//!
//! 1. Runs the base-constructor chain @ 0x0812468c (which bottoms out in
//!    the ported `framework_base_construct` @ 0x081110d0) with the first
//!    three arguments passed through verbatim, and adopts **its** return
//!    as `this` (`mov r4, r0`) — a relocating base constructor is
//!    honoured, and the incoming `storage` is never touched again.
//! 2. Plants the class vtable 0x089917d4 at +0x00 and its secondary
//!    (virtual-base) vtable at +0x1c, computed as primary + 0xdc — the
//!    image's secondary table at 0x089918b0 is 17 words of
//!    pure-virtual thunks (all 0x082a0464).
//! 3. Stores arg4 at +0x20 and clears +0x24 (an owned sub-object the
//!    deleting destructor @ 0x0820462c releases through its vtable slot
//!    +0x04).
//! 4. Pushes the object onto the current task's resource-provider chain:
//!    the head is field +0x30 of the current task's context block
//!    (`task_ctx_field_0x30`, ported) and the link at +0x14 is installed
//!    through its refcounting setter @ 0x082722a0 (release old, retain
//!    new — cf. `app/resource_chain.rs`).
//! 5. When no explicit initial target was supplied (r1 == 0) **and** the
//!    +0x20 value re-read from the object is not 0x0dad0167, adopts the
//!    framework root instance as the object's target by dispatching
//!    vtable slot +0x2c — the same "adopt this target" slot
//!    `framework_base_initialize` uses. 0x0dad0167 lies in retailOS's
//!    private 0x0dad0000..0x0dad0fff resource-id namespace (cf.
//!    `app/registry.rs`'s STOCK_KEY notes) and is passed only by the
//!    framework root's own constructor @ 0x081d25ac — the root cannot
//!    adopt itself, and its holder slot is only stored at the very end
//!    of that constructor, so the adoption would see a NULL/stale root.
//!
//! There are no NULL guards anywhere: a NULL base-ctor return faults at
//! the vtable store, a NULL current-task context faults inside
//! `task_ctx_field_0x30`, and a pre-init NULL framework root is passed
//! to slot +0x2c verbatim. The port keeps all three.
//!
//! # Deviations
//!
//! - The vtable address 0x089917d4 is static image data that survives
//!   the patch in place, so firmware builds plant the original address
//!   ([`SCREEN_BASE_VTABLE_ADDRESS`], the `application_resource_provider`
//!   precedent); the secondary store computes primary +
//!   `size_of::<ScreenBaseVtable>()`, which the 32-bit layout asserts pin
//!   to exactly 0xdc — the original's `add r0, r0, #220`. Host builds
//!   plant the modeled [`SCREEN_BASE_VTABLE`] so tests can install a
//!   recording slot +0x2c.
//! - Two direct callees are unported and sit behind [`SCREEN_BASE_OPS`]
//!   seams (the `app/class_6800.rs` precedent). The base-constructor
//!   chain @ 0x0812468c is modeled by a stub that returns `storage`
//!   verbatim — only its return-value contract is modeled; its side
//!   effects (intermediate vtables 0x089a5de0/0x08985da8/0x08983020,
//!   the +0x14/+0x18 clears, the task-ctx +0x34 registration) belong to
//!   those functions' own ports. The refcounted link setter @
//!   0x082722a0 is modeled by a stub that performs the link store
//!   (`if old != new { this->next = new; }`) and omits the retain @
//!   0x08124af4 / release @ 0x08124dbc calls. Both stubs are explicit
//!   seams, not fabrications of the unported bodies.
//! - The +0x20 field is named `resource_id` from the single observed
//!   nonzero writer (the root constructor passing its own id); its
//!   readers live in the class's unported methods.

use crate::app::class_6800::framework_root_instance;
use crate::util::context_field::task_ctx_field_0x30;
use core::ptr;

/// The primary vtable address the original plants (literal-pool word @
/// 0x08204624). Static image data, so firmware builds plant it directly
/// and host builds plant the modeled [`SCREEN_BASE_VTABLE`].
pub const SCREEN_BASE_VTABLE_ADDRESS: u32 = 0x0899_17d4;

/// Address of the base-constructor chain this constructor delegates to
/// (`bl 0x0812468c`). Unported; modeled by [`ScreenBaseOps::construct_base`].
pub const SCREEN_BASE_PARENT_CONSTRUCT_ADDRESS: u32 = 0x0812_468c;

/// Address of the refcounted `next`-link setter (`bl 0x082722a0`).
/// Unported; modeled by [`ScreenBaseOps::set_next_link`].
pub const SCREEN_BASE_NEXT_LINK_SETTER_ADDRESS: u32 = 0x0827_22a0;

/// The framework root's own resource id (literal-pool word @
/// 0x08204628), in retailOS's private 0x0dad0000..0x0dad0fff id space.
/// Passed only by the root's constructor @ 0x081d25ac; equality
/// suppresses the default root adoption.
pub const ROOT_RESOURCE_ID: u32 = 0x0dad_0167;

/// The class vtable. Only slot +0x2c — the "adopt this target"
/// operation this constructor dispatches — is decoded; the surrounding
/// words are filler sized so the decoded slot lands on its original
/// offset on the 32-bit target and the whole table spans exactly 0xdc
/// bytes there, making `primary + size_of::<ScreenBaseVtable>()` the
/// original's secondary-vtable address.
#[repr(C)]
pub struct ScreenBaseVtable {
    /// Slots +0x00..+0x28, not decoded by this port.
    pub slots_below: [u32; 11],
    /// Slot +0x2c — `adopt_target(this, target)`. Return value is dead
    /// at this call site (the original discards r0 after the `blx`).
    pub adopt_target: unsafe extern "C" fn(this: *mut ScreenBase, target: *mut u8) -> u32,
    /// Slots +0x30..+0xd8, not decoded by this port.
    pub slots_above: [u32; 43],
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x2c] = [0; core::mem::offset_of!(ScreenBaseVtable, adopt_target)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0xdc] = [0; core::mem::size_of::<ScreenBaseVtable>()];

/// The screen-base object, laid out to the original's offsets on the
/// 32-bit target. +0x04..+0x1b belong to the base classes (target, link
/// node, link owner, and one word the base ctor @ 0x0812468c clears);
/// only the fields this constructor touches are named.
#[repr(C)]
pub struct ScreenBase {
    /// +0x00 — primary vtable (0x089917d4 in the image).
    pub vtable: *const ScreenBaseVtable,
    /// +0x04..+0x13 — base-class state, not decoded by this port.
    pub base_state: [*mut u8; 4],
    /// +0x14 — next node in the current task's resource-provider chain;
    /// refcounted by its setter @ 0x082722a0 (cf. `app/resource_chain.rs`).
    pub next: *mut ScreenBase,
    /// +0x18 — cleared by the base ctor @ 0x0812468c, not decoded here.
    pub field_18: *mut u8,
    /// +0x1c — secondary (virtual-base) vtable: primary + 0xdc.
    pub secondary_vtable: *const u8,
    /// +0x20 — the object's resource id (arg4); 0x0dad0167 = the
    /// framework root constructing itself.
    pub resource_id: u32,
    /// +0x24 — owned sub-object, cleared here; the deleting destructor
    /// @ 0x0820462c releases it through its own vtable slot +0x04.
    pub owned_object: *mut u8,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x14] = [0; core::mem::offset_of!(ScreenBase, next)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x1c] = [0; core::mem::offset_of!(ScreenBase, secondary_vtable)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x20] = [0; core::mem::offset_of!(ScreenBase, resource_id)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x24] = [0; core::mem::offset_of!(ScreenBase, owned_object)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x28] = [0; core::mem::size_of::<ScreenBase>()];

/// The unported direct callees of [`screen_base_construct`].
#[derive(Clone, Copy)]
pub struct ScreenBaseOps {
    /// The base-constructor chain @ 0x0812468c. Receives the first three
    /// arguments verbatim (the chain passes r1/r2 down to
    /// `framework_base_construct`'s `initial_target`/`create_link`); the
    /// original's r3 never reaches it (saved into r6 by the caller first).
    pub construct_base: unsafe extern "C" fn(
        storage: *mut ScreenBase,
        initial_target: u32,
        create_link: u32,
    ) -> *mut ScreenBase,
    /// The refcounted `next`-link setter @ 0x082722a0: releases the old
    /// link, stores the new one at +0x14, retains the new one.
    pub set_next_link: unsafe extern "C" fn(this: *mut ScreenBase, new_link: *mut ScreenBase),
}

/// Default [`ScreenBaseOps::construct_base`] stub. Models only the
/// chain's return-value contract (a constructor hands back its object);
/// the real chain's side effects belong to the ports of 0x0812468c,
/// 0x08143978, and 0x08272418.
unsafe extern "C" fn unported_construct_base(
    storage: *mut ScreenBase,
    _initial_target: u32,
    _create_link: u32,
) -> *mut ScreenBase {
    storage
}

/// Default [`ScreenBaseOps::set_next_link`] stub. Models the setter's
/// store exactly — the original early-returns when old == new and
/// otherwise stores the new link at +0x14 — and omits the unported
/// release @ 0x08124dbc / retain @ 0x08124af4 calls. Like the original,
/// there is no NULL guard on `this`.
unsafe extern "C" fn unported_set_next_link(this: *mut ScreenBase, new_link: *mut ScreenBase) {
    if (*this).next != new_link {
        (*this).next = new_link;
    }
}

/// Wired defaults for [`SCREEN_BASE_OPS`].
pub const DEFAULT_SCREEN_BASE_OPS: ScreenBaseOps = ScreenBaseOps {
    construct_base: unported_construct_base,
    set_next_link: unported_set_next_link,
};

/// Active seams for the two unported direct callees. Host tests install
/// recording mocks; the defaults model only what is documented above.
pub static mut SCREEN_BASE_OPS: ScreenBaseOps = DEFAULT_SCREEN_BASE_OPS;

#[inline(always)]
unsafe fn screen_base_ops() -> ScreenBaseOps {
    ptr::read_volatile(ptr::addr_of!(SCREEN_BASE_OPS))
}

/// Host stand-in for the image vtable @ [`SCREEN_BASE_VTABLE_ADDRESS`].
/// Only `adopt_target` is ever dispatched by this port; its default is
/// an explicit no-op seam since the real slot body @ 0x081436dc is
/// unported. Tests install a recording slot.
#[cfg(not(target_os = "none"))]
pub static mut SCREEN_BASE_VTABLE: ScreenBaseVtable = ScreenBaseVtable {
    slots_below: [0; 11],
    adopt_target: unported_adopt_target,
    slots_above: [0; 43],
};

/// Default slot +0x2c body: the real implementation @ 0x081436dc is
/// unported, so this explicit no-op makes the seam visible without
/// inventing class behavior.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unported_adopt_target(_this: *mut ScreenBase, _target: *mut u8) -> u32 {
    0
}

/// The vtable pointer the constructor plants: the original image address
/// on device, the modeled static on host.
#[inline(always)]
fn class_vtable() -> *const ScreenBaseVtable {
    #[cfg(target_os = "none")]
    {
        SCREEN_BASE_VTABLE_ADDRESS as usize as *const ScreenBaseVtable
    }
    #[cfg(not(target_os = "none"))]
    unsafe {
        // addr_of a `static mut`: tests swap the table's slots at
        // runtime, so the address must not be constant-folded away.
        ptr::addr_of!(SCREEN_BASE_VTABLE)
    }
}

/// screen_base_construct — original: `FUN_082045ac` @ 0x082045ac
/// (128 bytes including the two literal-pool words; **16 `bl` call
/// sites**, binary-scanned).
///
/// Constructs the shared base of the Silver screen classes in
/// caller-owned storage and returns the base constructor's result:
/// chain the base constructor @ 0x0812468c, plant the class vtable and
/// its secondary at +0x1c, store `resource_id` at +0x20, clear the owned
/// sub-object at +0x24, link the object into the current task's
/// resource-provider chain through the refcounted setter @ 0x082722a0,
/// and — only when `initial_target == 0` and the object's re-read
/// resource id is not [`ROOT_RESOURCE_ID`] — adopt the framework root
/// instance as the target through vtable slot +0x2c. No NULL guards, no
/// deviations beyond the documented seams.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn screen_base_construct(
    storage: *mut ScreenBase,
    initial_target: u32,
    create_link: u32,
    resource_id: u32,
) -> *mut ScreenBase {
    let ops = screen_base_ops();
    let this = (ops.construct_base)(storage, initial_target, create_link);
    let vtable = class_vtable();
    (*this).vtable = vtable;
    // The original's `add r0, r0, #220`: on the 32-bit target the layout
    // asserts pin size_of::<ScreenBaseVtable>() to exactly 0xdc.
    (*this).secondary_vtable = (vtable as *const u8).add(core::mem::size_of::<ScreenBaseVtable>());
    (*this).resource_id = resource_id;
    (*this).owned_object = ptr::null_mut();
    let head = task_ctx_field_0x30();
    (ops.set_next_link)(this, head as usize as *mut ScreenBase);
    if initial_target == 0 && (*this).resource_id != ROOT_RESOURCE_ID {
        let root = framework_root_instance();
        ((*(*this).vtable).adopt_target)(this, root);
    }
    this
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::app::class_6800::FRAMEWORK_ROOT_HOLDER;
    use crate::testing::{CLASS_REGISTRY_TEST_LOCK, TASK_CTX_BLOCK_TEST_LOCK};
    use crate::util::context_field::CURRENT_TASK_CTX_BLOCK;
    use std::sync::MutexGuard;

    const CHAIN_HEAD_FIELD: usize = 0x30;

    /// A fake task context block exactly big enough to hold the chain
    /// head word at +0x30 (plus slack for alignment), host-pointer wide
    /// so the ported getter's u32 read lands on `head` below.
    #[repr(C)]
    struct FakeCtxBlock {
        pad: [u32; CHAIN_HEAD_FIELD / 4],
        head: u32,
    }

    static mut CTX_BLOCK: FakeCtxBlock = FakeCtxBlock {
        pad: [0; CHAIN_HEAD_FIELD / 4],
        head: 0,
    };

    static mut CTX_GETTER_CALLS: u32 = 0;

    unsafe extern "C" fn recording_ctx_block() -> *mut u8 {
        CTX_GETTER_CALLS += 1;
        ptr::addr_of_mut!(CTX_BLOCK) as *mut u8
    }

    /// Installs the recording getter into [`CURRENT_TASK_CTX_BLOCK`] and
    /// restores the slot on drop, even when a test panics.
    struct CtxSlotGuard {
        prior: unsafe extern "C" fn() -> *mut u8,
    }

    impl CtxSlotGuard {
        fn install(head_word: u32) -> CtxSlotGuard {
            unsafe {
                CTX_GETTER_CALLS = 0;
                CTX_BLOCK.head = head_word;
                let slot = ptr::addr_of_mut!(CURRENT_TASK_CTX_BLOCK);
                let prior = ptr::read_volatile(slot);
                ptr::write_volatile(slot, recording_ctx_block);
                CtxSlotGuard { prior }
            }
        }
    }

    impl Drop for CtxSlotGuard {
        fn drop(&mut self) {
            unsafe {
                ptr::write_volatile(ptr::addr_of_mut!(CURRENT_TASK_CTX_BLOCK), self.prior);
            }
        }
    }

    // ---- recording seams ----

    static mut CONSTRUCT_CALLS: u32 = 0;
    static mut CONSTRUCT_ARGS: [(*mut ScreenBase, u32, u32); 4] =
        [(ptr::null_mut(), 0, 0); 4];
    /// When non-NULL, the recording base constructor returns this instead
    /// of `storage` (the relocation case).
    static mut CONSTRUCT_RESULT: *mut ScreenBase = ptr::null_mut();

    unsafe extern "C" fn recording_construct_base(
        storage: *mut ScreenBase,
        initial_target: u32,
        create_link: u32,
    ) -> *mut ScreenBase {
        let call = CONSTRUCT_CALLS as usize;
        CONSTRUCT_CALLS += 1;
        CONSTRUCT_ARGS[call] = (storage, initial_target, create_link);
        if CONSTRUCT_RESULT.is_null() {
            storage
        } else {
            CONSTRUCT_RESULT
        }
    }

    static mut SET_LINK_CALLS: u32 = 0;
    static mut SET_LINK_ARGS: [(*mut ScreenBase, *mut ScreenBase); 4] =
        [(ptr::null_mut(), ptr::null_mut()); 4];

    unsafe extern "C" fn recording_set_next_link(
        this: *mut ScreenBase,
        new_link: *mut ScreenBase,
    ) {
        let call = SET_LINK_CALLS as usize;
        SET_LINK_CALLS += 1;
        SET_LINK_ARGS[call] = (this, new_link);
    }

    static mut ADOPT_CALLS: u32 = 0;
    static mut ADOPT_ARGS: [(*mut ScreenBase, *mut u8); 4] =
        [(ptr::null_mut(), ptr::null_mut()); 4];

    unsafe extern "C" fn recording_adopt_target(
        this: *mut ScreenBase,
        target: *mut u8,
    ) -> u32 {
        let call = ADOPT_CALLS as usize;
        ADOPT_CALLS += 1;
        ADOPT_ARGS[call] = (this, target);
        1
    }

    /// A zeroed object whose every named field starts as a poison
    /// pattern instead, so "the constructor wrote it" is observable.
    fn poisoned_object() -> ScreenBase {
        ScreenBase {
            vtable: ptr::null(),
            base_state: [0xa5a5_a5a5usize as *mut u8; 4],
            next: 0xa5a5_a5a5usize as *mut ScreenBase,
            field_18: 0xa5a5_a5a5usize as *mut u8,
            secondary_vtable: ptr::null(),
            resource_id: 0xa5a5_a5a5,
            owned_object: 0xa5a5_a5a5usize as *mut u8,
        }
    }

    /// Guards every slot a test swaps: the two module seams, the modeled
    /// vtable's adopt slot, and the framework-root holder. Restores all
    /// of them on drop.
    struct OpsGuard {
        prior_ops: ScreenBaseOps,
        prior_adopt: unsafe extern "C" fn(*mut ScreenBase, *mut u8) -> u32,
        prior_root: *mut u8,
    }

    impl OpsGuard {
        fn install(root: *mut u8) -> OpsGuard {
            unsafe {
                CONSTRUCT_CALLS = 0;
                SET_LINK_CALLS = 0;
                ADOPT_CALLS = 0;
                CONSTRUCT_RESULT = ptr::null_mut();
                let ops_slot = ptr::addr_of_mut!(SCREEN_BASE_OPS);
                let prior_ops = ptr::read_volatile(ops_slot);
                ptr::write_volatile(
                    ops_slot,
                    ScreenBaseOps {
                        construct_base: recording_construct_base,
                        set_next_link: recording_set_next_link,
                    },
                );
                let vtable_slot = ptr::addr_of_mut!(SCREEN_BASE_VTABLE);
                let prior_adopt = ptr::read_volatile(ptr::addr_of!((*vtable_slot).adopt_target));
                (*vtable_slot).adopt_target = recording_adopt_target;
                let prior_root = FRAMEWORK_ROOT_HOLDER.instance;
                FRAMEWORK_ROOT_HOLDER.instance = root;
                OpsGuard {
                    prior_ops,
                    prior_adopt,
                    prior_root,
                }
            }
        }
    }

    impl Drop for OpsGuard {
        fn drop(&mut self) {
            unsafe {
                ptr::write_volatile(ptr::addr_of_mut!(SCREEN_BASE_OPS), self.prior_ops);
                let vtable_slot = ptr::addr_of_mut!(SCREEN_BASE_VTABLE);
                (*vtable_slot).adopt_target = self.prior_adopt;
                FRAMEWORK_ROOT_HOLDER.instance = self.prior_root;
            }
        }
    }

    /// Both shared locks, always in this order.
    fn lock_all() -> (MutexGuard<'static, ()>, MutexGuard<'static, ()>) {
        let ctx = TASK_CTX_BLOCK_TEST_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let registry = CLASS_REGISTRY_TEST_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        (ctx, registry)
    }

    /// A chain-head word that is not a dereferenceable host pointer on
    /// purpose: the constructor must hand it to the link setter verbatim.
    const HEAD_WORD: u32 = 0x089a_b004;

    #[test]
    fn explicit_target_skips_root_adoption() {
        let _locks = lock_all();
        let _ctx = CtxSlotGuard::install(HEAD_WORD);
        let mut root = 0u8;
        let _ops = OpsGuard::install(ptr::addr_of_mut!(root));
        let mut object = poisoned_object();
        let storage = ptr::addr_of_mut!(object);
        unsafe {
            let result = screen_base_construct(storage, 0xdead_beef, 1, 0x0dad_05a9);
            assert_eq!(result, storage, "returns the base constructor's result");
            assert_eq!(CONSTRUCT_CALLS, 1);
            assert_eq!(
                CONSTRUCT_ARGS[0],
                (storage, 0xdead_beef, 1),
                "first three args pass to the base chain verbatim"
            );
            assert_eq!(object.vtable, ptr::addr_of!(SCREEN_BASE_VTABLE));
            assert_eq!(
                object.secondary_vtable,
                (ptr::addr_of!(SCREEN_BASE_VTABLE) as *const u8)
                    .add(core::mem::size_of::<ScreenBaseVtable>()),
                "secondary vtable = primary + one table, the original's add r0, r0, #220"
            );
            assert_eq!(object.resource_id, 0x0dad_05a9);
            assert!(object.owned_object.is_null(), "+0x24 is cleared");
            assert_eq!(SET_LINK_CALLS, 1, "linked into the task chain exactly once");
            assert_eq!(
                SET_LINK_ARGS[0],
                (storage, HEAD_WORD as usize as *mut ScreenBase),
                "the task-ctx +0x30 head word reaches the setter verbatim"
            );
            assert_eq!(CTX_GETTER_CALLS, 1, "chain head fetched exactly once");
            assert_eq!(ADOPT_CALLS, 0, "explicit target: no root adoption");
        }
    }

    #[test]
    fn zero_target_adopts_framework_root() {
        let _locks = lock_all();
        let _ctx = CtxSlotGuard::install(HEAD_WORD);
        let mut root = 0u8;
        let root_ptr = ptr::addr_of_mut!(root);
        let _ops = OpsGuard::install(root_ptr);
        let mut object = poisoned_object();
        let storage = ptr::addr_of_mut!(object);
        unsafe {
            let result = screen_base_construct(storage, 0, 1, 0);
            assert_eq!(result, storage);
            assert_eq!(ADOPT_CALLS, 1, "no explicit target: root is adopted");
            assert_eq!(
                ADOPT_ARGS[0],
                (storage, root_ptr),
                "slot +0x2c runs on the object with the root instance"
            );
        }
    }

    #[test]
    fn zero_target_with_null_root_still_dispatches() {
        let _locks = lock_all();
        let _ctx = CtxSlotGuard::install(HEAD_WORD);
        let _ops = OpsGuard::install(ptr::null_mut());
        let mut object = poisoned_object();
        let storage = ptr::addr_of_mut!(object);
        unsafe {
            screen_base_construct(storage, 0, 1, 0);
            assert_eq!(
                ADOPT_ARGS[0],
                (storage, ptr::null_mut()),
                "a pre-init NULL root is dispatched verbatim, no NULL guard"
            );
        }
    }

    #[test]
    fn root_resource_id_suppresses_adoption() {
        let _locks = lock_all();
        let _ctx = CtxSlotGuard::install(HEAD_WORD);
        let mut root = 0u8;
        let _ops = OpsGuard::install(ptr::addr_of_mut!(root));
        let mut object = poisoned_object();
        let storage = ptr::addr_of_mut!(object);
        unsafe {
            screen_base_construct(storage, 0, 1, ROOT_RESOURCE_ID);
            assert_eq!(ADOPT_CALLS, 0, "the root never adopts itself");
            assert_eq!(object.resource_id, ROOT_RESOURCE_ID);
        }
    }

    #[test]
    fn any_other_resource_id_still_adopts() {
        let _locks = lock_all();
        let _ctx = CtxSlotGuard::install(HEAD_WORD);
        let mut root = 0u8;
        let root_ptr = ptr::addr_of_mut!(root);
        let _ops = OpsGuard::install(root_ptr);
        let mut object = poisoned_object();
        let storage = ptr::addr_of_mut!(object);
        unsafe {
            // One off the sentinel on either side, plus an out-of-namespace id.
            for id in [ROOT_RESOURCE_ID - 1, ROOT_RESOURCE_ID + 1, 7] {
                ADOPT_CALLS = 0;
                screen_base_construct(storage, 0, 1, id);
                assert_eq!(ADOPT_CALLS, 1, "id {id:#x} is not the root: adopt");
                assert_eq!(ADOPT_ARGS[0], (storage, root_ptr));
            }
        }
    }

    #[test]
    fn base_ctor_relocation_is_honored() {
        let _locks = lock_all();
        let _ctx = CtxSlotGuard::install(HEAD_WORD);
        let mut root = 0u8;
        let _ops = OpsGuard::install(ptr::addr_of_mut!(root));
        let mut passed_in = poisoned_object();
        let mut relocated = poisoned_object();
        unsafe {
            CONSTRUCT_RESULT = ptr::addr_of_mut!(relocated);
            let result =
                screen_base_construct(ptr::addr_of_mut!(passed_in), 0, 1, 0x0dad_0e01);
            assert_eq!(
                result,
                ptr::addr_of_mut!(relocated),
                "the base constructor's return is this, not the incoming storage"
            );
            assert_eq!(
                relocated.vtable,
                ptr::addr_of!(SCREEN_BASE_VTABLE),
                "stores land on the relocated object"
            );
            assert_eq!(relocated.resource_id, 0x0dad_0e01);
            assert_eq!(SET_LINK_ARGS[0].0, result);
            assert_eq!(ADOPT_ARGS[0].0, result);
            assert!(
                passed_in.vtable.is_null(),
                "the incoming storage is never touched after the base call"
            );
        }
    }

    #[test]
    fn default_construct_base_returns_storage_verbatim() {
        let mut object = poisoned_object();
        let storage = ptr::addr_of_mut!(object);
        unsafe {
            assert_eq!(unported_construct_base(storage, 9, 1), storage);
            assert!(
                object.vtable.is_null(),
                "the stub performs none of the real chain's side effects"
            );
        }
    }

    #[test]
    fn default_set_next_link_models_the_store() {
        let mut object = poisoned_object();
        let first = 0x1111_0000usize as *mut ScreenBase;
        let second = 0x2222_0000usize as *mut ScreenBase;
        let this = ptr::addr_of_mut!(object);
        unsafe {
            object.next = first;
            unported_set_next_link(this, first);
            assert_eq!(object.next, first, "unchanged link: early return, still first");
            unported_set_next_link(this, second);
            assert_eq!(object.next, second, "changed link is stored at +0x14");
            unported_set_next_link(this, ptr::null_mut());
            assert!(object.next.is_null(), "a NULL new link is stored too");
        }
    }
}
