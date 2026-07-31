//! `object_dispatch_entry_construct` — original: `FUN_0810f9f0` @
//! 0x0810f9f0 (40 bytes).
//!
//! Constructs the 0x24-byte **object dispatch entry** that the factory
//! `FUN_0810f548` keeps in its registry, keyed by an application object's
//! address. That factory first allocates this object with `operator_new(0x24)`
//! @ 0x082aadd4, then passes the allocation and owner object in r0/r1.
//!
//! ```text
//! entry +0x00  owner object pointer
//! entry +0x04  embedded drain state (vtable + state + two opaque words)
//! entry +0x14  pending-dispatch word
//! entry +0x18  embedded condition-variable state (three words)
//! ```
//!
//! The constructor stores the owner, delegates construction of the embedded
//! drain state to `FUN_08271cec` (which in turn invokes its base constructor
//! @ 0x08275bb8), clears the pending-dispatch word, and delegates
//! condition-variable initialization to `FUN_0807f680`. The two unported
//! dependencies are explicit replaceable seams: target integration installs
//! their retailOS implementations, while host tests install recording mocks.
//! Crucially, the stock code derives its return object from the **returned**
//! drain-state pointer (`sub r4, r0, #4`), rather than retaining the incoming
//! allocation pointer; the port preserves that return-base adjustment.
//!
//! Sources: `ipod-decomp/decomp/c/010/0810f9f0_FUN_0810f9f0.c`,
//! `ipod-decomp/decomp/c/026/08271cec_FUN_08271cec.c`, and the instruction
//! sequence at 0x0810f9f0 in `ipod-decomp/decomp/osos.asm`.

use core::ffi::c_void;

/// Target byte size of [`ObjectDispatchEntry`]. The owning factory allocates
/// exactly this many bytes before invoking the constructor.
pub const OBJECT_DISPATCH_ENTRY_SIZE: usize = 0x24;

/// The embedded drain-state object initialized by `FUN_08271cec`.
#[repr(C)]
pub struct DrainState {
    /// +0x00: vtable installed by the unported constructor.
    pub vtable: u32,
    /// +0x04: state word cleared by that constructor.
    pub state: u32,
    /// +0x08..+0x0c: opaque words also cleared by that constructor.
    pub opaque: [u32; 2],
}

/// The three-word condition-variable state initialized by `FUN_0807f680`.
#[repr(C)]
pub struct ConditionVariableState {
    /// +0x00: handle supplied by the kernel/ROM dependency.
    pub handle: u32,
    /// +0x04..+0x08: dependency-owned state, initially zero.
    pub opaque: [u32; 2],
}

/// A dispatch entry for one application object. Pointer-valued target fields
/// are represented as `u32` so this layout remains exact in 64-bit host tests.
#[repr(C)]
pub struct ObjectDispatchEntry {
    /// +0x00: owning application object's target address.
    pub owner: u32,
    /// +0x04: drain state for the owner's queued dispatches.
    pub drain_state: DrainState,
    /// +0x14: cleared before the condition variable is initialized.
    pub pending_dispatch: u32,
    /// +0x18: condition-variable state.
    pub condition_variable: ConditionVariableState,
}

const _: [u8; 0x04] = [0; core::mem::offset_of!(ObjectDispatchEntry, drain_state)];
const _: [u8; 0x14] = [0; core::mem::offset_of!(ObjectDispatchEntry, pending_dispatch)];
const _: [u8; 0x18] = [0; core::mem::offset_of!(ObjectDispatchEntry, condition_variable)];
const _: [u8; OBJECT_DISPATCH_ENTRY_SIZE] = [0; core::mem::size_of::<ObjectDispatchEntry>()];
/// Return-preserving slot +0x4c of the target's virtual table. The target
/// class is not yet identified, so the return register stays a raw word.
pub type ObjectDispatchEntrySlot4cDispatch =
    unsafe extern "C" fn(*mut ObjectDispatchTarget) -> usize;

/// Return-unobserved slot +0x50 of the target's virtual table. The target
/// class and action are not recovered, but the raw tail branch binds its
/// target as the sole argument.
pub type ObjectDispatchEntrySlot50Dispatch = unsafe extern "C" fn(*mut ObjectDispatchTarget);

/// The virtual table reached through an object's dispatch target. The filler
/// keeps the named call slots at +0x4c and +0x50 on the 32-bit firmware
/// target while keeping host function-pointer fields disjoint.
#[repr(C)]
pub struct ObjectDispatchTargetVtable {
    /// Slots +0x00..+0x48: not dispatched by either veneer.
    pub unresolved_00_48: [usize; 19],
    /// +0x4c: target-specific action invoked by
    /// [`object_dispatch_entry_dispatch`].
    pub dispatch_slot_4c: ObjectDispatchEntrySlot4cDispatch,
    /// +0x50: target-specific action invoked by
    /// [`object_dispatch_entry_dispatch_vtable_slot_50`].
    pub dispatch_slot_50: ObjectDispatchEntrySlot50Dispatch,
}

/// The vtable-bearing target selected from a dispatch source's +0x88 word.
#[repr(C)]
pub struct ObjectDispatchTarget {
    /// +0x00: virtual table loaded immediately before the +0x4c dispatch.
    pub vtable: *const ObjectDispatchTargetVtable,
}

/// The portion of the source object observed by
/// [`object_dispatch_entry_dispatch`].
///
/// The preceding words remain opaque: this small veneer only selects the
/// target pointer at +0x88 and never reads the source object otherwise.
#[repr(C)]
pub struct ObjectDispatchSource {
    /// +0x00..+0x84: source-class state not observed here.
    pub opaque_00_84: [usize; 34],
    /// +0x88: target whose virtual +0x4c slot is invoked.
    pub dispatch_target: *mut ObjectDispatchTarget,
}

// Target-exact field offsets. Host tests intentionally use pointer-width
// fields so real host function pointers remain valid.
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x88] = [0; core::mem::offset_of!(ObjectDispatchSource, dispatch_target)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x4c] = [0; core::mem::offset_of!(ObjectDispatchTargetVtable, dispatch_slot_4c)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x50] = [0; core::mem::offset_of!(ObjectDispatchTargetVtable, dispatch_slot_50)];

/// Injection point for the embedded drain-state constructor @ 0x08271cec.
pub type DrainStateConstruct = unsafe extern "C" fn(*mut DrainState) -> *mut DrainState;
/// Injection point for the condition-variable initializer @ 0x0807f680.
pub type ConditionVariableConstruct = unsafe extern "C" fn(*mut ConditionVariableState);

/// The two retailOS constructor dependencies used by
/// [`object_dispatch_entry_construct`].
#[derive(Clone, Copy)]
pub struct ObjectDispatchEntryOps {
    pub construct_drain_state: DrainStateConstruct,
    pub construct_condition_variable: ConditionVariableConstruct,
}

// Calling the port before target integration supplies the dependent retailOS
// constructors is a configuration error. Fail hard rather than pretending a
// drain state or condition variable was initialized.
unsafe extern "C" fn missing_drain_state_construct(_state: *mut DrainState) -> *mut DrainState {
    loop {
        core::hint::spin_loop();
    }
}

unsafe extern "C" fn missing_condition_variable_construct(_state: *mut ConditionVariableState) {
    loop {
        core::hint::spin_loop();
    }
}

/// Replace before first use on target; tests temporarily install mocks.
pub static mut OBJECT_DISPATCH_ENTRY_OPS: ObjectDispatchEntryOps = ObjectDispatchEntryOps {
    construct_drain_state: missing_drain_state_construct,
    construct_condition_variable: missing_condition_variable_construct,
};

#[inline(always)]
unsafe fn dispatch_entry_ops() -> ObjectDispatchEntryOps {
    core::ptr::read_volatile(core::ptr::addr_of!(OBJECT_DISPATCH_ENTRY_OPS))
}
/// object_dispatch_entry_dispatch — original: `FUN_0811c178` @ 0x0811c178
/// (16 bytes).
///
/// Loads the dispatch target from `source + 0x88`, then tail-dispatches the
/// target's vtable slot +0x4c with that target as its sole argument. The raw
/// sequence is `ldr r0, [r0, #0x88]`, `ldr r1, [r0]`, `ldr r1, [r1, #0x4c]`,
/// `bx r1`; consequently there is no NULL guard and the target's raw r0
/// return word becomes this veneer’s return word unchanged.
///
/// The target class and slot semantics are not recovered. The port therefore
/// uses neutral source/target types and an `usize` result rather than
/// assigning an unsupported meaning. On the 64-bit host, `usize` filler
/// fields keep the typed +0x4c dispatch slot disjoint; the documented layout
/// and compile-time offset checks are exact on the 32-bit firmware target.
///
/// Sources: `ipod-decomp/decomp/c/010/0811c178_FUN_0811c178.c` and the raw
/// instruction sequence at 0x0811c178 in `ipod-decomp/decomp/osos.asm`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn object_dispatch_entry_dispatch(
    source: *mut ObjectDispatchSource,
) -> usize {
    let target = core::ptr::read_volatile(core::ptr::addr_of!((*source).dispatch_target));
    let vtable = core::ptr::read_volatile(core::ptr::addr_of!((*target).vtable));
    ((*vtable).dispatch_slot_4c)(target)
}

/// object_dispatch_entry_dispatch_vtable_slot_50 — original:
/// `FUN_0811c298` @ 0x0811c298 (16 bytes).
///
/// Loads the dispatch target from `source + 0x88`, then tail-dispatches the
/// target's vtable slot +0x50 with that target as its sole argument. The raw
/// sequence is `ldr r0, [r0, #0x88]`, `ldr r1, [r0]`, `ldr r1, [r1, #0x50]`,
/// `bx r1`; consequently there is no NULL guard, no additional argument, and
/// no return value observed by this void veneer.
///
/// The target class and slot action are not recovered. The port therefore
/// keeps neutral source/target types and exposes the verified slot offset
/// rather than assigning a speculative operation name. On the 64-bit host,
/// `usize` filler fields keep the typed +0x50 dispatch slot disjoint; the
/// documented layout and compile-time offset checks are exact on the 32-bit
/// firmware target.
///
/// Sources: `ipod-decomp/decomp/c/010/0811c298_FUN_0811c298.c` and the raw
/// instruction sequence at 0x0811c298 in `ipod-decomp/decomp/osos.asm`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn object_dispatch_entry_dispatch_vtable_slot_50(
    source: *mut ObjectDispatchSource,
) {
    let target = core::ptr::read_volatile(core::ptr::addr_of!((*source).dispatch_target));
    let vtable = core::ptr::read_volatile(core::ptr::addr_of!((*target).vtable));
    ((*vtable).dispatch_slot_50)(target)
}

/// object_dispatch_entry_construct — original: `FUN_0810f9f0` @ 0x0810f9f0
/// (40 bytes).
///
/// Initializes an already-allocated entry for `owner` and returns the entry
/// base. There is no NULL guard, allocation, or whole-object clear: the
/// caller owns allocation, and the two injected constructors own their
/// embedded subobjects. The base returned by the drain-state constructor is
/// adjusted by -4 exactly as the stock `sub r4, r0, #4` does.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn object_dispatch_entry_construct(
    this: *mut ObjectDispatchEntry,
    owner: *mut c_void,
) -> *mut ObjectDispatchEntry {
    core::ptr::addr_of_mut!((*this).owner).write_volatile(owner as usize as u32);

    let ops = dispatch_entry_ops();
    let drain_state = (ops.construct_drain_state)(core::ptr::addr_of_mut!((*this).drain_state));
    let entry = drain_state.cast::<u8>().sub(core::mem::offset_of!(ObjectDispatchEntry, drain_state))
        .cast::<ObjectDispatchEntry>();

    core::ptr::addr_of_mut!((*entry).pending_dispatch).write_volatile(0);
    (ops.construct_condition_variable)(core::ptr::addr_of_mut!((*entry).condition_variable));
    entry
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::ptr;
    use std::sync::{Mutex, MutexGuard};

    #[repr(C, align(4))]
    struct EntryStorage([u8; OBJECT_DISPATCH_ENTRY_SIZE]);

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut EXPECTED_DRAIN_STATE: *mut DrainState = ptr::null_mut();
    static mut EXPECTED_CONDITION_VARIABLE: *mut ConditionVariableState = ptr::null_mut();
    static mut CALLS: [u8; 2] = [0; 2];
    static mut CALL_COUNT: usize = 0;
    static mut EXPECTED_DISPATCH_TARGET: *mut ObjectDispatchTarget = ptr::null_mut();
    static mut DISPATCH_CALLS: usize = 0;
    static mut SLOT_50_CALLS: usize = 0;
    static mut DISPATCH_RESULT: usize = 0;

    unsafe extern "C" fn record_dispatch(target: *mut ObjectDispatchTarget) -> usize {
        assert_eq!(
            target, EXPECTED_DISPATCH_TARGET,
            "the selected +0x88 target is forwarded as the slot's r0"
        );
        DISPATCH_CALLS += 1;
        DISPATCH_RESULT
    }

    unsafe extern "C" fn record_dispatch_slot_50(target: *mut ObjectDispatchTarget) {
        assert_eq!(
            target, EXPECTED_DISPATCH_TARGET,
            "the selected +0x88 target is forwarded as the slot's r0"
        );
        SLOT_50_CALLS += 1;
    }

    unsafe fn clear_dispatch_recording() {
        EXPECTED_DISPATCH_TARGET = ptr::null_mut();
        DISPATCH_CALLS = 0;
        SLOT_50_CALLS = 0;
        DISPATCH_RESULT = 0;
    }

    unsafe extern "C" fn record_drain_state(state: *mut DrainState) -> *mut DrainState {
        assert_eq!(state, EXPECTED_DRAIN_STATE);
        CALLS[CALL_COUNT] = 1;
        CALL_COUNT += 1;
        state
    }

    unsafe extern "C" fn record_condition_variable(state: *mut ConditionVariableState) {
        assert_eq!(state, EXPECTED_CONDITION_VARIABLE);
        CALLS[CALL_COUNT] = 2;
        CALL_COUNT += 1;
        ptr::addr_of_mut!((*state).handle).write_volatile(0xfeed_beef);
        ptr::addr_of_mut!((*state).opaque[0]).write_volatile(0);
        ptr::addr_of_mut!((*state).opaque[1]).write_volatile(0);
    }

    unsafe fn install_recording_ops(entry: *mut ObjectDispatchEntry) -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        EXPECTED_DRAIN_STATE = ptr::addr_of_mut!((*entry).drain_state);
        EXPECTED_CONDITION_VARIABLE = ptr::addr_of_mut!((*entry).condition_variable);
        CALLS = [0; 2];
        CALL_COUNT = 0;
        OBJECT_DISPATCH_ENTRY_OPS = ObjectDispatchEntryOps {
            construct_drain_state: record_drain_state,
            construct_condition_variable: record_condition_variable,
        };
        guard
    }

    unsafe fn restore_ops() {
        OBJECT_DISPATCH_ENTRY_OPS = ObjectDispatchEntryOps {
            construct_drain_state: missing_drain_state_construct,
            construct_condition_variable: missing_condition_variable_construct,
        };
        EXPECTED_DRAIN_STATE = ptr::null_mut();
        EXPECTED_CONDITION_VARIABLE = ptr::null_mut();
    }

    fn word_at(storage: &EntryStorage, offset: usize) -> u32 {
        u32::from_le_bytes(storage.0[offset..offset + 4].try_into().unwrap())
    }

    #[test]
    fn construction_uses_embedded_bases_and_returns_the_adjusted_entry_base() {
        let mut storage = EntryStorage([0xa5; OBJECT_DISPATCH_ENTRY_SIZE]);
        let entry = storage.0.as_mut_ptr().cast::<ObjectDispatchEntry>();
        let owner = 0x1234_5678usize as *mut c_void;
        let guard = unsafe { install_recording_ops(entry) };

        let result = unsafe { object_dispatch_entry_construct(entry, owner) };

        assert_eq!(result, entry, "drain-state return is adjusted back by four bytes");
        assert_eq!(unsafe { CALL_COUNT }, 2);
        assert_eq!(unsafe { CALLS }, [1, 2], "drain state precedes condition variable");
        assert_eq!(word_at(&storage, 0x00), owner as usize as u32);
        assert_eq!(word_at(&storage, 0x14), 0, "pending dispatch is cleared");
        assert_eq!(word_at(&storage, 0x18), 0xfeed_beef);
        assert_eq!(word_at(&storage, 0x1c), 0);
        assert_eq!(word_at(&storage, 0x20), 0);

        // Only the owner, pending word, and dependency-owned condition state
        // changed. The unported drain-state constructor mock intentionally
        // leaves its four words untouched.
        for offset in (0..OBJECT_DISPATCH_ENTRY_SIZE).step_by(4) {
            if matches!(offset, 0x00 | 0x14 | 0x18 | 0x1c | 0x20) {
                continue;
            }
            assert_eq!(word_at(&storage, offset), 0xa5a5_a5a5, "word +{offset:#x}");
        }

        unsafe { restore_ops() };
        drop(guard);
    }
    #[test]
    fn dispatch_uses_the_4c_slot_and_forwards_the_selected_target() {
        let vtable = ObjectDispatchTargetVtable {
            unresolved_00_48: [0xdead_beef; 19],
            dispatch_slot_4c: record_dispatch,
            dispatch_slot_50: record_dispatch_slot_50,
        };
        let mut target = ObjectDispatchTarget { vtable: &vtable };
        let mut source = ObjectDispatchSource {
            opaque_00_84: [0xa5a5_a5a5; 34],
            dispatch_target: ptr::addr_of_mut!(target),
        };

        unsafe {
            clear_dispatch_recording();
            EXPECTED_DISPATCH_TARGET = ptr::addr_of_mut!(target);
            DISPATCH_RESULT = 0xcafe_babe;

            assert_eq!(
                object_dispatch_entry_dispatch(ptr::addr_of_mut!(source)),
                DISPATCH_RESULT,
                "the slot's r0 result is returned by the tail-dispatch veneer"
            );
            assert_eq!(DISPATCH_CALLS, 1, "only the named +0x4c slot runs");
            clear_dispatch_recording();
        }
    }

    #[test]
    fn dispatch_vtable_slot_50_skips_4c_and_forwards_the_selected_target() {
        let vtable = ObjectDispatchTargetVtable {
            unresolved_00_48: [0xdead_beef; 19],
            dispatch_slot_4c: record_dispatch,
            dispatch_slot_50: record_dispatch_slot_50,
        };
        let mut target = ObjectDispatchTarget { vtable: &vtable };
        let mut source = ObjectDispatchSource {
            opaque_00_84: [0xa5a5_a5a5; 34],
            dispatch_target: ptr::addr_of_mut!(target),
        };

        unsafe {
            clear_dispatch_recording();
            EXPECTED_DISPATCH_TARGET = ptr::addr_of_mut!(target);

            object_dispatch_entry_dispatch_vtable_slot_50(ptr::addr_of_mut!(source));

            assert_eq!(SLOT_50_CALLS, 1, "the named +0x50 slot runs once");
            assert_eq!(DISPATCH_CALLS, 0, "the neighboring +0x4c slot is not called");
            clear_dispatch_recording();
        }
    }
}
