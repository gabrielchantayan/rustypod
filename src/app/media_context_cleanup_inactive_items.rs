//! Media-context-gated cleanup of registry class 0x9300.

use core::{mem::MaybeUninit, ptr};
use crate::app::scoped_context::{ScopedContext, scoped_context_construct, scoped_context_destroy};
use crate::cxx::vtable_predicate_state_flag::{VtablePredicateObject, vtable_predicate_state_flag_set};

type Get = unsafe extern "C" fn() -> *mut u8;
type Cleanup = unsafe extern "C" fn(*mut u8) -> u32;
type Update = unsafe extern "C" fn(*mut u8, u32) -> u32;
type DispatchUpdate = unsafe extern "C" fn(*mut u8, u32);
type Predicate = unsafe extern "C" fn(*mut u8) -> u32;
type FillContext = unsafe extern "C" fn(*mut u8, *mut ScopedContext) -> u32;

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct HostOperations {
    pub player_get: Get,
    pub owner_get: Get,
    pub cleanup: Cleanup,
    pub update_needed: Update,
    pub update: DispatchUpdate,
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_get() -> *mut u8 { panic!("install media cleanup host operations") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_cleanup(_: *mut u8) -> u32 { panic!("install media cleanup host operations") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_update(_: *mut u8, _: u32) -> u32 { panic!("install media cleanup host operations") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_dispatch(_: *mut u8, _: u32) { panic!("install media cleanup host operations") }
#[cfg(not(target_os = "none"))]
static mut HOST_OPERATIONS: HostOperations = HostOperations {
    player_get: missing_get, owner_get: missing_get, cleanup: missing_cleanup,
    update_needed: missing_update, update: missing_dispatch,
};
/// Install host substitutes for singleton access and retail class-0x9300 operations.
/// # Safety
/// Calls and installation must be externally serialized; callbacks must obey their ABI.
#[cfg(not(target_os = "none"))]
pub unsafe fn set_host_operations(operations: HostOperations) {
    ptr::addr_of_mut!(HOST_OPERATIONS).write(operations);
}

/// Original `FUN_081a6b70` @ 0x081a6b70; true extent 192 bytes, ending
/// before the independent function at 0x081a6c30. Raw A32 decoding finds
/// 10 plain outgoing BLs, three plain virtual BLXs, zero predicated calls;
/// whole-image decoding finds two inbound plain BLs and zero predicated BLs.
///
/// Query media-player slots +0x190, then +0x194 only if the first is zero.
/// If either succeeds, construct a scoped context and fill it through +0x15c.
/// A successful fill and state-flag predicate (+0xbc bit 0x8000) suppress
/// cleanup, but always destroy the context first. Otherwise fetch class 0x9300,
/// remove inactive items, fetch again, query updates with mode zero, and only
/// on nonzero fetch again and invoke the update helper with mode one.
///
/// Deliberate deviations: unported FUN_0812fb64 uses a verified fixed-address
/// call on ARM and an explicit host substitute. Update dispatch reuses the
/// ported class_9300_update_dispatch. Native-pointer host
/// layouts adapt the scoped context prefix for the existing flag predicate.
/// The incoming r0 is unused; Ghidra's caller-supplied object is not an argument.
/// # Safety
/// Singleton objects and all reached virtual slots must be valid. Host calls
/// require installed, externally serialized operations.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn media_context_cleanup_inactive_items() {
    #[cfg(target_os = "none")]
    let (player_get, owner_get, cleanup, update_needed, update): (Get, Get, Cleanup, Update, DispatchUpdate) = (
        crate::app::singletons::media_player_get,
        crate::app::singletons::singleton_class_9300,
        crate::app::class_9300_remove_inactive_items::class_9300_remove_inactive_items,
        core::mem::transmute(0x0812_fb64usize),
        crate::app::class_9300_update_dispatch::class_9300_update_dispatch,
    );
    #[cfg(not(target_os = "none"))]
    let HostOperations { player_get, owner_get, cleanup, update_needed, update } =
        ptr::read_volatile(ptr::addr_of!(HOST_OPERATIONS));
    let player = player_get();
    let vtable = player.cast::<*const usize>().read();
    let first: Predicate = core::mem::transmute(vtable.add(0x190 / 4).read());
    let available = if first(player) != 0 { true } else {
        let vtable = player.cast::<*const usize>().read();
        let second: Predicate = core::mem::transmute(vtable.add(0x194 / 4).read());
        second(player) != 0
    };
    if available {
        let mut context = MaybeUninit::<ScopedContext>::uninit();
        scoped_context_construct(context.as_mut_ptr(), ptr::null_mut(), 0);
        let vtable = player.cast::<*const usize>().read();
        let fill: FillContext = core::mem::transmute(vtable.add(0x15c / 4).read());
        let filled = fill(player, context.as_mut_ptr());
        let mut suppress = false;
        if filled != 0 {
            #[cfg(target_os = "none")]
            { suppress = vtable_predicate_state_flag_set(context.as_mut_ptr().cast()) != 0; }
            #[cfg(not(target_os = "none"))]
            {
                let context = context.assume_init_ref();
                let mut prefix = VtablePredicateObject {
                    vtable: context.vtable.cast(), unresolved_04: context.owner_valid,
                    state: context.owner.cast(),
                };
                suppress = vtable_predicate_state_flag_set(&mut prefix) != 0;
            }
        }
        scoped_context_destroy(context.as_mut_ptr());
        if suppress { return; }
    }
    cleanup(owner_get());
    if update_needed(owner_get(), 0) != 0 {
        update(owner_get(), 1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::scoped_context::ScopedContextVtable;
    use crate::cxx::vtable_predicate_state_flag::{VtablePredicateState, VtablePredicate};
    use parking_lot::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());
    #[repr(C)]
    struct Player { vtable: *const usize, first: u32, second: u32, fill: u32, flags: u32 }
    static mut PLAYER: *mut Player = ptr::null_mut();
    static mut GETS: u32 = 0;
    static mut REMAINING: u32 = 0;
    static mut UPDATES: u32 = 0;
    static mut NEEDED: u32 = 0;
    static mut STATE: VtablePredicateState = VtablePredicateState { unresolved_before_flags: [0; 47], flags: 0 };
    unsafe extern "C" fn get_player() -> *mut u8 { PLAYER.cast() }
    unsafe extern "C" fn get_owner() -> *mut u8 { GETS += 1; ptr::null_mut() }
    unsafe extern "C" fn cleanup(_: *mut u8) -> u32 { REMAINING = 0; 1 }
    unsafe extern "C" fn needed(_: *mut u8, mode: u32) -> u32 { assert_eq!(mode, 0); assert_eq!(REMAINING, 0); NEEDED }
    unsafe extern "C" fn update(_: *mut u8, mode: u32) { assert_eq!(mode, 1); UPDATES += 1; }
    unsafe extern "C" fn first(p: *mut u8) -> u32 { (*p.cast::<Player>()).first }
    unsafe extern "C" fn second(p: *mut u8) -> u32 { assert_eq!((*p.cast::<Player>()).first, 0); (*p.cast::<Player>()).second }
    unsafe extern "C" fn valid(_: *mut VtablePredicateObject) -> u32 { 2 }
    static CONTEXT_VTABLE: ScopedContextVtable = ScopedContextVtable { slots: [0; 15] };
    unsafe extern "C" fn fill(p: *mut u8, context: *mut ScopedContext) -> u32 {
        // The fixture vtable lives for the entire synchronous call.
        (*context).owner = ptr::addr_of_mut!(STATE).cast();
        (*context).vtable = CONTEXT_TABLE;
        STATE.flags = (*p.cast::<Player>()).flags;
        (*p.cast::<Player>()).fill
    }
    static mut CONTEXT_TABLE: *const ScopedContextVtable = &CONTEXT_VTABLE;

    #[test]
    fn flag_gate_and_failed_fill_preserve_cleanup_and_update_transitions() {
        let _lock = LOCK.lock();
        unsafe {
            let mut table = [0usize; 102];
            table[0x190 / 4] = first as Predicate as usize;
            table[0x194 / 4] = second as Predicate as usize;
            table[0x15c / 4] = fill as FillContext as usize;
            let mut context_table = ScopedContextVtable { slots: [0; 15] };
            context_table.slots[2] = valid as VtablePredicate as usize;
            CONTEXT_TABLE = &context_table;
            set_host_operations(HostOperations { player_get: get_player, owner_get: get_owner,
                cleanup, update_needed: needed, update });
            for (a, b, filled, flags, needed_value, suppressed) in [
                (2, 0, 3, 0x8000, 1, true),
                (0, 7, 3, 0x8000, 1, true),
                (0, 0, 0, 0x8000, 1, false),
                (2, 0, 0, 0x8000, 1, false),
                (2, 0, 3, 0x4000, 1, false),
                (0, 7, 3, 0, 0, false),
            ] {
                let mut player = Player { vtable: table.as_ptr(), first: a, second: b, fill: filled, flags };
                PLAYER = &mut player;
                GETS = 0; REMAINING = 9; UPDATES = 0; NEEDED = needed_value;
                media_context_cleanup_inactive_items();
                assert_eq!(REMAINING, if suppressed { 9 } else { 0 });
                assert_eq!(UPDATES, u32::from(!suppressed && needed_value != 0));
                assert_eq!(GETS, if suppressed { 0 } else if needed_value != 0 { 3 } else { 2 });
            }
            set_host_operations(HostOperations { player_get: missing_get, owner_get: missing_get,
                cleanup: missing_cleanup, update_needed: missing_update, update: missing_dispatch });
            PLAYER = ptr::null_mut(); CONTEXT_TABLE = &CONTEXT_VTABLE;
        }
    }
}
