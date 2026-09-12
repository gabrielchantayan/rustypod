//! `handler_list_activate` — original: `FUN_08134720` @ `0x08134720`
//! (**124 bytes**: 120 bytes of code, 0x08134720..0x08134798, plus the one
//! trailing literal-pool word Ghidra drops — `0x0dad0195` @ 0x08134798,
//! reached by `ldr r4, [pc, #56]`; the next function opens
//! `push {r4, r5, r6, r7, r8, r9, sl, lr}` @ 0x0813479c. **14 `bl` call
//! sites**, verified by decoding every ARM B/BL word in
//! `work/firmware/osos.dec`: 11 unconditional plus 3 predicated `blne`
//! @ 0x08223084, 0x08226d04, 0x08239650, each immediately after
//! `cmn r0, #1` — the CALLER skips activation when its preceding virtual
//! query answered -1; this function itself carries no such guard. No
//! plain-`b` tail-call sites.)
//!
//! # Algorithm
//!
//! The consumer half of the handler-list protocol: callers stack-build a
//! 24-byte [`HandlerList`] (`handler_list_construct` @ 0x0816cbfc, then
//! `vector_push_back_elem12` pushes of `{command_id, handler_name, flag}`
//! records such as `{"HandleAddToOTG" + 1, 1}`), hand it here, and destroy
//! it afterwards. Raw ARM:
//!
//! ```text
//! 08134720  push {r2, r3, r4, r5, r6, lr}
//! 08134724  mov  r5, r0             @ owner (this)
//! 08134728  mov  r4, r1             @ handlers
//! 0813472c  bl   0x081e8ca0         @ context = handler_context_get()
//! 08134730  mov  r1, r4
//! 08134734  bl   0x081e8da0         @ handler_context_install_list(context, handlers)
//! 08134738  bl   0x081e8ca0         @ context = handler_context_get()  (again)
//! 0813473c  bl   0x081e8cd0         @ state = handler_context_active_state(context)
//! 08134740  mov  r6, r0
//! 08134744  mov  r4, #0
//! 08134748  bl   0x0817ee04         @ app_controller_get()
//! 0813474c  mov  r3, r4             @ 0
//! 08134750  mov  r2, r4             @ 0
//! 08134754  str  r4, [sp, #4]       @ stack arg: 0
//! 08134758  ldr  r4, [pc, #56]      @ r4 = 0x0dad0195
//! 0813475c  str  r6, [sp]           @ stack arg: state
//! 08134760  mov  r1, r4
//! 08134764  bl   0x08181110         @ app_controller_begin_command(ctl,
//!                                   @   0x0dad0195, 0, 0, state, 0)
//! 08134768  bl   0x081dfa20         @ command_dispatcher_get()
//! 0813476c  mov  r3, #0
//! 08134770  add  r2, r4, #1         @ 0x0dad0196
//! 08134774  mov  r1, r4
//! 08134778  bl   0x081dfab0         @ command_dispatch_by_resource(disp,
//!                                   @   0x0dad0195, 0x0dad0196, 0)
//! 0813477c  mov  r1, r0
//! 08134780  ldr  r0, [r5]
//! 08134784  ldr  r2, [r0, #208]     @ vtable slot +0xd0
//! 08134788  add  sp, sp, #8
//! 0813478c  mov  r0, r5
//! 08134790  pop  {r4, r5, r6, lr}
//! 08134794  bx   r2                 @ owner->vtable[0xd0/4](owner, result)
//! ```
//!
//! So: install the caller's handler list into the handler-context
//! singleton, read the context's active-state word back out, post command
//! `0x0dad0195` to the application controller's pending-command record
//! with that state attached, dispatch command `0x0dad0196` (resource
//! `0x0dad0195`, the private `0x0dad0000` namespace the
//! `command_dispatch_by_resource` ledger entry documents) through the
//! command dispatcher, and hand the dispatch result to the owner's
//! virtual slot `+0xd0`. The singleton getter is genuinely called twice
//! (two separate `bl`s), not cached across the install.
//!
//! The three unported retailOS handler-context callees ride the
//! [`HANDLER_LIST_ACTIVATE_OPS`] `read_volatile` dispatch table (house
//! pattern):
//!
//! - `handler_context_get` @ 0x081e8ca0 — the lazy-singleton getter of a
//!   0x34-byte handler-context object (cache word 0x089cfe38, ctor
//!   0x081e8ee8, `operator new(0x34)`); same four-step idiom as the
//!   `app/singletons` family.
//! - `handler_context_install_list` @ 0x081e8da0 — copies the supplied
//!   HandlerList's `mode`/`state`/`state_flag` fields into the context's
//!   embedded list at +0x18 (via 0x083e1450) and, when `state_flag != 0`
//!   and the context's +0x30 word is set, re-links it through
//!   0x0816cbb0.
//! - `handler_context_active_state` @ 0x081e8cd0 — answers 0 when the
//!   context's +0x30 word is NULL, else `FUN_0816cae4(context + 0x18,
//!   that word)`.
//!
//! # Deliberate deviations
//!
//! - Firmware vtable words are 32-bit pointers. The host model gives the
//!   owner vtable a structural pointer representation so its +0xd0 slot
//!   stays separately callable on 64-bit hosts; target-width assertions
//!   retain the firmware offset (the `controller_layout_dispatch.rs`
//!   pattern). The dynamic slot's identity is not recoverable from the
//!   static image, so it is dispatched through the supplied owner's
//!   vtable, exactly like the original's `bx r2`.
//! - `app_controller_get`, `app_controller_begin_command`,
//!   `command_dispatcher_get`, and `command_dispatch_by_resource` are
//!   already ported and are called directly, matching the original's
//!   direct `bl`s.

use crate::app::singletons::{app_controller_get, command_dispatcher_get};
use crate::app::command_dispatch::command_dispatch_by_resource;
use crate::app::controller_pending_command::app_controller_begin_command;
use crate::cxx::handler_list_construct::HandlerList;

/// Resource id the activation is posted under (the literal-pool word @
/// 0x08134798), in the private `0x0dad0000` command namespace.
pub const HANDLER_LIST_RESOURCE: u32 = 0x0dad_0195;

/// Command id dispatched through the command dispatcher —
/// [`HANDLER_LIST_RESOURCE`] + 1, the namespace's resource/command
/// pairing convention.
pub const HANDLER_LIST_ACTIVATE_COMMAND: u32 = 0x0dad_0196;

/// The handler-list owner (`this`) observed by [`handler_list_activate`]:
/// only the runtime vtable pointer is touched.
#[repr(C)]
pub struct HandlerListOwner {
    /// +0x00: runtime vtable pointer.
    pub vtable: *const HandlerListOwnerVtable,
}

/// Owner vtable portion observed by [`handler_list_activate`].
#[repr(C)]
pub struct HandlerListOwnerVtable {
    /// Slots +0x00..+0xcc, not dispatched here.
    pub unresolved_00_cc: [usize; 52],
    /// +0xd0: receives the owner and the dispatch result once the
    /// handler list has been installed and the activation command has
    /// run.
    pub handlers_activated: unsafe extern "C" fn(*mut HandlerListOwner, *mut u8),
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0xd0] = [0; core::mem::offset_of!(HandlerListOwnerVtable, handlers_activated)];

/// The retailOS dependencies of [`handler_list_activate`] — see the
/// module header for what each does in the original.
#[derive(Clone, Copy)]
pub struct HandlerListActivateOps {
    /// `FUN_081e8ca0` @ 0x081e8ca0 — handler-context singleton getter.
    pub handler_context_get: unsafe extern "C" fn() -> *mut u8,
    /// `FUN_081e8da0` @ 0x081e8da0 — installs the caller's handler list
    /// into the context singleton.
    pub handler_context_install_list: unsafe extern "C" fn(*mut u8, *mut HandlerList),
    /// `FUN_081e8cd0` @ 0x081e8cd0 — the context's active-state word (0
    /// when the context's +0x30 link is NULL).
    pub handler_context_active_state: unsafe extern "C" fn(*mut u8) -> u32,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_handler_context_get() -> *mut u8 {
    let get: unsafe extern "C" fn() -> *mut u8 = unsafe { core::mem::transmute(0x081e_8ca0usize) };
    unsafe { get() }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_handler_context_get() -> *mut u8 {
    panic!("handler_list_activate requires handler-context getter 0x081e8ca0")
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_handler_context_install_list(
    context: *mut u8,
    handlers: *mut HandlerList,
) {
    let install: unsafe extern "C" fn(*mut u8, *mut HandlerList) =
        unsafe { core::mem::transmute(0x081e_8da0usize) };
    unsafe { install(context, handlers) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_handler_context_install_list(
    _context: *mut u8,
    _handlers: *mut HandlerList,
) {
    panic!("handler_list_activate requires handler-context install 0x081e8da0")
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_handler_context_active_state(context: *mut u8) -> u32 {
    let state: unsafe extern "C" fn(*mut u8) -> u32 =
        unsafe { core::mem::transmute(0x081e_8cd0usize) };
    unsafe { state(context) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_handler_context_active_state(_context: *mut u8) -> u32 {
    panic!("handler_list_activate requires handler-context state 0x081e8cd0")
}


/// Wired defaults for [`HANDLER_LIST_ACTIVATE_OPS`].
#[cfg(target_os = "none")]
pub const DEFAULT_HANDLER_LIST_ACTIVATE_OPS: HandlerListActivateOps =
    HandlerListActivateOps {
        handler_context_get: firmware_handler_context_get,
        handler_context_install_list: firmware_handler_context_install_list,
        handler_context_active_state: firmware_handler_context_active_state,
    };

/// Wired defaults for [`HANDLER_LIST_ACTIVATE_OPS`].
#[cfg(not(target_os = "none"))]
pub const DEFAULT_HANDLER_LIST_ACTIVATE_OPS: HandlerListActivateOps =
    HandlerListActivateOps {
        handler_context_get: missing_handler_context_get,
        handler_context_install_list: missing_handler_context_install_list,
        handler_context_active_state: missing_handler_context_active_state,
    };

/// Active model of the unported handler-context dependencies. Target
/// integration replaces these slots as 0x081e8ca0 / 0x081e8da0 /
/// 0x081e8cd0 are ported; host tests install recording mocks.
pub static mut HANDLER_LIST_ACTIVATE_OPS: HandlerListActivateOps =
    DEFAULT_HANDLER_LIST_ACTIVATE_OPS;

#[inline(always)]
unsafe fn activate_ops() -> HandlerListActivateOps {
    core::ptr::read_volatile(core::ptr::addr_of!(HANDLER_LIST_ACTIVATE_OPS))
}

/// handler_list_activate — original: `FUN_08134720` @ 0x08134720
/// (124 bytes incl. the pool word; **14 `bl` call sites**, 11
/// unconditional + 3 `blne`, binary-scanned).
///
/// Installs `handlers` into the handler-context singleton, posts command
/// [`HANDLER_LIST_RESOURCE`] with the context's active-state word to the
/// application controller's pending-command record, dispatches
/// [`HANDLER_LIST_ACTIVATE_COMMAND`] through the command dispatcher, and
/// tail-dispatches the owner's vtable slot +0xd0 with the dispatch
/// result. There is no NULL guard on `owner` or `handlers`: the original
/// dereferences both unconditionally.
///
/// # Safety
///
/// `owner` must have a readable vtable whose +0xd0 entry accepts this
/// ABI, `handlers` must be valid for the duration of the install, and the
/// handler-context dependencies must be wired (on device the defaults are the
/// real firmware functions).
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn handler_list_activate(
    owner: *mut HandlerListOwner,
    handlers: *mut HandlerList,
) {
    let ops = activate_ops();
    let context = (ops.handler_context_get)();
    (ops.handler_context_install_list)(context, handlers);
    let context = (ops.handler_context_get)();
    let state = (ops.handler_context_active_state)(context);
    let controller = app_controller_get();
    app_controller_begin_command(
        controller.cast(),
        HANDLER_LIST_RESOURCE,
        0,
        0,
        state,
        0,
    );
    let dispatcher = command_dispatcher_get();
    let result = command_dispatch_by_resource(
        dispatcher,
        HANDLER_LIST_RESOURCE,
        HANDLER_LIST_ACTIVATE_COMMAND,
        0,
    );
    let vtable = core::ptr::read_volatile(core::ptr::addr_of!((*owner).vtable));
    (vtable.as_ref().unwrap_unchecked().handlers_activated)(owner, result);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::app::command_dispatch::{
        CommandDispatchByResourceOps, COMMAND_DISPATCH_BY_RESOURCE_OPS,
        DEFAULT_COMMAND_DISPATCH_BY_RESOURCE_OPS,
    };
    use crate::app::controller_pending_command::{
        AppControllerPendingCommand, CommandRecordResolverOps, PendingCommandRecord,
        COMMAND_RECORD_RESOLVER_OPS, DEFAULT_COMMAND_RECORD_RESOLVER_OPS,
    };
    use crate::app::silver_list_table::{
        SilverItemMap, SilverListTable, SilverListTableCtorOps, SILVER_LIST_TABLE_CTOR_OPS,
        DEFAULT_SILVER_LIST_TABLE_CTOR_OPS,
    };
    use crate::cxx::templates::VectorStorage;
    use crate::heap::types::{HeapDescriptor, HeapDescriptorDescriptor};
    use crate::heap::veneers::HEAP_OPS;
    use core::ptr;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes this module's ops table first, then the singleton
    /// caches, then the heap ops (lock order, never two guards of one
    /// lock in a single test).
    static OPS_LOCK: Mutex<()> = Mutex::new(());

    /// The borrowed record the mock resolver hands the table ctor.
    static RESOLVED_NAME: &[u8] = b"handlers.activate";

    /// 16 bytes cover the three words the table ctor links.
    #[repr(C, align(4))]
    struct HeaderNode([u32; 4]);
    static mut HEADER_NODE: HeaderNode = HeaderNode([0xdead_beef; 4]);

    /// Bump arena backing the real COW string construction.
    const ARENA_SIZE: usize = 4096;
    #[repr(C, align(8))]
    struct Arena([u8; ARENA_SIZE]);
    static mut ARENA: Arena = Arena([0; ARENA_SIZE]);
    static mut ARENA_USED: usize = 0;

    /// Dependency call log, in order.
    static mut EVENTS: Vec<&'static str> = Vec::new();
    static mut CONTEXT: *mut u8 = ptr::null_mut();
    static mut CONTROLLER: *mut u8 = ptr::null_mut();
    static mut CONTROLLER_OBJECT: AppControllerPendingCommand = AppControllerPendingCommand {
        opaque_00_3b: [0; 15],
        record_map_word: 0,
        opaque_40_87: [0; 18],
        pending_command: PendingCommandRecord {
            arg2: 0,
            arg3: 0,
            state: 0,
            aux: 0,
        },
    };
    static mut COMMAND_RECORD: PendingCommandRecord = PendingCommandRecord {
        arg2: 0,
        arg3: 0,
        state: 0,
        aux: 0,
    };
    static mut COMMAND_RECORD_SLOT: *mut PendingCommandRecord = ptr::null_mut();
    static mut DISPATCHER: *mut u8 = ptr::null_mut();
    static mut STATE_VALUE: u32 = 0;
    static mut DISPATCH_RESULT: *mut u8 = ptr::null_mut();
    static mut INSTALL_SEEN: (*mut u8, *mut HandlerList) = (ptr::null_mut(), ptr::null_mut());
    static mut DISPATCH_SEEN: (*mut u8, u32, u32, u32) = (ptr::null_mut(), 0, 0, 0);
    static mut OWNER_SEEN: (*mut HandlerListOwner, *mut u8) = (ptr::null_mut(), ptr::null_mut());

    fn events() -> &'static mut Vec<&'static str> {
        unsafe { &mut *ptr::addr_of_mut!(EVENTS) }
    }

    unsafe extern "C" fn mock_context_get() -> *mut u8 {
        events().push("context-get");
        CONTEXT
    }

    unsafe extern "C" fn mock_context_install(context: *mut u8, handlers: *mut HandlerList) {
        events().push("install");
        INSTALL_SEEN = (context, handlers);
    }

    unsafe extern "C" fn mock_context_state(context: *mut u8) -> u32 {
        events().push("state");
        assert_eq!(context, CONTEXT, "the getter result is threaded through");
        STATE_VALUE
    }

    unsafe extern "C" fn mock_begin_command_lookup(
        _map: *mut u32,
        _command: u32,
        _zero: u32,
    ) -> *mut *mut PendingCommandRecord {
        events().push("begin-command");
        ptr::addr_of_mut!(COMMAND_RECORD_SLOT)
    }

    unsafe extern "C" fn record_handlers_activated(
        owner: *mut HandlerListOwner,
        result: *mut u8,
    ) {
        events().push("owner-slot");
        OWNER_SEEN = (owner, result);
    }

    static VTABLE: HandlerListOwnerVtable = HandlerListOwnerVtable {
        unresolved_00_cc: [0; 52],
        handlers_activated: record_handlers_activated,
    };

    unsafe extern "C" fn arena_alloc(
        _heap: *mut HeapDescriptorDescriptor,
        size: usize,
        _tag: usize,
    ) -> *mut u8 {
        let used = ARENA_USED;
        let aligned = (size + 7) & !7;
        if used + aligned > ARENA_SIZE {
            return ptr::null_mut();
        }
        ARENA_USED = used + aligned;
        ptr::addr_of_mut!(ARENA.0).cast::<u8>().add(used)
    }

    unsafe extern "C" fn arena_free(
        _heap: *mut HeapDescriptorDescriptor,
        _ptr: *mut u8,
        _tag: usize,
    ) {
    }

    unsafe extern "C" fn arena_create(
        desc: *mut HeapDescriptor,
        _start: *mut u8,
        _size: usize,
    ) -> *mut HeapDescriptorDescriptor {
        desc as *mut HeapDescriptorDescriptor
    }

    unsafe extern "C" fn mock_header_alloc(_map: *mut SilverItemMap) -> *mut u8 {
        events().push("alloc");
        ptr::addr_of_mut!(HEADER_NODE).cast::<u8>()
    }

    unsafe extern "C" fn mock_populate(_table: *mut SilverListTable) {
        events().push("populate");
    }

    static mut REGISTRY_OBJECT: [u8; 8] = [0; 8];

    unsafe extern "C" fn mock_registry() -> *mut u8 {
        events().push("registry");
        ptr::addr_of_mut!(REGISTRY_OBJECT).cast::<u8>()
    }

    unsafe extern "C" fn mock_resolve(
        _registry: *mut u8,
        _tag: u32,
        _value: u32,
        length_out: *mut u32,
    ) -> *const u8 {
        events().push("resolve");
        length_out.write(RESOLVED_NAME.len() as u32);
        RESOLVED_NAME.as_ptr()
    }

    unsafe extern "C" fn mock_ctor_fail() {
        events().push("ctor-fail");
    }

    unsafe extern "C" fn mock_dispatch_by_name(
        dispatcher: *mut u8,
        _name: *mut u8,
        _name_again: *mut u8,
        resource_id: u32,
        command: u32,
        aux: u32,
    ) -> *mut u8 {
        events().push("dispatch");
        DISPATCH_SEEN = (dispatcher, resource_id, command, aux);
        DISPATCH_RESULT
    }

    unsafe extern "C" fn mock_table_dtor(_table: *mut SilverListTable) {
        events().push("dtor");
    }

    unsafe extern "C" fn mock_fail() {
        events().push("fail");
    }

    struct Installed {
        _mine: MutexGuard<'static, ()>,
        _singletons: MutexGuard<'static, ()>,
        _heap: MutexGuard<'static, ()>,
    }

    fn handler_list() -> HandlerList {
        HandlerList {
            handlers: VectorStorage {
                begin: ptr::null_mut(),
                end: ptr::null_mut(),
                end_of_storage: ptr::null_mut(),
            },
            mode: 0,
            state: 0,
            state_flag: 0,
        }
    }

    unsafe fn install(state: u32, result: *mut u8) -> Installed {
        let mine = OPS_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let singletons = crate::app::singletons::SINGLETON_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let heap = crate::heap::veneers::tests::mock_heap();

        events().clear();
        CONTEXT = 0x2000_0000usize as *mut u8;
        CONTROLLER = ptr::addr_of_mut!(CONTROLLER_OBJECT).cast();
        DISPATCHER = 0x2000_2000usize as *mut u8;
        STATE_VALUE = state;
        DISPATCH_RESULT = result;
        INSTALL_SEEN = (ptr::null_mut(), ptr::null_mut());
        DISPATCH_SEEN = (ptr::null_mut(), 0, 0, 0);
        OWNER_SEEN = (ptr::null_mut(), ptr::null_mut());

        crate::app::singletons::APP_CONTROLLER = CONTROLLER;
        crate::app::singletons::COMMAND_DISPATCHER_INSTANCE = DISPATCHER;

        COMMAND_RECORD_SLOT = ptr::addr_of_mut!(COMMAND_RECORD);
        HANDLER_LIST_ACTIVATE_OPS = HandlerListActivateOps {
            handler_context_get: mock_context_get,
            handler_context_install_list: mock_context_install,
            handler_context_active_state: mock_context_state,
        };
        COMMAND_RECORD_RESOLVER_OPS = CommandRecordResolverOps {
            lookup_slot: mock_begin_command_lookup,
        };
        SILVER_LIST_TABLE_CTOR_OPS = SilverListTableCtorOps {
            map_header_alloc: mock_header_alloc,
            populate: mock_populate,
            registry: mock_registry,
            resolve: mock_resolve,
            fail: mock_ctor_fail,
        };
        COMMAND_DISPATCH_BY_RESOURCE_OPS = CommandDispatchByResourceOps {
            dispatch_by_name: mock_dispatch_by_name,
            table_dtor: mock_table_dtor,
            fail: mock_fail,
        };
        ARENA_USED = 0;
        let heap_ops = ptr::addr_of_mut!(HEAP_OPS);
        (*heap_ops).alloc = arena_alloc;
        (*heap_ops).free = arena_free;
        (*heap_ops).create = arena_create;

        Installed { _mine: mine, _singletons: singletons, _heap: heap }
    }

    unsafe fn restore() {
        HANDLER_LIST_ACTIVATE_OPS = DEFAULT_HANDLER_LIST_ACTIVATE_OPS;
        SILVER_LIST_TABLE_CTOR_OPS = DEFAULT_SILVER_LIST_TABLE_CTOR_OPS;
        COMMAND_DISPATCH_BY_RESOURCE_OPS = DEFAULT_COMMAND_DISPATCH_BY_RESOURCE_OPS;
        COMMAND_RECORD_RESOLVER_OPS = DEFAULT_COMMAND_RECORD_RESOLVER_OPS;
        crate::app::singletons::APP_CONTROLLER = ptr::null_mut();
        crate::app::singletons::COMMAND_DISPATCHER_INSTANCE = ptr::null_mut();
        events().clear();
    }

    #[test]
    fn installs_posts_dispatches_and_tail_calls_in_the_original_order() {
        let mut owner = HandlerListOwner { vtable: &VTABLE };
        let mut list = handler_list();
        let result = 0x2000_3000usize as *mut u8;

        unsafe {
            let _installed = install(0x5a5a_0001, result);

            handler_list_activate(ptr::addr_of_mut!(owner), ptr::addr_of_mut!(list));

            assert_eq!(
                events().as_slice(),
                [
                    "context-get",
                    "install",
                    "context-get",
                    "state",
                    "begin-command",
                    "alloc",
                    "registry",
                    "resolve",
                    "dispatch",
                    "dtor",
                    "owner-slot",
                ],
                "install -> state -> controller post -> dispatch -> owner slot"
            );
            assert_eq!(INSTALL_SEEN, (CONTEXT, ptr::addr_of_mut!(list)));
            assert_eq!(
                [
                    CONTROLLER_OBJECT.pending_command.arg2,
                    CONTROLLER_OBJECT.pending_command.arg3,
                    CONTROLLER_OBJECT.pending_command.state,
                    CONTROLLER_OBJECT.pending_command.aux,
                ],
                [0, 0, 0x5a5a_0001, 0],
                "the context state word rides the controller's pending-command record"
            );
            assert_eq!(
                DISPATCH_SEEN,
                (
                    DISPATCHER,
                    HANDLER_LIST_RESOURCE,
                    HANDLER_LIST_ACTIVATE_COMMAND,
                    0
                ),
                "resource = command - 1, aux = 0, as in the raw ARM"
            );
            assert_eq!(
                OWNER_SEEN,
                (ptr::addr_of_mut!(owner), result),
                "the dispatch result crosses to vtable slot +0xd0 verbatim"
            );

            restore();
        }
    }

    #[test]
    fn forwards_a_zero_state_and_the_dispatch_result_verbatim() {
        let mut owner = HandlerListOwner { vtable: &VTABLE };
        let mut list = handler_list();
        let result = 0x2000_4000usize as *mut u8;

        unsafe {
            let _installed = install(0, result);

            handler_list_activate(ptr::addr_of_mut!(owner), ptr::addr_of_mut!(list));

            assert_eq!(
                [
                    CONTROLLER_OBJECT.pending_command.arg2,
                    CONTROLLER_OBJECT.pending_command.arg3,
                    CONTROLLER_OBJECT.pending_command.state,
                    CONTROLLER_OBJECT.pending_command.aux,
                ],
                [0, 0, 0, 0],
                "a NULL context link surfaces as state 0, not a skipped post"
            );
            assert_eq!(OWNER_SEEN, (ptr::addr_of_mut!(owner), result));
            assert_eq!(
                events().last().copied(),
                Some("owner-slot"),
                "the virtual tail dispatch always runs"
            );

            restore();
        }
    }
}
