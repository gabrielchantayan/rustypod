//! `command_dispatch_by_resource` — original: `FUN_081dfab0` @
//! 0x081dfab0 (**96 bytes**, 0x081dfab0..0x081dfb10 — Ghidra's extent is
//! correct this time: the next function opens `push {r0, r1, r2, r3, r4,
//! r5, r6, r7, r8, lr}` @ 0x081dfb10; **40 `bl` and 0 `b` call sites**,
//! binary-scanned by decoding every B/BL word in
//! `work/firmware/osos.dec`; all 40 are unconditional, no predicated
//! forms).
//!
//! A method of the command dispatcher singleton
//! ([`crate::app::singletons::command_dispatcher_get`] @ 0x081dfa20 —
//! `this` is `r0`): dispatch a command selected by **resource id**. The
//! dispatcher's own map at +0x04 is keyed by command-NAME string, so the
//! id must first be turned into a name — which is exactly what the
//! `"SCST"` resolution in the Silver list table constructor does. This
//! function is the bridge:
//!
//! ```text
//! 081dfab0  push {r4, r5, r6, r7, lr}
//! 081dfab4  sub  sp, sp, #60        @ 48-byte table @ sp+12 fills the frame
//! 081dfab8  mov  r5, r2             @ command
//! 081dfabc  mov  r4, r0             @ dispatcher (this)
//! 081dfac0  add  r0, sp, #12        @ &table
//! 081dfac4  mov  r2, #0             @ populate = 0
//! 081dfac8  mov  r7, r1             @ resource_id
//! 081dfacc  mov  r6, r3             @ aux
//! 081dfad0  bl   0x081473d8         @ silver_list_table_ctor(&table, resource_id, 0)
//! 081dfad4  ldr  r0, [sp, #52]      @ table.name  (table +0x28)
//! 081dfad8  mov  r3, r7             @ resource_id
//! 081dfadc  mov  r1, r0             @ name
//! 081dfae0  mov  r2, r0             @ name, a second time
//! 081dfae4  mov  r0, r4             @ dispatcher
//! 081dfae8  stm  sp, {r5, r6}       @ stack args: command, aux
//! 081dfaec  bl   0x081dfb10         @ dispatch_by_name(dispatcher, name, name,
//!                                   @                  resource_id, command, aux)
//! 081dfaf0  cmp  r0, #0
//! 081dfaf4  bleq 0x08030f44         @ heap_panic() on NULL — does not return
//! 081dfaf8  mov  r4, r0
//! 081dfafc  add  r0, sp, #12
//! 081dfb00  bl   0x081474d0         @ silver_list_table_dtor(&table)
//! 081dfb04  mov  r0, r4
//! 081dfb08  add  sp, sp, #60
//! 081dfb0c  pop  {r4, r5, r6, r7, pc}
//! ```
//!
//! The temporary table is constructed **unpopulated** (`populate = 0`):
//! no `"SLst"` items are ever loaded — the object exists only to carry
//! the `"SCST"` record's resolved name at its +0x28, which is then read
//! once (`ldr r0, [sp, #52]`, one past Ghidra's 40-byte `auStack_44`
//! because Ghidra sized the buffer from the constructor's *visible*
//! writes and missed the +0x2c store) and handed to the by-name
//! dispatcher **twice** (both `r1` and `r2`).
//!
//! `FUN_081dfb10` (unported; the very next function, 0x081dfb10..) builds
//! a temporary COW string from the name (`cxx_string_from_cstr` @
//! 0x083d8b5c), looks the key up in the dispatcher's +0x04 map
//! (`FUN_083db41c`), releases the temporary, compares the resulting
//! iterator against the map end word cached at dispatcher +0x14
//! (`FUN_083cf800`) and answers NULL on a miss; on a hit it invokes the
//! found record's +0x18 handler slot with `(name, resource_id, command,
//! aux)`, panicking (`bleq heap_panic`) if that slot itself is NULL.
//!
//! A NULL answer from the by-name dispatcher is **fatal** here too
//! (`cmp r0, #0; bleq 0x08030f44`): the destructor never runs on that
//! path, the temporary table simply dies with the frame.
//!
//! # Call sites
//!
//! All 40 sites sit in Silver controller code and follow one shape —
//! [`command_dispatcher_get`], then this function with
//! `(resource_id - 1, resource_id, 0)` (observed also `aux = 6`), then
//! the result handed to a virtual slot of the controller (`vtable +4`,
//! `+0xd0`, ...). The ids live in the private 0x0dad0000 namespace the
//! `command_dispatcher_get` ledger entry documents. Example
//! (`FUN_0810359c`):
//!
//! ```text
//! uVar4 = command_dispatcher_get();
//! uVar4 = FUN_081dfab0(uVar4, DAT_081036b8 + -1, DAT_081036b8, 0);
//! ```
//!
//! # Deviations
//!
//! - The by-name dispatcher `FUN_081dfb10` and the table destructor
//!   `FUN_081474d0` are **unported** and ride the
//!   [`COMMAND_DISPATCH_BY_RESOURCE_OPS`] `read_volatile` dispatch table
//!   (house pattern); `fail` (`heap_panic`, ported) sits beside them so
//!   the fatal path is observable in host tests — the same call-boundary
//!   decision `app/silver_list_table.rs`'s ctor seam makes. The target
//!   defaults transmute the real firmware addresses 0x081dfb10 /
//!   0x081474d0 / 0x08030f44, so the port **is hook-ready on device**.
//! - A swapped-in `fail` hook that returns stops the dispatch at the
//!   NULL answer and returns it without running the destructor — the
//!   original never reaches the destructor on that path either
//!   (`heap_panic` does not return), so skipping it is the faithful
//!   shape; only the (unobservable) register clobber of a returning
//!   `heap_panic` differs.
//! - The temporary table is `MaybeUninit` stack storage, exactly the
//!   original's `sub sp, sp, #60` frame: the constructor writes every
//!   field before anything reads it.

use crate::app::silver_list_table::{silver_list_table_ctor, SilverListTable};

/// The retailOS dependencies of [`command_dispatch_by_resource`].
#[derive(Clone, Copy)]
pub struct CommandDispatchByResourceOps {
    /// `FUN_081dfb10` @ 0x081dfb10 — the by-name dispatcher: looks `name`
    /// up in the command dispatcher's +0x04 string-keyed map and invokes
    /// the found record's +0x18 handler with `(name, resource_id,
    /// command, aux)`, NULL on a miss. The original passes the name word
    /// in both `r1` and `r2`; `name_again` preserves that.
    pub dispatch_by_name: unsafe extern "C" fn(
        dispatcher: *mut u8,
        name: *mut u8,
        name_again: *mut u8,
        resource_id: u32,
        command: u32,
        aux: u32,
    ) -> *mut u8,
    /// `FUN_081474d0` @ 0x081474d0 — the Silver list table destructor
    /// (252 bytes, 0x081474d0..0x081475cc; re-plants the same vtable
    /// 0x08986434 the constructor plants, then tears down the map and
    /// the +0x28 name string).
    pub table_dtor: unsafe extern "C" fn(table: *mut SilverListTable),
    /// `FUN_08030f44` (`heap_panic`) — the fatal NULL-result path; it
    /// does not return. Host test replacements may return, in which case
    /// the dispatch stops at the NULL answer and hands it back.
    pub fail: unsafe extern "C" fn(),
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_dispatch_by_name(
    dispatcher: *mut u8,
    name: *mut u8,
    name_again: *mut u8,
    resource_id: u32,
    command: u32,
    aux: u32,
) -> *mut u8 {
    let dispatch: unsafe extern "C" fn(*mut u8, *mut u8, *mut u8, u32, u32, u32) -> *mut u8 =
        unsafe { core::mem::transmute(0x081d_fb10usize) };
    unsafe { dispatch(dispatcher, name, name_again, resource_id, command, aux) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_dispatch_by_name(
    _dispatcher: *mut u8,
    _name: *mut u8,
    _name_again: *mut u8,
    _resource_id: u32,
    _command: u32,
    _aux: u32,
) -> *mut u8 {
    panic!("command_dispatch_by_resource requires by-name dispatcher 0x081dfb10")
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_table_dtor(table: *mut SilverListTable) {
    let dtor: unsafe extern "C" fn(*mut SilverListTable) =
        unsafe { core::mem::transmute(0x0814_74d0usize) };
    unsafe { dtor(table) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_table_dtor(_table: *mut SilverListTable) {
    panic!("command_dispatch_by_resource requires list table destructor 0x081474d0")
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_dispatch_fail() {
    let fail: unsafe extern "C" fn() -> ! = unsafe { core::mem::transmute(0x0803_0f44usize) };
    unsafe { fail() }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_dispatch_fail() {
    panic!("command_dispatch_by_resource: the by-name dispatcher answered NULL")
}

/// Wired defaults for [`COMMAND_DISPATCH_BY_RESOURCE_OPS`].
#[cfg(target_os = "none")]
pub const DEFAULT_COMMAND_DISPATCH_BY_RESOURCE_OPS: CommandDispatchByResourceOps =
    CommandDispatchByResourceOps {
        dispatch_by_name: firmware_dispatch_by_name,
        table_dtor: firmware_table_dtor,
        fail: firmware_dispatch_fail,
    };

/// Wired defaults for [`COMMAND_DISPATCH_BY_RESOURCE_OPS`].
#[cfg(not(target_os = "none"))]
pub const DEFAULT_COMMAND_DISPATCH_BY_RESOURCE_OPS: CommandDispatchByResourceOps =
    CommandDispatchByResourceOps {
        dispatch_by_name: missing_dispatch_by_name,
        table_dtor: missing_table_dtor,
        fail: missing_dispatch_fail,
    };

/// Active model of the unported retailOS dependencies. Target
/// integration replaces the slots as 0x081dfb10 / 0x081474d0 are ported;
/// host tests install recording mocks.
pub static mut COMMAND_DISPATCH_BY_RESOURCE_OPS: CommandDispatchByResourceOps =
    DEFAULT_COMMAND_DISPATCH_BY_RESOURCE_OPS;

#[inline(always)]
unsafe fn dispatch_ops() -> CommandDispatchByResourceOps {
    core::ptr::read_volatile(core::ptr::addr_of!(COMMAND_DISPATCH_BY_RESOURCE_OPS))
}

/// command_dispatch_by_resource — original: `FUN_081dfab0` @ 0x081dfab0
/// (96 bytes; **40 `bl` call sites**, all unconditional, binary-scanned).
///
/// Dispatches the command selected by `resource_id` through the command
/// dispatcher singleton:
///
/// 1. Stack-constructs a temporary Silver list table for `resource_id`
///    **unpopulated** (`populate = 0`) — the object exists only to
///    resolve the `"SCST"` record's name into its +0x28 word.
/// 2. Reads that name word once and calls the by-name dispatcher
///    `FUN_081dfb10` with the name in **both** name slots, plus
///    `resource_id`, `command` and `aux` forwarded verbatim.
/// 3. A NULL answer is fatal (`heap_panic`, non-returning) — the
///    destructor does not run on that path.
/// 4. Otherwise the temporary table is destroyed and the handler's
///    return value handed back untouched.
///
/// There is no NULL guard on `dispatcher`: the original hands `r0`
/// straight through to the by-name dispatcher.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn command_dispatch_by_resource(
    dispatcher: *mut u8,
    resource_id: u32,
    command: u32,
    aux: u32,
) -> *mut u8 {
    let ops = dispatch_ops();
    let mut table = core::mem::MaybeUninit::<SilverListTable>::uninit();
    let table = table.as_mut_ptr();
    silver_list_table_ctor(table, resource_id, 0);
    let name = (*table).name;
    let result = (ops.dispatch_by_name)(dispatcher, name, name, resource_id, command, aux);
    if result.is_null() {
        (ops.fail)();
        // heap_panic does not return; a swapped-in host hook may, in
        // which case the dispatch stops at the NULL answer — the
        // destructor is not reached on this path, as in the original.
        return result;
    }
    (ops.table_dtor)(table);
    result
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::app::silver_list_table::{
        SilverItemMap, SilverListTableCtorOps, SILVER_LIST_TABLE_CTOR_OPS,
        DEFAULT_SILVER_LIST_TABLE_CTOR_OPS,
    };
    use crate::heap::types::{HeapDescriptor, HeapDescriptorDescriptor};
    use crate::heap::veneers::HEAP_OPS;
    use core::ptr;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    static OPS_LOCK: Mutex<()> = Mutex::new(());

    /// The borrowed record the mock resolver hands out.
    static RESOLVED_NAME: &[u8] = b"silver.command.pane";

    /// The header node the mock map allocator hands the table ctor; 16
    /// bytes cover the three words the constructor links (silver_list_
    /// table.rs's test pattern).
    #[repr(C, align(4))]
    struct HeaderNode([u32; 4]);
    static mut HEADER_NODE: HeaderNode = HeaderNode([0xdead_beef; 4]);

    /// Bump arena backing the real COW string construction.
    const ARENA_SIZE: usize = 4096;
    #[repr(C, align(8))]
    struct Arena([u8; ARENA_SIZE]);
    static mut ARENA: Arena = Arena([0; ARENA_SIZE]);
    static mut ARENA_USED: usize = 0;

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

    /// Dependency call log, in order.
    static mut EVENTS: Vec<&'static str> = Vec::new();
    static mut POPULATE_CALLS: usize = 0;
    static mut RESOLVE_SEEN_ID: u32 = 0;
    static mut REGISTRY_OBJECT: [u8; 8] = [0; 8];
    static mut DISPATCH_SEEN: (
        *mut u8,
        *mut u8,
        *mut u8,
        u32,
        u32,
        u32,
    ) = (ptr::null_mut(), ptr::null_mut(), ptr::null_mut(), 0, 0, 0);
    static mut DISPATCH_RESULT: *mut u8 = ptr::null_mut();
    static mut DTOR_SEEN: *mut SilverListTable = ptr::null_mut();
    /// Snapshots taken inside the dtor mock — the table is dead stack
    /// storage once the port returns, so its fields are read at dtor
    /// time, not afterwards.
    static mut DTOR_SEEN_NAME: *mut u8 = ptr::null_mut();
    static mut DTOR_SEEN_RESOURCE_ID: u32 = 0;

    fn events() -> &'static mut Vec<&'static str> {
        unsafe { &mut *ptr::addr_of_mut!(EVENTS) }
    }

    unsafe extern "C" fn mock_header_alloc(_map: *mut SilverItemMap) -> *mut u8 {
        events().push("alloc");
        ptr::addr_of_mut!(HEADER_NODE).cast::<u8>()
    }

    unsafe extern "C" fn mock_populate(_table: *mut SilverListTable) {
        POPULATE_CALLS += 1;
        events().push("populate");
    }

    unsafe extern "C" fn mock_registry() -> *mut u8 {
        events().push("registry");
        ptr::addr_of_mut!(REGISTRY_OBJECT).cast::<u8>()
    }

    unsafe extern "C" fn mock_resolve(
        _registry: *mut u8,
        _tag: u32,
        value: u32,
        length_out: *mut u32,
    ) -> *const u8 {
        events().push("resolve");
        RESOLVE_SEEN_ID = value;
        length_out.write(RESOLVED_NAME.len() as u32);
        RESOLVED_NAME.as_ptr()
    }

    unsafe extern "C" fn mock_resolve_miss(
        _registry: *mut u8,
        _tag: u32,
        value: u32,
        _length_out: *mut u32,
    ) -> *const u8 {
        events().push("resolve");
        RESOLVE_SEEN_ID = value;
        ptr::null()
    }

    unsafe extern "C" fn mock_ctor_fail() {
        // heap_panic does not return; this host mock does, so the ctor's
        // documented stop-at-the-failed-resolution path runs.
        events().push("ctor-fail");
    }

    unsafe extern "C" fn mock_dispatch_by_name(
        dispatcher: *mut u8,
        name: *mut u8,
        name_again: *mut u8,
        resource_id: u32,
        command: u32,
        aux: u32,
    ) -> *mut u8 {
        events().push("dispatch");
        DISPATCH_SEEN = (dispatcher, name, name_again, resource_id, command, aux);
        DISPATCH_RESULT
    }

    unsafe extern "C" fn mock_table_dtor(table: *mut SilverListTable) {
        events().push("dtor");
        DTOR_SEEN = table;
        DTOR_SEEN_NAME = (*table).name;
        DTOR_SEEN_RESOURCE_ID = (*table).resource_id;
    }

    unsafe extern "C" fn mock_fail() {
        events().push("fail");
    }

    /// Serializes both ops tables and the heap arena: mine first, then
    /// the heap lock (never a second guard of the same lock in one test).
    unsafe fn install(hit: bool, result: *mut u8) -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        events().clear();
        POPULATE_CALLS = 0;
        RESOLVE_SEEN_ID = 0;
        DISPATCH_SEEN = (ptr::null_mut(), ptr::null_mut(), ptr::null_mut(), 0, 0, 0);
        DISPATCH_RESULT = result;
        DTOR_SEEN = ptr::null_mut();
        DTOR_SEEN_NAME = ptr::null_mut();
        DTOR_SEEN_RESOURCE_ID = 0;
        SILVER_LIST_TABLE_CTOR_OPS = SilverListTableCtorOps {
            map_header_alloc: mock_header_alloc,
            populate: mock_populate,
            registry: mock_registry,
            resolve: if hit { mock_resolve } else { mock_resolve_miss },
            fail: mock_ctor_fail,
        };
        COMMAND_DISPATCH_BY_RESOURCE_OPS = CommandDispatchByResourceOps {
            dispatch_by_name: mock_dispatch_by_name,
            table_dtor: mock_table_dtor,
            fail: mock_fail,
        };
        guard
    }

    unsafe fn restore() {
        SILVER_LIST_TABLE_CTOR_OPS = DEFAULT_SILVER_LIST_TABLE_CTOR_OPS;
        COMMAND_DISPATCH_BY_RESOURCE_OPS = DEFAULT_COMMAND_DISPATCH_BY_RESOURCE_OPS;
        events().clear();
    }

    fn install_arena() -> MutexGuard<'static, ()> {
        let guard = crate::heap::veneers::tests::mock_heap();
        unsafe {
            ARENA_USED = 0;
            let ops = ptr::addr_of_mut!(HEAP_OPS);
            (*ops).alloc = arena_alloc;
            (*ops).free = arena_free;
            (*ops).create = arena_create;
        }
        guard
    }

    unsafe fn name_bytes(name: *mut u8) -> &'static [u8] {
        let rep = crate::cxx::string::data_rep(name);
        core::slice::from_raw_parts(name, (*rep).length as usize)
    }

    #[test]
    fn happy_path_builds_an_unpopulated_table_and_forwards_its_name_twice() {
        let created = 0x2000_0000usize as *mut u8;
        let dispatcher = 0x1000_0000usize as *mut u8;

        unsafe {
            let guard = install(true, created);
            let _heap = install_arena();

            let result = command_dispatch_by_resource(dispatcher, 0x0dad_05b7, 0x0dad_05b8, 6);

            assert_eq!(result, created, "the handler's return crosses back verbatim");
            assert_eq!(
                events().as_slice(),
                ["alloc", "registry", "resolve", "dispatch", "dtor"],
                "ctor (no populate) -> dispatch -> dtor, in the original's order"
            );
            assert_eq!(POPULATE_CALLS, 0, "the temporary table is built with populate = 0");
            assert_eq!(RESOLVE_SEEN_ID, 0x0dad_05b7, "the ctor resolved resource_id");

            let (seen_dispatcher, name, name_again, id, command, aux) = DISPATCH_SEEN;
            assert_eq!(seen_dispatcher, dispatcher, "this is forwarded as r0");
            assert_eq!(name, name_again, "the name word goes in both r1 and r2");
            assert_eq!(name_bytes(name), RESOLVED_NAME, "the SCST-resolved name");
            assert_eq!((id, command, aux), (0x0dad_05b7, 0x0dad_05b8, 6));

            assert!(!DTOR_SEEN.is_null(), "the temporary table is destroyed");
            assert_eq!(
                DTOR_SEEN_NAME, name,
                "the dtor runs on the same table whose name was dispatched"
            );
            assert_eq!(
                DTOR_SEEN_RESOURCE_ID, 0x0dad_05b7,
                "the temporary table carried the requested resource"
            );
            restore();
            drop(guard);
        }
    }

    #[test]
    fn a_null_answer_is_fatal_and_skips_the_destructor() {
        let dispatcher = 0x1000_0000usize as *mut u8;

        unsafe {
            let guard = install(true, ptr::null_mut());
            let _heap = install_arena();

            let result = command_dispatch_by_resource(dispatcher, 0x0dad_01d6, 0x0dad_01d7, 0);

            assert!(result.is_null(), "the NULL answer is handed back when fail returns");
            assert_eq!(
                events().as_slice(),
                ["alloc", "registry", "resolve", "dispatch", "fail"],
                "heap_panic fires immediately after the NULL answer"
            );
            assert!(
                DTOR_SEEN.is_null(),
                "the destructor never runs on the fatal path — as in the original"
            );
            restore();
            drop(guard);
        }
    }

    #[test]
    fn a_failed_resolution_dispatches_the_empty_name() {
        // The ctor's own fail path parks the name on the shared empty
        // rep; the dispatch still goes ahead with that word — nothing in
        // FUN_081dfab0 gates on the resolution having succeeded.
        let created = 0x2000_0000usize as *mut u8;
        let dispatcher = 0x1000_0000usize as *mut u8;

        unsafe {
            let guard = install(false, created);
            let _heap = install_arena();

            let result = command_dispatch_by_resource(dispatcher, 0x0dad_0e00, 0x0dad_0e01, 0);

            assert_eq!(result, created);
            assert_eq!(
                events().as_slice(),
                ["alloc", "registry", "resolve", "ctor-fail", "dispatch", "dtor"]
            );
            let (_, name, name_again, id, ..) = DISPATCH_SEEN;
            assert_eq!(name, name_again);
            assert_eq!(
                name,
                crate::cxx::string::empty_rep_data(),
                "the unresolved table dispatches its empty-rep name"
            );
            assert_eq!(id, 0x0dad_0e00);
            restore();
            drop(guard);
        }
    }
}
