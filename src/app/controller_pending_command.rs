//! Controller pending-command support.
//!
//! `command_record_resolve_or_allocate` — original: `FUN_08182c78` @
//! **0x08182c78**. The raw extent is **104 bytes**, `0x08182c78..0x08182ce0`:
//! `0x08182ce0` starts the separately linked next function with `push
//! {r4-r11,lr}`. Decoding every ARM B/BL word in `osos.dec` finds eight direct
//! `bl` sites, all unconditional, at `0x0817ebf4`, `0x0817eedc`,
//! `0x0817eef8`, `0x0817fdb8`, `0x0817fe08`, `0x0818112c`, `0x08183968`, and
//! `0x081847e0`; there are no predicated calls. One additional unconditional
//! plain-`b` tail site at `0x0817f404` reaches it.
//!
//! # Algorithm
//!
//! A zero first key returns NULL without touching the controller. Otherwise,
//! look up the `(first_key, second_key)` slot in the controller's map state at
//! `+0x3c`. A non-NULL record already in that slot is returned. On a NULL slot,
//! a zero `allocate` also returns NULL; a nonzero `allocate` obtains 16 bytes
//! through `operator_new`, initializes it as `{0, 0, 0, 0xffffffff}`, looks up
//! the slot again, stores the record there, and returns it. The allocation
//! result has no NULL guard, exactly as the retail body calls the initializer
//! immediately after new.
//!
//! # Deliberate deviations
//!
//! The slot-lookup helper `FUN_083daf6c` is not ported. Its identity is not
//! inferred: the observed contract is represented by the volatile
//! `COMMAND_RECORD_RESOLVER_OPS.lookup_slot` dispatch. Device builds call its
//! stock address; host tests provide a slot fixture. The previous
//! `FUN_08182c78` dispatch seam in this module is removed, so the ported
//! `app_controller_begin_command` caller now invokes this function directly.

/// The four argument words in a controller command record.
#[repr(C)]
pub struct PendingCommandRecord {
    pub arg2: u32,
    pub arg3: u32,
    pub state: u32,
    pub aux: u32,
}

/// The controller prefix observed by the command-record resolver and
/// [`app_controller_begin_command`].
#[repr(C)]
pub struct AppControllerPendingCommand {
    /// +0x00..+0x3b: controller state not observed here.
    pub opaque_00_3b: [u32; 15],
    /// +0x3c: beginning of the inline map state consumed by `FUN_083daf6c`.
    /// Its full layout is not recovered; only its address is passed through.
    pub record_map_word: u32,
    /// +0x40..+0x87: controller state not observed here.
    pub opaque_40_87: [u32; 18],
    /// +0x88: four-word command data mirrored from the resolved record.
    pub pending_command: PendingCommandRecord,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x3c] = [0; core::mem::offset_of!(AppControllerPendingCommand, record_map_word)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x88] = [0; core::mem::offset_of!(AppControllerPendingCommand, pending_command)];

/// The observed interface of unported `FUN_083daf6c`: return the slot holding
/// the record keyed by the two supplied words in the map state at `map`.
#[derive(Clone, Copy)]
pub struct CommandRecordResolverOps {
    pub lookup_slot: unsafe extern "C" fn(
        map: *mut u32,
        first_key: u32,
        second_key: u32,
    ) -> *mut *mut PendingCommandRecord,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_lookup_slot(
    map: *mut u32,
    first_key: u32,
    second_key: u32,
) -> *mut *mut PendingCommandRecord {
    let lookup: unsafe extern "C" fn(*mut u32, *const u32) -> *mut *mut PendingCommandRecord =
        unsafe { core::mem::transmute(0x083d_af6cusize) };
    let key = [first_key, second_key];
    unsafe { lookup(map, key.as_ptr()) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_lookup_slot(
    _map: *mut u32,
    _first_key: u32,
    _second_key: u32,
) -> *mut *mut PendingCommandRecord {
    panic!("command_record_resolve_or_allocate requires slot lookup 0x083daf6c")
}

/// Default wiring for the unported command-record slot lookup.
#[cfg(target_os = "none")]
pub const DEFAULT_COMMAND_RECORD_RESOLVER_OPS: CommandRecordResolverOps = CommandRecordResolverOps {
    lookup_slot: firmware_lookup_slot,
};

/// Default wiring for the unported command-record slot lookup.
#[cfg(not(target_os = "none"))]
pub const DEFAULT_COMMAND_RECORD_RESOLVER_OPS: CommandRecordResolverOps = CommandRecordResolverOps {
    lookup_slot: missing_lookup_slot,
};

/// Active implementation of the unported command-record slot lookup.
pub static mut COMMAND_RECORD_RESOLVER_OPS: CommandRecordResolverOps =
    DEFAULT_COMMAND_RECORD_RESOLVER_OPS;

#[inline(always)]
fn command_record_resolver_ops() -> CommandRecordResolverOps {
    unsafe {
        core::ptr::read_volatile(core::ptr::addr_of!(COMMAND_RECORD_RESOLVER_OPS))
    }
}

/// Resolves a controller command record and optionally creates it.
///
/// Original: `FUN_08182c78` @ `0x08182c78` (104 bytes, **8 unconditional
/// `bl` call sites** and one unconditional plain-`b` tail site,
/// binary-scanned). A zero `first_key` returns NULL before reading
/// `controller`; a NULL slot with nonzero `allocate` is allocated and
/// initialized without an allocation-result guard.
///
/// # Safety
///
/// When `first_key` is nonzero, `controller` must be aligned and valid through
/// its map state. The active lookup must return a writable slot. If that slot
/// is NULL and `allocate` is nonzero, the allocator must return writable,
/// four-word-aligned storage, as the retail initializer dereferences it
/// unconditionally.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.command_record_resolve_or_allocate")]
pub unsafe extern "C" fn command_record_resolve_or_allocate(
    controller: *mut AppControllerPendingCommand,
    first_key: u32,
    second_key: u32,
    allocate: u32,
) -> *mut PendingCommandRecord {
    if first_key == 0 {
        return core::ptr::null_mut();
    }

    let ops = command_record_resolver_ops();
    let slot = (ops.lookup_slot)(
        core::ptr::addr_of_mut!((*controller).record_map_word),
        first_key,
        second_key,
    );
    let record = slot.read();
    if !record.is_null() {
        return record;
    }
    if allocate == 0 {
        return core::ptr::null_mut();
    }

    let record = crate::heap::veneers::operator_new(16).cast::<u32>();
    let record = crate::util::four_word_sentinel_init::four_word_sentinel_init(record)
        .cast::<PendingCommandRecord>();
    let slot = (ops.lookup_slot)(
        core::ptr::addr_of_mut!((*controller).record_map_word),
        first_key,
        second_key,
    );
    slot.write(record);
    record
}

/// Posts a four-word command record and mirrors it at the controller's
/// `+0x88` pending-command slot.
///
/// Original: `FUN_08181110` @ `0x08181110` (48 bytes, **9 unconditional
/// `bl` call sites**, binary-scanned). The resolved record and `controller`
/// are dereferenced without NULL guards, as in retailOS.
///
/// # Safety
///
/// `controller` must be valid through its pending-command field; the command
/// record lookup must return a writable record for `(command, 0)`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn app_controller_begin_command(
    controller: *mut AppControllerPendingCommand,
    command: u32,
    arg2: u32,
    arg3: u32,
    state: u32,
    aux: u32,
) {
    let record = command_record_resolve_or_allocate(controller, command, 0, 1);
    (*record).arg2 = arg2;
    (*record).arg3 = arg3;
    (*record).state = state;
    (*record).aux = aux;
    (*controller).pending_command.arg2 = arg2;
    (*controller).pending_command.arg3 = arg3;
    (*controller).pending_command.state = state;
    (*controller).pending_command.aux = aux;
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr;
    use std::sync::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut RECORD_SLOT: *mut PendingCommandRecord = ptr::null_mut();
    static mut LOOKUP_CALLS: usize = 0;
    static mut LOOKUP_SEEN: (*mut u32, u32, u32) = (ptr::null_mut(), 0, 0);

    unsafe extern "C" fn mock_lookup_slot(
        map: *mut u32,
        first_key: u32,
        second_key: u32,
    ) -> *mut *mut PendingCommandRecord {
        LOOKUP_CALLS += 1;
        LOOKUP_SEEN = (map, first_key, second_key);
        ptr::addr_of_mut!(RECORD_SLOT)
    }

    struct Installed {
        _ops: MutexGuard<'static, ()>,
        _heap: MutexGuard<'static, ()>,
    }

    unsafe fn install(record: *mut PendingCommandRecord) -> Installed {
        let ops = OPS_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let heap = crate::heap::veneers::tests::mock_heap();
        RECORD_SLOT = record;
        LOOKUP_CALLS = 0;
        LOOKUP_SEEN = (ptr::null_mut(), 0, 0);
        COMMAND_RECORD_RESOLVER_OPS = CommandRecordResolverOps {
            lookup_slot: mock_lookup_slot,
        };
        Installed { _ops: ops, _heap: heap }
    }

    unsafe fn restore() {
        COMMAND_RECORD_RESOLVER_OPS = DEFAULT_COMMAND_RECORD_RESOLVER_OPS;
        RECORD_SLOT = ptr::null_mut();
    }

    fn controller() -> AppControllerPendingCommand {
        AppControllerPendingCommand {
            opaque_00_3b: [0xa5a5_a5a5; 15],
            record_map_word: 0xa5a5_a5a5,
            opaque_40_87: [0xa5a5_a5a5; 18],
            pending_command: PendingCommandRecord {
                arg2: 0x1111_1111,
                arg3: 0x2222_2222,
                state: 0x3333_3333,
                aux: 0x4444_4444,
            },
        }
    }

    #[test]
    fn zero_first_key_skips_lookup_and_allocation() {
        unsafe {
            let _installed = install(ptr::null_mut());
            let record = command_record_resolve_or_allocate(ptr::null_mut(), 0, 0xfeed_face, 1);

            assert!(record.is_null());
            assert_eq!(LOOKUP_SEEN, (ptr::null_mut(), 0, 0));
            assert_eq!(crate::heap::veneers::tests::alloc_log().0, 0);
            assert_eq!(LOOKUP_CALLS, 0);
            restore();
        }
    }

    #[test]
    fn existing_record_returns_without_allocation() {
        let mut controller = controller();
        let mut record = PendingCommandRecord {
            arg2: 1,
            arg3: 2,
            state: 3,
            aux: 4,
        };

        unsafe {
            let _installed = install(ptr::addr_of_mut!(record));
            let resolved = command_record_resolve_or_allocate(
                ptr::addr_of_mut!(controller), 0x0dad_0195, 0x0123_4567, 1,
            );

            assert_eq!(resolved, ptr::addr_of_mut!(record));
            assert_eq!(
                LOOKUP_SEEN,
                (
                    ptr::addr_of_mut!(controller.record_map_word),
                    0x0dad_0195,
                    0x0123_4567,
                ),
            );
            assert_eq!([record.arg2, record.arg3, record.state, record.aux], [1, 2, 3, 4]);
            assert_eq!(crate::heap::veneers::tests::alloc_log().0, 0);
            assert_eq!(LOOKUP_CALLS, 1);
            restore();
        }
    }

    #[test]
    fn missing_record_without_allocate_returns_null() {
        let mut controller = controller();

        unsafe {
            let _installed = install(ptr::null_mut());
            let resolved = command_record_resolve_or_allocate(
                ptr::addr_of_mut!(controller), 7, 0x8000_0000, 0,
            );

            assert!(resolved.is_null());
            assert!(RECORD_SLOT.is_null());
            assert_eq!(crate::heap::veneers::tests::alloc_log().0, 0);
            assert_eq!(LOOKUP_CALLS, 1);
            restore();
        }
    }

    #[test]
    fn missing_record_allocates_initializes_and_caches_sentinel() {
        let mut controller = controller();
        let mut storage = PendingCommandRecord {
            arg2: 0xaaaa_aaaa,
            arg3: 0xbbbb_bbbb,
            state: 0xcccc_cccc,
            aux: 0xdddd_dddd,
        };

        unsafe {
            let _installed = install(ptr::null_mut());
            crate::heap::veneers::tests::set_alloc_ret(ptr::addr_of_mut!(storage).cast());
            let resolved = command_record_resolve_or_allocate(
                ptr::addr_of_mut!(controller), 1, 0, 0xffff_ffff,
            );

            assert_eq!(resolved, ptr::addr_of_mut!(storage));
            assert_eq!(resolved, RECORD_SLOT);
            assert_eq!(
                [storage.arg2, storage.arg3, storage.state, storage.aux],
                [0, 0, 0, u32::MAX],
            );
            assert_eq!(crate::heap::veneers::tests::alloc_log(), (1, 16, 2));
            assert_eq!(LOOKUP_CALLS, 2, "the retail miss path re-looks up the slot before storing");
            restore();
        }
    }
    #[test]
    fn begin_command_resolves_allocating_record_and_mirrors_every_argument_word() {
        let mut controller = controller();
        let mut record = PendingCommandRecord {
            arg2: 0,
            arg3: 0,
            state: 0,
            aux: 0,
        };

        unsafe {
            let _installed = install(ptr::addr_of_mut!(record));
            app_controller_begin_command(
                ptr::addr_of_mut!(controller),
                0x0dad_0195,
                0xffff_ffff,
                0x8000_0000,
                0,
                0x7fff_ffff,
            );

            assert_eq!(
                LOOKUP_SEEN,
                (ptr::addr_of_mut!(controller.record_map_word), 0x0dad_0195, 0),
                "the raw resolver call uses zero key extension and allocates"
            );
            assert_eq!(record.arg2, 0xffff_ffff);
            assert_eq!(record.arg3, 0x8000_0000);
            assert_eq!(record.state, 0);
            assert_eq!(record.aux, 0x7fff_ffff);
            assert_eq!(controller.pending_command.arg2, record.arg2);
            assert_eq!(controller.pending_command.arg3, record.arg3);
            assert_eq!(controller.pending_command.state, record.state);
            assert_eq!(controller.pending_command.aux, record.aux);
            assert!(
                controller.opaque_00_3b.iter().all(|word| *word == 0xa5a5_a5a5)
                    && controller.record_map_word == 0xa5a5_a5a5
                    && controller.opaque_40_87.iter().all(|word| *word == 0xa5a5_a5a5),
                "only controller +0x88..+0x97 is written"
            );
            restore();
        }
    }

    #[test]
    fn begin_command_overwrites_a_prior_record_without_replacing_slot_value() {
        let mut controller = controller();
        let mut record = PendingCommandRecord {
            arg2: 0xaaaa_aaaa,
            arg3: 0xbbbb_bbbb,
            state: 0xcccc_cccc,
            aux: 0xdddd_dddd,
        };

        unsafe {
            let _installed = install(ptr::addr_of_mut!(record));
            app_controller_begin_command(ptr::addr_of_mut!(controller), 1, 2, 3, 4, 5);

            assert_eq!([record.arg2, record.arg3, record.state, record.aux], [2, 3, 4, 5]);
            assert_eq!(
                [
                    controller.pending_command.arg2,
                    controller.pending_command.arg3,
                    controller.pending_command.state,
                    controller.pending_command.aux,
                ],
                [2, 3, 4, 5]
            );
            assert_eq!(RECORD_SLOT, ptr::addr_of_mut!(record));
            restore();
        }
    }
}
