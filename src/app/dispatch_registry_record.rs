//! `dispatch_registry_record` — `FUN_0826e4f0` @ 0x0826e4f0.
//! True extent: 208 bytes, ending at the next function's push @ 0x0826e5c0.
//! Raw A32 decoding: 2 inbound plain BL sites, 0 predicated; body has 4
//! plain BL, 0 predicated BL, and 4 BLX-register instructions.
//!
//! Resolve the target according to record word 3, obtain the initial framework
//! target (optionally replace it with a newly constructed class-0x6800 object),
//! and search the task registry by record word 0 using slot +0x48 and a four-byte
//! key. A hit copies an owner/callback pair through slot +0x3c; invoke the
//! copied callback, not the record, and return its result. A miss returns zero.
//! The original owner argument survives the copied entry's owner overwrite.
//!
//! Deviations: typed C layouts expand pointer fields on hosts; direct calls
//! reuse existing ports. The private algorithm accepts environment operations
//! for host testing without executing the firmware or changing target seams.

use crate::app::class_6800::{class_6800_new, framework_base_current_task_initial_target};
use crate::heap::veneers::operator_new;
use crate::kernel::task::current_task_ctx_block;

pub type RecordTargetSelector = unsafe extern "C" fn(*mut u8) -> *mut u8;
pub type RecordCallback = unsafe extern "C" fn(
    *mut u8, *mut u8, *mut u8, *mut u8, *mut u8,
) -> usize;

#[repr(C)]
pub struct DispatchRegistryEntry {
    pub owner: *mut u8,
    pub callback: *mut u8,
}

#[repr(C)]
pub struct DispatchRegistry {
    pub vtable: *const DispatchRegistryVtable,
}

#[repr(C)]
pub struct DispatchRegistryVtable {
    pub unresolved_00_38: [usize; 15],
    pub entry_at: unsafe extern "C" fn(*mut DispatchRegistry, i32, *mut DispatchRegistryEntry) -> usize,
    pub unresolved_40_44: [usize; 2],
    pub find_key: unsafe extern "C" fn(*mut DispatchRegistry, *mut u32, u32) -> i32,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x3c] = [0; core::mem::offset_of!(DispatchRegistryVtable, entry_at)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x48] = [0; core::mem::offset_of!(DispatchRegistryVtable, find_key)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 8] = [0; core::mem::size_of::<DispatchRegistryEntry>()];

unsafe fn task_dispatch_registry() -> *mut DispatchRegistry {
    let context = current_task_ctx_block();
    core::ptr::addr_of!((*context).registry).read_volatile().cast()
}

unsafe fn new_framework_target() -> *mut u8 {
    class_6800_new(operator_new(28).cast()).cast()
}

unsafe fn dispatch_with_environment(
    mut target: *mut u8,
    owner: *mut u8,
    record: *mut u8,
    selector: *mut u8,
    create_target: u32,
    initial_target: unsafe extern "C" fn() -> *mut u8,
    new_target: unsafe fn() -> *mut u8,
    registry_get: unsafe fn() -> *mut DispatchRegistry,
) -> usize {
    let mode = record.cast::<u32>().add(3).read();
    if mode == 0 {
        target = core::ptr::null_mut();
    } else if mode != u32::MAX {
        let select: RecordTargetSelector = core::mem::transmute(selector);
        let selected = select(record);
        if !selected.is_null() {
            target = selected;
        }
    }
    let mut framework_target = initial_target();
    if create_target != 0 {
        framework_target = new_target();
    }
    let registry = registry_get();
    let mut key = record.cast::<u32>().read();
    let index = ((*(*registry).vtable).find_key)(registry, &mut key, 4);
    if index == -1 {
        return 0;
    }
    let mut entry = DispatchRegistryEntry { owner, callback: record };
    ((*(*registry).vtable).entry_at)(registry, index, &mut entry);
    let callback: RecordCallback = core::mem::transmute(entry.callback);
    callback(target, owner, framework_target, record, selector)
}

/// Dispatch a firmware record and return its registered callback's result.
///
/// # Safety
/// `record` contains at least four aligned words; `selector` is callable when
/// word 3 is neither zero nor -1. The current task owns a live dispatch registry
/// whose hit entries contain callable five-argument callbacks. Allocation and
/// constructor preconditions are those of the existing class-0x6800 port.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn dispatch_registry_record(
    target: *mut u8, owner: *mut u8, record: *mut u8, selector: *mut u8, create_target: u32,
) -> usize {
    dispatch_with_environment(target, owner, record, selector, create_target,
        framework_base_current_task_initial_target, new_framework_target, task_dispatch_registry)
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut SELECTED: usize = 0;
    static mut SELECT_CALLS: usize = 0;
    static mut NEW_CALLS: usize = 0;
    static mut INITIAL_CALLS: usize = 0;
    static mut INDEX: i32 = 0;
    static mut OBSERVED: [usize; 5] = [0; 5];
    static mut CALLBACK_CALLS: usize = 0;
    static mut REGISTRY: DispatchRegistry = DispatchRegistry { vtable: &VTABLE };

    unsafe extern "C" fn select(_: *mut u8) -> *mut u8 {
        SELECT_CALLS += 1;
        SELECTED as *mut u8
    }
    unsafe extern "C" fn initial() -> *mut u8 {
        INITIAL_CALLS += 1;
        0x1230usize as *mut u8
    }
    unsafe fn new_target() -> *mut u8 {
        NEW_CALLS += 1;
        0x4560usize as *mut u8
    }
    unsafe fn registry() -> *mut DispatchRegistry { core::ptr::addr_of_mut!(REGISTRY) }
    unsafe extern "C" fn find(_: *mut DispatchRegistry, key: *mut u32, size: u32) -> i32 {
        assert_eq!(key.read(), 0x6800);
        assert_eq!(size, 4);
        // The key buffer is writable; changing it must not change the record.
        key.write(0x9999);
        INDEX
    }
    unsafe extern "C" fn entry(_: *mut DispatchRegistry, index: i32, out: *mut DispatchRegistryEntry) -> usize {
        assert_eq!(index, INDEX);
        assert_ne!(index, -1);
        (*out).owner = 0xdeadu32 as usize as *mut u8;
        (*out).callback = callback as *mut u8;
        0
    }
    unsafe extern "C" fn callback(a: *mut u8, b: *mut u8, c: *mut u8, d: *mut u8, e: *mut u8) -> usize {
        CALLBACK_CALLS += 1;
        OBSERVED = [a as usize, b as usize, c as usize, d as usize, e as usize];
        0xcafe
    }
    static VTABLE: DispatchRegistryVtable = DispatchRegistryVtable {
        unresolved_00_38: [0; 15], entry_at: entry,
        unresolved_40_44: [0; 2], find_key: find,
    };

    #[test]
    fn target_selection_registry_replacement_and_return_value() {
        let _guard = LOCK.lock();
        unsafe {
            for (mode, selected, expected, calls) in [
                (0, 0x7700, 0, 0), (u32::MAX, 0x7700, 0x1100, 0),
                (1, 0, 0x1100, 1), (2, 0x7700, 0x7700, 1),
            ] {
                for create in [0, 7] {
                    let mut record = [0x6800, 0, 0, mode];
                    SELECTED = selected;
                    SELECT_CALLS = 0; NEW_CALLS = 0; INITIAL_CALLS = 0;
                    INDEX = 0; CALLBACK_CALLS = 0;
                    let result = dispatch_with_environment(0x1100usize as *mut u8,
                        0x2200usize as *mut u8, record.as_mut_ptr().cast(), select as *mut u8,
                        create, initial, new_target, registry);
                    assert_eq!(result, 0xcafe);
                    let observed = OBSERVED;
                    assert_eq!(observed, [expected, 0x2200, if create == 0 { 0x1230 } else { 0x4560 },
                        record.as_mut_ptr() as usize, select as *const () as usize]);
                    assert_eq!(record[0], 0x6800);
                    assert_eq!(SELECT_CALLS, calls);
                    assert_eq!(NEW_CALLS, usize::from(create != 0));
                    assert_eq!(INITIAL_CALLS, 1);
                    assert_eq!(CALLBACK_CALLS, 1);
                }
            }
        }
    }

    #[test]
    fn missing_key_returns_zero_after_optional_target_creation() {
        let _guard = LOCK.lock();
        unsafe {
            let mut record = [0x6800, 0, 0, u32::MAX];
            INDEX = -1; CALLBACK_CALLS = 0; NEW_CALLS = 0; INITIAL_CALLS = 0;
            assert_eq!(dispatch_with_environment(core::ptr::null_mut(), core::ptr::null_mut(),
                record.as_mut_ptr().cast(), core::ptr::null_mut(), 1,
                initial, new_target, registry), 0);
            assert_eq!(CALLBACK_CALLS, 0);
            assert_eq!(NEW_CALLS, 1);
            assert_eq!(INITIAL_CALLS, 1);
        }
    }
}
