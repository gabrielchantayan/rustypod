//! `class_8900_apply_directory_transition` — original: `FUN_081ec31c` @
//! `0x081ec31c` (128 bytes; five plain direct `bl` calls, one predicated
//! `blxne`, and two unconditional virtual `blx` calls).
//!
//! Raw ARM establishes the code extent `0x081ec31c..0x081ec39c`; the next
//! word is the transition-string table, not code. The index selects a
//! 12-byte record from that table: its +4 action word is dispatched through
//! the current task context's class-0x80 object at vtable slot +0x74, and
//! its +8 string address is written to the Class8900 provider chain as
//! `("DirP", 0x6066, string, 4)`. A current window, if any, receives its
//! vtable +0xd8 notification; finally the lazy 0x80 singleton receives its
//! vtable +0x24 notification.
//!
//! Deliberate deviation: host tests install native-pointer operation seams,
//! because the retail task-context word and singleton are target-owned.
//! Target builds call the verified existing ports and dispatch the original
//! object vtables directly.

use crate::app::class_8900::Class8900;
#[cfg(target_os = "none")]
use crate::app::registry::{object_cast_to_class, FrameworkObject};
#[cfg(target_os = "none")]
use crate::app::resource_chain::{resource_chain_write, ResourceKind, ResourceProvider};
#[cfg(target_os = "none")]
use crate::app::singletons::lazy_singleton_0x80;
#[cfg(target_os = "none")]
use crate::ui::current_window::ui_current_window;
#[cfg(target_os = "none")]
use crate::util::context_field::task_ctx_field_0x30;

#[cfg(target_os = "none")]
const CLASS_ID_80: u32 = 0x80;
#[cfg(target_os = "none")]
const RESOURCE_KIND_DIRP: ResourceKind = ResourceKind(0x7072_4944);
#[cfg(target_os = "none")]
const RESOURCE_ID_6066: u32 = 0x6066;
#[cfg(target_os = "none")]
const TRANSITION_RECORDS_ADDRESS: usize = 0x089c_c3cc;

#[repr(C)]
struct TransitionRecord {
    _prefix: u32,
    action: u32,
    resource_name: u32,
}

#[repr(C)]
struct TransitionTargetVTable {
    slots_before: [usize; 29],
    apply_action: unsafe extern "C" fn(*mut u8, u32),
}

#[repr(C)]
struct WindowVTable {
    slots_before: [usize; 54],
    notify_transition: unsafe extern "C" fn(),
}

#[repr(C)]
struct Singleton80VTable {
    slots_before: [usize; 9],
    notify_transition: unsafe extern "C" fn(),
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x74] = [0; core::mem::offset_of!(TransitionTargetVTable, apply_action)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0xd8] = [0; core::mem::offset_of!(WindowVTable, notify_transition)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x24] = [0; core::mem::offset_of!(Singleton80VTable, notify_transition)];

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn apply_action(record: *const TransitionRecord) {
    let context = task_ctx_field_0x30() as usize as *mut FrameworkObject;
    let target = object_cast_to_class(context, CLASS_ID_80);
    let vtable = core::ptr::read_volatile(target.cast::<*const TransitionTargetVTable>());
    ((*vtable).apply_action)(target, (*record).action);
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn write_transition_resource(owner: *mut Class8900, record: *const TransitionRecord) {
    resource_chain_write(
        (*owner).store.cast::<ResourceProvider>(),
        RESOURCE_KIND_DIRP,
        RESOURCE_ID_6066,
        record as usize as u32 + 8,
        4,
    );
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn notify_window() {
    let window = ui_current_window();
    if !window.is_null() {
        let vtable = core::ptr::read_volatile(window.cast::<*const WindowVTable>());
        ((*vtable).notify_transition)();
    }
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn notify_singleton() {
    let singleton = lazy_singleton_0x80();
    let vtable = core::ptr::read_volatile(singleton.cast::<*const Singleton80VTable>());
    ((*vtable).notify_transition)();
}

#[cfg(not(target_os = "none"))]
struct HostOperations {
    apply_action: unsafe fn(u32),
    write_transition_resource: unsafe fn(*mut Class8900, u32),
    notify_window: unsafe fn(),
    notify_singleton: unsafe fn(),
}

#[cfg(not(target_os = "none"))]
unsafe fn missing_action(_: u32) { panic!("class_8900_apply_directory_transition requires test operations") }
#[cfg(not(target_os = "none"))]
unsafe fn missing_write(_: *mut Class8900, _: u32) { panic!("class_8900_apply_directory_transition requires test operations") }
#[cfg(not(target_os = "none"))]
unsafe fn missing_notify() { panic!("class_8900_apply_directory_transition requires test operations") }

#[cfg(not(target_os = "none"))]
static mut HOST_OPERATIONS: HostOperations = HostOperations {
    apply_action: missing_action,
    write_transition_resource: missing_write,
    notify_window: missing_notify,
    notify_singleton: missing_notify,
};
#[cfg(not(target_os = "none"))]
static mut HOST_RECORDS: *const TransitionRecord = core::ptr::null();

/// class_8900_apply_directory_transition — original: `FUN_081ec31c` @
/// `0x081ec31c` (128 bytes).
///
/// Applies transition record `index`: dispatches its action word, writes its
/// inline string pointer as the `("DirP", 0x6066)` resource, conditionally
/// notifies the current window, then notifies the lazy 0x80 singleton.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn class_8900_apply_directory_transition(this: *mut Class8900, index: u32) {
    #[cfg(target_os = "none")]
    let record = (TRANSITION_RECORDS_ADDRESS as *const TransitionRecord).add(index as usize);
    #[cfg(not(target_os = "none"))]
    let record = HOST_RECORDS.add(index as usize);

    #[cfg(target_os = "none")]
    {
        apply_action(record);
        write_transition_resource(this, record);
        notify_window();
        notify_singleton();
    }
    #[cfg(not(target_os = "none"))]
    {
        (HOST_OPERATIONS.apply_action)((*record).action);
        (HOST_OPERATIONS.write_transition_resource)(this, record as usize as u32 + 8);
        (HOST_OPERATIONS.notify_window)();
        (HOST_OPERATIONS.notify_singleton)();
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut EVENTS: [u32; 4] = [0; 4];
    static mut ACTION: u32 = 0;
    static mut OWNER: *mut Class8900 = core::ptr::null_mut();
    static mut RESOURCE: u32 = 0;

    unsafe fn action(value: u32) { ACTION = value; EVENTS[0] = 1; }
    unsafe fn write(owner: *mut Class8900, resource: u32) {
        OWNER = owner;
        RESOURCE = resource;
        EVENTS[1] = 2;
    }
    unsafe fn window() { EVENTS[2] = 3; }
    unsafe fn singleton() { EVENTS[3] = 4; }

    #[test]
    fn dispatches_the_selected_record_in_retail_order() {
        let _guard = TEST_LOCK.lock();
        let records = [
            TransitionRecord { _prefix: 0, action: 0x1111_2222, resource_name: 0 },
            TransitionRecord { _prefix: 0, action: 0x3333_4444, resource_name: 0 },
        ];
        unsafe {
            HOST_RECORDS = records.as_ptr();
            HOST_OPERATIONS = HostOperations {
                apply_action: action,
                write_transition_resource: write,
                notify_window: window,
                notify_singleton: singleton,
            };
            EVENTS = [0; 4]; ACTION = 0; OWNER = core::ptr::null_mut(); RESOURCE = 0;
            let mut owner = core::mem::MaybeUninit::<Class8900>::zeroed();
            class_8900_apply_directory_transition(owner.as_mut_ptr(), 1);
            assert_eq!(ACTION, 0x3333_4444);
            assert_eq!(OWNER, owner.as_mut_ptr());
            assert_eq!(RESOURCE, records.as_ptr().add(1) as u32 + 8);
            assert_eq!(EVENTS, [1, 2, 3, 4]);
        }
    }
}
