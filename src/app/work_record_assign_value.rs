//! `work_record_assign_value` — original: `FUN_081484e0` @ `0x081484e0`
//! (76 bytes). Raw ARM establishes the exact extent `0x081484e0..0x0814852b`;
//! `0x0814852c` begins the next function.
//!
//! The body has one unconditional plain `bl` to the unported object factory at
//! `0x081e1624` and one predicated `blxne` through the replaced object's
//! vtable slot `+0x4`. Raw A32 decoding finds three inbound plain `bl` sites
//! and no predicated inbound calls.
//!
//! # Algorithm
//!
//! Returns when `value` already occupies work-record word `+0x5c`. Otherwise,
//! stores it, obtains its corresponding opaque object from the retail factory,
//! releases the replaced object through virtual slot `+0x4` when necessary,
//! and stores the new object at word `+0x3c`.
//!
//! # Deliberate deviations
//!
//! The factory and virtual release target have no established semantic Rust
//! ports. Target builds call their verified retail addresses; host builds use
//! replaceable operations to verify the field updates and dispatch ordering.

use core::ptr::{read_volatile, write_volatile};

type ObjectFactory = unsafe extern "C" fn(u32, u32) -> *mut u8;
type ObjectRelease = unsafe extern "C" fn(*mut u8);

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct WorkRecordAssignValueOps {
    pub factory: ObjectFactory,
    pub release: ObjectRelease,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_factory(_value: u32, _zero: u32) -> *mut u8 {
    core::ptr::null_mut()
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_release(_object: *mut u8) {}

#[cfg(not(target_os = "none"))]
pub static mut WORK_RECORD_ASSIGN_VALUE_OPS: WorkRecordAssignValueOps = WorkRecordAssignValueOps {
    factory: missing_factory,
    release: missing_release,
};

#[inline(always)]
unsafe fn factory() -> ObjectFactory {
    #[cfg(target_os = "none")]
    {
        unsafe { core::mem::transmute(0x081e_1624usize) }
    }
    #[cfg(not(target_os = "none"))]
    {
        unsafe { read_volatile(core::ptr::addr_of!(WORK_RECORD_ASSIGN_VALUE_OPS.factory)) }
    }
}

#[inline(always)]
unsafe fn release(object: *mut u8) {
    #[cfg(target_os = "none")]
    {
        let vtable = unsafe { read_volatile(object.cast::<u32>()) };
        let method: ObjectRelease = unsafe {
            core::mem::transmute(read_volatile((vtable as usize as *const u32).add(1)))
        };
        unsafe { method(object) };
    }
    #[cfg(not(target_os = "none"))]
    {
        let method = unsafe { read_volatile(core::ptr::addr_of!(WORK_RECORD_ASSIGN_VALUE_OPS.release)) };
        unsafe { method(object) };
    }
}

/// Assigns `value` to a work record and replaces its resolved opaque object.
/// Original: `FUN_081484e0` @ `0x081484e0` (76 bytes; 3 inbound plain `bl`,
/// 0 predicated; 1 outbound plain `bl`, 1 predicated `blx`).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn work_record_assign_value(record: *mut u8, value: u32) {
    unsafe {
        let value_slot = record.add(0x5c).cast::<u32>();
        if read_volatile(value_slot) == value {
            return;
        }

        write_volatile(value_slot, value);
        let replacement = factory()(value, 0);
        let object_slot = record.add(0x3c).cast::<u32>();
        let previous = read_volatile(object_slot) as usize as *mut u8;
        if previous != replacement {
            if !previous.is_null() {
                release(previous);
            }
            write_volatile(object_slot, replacement as usize as u32);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut FACTORY_RESULT: *mut u8 = core::ptr::null_mut();
    static mut FACTORY_ARGS: (u32, u32) = (0, 0);
    static mut RELEASED: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn factory(value: u32, zero: u32) -> *mut u8 {
        unsafe {
            FACTORY_ARGS = (value, zero);
            FACTORY_RESULT
        }
    }

    unsafe extern "C" fn release(object: *mut u8) {
        unsafe { RELEASED = object };
    }

    #[test]
    fn replaces_changed_value_and_releases_previous_object() {
        let _guard = OPS_LOCK.lock();
        let Some(record) = try_map_u32_slab(hints::WORK_RECORD_ASSIGN_VALUE, 0x1000) else {
            assert!(note_missing_u32_fixture("app/work_record_assign_value"));
            return;
        };
        let previous = unsafe { record.add(0x200) };
        let replacement = unsafe { record.add(0x300) };
        unsafe {
            write_volatile(record.add(0x5c).cast::<u32>(), 7);
            write_volatile(record.add(0x3c).cast::<u32>(), previous as usize as u32);
            FACTORY_RESULT = replacement;
            FACTORY_ARGS = (0, 0);
            RELEASED = core::ptr::null_mut();
            let old_ops = WORK_RECORD_ASSIGN_VALUE_OPS;
            WORK_RECORD_ASSIGN_VALUE_OPS = WorkRecordAssignValueOps { factory, release };
            work_record_assign_value(record, 9);
            WORK_RECORD_ASSIGN_VALUE_OPS = old_ops;
            assert_eq!(read_volatile(record.add(0x5c).cast::<u32>()), 9);
            assert_eq!(read_volatile(record.add(0x3c).cast::<u32>()), replacement as usize as u32);
            assert_eq!(FACTORY_ARGS, (9, 0));
            assert_eq!(RELEASED, previous);
        }
    }

    #[test]
    fn leaves_object_untouched_when_value_is_unchanged() {
        let _guard = OPS_LOCK.lock();
        let Some(record) = try_map_u32_slab(hints::WORK_RECORD_ASSIGN_VALUE_UNCHANGED, 0x1000) else {
            assert!(note_missing_u32_fixture("app/work_record_assign_value"));
            return;
        };
        let previous = unsafe { record.add(0x200) };
        unsafe {
            write_volatile(record.add(0x5c).cast::<u32>(), 9);
            write_volatile(record.add(0x3c).cast::<u32>(), previous as usize as u32);
            FACTORY_ARGS = (0, 0);
            RELEASED = core::ptr::null_mut();
            let old_ops = WORK_RECORD_ASSIGN_VALUE_OPS;
            WORK_RECORD_ASSIGN_VALUE_OPS = WorkRecordAssignValueOps { factory, release };
            work_record_assign_value(record, 9);
            WORK_RECORD_ASSIGN_VALUE_OPS = old_ops;
            assert_eq!(read_volatile(record.add(0x3c).cast::<u32>()), previous as usize as u32);
            assert_eq!(FACTORY_ARGS, (0, 0));
            assert!(RELEASED.is_null());
        }
    }
    #[test]
    fn keeps_equal_replacement_without_releasing_it() {
        let _guard = OPS_LOCK.lock();
        let Some(record) = try_map_u32_slab(hints::WORK_RECORD_ASSIGN_VALUE_SAME_OBJECT, 0x1000) else {
            assert!(note_missing_u32_fixture("app/work_record_assign_value"));
            return;
        };
        let object = unsafe { record.add(0x200) };
        unsafe {
            write_volatile(record.add(0x5c).cast::<u32>(), 7);
            write_volatile(record.add(0x3c).cast::<u32>(), object as usize as u32);
            FACTORY_RESULT = object;
            FACTORY_ARGS = (0, 0);
            RELEASED = core::ptr::null_mut();
            let old_ops = WORK_RECORD_ASSIGN_VALUE_OPS;
            WORK_RECORD_ASSIGN_VALUE_OPS = WorkRecordAssignValueOps { factory, release };
            work_record_assign_value(record, 9);
            WORK_RECORD_ASSIGN_VALUE_OPS = old_ops;
            assert_eq!(read_volatile(record.add(0x5c).cast::<u32>()), 9);
            assert_eq!(read_volatile(record.add(0x3c).cast::<u32>()), object as usize as u32);
            assert_eq!(FACTORY_ARGS, (9, 0));
            assert!(RELEASED.is_null());
        }
    }
}

