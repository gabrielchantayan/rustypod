//! `work_record_construct` — original: `FUN_08148600` @ `0x08148600` (164
//! bytes of code). The next real function starts at `0x081486a8`, after the
//! constructor's vtable literal at `0x081486a4`.
//!
//! Raw decoding found four inbound unconditional plain `bl` calls and no
//! predicated calls. Its body makes eight unconditional plain `bl` calls:
//! `0x0814878c`, `0x081ba980`, `0x0820b20c`, `0x08135ba4`, `0x0839eba4`,
//! `0x081bb6b8`, `0x081484e0`, and `0x0814848c`.
//!
//! # Algorithm
//!
//! Installs the work-record vtable and context, constructs six nested
//! subobjects through the retail constructor chain, clears the resulting
//! pair and state fields, records the supplied value and sentinel, then
//! assigns and initializes the work record before returning it.
//!
//! # Deliberate deviations
//!
//! The six nested constructors and final lifecycle calls have not been given
//! independent Rust ports. Target builds call their verified retail addresses;
//! host builds use replaceable operations so the exact pointer/argument chain
//! can be tested without mapping retailOS code.

use core::ptr::write_volatile;
#[cfg(not(target_os = "none"))]
use core::ptr::{addr_of, read_volatile};

const WORK_RECORD_VTABLE: u32 = 0x0898_65b4;

type Constructor = unsafe extern "C" fn(*mut u8, u32, u32, u32) -> *mut u8;
type AssignValue = unsafe extern "C" fn(*mut u8, u32, u32, u32);
type InitializeWork = unsafe extern "C" fn(*mut u8, u32, u32, u32);

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct WorkRecordConstructorOps {
    pub construct_first: Constructor,
    pub construct_second: Constructor,
    pub construct_third: Constructor,
    pub construct_fourth: Constructor,
    pub construct_observable_array: Constructor,
    pub zero_pair: Constructor,
    pub assign_value: AssignValue,
    pub initialize_work: InitializeWork,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_constructor(this: *mut u8, _a1: u32, _a2: u32, _a3: u32) -> *mut u8 {
    this
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_lifecycle(_this: *mut u8, _a1: u32, _a2: u32, _a3: u32) {}

#[cfg(not(target_os = "none"))]
pub static mut WORK_RECORD_CONSTRUCTOR_OPS: WorkRecordConstructorOps = WorkRecordConstructorOps {
    construct_first: missing_constructor,
    construct_second: missing_constructor,
    construct_third: missing_constructor,
    construct_fourth: missing_constructor,
    construct_observable_array: missing_constructor,
    zero_pair: missing_constructor,
    assign_value: missing_lifecycle,
    initialize_work: missing_lifecycle,
};

#[inline(always)]
unsafe fn constructor(which: usize) -> Constructor {
    #[cfg(target_os = "none")]
    {
        unsafe { core::mem::transmute(which) }
    }
    #[cfg(not(target_os = "none"))]
    {
        let ops = unsafe { read_volatile(addr_of!(WORK_RECORD_CONSTRUCTOR_OPS)) };
        match which {
            0x0814_878c => ops.construct_first,
            0x081b_a980 => ops.construct_second,
            0x0820_b20c => ops.construct_third,
            0x0813_5ba4 => ops.construct_fourth,
            0x0839_eba4 => ops.construct_observable_array,
            _ => ops.zero_pair,
        }
    }
}

#[inline(always)]
unsafe fn lifecycle(which: usize) -> AssignValue {
    #[cfg(target_os = "none")]
    {
        unsafe { core::mem::transmute(which) }
    }
    #[cfg(not(target_os = "none"))]
    {
        let ops = unsafe { read_volatile(addr_of!(WORK_RECORD_CONSTRUCTOR_OPS)) };
        if which == 0x0814_84e0 { ops.assign_value } else { ops.initialize_work }
    }
}

/// Constructs a work record in caller-provided storage and returns its base.
/// Original: `FUN_08148600` @ `0x08148600` (164 bytes; 4 inbound plain `bl`,
/// 0 predicated; 8 outbound plain `bl`, 0 predicated).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn work_record_construct(
    this: *mut u8,
    context: u32,
    value: u32,
    work_kind: u32,
) -> *mut u8 {
    unsafe {
        write_volatile(this.cast::<u32>(), WORK_RECORD_VTABLE);
        write_volatile(this.add(4).cast::<u32>(), context);

        let current = constructor(0x0814_878c)(this.add(8), 0, value, work_kind);
        let current = constructor(0x081b_a980)(current.add(12), 0, 0, work_kind);
        let current = constructor(0x0820_b20c)(current.add(16), 0, 0, work_kind);
        let current = constructor(0x0813_5ba4)(current.add(12), 0, 0, work_kind);
        let current = current.add(12);
        write_volatile(current.cast::<u32>(), 0);
        let current = constructor(0x0839_eba4)(current.add(4), 0, 0, work_kind);
        let current = constructor(0x081b_b6b8)(current.add(20), 0, 0, work_kind);
        write_volatile(current.add(8).cast::<u32>(), 0);
        write_volatile(current.add(12), 0);
        write_volatile(current.add(13), 0);
        write_volatile(current.add(14), 0);
        write_volatile(current.add(15), 0);

        let record = current.sub(0x54);
        write_volatile(current.add(20).cast::<u32>(), work_kind);
        write_volatile(current.add(24).cast::<u32>(), u32::MAX);
        lifecycle(0x0814_84e0)(record, value, 0, work_kind);
        lifecycle(0x0814_848c)(record, value, 0, work_kind);
        record
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static mut CALLS: [(usize, usize, u32, u32, u32); 8] = [(0, 0, 0, 0, 0); 8];
    static mut CALL_COUNT: usize = 0;
    static mut RETURNS: [usize; 6] = [0; 6];

    unsafe extern "C" fn construct(this: *mut u8, a1: u32, a2: u32, a3: u32) -> *mut u8 {
        unsafe {
            CALLS[CALL_COUNT] = (0, this as usize, a1, a2, a3);
            let result = RETURNS[CALL_COUNT];
            CALL_COUNT += 1;
            result as *mut u8
        }
    }
    unsafe extern "C" fn lifecycle_call(this: *mut u8, a1: u32, a2: u32, a3: u32) {
        unsafe {
            CALLS[CALL_COUNT] = (1, this as usize, a1, a2, a3);
            CALL_COUNT += 1;
        }
    }

    #[test]
    fn constructs_nested_records_and_preserves_lifecycle_arguments() {
        let mut storage = [0u8; 192];
        let base = unsafe { storage.as_mut_ptr().add(32) };
        unsafe {
            CALL_COUNT = 0;
            RETURNS = [base as usize + 8, base as usize + 20, base as usize + 36,
                base as usize + 48, base as usize + 64, base as usize + 84];
            let previous = WORK_RECORD_CONSTRUCTOR_OPS;
            WORK_RECORD_CONSTRUCTOR_OPS = WorkRecordConstructorOps {
                construct_first: construct, construct_second: construct, construct_third: construct,
                construct_fourth: construct, construct_observable_array: construct, zero_pair: construct,
                assign_value: lifecycle_call, initialize_work: lifecycle_call,
            };
            let result = work_record_construct(base, 0x11, 0x22, 0x33);
            WORK_RECORD_CONSTRUCTOR_OPS = previous;
            assert_eq!(result, base);
            assert_eq!(*(base as *const u32), WORK_RECORD_VTABLE);
            assert_eq!(*(base.add(4) as *const u32), 0x11);
            assert_eq!(CALL_COUNT, 8);
            assert_eq!(CALLS[0], (0, base as usize + 8, 0, 0x22, 0x33));
            assert_eq!(CALLS[4], (0, base as usize + 64, 0, 0, 0x33));
            assert_eq!(CALLS[5], (0, base as usize + 84, 0, 0, 0x33));
            assert_eq!(CALLS[6], (1, base as usize, 0x22, 0, 0x33));
            assert_eq!(CALLS[7], (1, base as usize, 0x22, 0, 0x33));
            assert_eq!(*(base.add(104) as *const u32), 0x33);
            assert_eq!(*(base.add(108) as *const u32), u32::MAX);
            assert_eq!(&storage[128..132], &[0, 0, 0, 0]);
        }
    }
}
