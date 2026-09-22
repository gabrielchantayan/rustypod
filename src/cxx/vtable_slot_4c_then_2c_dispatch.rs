//! `vtable_slot_4c_then_2c_dispatch` — original: `FUN_08271a00` @
//! **0x08271a00** (60 bytes).
//!
//! Raw ARM establishes the 60-byte extent: `push {r4,r5,r6,lr}` at
//! `0x08271a00` through `pop {r4,r5,r6,pc}` at `0x08271a38`; the next
//! independent function begins at `0x08271a3c`. The body contains no
//! immediate `bl`: it performs one unconditional `blx r2` through vtable
//! slot `+0x4c`, then one predicated `blxne r2` through slot `+0x2c`.
//! Decoding inbound immediate branches finds two plain `bl` callers
//! (`0x0819e3cc`, `0x082776b8`) and no predicated `bl` callers; Ghidra's
//! reported third call site is not present in the raw image.
//!
//! # Algorithm
//!
//! Invoke `this`'s virtual slot `+0x4c` as `fn(this) -> i32`. If its result
//! is not `-1`, invoke slot `+0x2c` as `fn(this, result)`. Return the first
//! result. The concrete virtual methods remain unrecovered and are not named.
//!
//! # Deliberate deviation
//!
//! Target vtable entries are 32-bit words; host function pointers are native
//! width, so the port reads `usize` entries. This preserves the ARM slots and
//! permits host fixtures without truncating callbacks.

const FIRST_SLOT: usize = 0x4c / 4;
const RESULT_SLOT: usize = 0x2c / 4;

type FirstMethod = unsafe extern "C" fn(*mut u8) -> i32;
type ResultMethod = unsafe extern "C" fn(*mut u8, i32);

/// Calls vtable slot `+0x4c`, then reports its non-sentinel result to slot `+0x2c`.
///
/// # Safety
///
/// `this` must point to an object whose first word is a readable vtable with
/// entries at target offsets `+0x2c` and `+0x4c`. Both entries must name
/// callable functions with the declared ABIs.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vtable_slot_4c_then_2c_dispatch(this: *mut u8) -> i32 {
    let vtable = unsafe { (this as *const usize).read() as *const usize };
    let first: FirstMethod = unsafe { core::mem::transmute(vtable.add(FIRST_SLOT).read()) };
    let result = unsafe { first(this) };
    if result != -1 {
        let report: ResultMethod = unsafe { core::mem::transmute(vtable.add(RESULT_SLOT).read()) };
        unsafe { report(this, result) };
    }
    result
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static DISPATCH_LOCK: Mutex<()> = Mutex::new(());
    static mut FIRST_RESULT: i32 = 0;
    static mut FIRST_OBJECT: usize = 0;
    static mut REPORTED_OBJECT: usize = 0;
    static mut REPORTED_RESULT: i32 = 0;
    static mut REPORT_CALLS: u32 = 0;

    unsafe extern "C" fn first_method(this: *mut u8) -> i32 {
        unsafe { FIRST_OBJECT = this as usize; FIRST_RESULT }
    }

    unsafe extern "C" fn report_method(this: *mut u8, result: i32) {
        unsafe {
            REPORTED_OBJECT = this as usize;
            REPORTED_RESULT = result;
            REPORT_CALLS += 1;
        }
    }

    struct Bench {
        _lock: MutexGuard<'static, ()>,
    }

    fn bench(result: i32) -> Bench {
        let lock = DISPATCH_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            FIRST_RESULT = result;
            FIRST_OBJECT = 0;
            REPORTED_OBJECT = 0;
            REPORTED_RESULT = 0;
            REPORT_CALLS = 0;
        }
        Bench { _lock: lock }
    }

    fn fixture() -> ([usize; FIRST_SLOT + 1], [usize; 2]) {
        let mut vtable = [0usize; FIRST_SLOT + 1];
        vtable[FIRST_SLOT] = first_method as usize;
        vtable[RESULT_SLOT] = report_method as usize;
        let object = [vtable.as_ptr() as usize, 0xdead_beef];
        (vtable, object)
    }

    #[test]
    fn reports_non_sentinel_result_through_slot_2c() {
        let _bench = bench(37);
        let (vtable, mut object) = fixture();
        object[0] = vtable.as_ptr() as usize;
        let this = object.as_mut_ptr().cast::<u8>();

        let result = unsafe { vtable_slot_4c_then_2c_dispatch(this) };

        assert_eq!(result, 37);
        assert_eq!(unsafe { FIRST_OBJECT }, this as usize);
        assert_eq!(unsafe { REPORT_CALLS }, 1);
        assert_eq!(unsafe { REPORTED_OBJECT }, this as usize);
        assert_eq!(unsafe { REPORTED_RESULT }, 37);
        assert_eq!(object[1], 0xdead_beef);
    }

    #[test]
    fn sentinel_result_skips_slot_2c() {
        let _bench = bench(-1);
        let (vtable, mut object) = fixture();
        object[0] = vtable.as_ptr() as usize;
        let this = object.as_mut_ptr().cast::<u8>();

        assert_eq!(unsafe { vtable_slot_4c_then_2c_dispatch(this) }, -1);
        assert_eq!(unsafe { FIRST_OBJECT }, this as usize);
        assert_eq!(unsafe { REPORT_CALLS }, 0);
        assert_eq!(unsafe { REPORTED_OBJECT }, 0);
    }
}
