//! Kernel object-class-three allocation.
//!
//! The class-three object is used as the inline semaphore handle in POSIX
//! mutexes. The mask-ROM dispatcher is outside `osos`, so this port retains a
//! narrow seam for it while preserving the stock status/slot contract.

/// Stock failure returned when creation fails or produces a null handle.
pub const OBJECT_CREATE_FAILED: u32 = 0x27;
const OBJECT_CLASS: u32 = 3;
type ObjectCreationCallback = unsafe extern "C" fn();
type ObjectCreationPrelude = unsafe extern "C" fn(*mut u32, ObjectCreationCallback) -> u32;
type KernelCreateDispatch = unsafe extern "C" fn(u32, *mut u32) -> u32;

/// The two fixed calls made by [`kernel_object3_allocate`].
///
/// `creation_prelude` is the otherwise-unported `FUN_080f4f74` call with its
/// stock literal arguments. `create` is the ROM dispatcher reached through
/// osos veneer `0x08037e70`.
#[derive(Clone, Copy)]
pub struct Object3AllocateOps {
    pub creation_prelude: unsafe extern "C" fn() -> u32,
    pub create: KernelCreateDispatch,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn stock_creation_prelude() -> u32 {
    let prelude: ObjectCreationPrelude = core::mem::transmute(0x080f4f74usize);
    let callback: ObjectCreationCallback = core::mem::transmute(0x08080330usize);
    prelude(0x08a096fcusize as *mut u32, callback)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn stock_creation_prelude() -> u32 { 0 }

#[cfg(target_os = "none")]
unsafe extern "C" fn stock_kernel_create_dispatch(kind: u32, slot: *mut u32) -> u32 {
    let create: KernelCreateDispatch = core::mem::transmute(0x08037e70usize);
    create(kind, slot)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn stock_kernel_create_dispatch(_kind: u32, slot: *mut u32) -> u32 {
    slot.write(1);
    0
}

pub const DEFAULT_OBJECT3_ALLOCATE_OPS: Object3AllocateOps = Object3AllocateOps {
    creation_prelude: stock_creation_prelude,
    create: stock_kernel_create_dispatch,
};

/// Active fixed-call seam. Host tests replace it; target defaults invoke the
/// stock prelude and ROM dispatcher.
pub static mut OBJECT3_ALLOCATE_OPS: Object3AllocateOps = DEFAULT_OBJECT3_ALLOCATE_OPS;

#[inline(always)]
fn ops() -> Object3AllocateOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(OBJECT3_ALLOCATE_OPS)) }
}

/// `kernel_object3_allocate` — original: `FUN_0808b1c0` @ `0x0808b1c0`
/// (72 bytes, `0x0808b1c0..0x0808b208`: 64 bytes of instructions plus an
/// 8-byte literal pool). Raw words establish the next function at
/// `0x0808b208` and exactly **2 plain `bl` calls** (`0x080f4f74`,
/// `0x08037e70`), with **0 predicated `bl` calls**.
///
/// Runs the stock object-creation prelude, asks the ROM create dispatcher for
/// class 3 into `slot`, then succeeds only when both the dispatcher status and
/// resulting handle are nonzero; otherwise returns `0x27`. Deliberate
/// deviation: the unported prelude and mask-ROM dispatcher are explicit
/// function-pointer seams. Target defaults call their verified stock entries;
/// the host default models a successful dispatcher and leaves the prelude
/// inert.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn kernel_object3_allocate(slot: *mut u32) -> u32 {
    let calls = ops();
    (calls.creation_prelude)();
    if (calls.create)(OBJECT_CLASS, slot) == 0 && slot.read() != 0 {
        0
    } else {
        OBJECT_CREATE_FAILED
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr::{addr_of_mut, write_volatile};
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static CALLS: Mutex<[(u32, usize); 2]> = Mutex::new([(0, 0); 2]);
    static CALL_COUNT: Mutex<usize> = Mutex::new(0);
    static mut CREATE_STATUS: u32 = 0;
    static mut CREATE_HANDLE: u32 = 1;

    unsafe extern "C" fn record_prelude() -> u32 {
        let mut count = CALL_COUNT.lock();
        CALLS.lock()[*count] = (0, 0);
        *count += 1;
        0
    }

    unsafe extern "C" fn record_create(kind: u32, slot: *mut u32) -> u32 {
        let mut count = CALL_COUNT.lock();
        CALLS.lock()[*count] = (kind, slot as usize);
        *count += 1;
        slot.write(CREATE_HANDLE);
        CREATE_STATUS
    }

    fn install() -> parking_lot::MutexGuard<'static, ()> {
        let guard = TEST_LOCK.lock();
        *CALL_COUNT.lock() = 0;
        unsafe {
            CREATE_STATUS = 0;
            CREATE_HANDLE = 1;
            write_volatile(addr_of_mut!(OBJECT3_ALLOCATE_OPS), Object3AllocateOps {
                creation_prelude: record_prelude,
                create: record_create,
            });
        }
        guard
    }

    fn reset() {
        unsafe { write_volatile(addr_of_mut!(OBJECT3_ALLOCATE_OPS), DEFAULT_OBJECT3_ALLOCATE_OPS) }
    }

    #[test]
    fn allocates_class_three_only_when_rom_sets_a_handle() {
        let _guard = install();
        let mut slot = 0;
        assert_eq!(unsafe { kernel_object3_allocate(&mut slot) }, 0);
        assert_eq!(&CALLS.lock()[..*CALL_COUNT.lock()], &[(0, 0), (3, &mut slot as *mut u32 as usize)]);
        reset();
    }

    #[test]
    fn rejects_rom_failure_even_when_the_slot_is_written() {
        let _guard = install();
        unsafe { CREATE_STATUS = 9; }
        let mut slot = 0;
        assert_eq!(unsafe { kernel_object3_allocate(&mut slot) }, OBJECT_CREATE_FAILED);
        assert_eq!(slot, 1);
        reset();
    }

    #[test]
    fn rejects_success_without_a_handle() {
        let _guard = install();
        unsafe { CREATE_HANDLE = 0; }
        let mut slot = 0xfeed_beef;
        assert_eq!(unsafe { kernel_object3_allocate(&mut slot) }, OBJECT_CREATE_FAILED);
        assert_eq!(slot, 0);
        reset();
    }
}
