//! Dequeueing and dispatching a front polymorphic object.

use crate::cxx::templates::container_is_empty;

/// ABI of the unported `FUN_082156f0` front-object removal helper.
type DequeFrontRemove = unsafe extern "C" fn(*mut u8) -> *mut u8;
type FrontDispatch = unsafe extern "C" fn(*mut u8, u32) -> u32;
type FrontStatus = unsafe extern "C" fn(*mut u8) -> u32;
type FrontRelease = unsafe extern "C" fn(*mut u8);

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn deque_front_remove() -> DequeFrontRemove {
    core::mem::transmute(0x0821_56f0usize)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_deque_front_remove(_deque: *mut u8) -> *mut u8 {
    panic!("deque_front_dispatch requires a deque-front-removal seam on host")
}

/// Host replacement for unported `FUN_082156f0`.
#[cfg(not(target_os = "none"))]
pub static mut DEQUE_FRONT_REMOVE: DequeFrontRemove = missing_deque_front_remove;

#[inline(always)]
unsafe fn remove_front_object(deque: *mut u8) -> *mut u8 {
    #[cfg(target_os = "none")]
    { deque_front_remove()(deque) }
    #[cfg(not(target_os = "none"))]
    { DEQUE_FRONT_REMOVE(deque) }
}

/// `deque_front_dispatch` — original: `FUN_0821583c` @ `0x0821583c`.
///
/// Raw A32 establishes the 116-byte extent `0x0821583c..0x082158af`; the
/// independent next function begins at `0x082158b0`. It contains two plain
/// unconditional `bl` instructions (`container_is_empty` and `FUN_082156f0`),
/// three indirect `blx` instructions, two of them predicated `blxne`, and no
/// predicated plain `bl` instructions.
///
/// When the deque count word at `+0x20` is nonzero, returns zero. Otherwise it
/// removes the front object, calls its vtable `+0x10` method with `argument`,
/// then calls its `+0x18` status method. A set low status bit invokes vtable
/// `+0x04` to release the object. The `+0x10` result is returned unchanged.
///
/// Deliberate deviation: `FUN_082156f0` has no verified Rust identity or port,
/// so target builds call its verified address and host builds use a typed seam.
/// The three virtual calls are expressed as typed calls rather than `blx`.
///
/// # Safety
///
/// `deque` must satisfy `container_is_empty`. When nonempty, its front-removal
/// helper must return an object with a readable vtable and callable slots
/// `+0x04`, `+0x10`, and `+0x18`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn deque_front_dispatch(deque: *mut u8, argument: u32) -> u32 {
    if unsafe { container_is_empty(deque) } != 0 {
        return 0;
    }

    let object = unsafe { remove_front_object(deque) };
    let vtable = unsafe { (object as *const *const usize).read() };
    let dispatch: FrontDispatch = unsafe { core::mem::transmute(vtable.add(4).read()) };
    let result = unsafe { dispatch(object, argument) };
    let status: FrontStatus = unsafe { core::mem::transmute(vtable.add(6).read()) };

    if unsafe { status(object) } & 1 != 0 {
        let release: FrontRelease = unsafe { core::mem::transmute(vtable.add(1).read()) };
        unsafe { release(object) };
    }

    result
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{deque_front_dispatch, DequeFrontRemove, DEQUE_FRONT_REMOVE};
    use parking_lot::{Mutex, MutexGuard};

    static SEAM_LOCK: Mutex<()> = Mutex::new(());
    static mut FRONT_OBJECT: *mut u8 = core::ptr::null_mut();
    static mut REMOVE_CALLS: u32 = 0;
    static mut DISPATCH_ARGUMENT: u32 = 0;
    static mut STATUS_CALLS: u32 = 0;
    static mut RELEASE_CALLS: u32 = 0;
    static mut STATUS: u32 = 0;

    unsafe extern "C" fn remove_front(_deque: *mut u8) -> *mut u8 {
        unsafe { REMOVE_CALLS += 1; FRONT_OBJECT }
    }
    unsafe extern "C" fn dispatch(_object: *mut u8, argument: u32) -> u32 {
        unsafe { DISPATCH_ARGUMENT = argument; 0x8bad_f00d }
    }
    unsafe extern "C" fn status(_object: *mut u8) -> u32 {
        unsafe { STATUS_CALLS += 1; STATUS }
    }
    unsafe extern "C" fn release(_object: *mut u8) {
        unsafe { RELEASE_CALLS += 1 }
    }

    fn setup() -> MutexGuard<'static, ()> {
        let lock = SEAM_LOCK.lock();
        unsafe {
            REMOVE_CALLS = 0;
            DISPATCH_ARGUMENT = 0;
            STATUS_CALLS = 0;
            RELEASE_CALLS = 0;
            STATUS = 0;
            DEQUE_FRONT_REMOVE = remove_front as DequeFrontRemove;
        }
        lock
    }

    #[test]
    fn empty_deque_returns_zero_without_removing_or_dispatching() {
        let _lock = setup();
        let mut deque = [0u32; 9];
        unsafe {
            assert_eq!(deque_front_dispatch(deque.as_mut_ptr().cast(), 0x1234), 0);
            assert_eq!(REMOVE_CALLS, 0);
        }
    }

    #[test]
    fn dispatches_front_object_and_releases_only_when_status_low_bit_is_set() {
        let _lock = setup();
        let vtable = [0usize, release as usize, 0, 0, dispatch as usize, 0, status as usize];
        let mut object = [vtable.as_ptr() as usize];
        let mut deque = [0u32; 9];
        deque[8] = 1;
        unsafe {
            FRONT_OBJECT = object.as_mut_ptr().cast();
            STATUS = 3;
            assert_eq!(deque_front_dispatch(deque.as_mut_ptr().cast(), 0xa5a5_5a5a), 0x8bad_f00d);
            assert_eq!(REMOVE_CALLS, 1);
            assert_eq!(DISPATCH_ARGUMENT, 0xa5a5_5a5a);
            assert_eq!(STATUS_CALLS, 1);
            assert_eq!(RELEASE_CALLS, 1);

            STATUS = 2;
            assert_eq!(deque_front_dispatch(deque.as_mut_ptr().cast(), 1), 0x8bad_f00d);
            assert_eq!(RELEASE_CALLS, 1);
        }
    }
}
