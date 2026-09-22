//! Dequeueing and dispatching a front polymorphic object.

use crate::cxx::templates::deque_iter_assign_alias_a34c;
use crate::heap::block_deque::BlockDeque;

/// ABI of the unported `FUN_083df490` deque-pop member.
type DequePopFront = unsafe extern "C" fn(*mut BlockDeque);
type FrontDispatch = unsafe extern "C" fn(*mut u8, u32) -> u32;
type FrontStatus = unsafe extern "C" fn(*mut u8) -> u32;
type FrontRelease = unsafe extern "C" fn(*mut u8);

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn deque_pop_front() -> DequePopFront {
    core::mem::transmute(0x083d_f490usize)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_deque_pop_front(_deque: *mut BlockDeque) {
    panic!("deque_front_remove requires a deque-pop-front seam on host")
}

/// Host replacement for the verified but unported `FUN_083df490` callee.
#[cfg(not(target_os = "none"))]
pub static mut DEQUE_POP_FRONT: DequePopFront = missing_deque_pop_front;

#[inline(always)]
unsafe fn pop_front(deque: *mut BlockDeque) {
    #[cfg(target_os = "none")]
    { deque_pop_front()(deque) }
    #[cfg(not(target_os = "none"))]
    { DEQUE_POP_FRONT(deque) }
}

/// deque_front_remove — original: `FUN_082156f0` @ `0x082156f0`.
///
/// Raw `osos.dec` fixes the 64-byte extent through `pop {r4,r5,r6,pc}` at
/// `0x0821572c`; the next independently linked function begins at
/// `0x08215730`. Complete A32 branch-immediate decoding finds three inbound
/// calls: two plain `bl` at `0x08215674` and `0x0821585c`, plus predicated
/// `blne` at `0x082155bc`.
///
/// If the deque count is zero, returns NULL without reading its iterator. For
/// a nonempty deque, copies the begin iterator into a stack temporary through
/// `deque_iter_assign_alias_a34c`, reads that copy's current object pointer,
/// then calls the deque's `FUN_083df490` pop-front member and returns the saved
/// object. The copy preserves the retail read-before-pop order.
///
/// # Deliberate deviations
///
/// `FUN_083df490` has a verified address and ABI but no Rust port, so this
/// target path calls it through a typed boundary and host tests install a
/// recorder. The existing iterator-copy port replaces the direct retail call.
///
/// # Safety
///
/// `deque` must point to a valid [`BlockDeque`]. If its count is nonzero,
/// its begin iterator must be readable and its pop-front member must accept
/// the deque's current nonempty state.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.deque_front_remove")]
#[inline(never)]
pub unsafe extern "C" fn deque_front_remove(deque: *mut BlockDeque) -> *mut u8 {
    if (*deque).count == 0 {
        return core::ptr::null_mut();
    }

    let mut begin = core::mem::MaybeUninit::<crate::heap::block_deque::DequeIter>::uninit();
    deque_iter_assign_alias_a34c(begin.as_mut_ptr().cast(), core::ptr::addr_of!((*deque).begin).cast());
    let object = begin.assume_init().cur;
    pop_front(deque);
    object
}

#[inline(always)]
unsafe fn remove_front_object(deque: *mut u8) -> *mut u8 {
    deque_front_remove(deque.cast())
}

/// `deque_front_dispatch` — original: `FUN_0821583c` @ `0x0821583c`.
///
/// Raw A32 establishes the 116-byte extent `0x0821583c..0x082158af`; the
/// independent next function begins at `0x082158b0`. It contains two plain
/// unconditional `bl` instructions (`container_is_empty` and `FUN_082156f0`),
/// three indirect `blx` instructions, two of them predicated `blxne`, and no
/// predicated plain `bl` instructions.
///
/// When the deque count word at `+0x20` is zero, returns zero. Otherwise it
/// removes the front object, calls its vtable `+0x10` method with `argument`,
/// then calls its `+0x18` status method. A set low status bit invokes vtable
/// `+0x04` to release the object. The `+0x10` result is returned unchanged.
///
/// # Deliberate deviation
///
/// [`deque_front_remove`] crosses the verified, unported `FUN_083df490`
/// boundary through a typed call; the three virtual calls are expressed as
/// typed calls rather than `blx`.
///
/// # Safety
///
/// `deque` must identify a valid [`BlockDeque`]. When nonempty, its
/// front-removal helper must return an object with a readable vtable and
/// callable slots `+0x04`, `+0x10`, and `+0x18`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn deque_front_dispatch(deque: *mut u8, argument: u32) -> u32 {
    if (*deque.cast::<BlockDeque>()).count == 0 {
        return 0;
    }

    let object = remove_front_object(deque);
    let vtable = (object as *const *const usize).read();
    let dispatch: FrontDispatch = core::mem::transmute(vtable.add(4).read());
    let result = dispatch(object, argument);
    let status: FrontStatus = core::mem::transmute(vtable.add(6).read());

    if status(object) & 1 != 0 {
        let release: FrontRelease = core::mem::transmute(vtable.add(1).read());
        release(object);
    }

    result
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{deque_front_dispatch, deque_front_remove, BlockDeque, DequePopFront, DEQUE_POP_FRONT};
    use crate::heap::block_deque::DequeIter;
    use parking_lot::{Mutex, MutexGuard};

    static SEAM_LOCK: Mutex<()> = Mutex::new(());
    static mut POP_CALLS: u32 = 0;
    static mut DISPATCH_ARGUMENT: u32 = 0;
    static mut STATUS_CALLS: u32 = 0;
    static mut RELEASE_CALLS: u32 = 0;
    static mut STATUS: u32 = 0;

    unsafe extern "C" fn pop_front(_deque: *mut BlockDeque) {
        unsafe { POP_CALLS += 1 }
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

    fn deque(count: u32, object: *mut u8) -> BlockDeque {
        BlockDeque {
            begin: DequeIter { cur: object, ..DequeIter::NULL },
            end: DequeIter::NULL,
            count,
            map: core::ptr::null_mut(),
            map_cap: 0,
        }
    }

    fn setup() -> MutexGuard<'static, ()> {
        let lock = SEAM_LOCK.lock();
        unsafe {
            POP_CALLS = 0;
            DISPATCH_ARGUMENT = 0;
            STATUS_CALLS = 0;
            RELEASE_CALLS = 0;
            STATUS = 0;
            DEQUE_POP_FRONT = pop_front as DequePopFront;
        }
        lock
    }

    #[test]
    fn removal_returns_null_for_empty_and_saves_front_before_popping() {
        let _lock = setup();
        let mut empty = deque(0, core::ptr::null_mut());
        let mut object = 0u8;
        let mut nonempty = deque(1, core::ptr::addr_of_mut!(object));
        unsafe {
            assert!(deque_front_remove(&mut empty).is_null());
            assert_eq!(POP_CALLS, 0);
            assert_eq!(deque_front_remove(&mut nonempty), core::ptr::addr_of_mut!(object));
            assert_eq!(POP_CALLS, 1);
        }
    }

    #[test]
    fn dispatches_front_object_and_releases_only_when_status_low_bit_is_set() {
        let _lock = setup();
        let vtable = [0usize, release as usize, 0, 0, dispatch as usize, 0, status as usize];
        let mut object = [vtable.as_ptr() as usize];
        let mut deque = deque(1, object.as_mut_ptr().cast());
        unsafe {
            STATUS = 3;
            assert_eq!(deque_front_dispatch((&mut deque as *mut BlockDeque).cast(), 0xa5a5_5a5a), 0x8bad_f00d);
            assert_eq!(POP_CALLS, 1);
            assert_eq!(DISPATCH_ARGUMENT, 0xa5a5_5a5a);
            assert_eq!(STATUS_CALLS, 1);
            assert_eq!(RELEASE_CALLS, 1);

            STATUS = 2;
            assert_eq!(deque_front_dispatch((&mut deque as *mut BlockDeque).cast(), 1), 0x8bad_f00d);
            assert_eq!(RELEASE_CALLS, 1);
        }
    }
}
