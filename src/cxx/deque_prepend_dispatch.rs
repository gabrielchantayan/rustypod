//! Transactional insertion of a polymorphic front object.

#[repr(C)]
pub struct FrontObject {
    pub vtable: *const FrontVtable,
}

#[repr(C)]
pub struct FrontVtable {
    pub preceding: [usize; 2],
    pub check: unsafe extern "C" fn(*mut FrontObject, *mut FrontObject) -> u32,
    pub middle: [usize; 2],
    pub dispatch: unsafe extern "C" fn(*mut FrontObject, u32) -> u32,
}

pub type FrontLookup = unsafe extern "C" fn(*mut u8) -> *mut FrontObject;
pub type FrontPrepend = unsafe extern "C" fn(*mut u8, *mut FrontObject);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_lookup(_: *mut u8) -> *mut FrontObject {
    panic!("install verified deque lookup/removal host seams")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_prepend(_: *mut u8, _: *mut FrontObject) {
    panic!("install verified deque prepend host seam")
}

/// Host substitutes for stock 0x082156b8, 0x08215618, and 0x082156f0.
/// Install only while no concurrent caller can access these seams.
#[cfg(not(target_os = "none"))]
pub static mut FRONT_OPERATIONS: (FrontLookup, FrontPrepend, FrontLookup) =
    (missing_lookup, missing_prepend, missing_lookup);

/// `deque_prepend_dispatch` — FUN_0821554c @ 0x0821554c, 124 bytes.
/// True extent ends at 0x082155c8's independent push. Raw A32 verifies two
/// plain BLs, one BLNE, and two BLX calls; inbound calls are two plain BLs
/// (0x0818b9b4, 0x0818bc20), with no predicated BLs.
/// Always look up the front before checking candidate NULL (error 9).
/// If requested and the front is non-NULL, invoke its slot 2 check; any
/// nonzero result vetoes insertion. Otherwise prepend the candidate, invoke
/// its slot 5 with argument, and remove the front on any nonzero result.
/// Return the check/dispatch result without masking it.
/// Deliberate deviations: typed virtual calls and native-width host vtables;
/// retain all three verified stock helpers, because existing Rust lookup and
/// removal ports return the cursor rather than dereferencing it. Hosts use
/// explicit seams rather than reimplement segmented allocation.
///
/// # Safety
/// The deque must satisfy the stock helper contracts, even for NULL candidate.
/// Non-NULL objects require callable vtable slots 2 and 5 as used above.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn deque_prepend_dispatch(
    deque: *mut u8, candidate: *mut FrontObject, argument: u32, check_front: u32,
) -> u32 {
    #[cfg(target_os = "none")]
    let (lookup, prepend, remove): (FrontLookup, FrontPrepend, FrontLookup) = (
        core::mem::transmute(0x0821_56b8usize),
        core::mem::transmute(0x0821_5618usize),
        core::mem::transmute(0x0821_56f0usize),
    );
    #[cfg(not(target_os = "none"))]
    let (lookup, prepend, remove) = FRONT_OPERATIONS;

    let front = lookup(deque);
    if candidate.is_null() {
        return 9;
    }
    if !front.is_null() && check_front != 0 {
        let result = ((*(*front).vtable).check)(front, candidate);
        if result != 0 {
            return result;
        }
    }
    prepend(deque, candidate);
    let result = ((*(*candidate).vtable).dispatch)(candidate, argument);
    if result != 0 {
        remove(deque);
    }
    result
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    struct Queue { objects: Vec<*mut FrontObject>, events: Vec<u32> }
    #[repr(C)]
    struct Object {
        base: FrontObject,
        queue: *mut Queue,
        result: u32,
        argument: u32,
    }
    unsafe extern "C" fn lookup(queue: *mut u8) -> *mut FrontObject {
        let queue = &mut *queue.cast::<Queue>();
        queue.events.push(1);
        queue.objects.first().copied().unwrap_or(core::ptr::null_mut())
    }
    unsafe extern "C" fn prepend(queue: *mut u8, object: *mut FrontObject) {
        let queue = &mut *queue.cast::<Queue>();
        queue.events.push(3);
        queue.objects.insert(0, object);
    }
    unsafe extern "C" fn remove(queue: *mut u8) -> *mut FrontObject {
        let queue = &mut *queue.cast::<Queue>();
        queue.events.push(5);
        queue.objects.remove(0)
    }
    unsafe extern "C" fn check(front: *mut FrontObject, candidate: *mut FrontObject) -> u32 {
        let front = &*front.cast::<Object>();
        assert!(!candidate.is_null());
        assert_eq!((&(*front.queue).objects)[0], &front.base as *const _ as *mut _);
        (*front.queue).events.push(2);
        front.result
    }
    unsafe extern "C" fn dispatch(candidate: *mut FrontObject, argument: u32) -> u32 {
        let candidate = &*candidate.cast::<Object>();
        assert_eq!(argument, candidate.argument);
        assert_eq!((&(*candidate.queue).objects)[0], &candidate.base as *const _ as *mut _);
        (*candidate.queue).events.push(4);
        candidate.result
    }
    static VTABLE: FrontVtable = FrontVtable {
        preceding: [0; 2], check, middle: [0; 2], dispatch,
    };

    #[test]
    fn insertion_veto_and_rollback_preserve_queue_and_all_status_bits() {
        unsafe {
            let saved = FRONT_OPERATIONS;
            FRONT_OPERATIONS = (lookup, prepend, remove);
            for populated in [false, true] {
                for enabled in [0, 1, 0x8000_0000] {
                    for veto in [0, 0x1000, u32::MAX] {
                        for result in [0, 1, 0x1000, u32::MAX] {
                            for null_candidate in [false, true] {
                                let mut queue = Queue { objects: Vec::new(), events: Vec::new() };
                                let mut front = Object { base: FrontObject { vtable: &VTABLE }, queue: &mut queue, result: veto, argument: 0 };
                                let mut candidate = Object { base: FrontObject { vtable: &VTABLE }, queue: &mut queue, result, argument: 0xa5a5_1234 };
                                let front_ptr = &mut front.base as *mut FrontObject;
                                let candidate_ptr = &mut candidate.base as *mut FrontObject;
                                if populated { queue.objects.push(front_ptr); }
                                let before = queue.objects.clone();
                                let rejected = populated && enabled != 0 && veto != 0;
                                let actual = deque_prepend_dispatch((&mut queue as *mut Queue).cast(), if null_candidate { core::ptr::null_mut() } else { candidate_ptr }, candidate.argument, enabled);
                                let expected = if null_candidate { 9 } else if rejected { veto } else { result };
                                assert_eq!(actual, expected);
                                let mut events = std::vec![1];
                                if !null_candidate {
                                    if populated && enabled != 0 { events.push(2); }
                                    if !rejected { events.extend([3, 4]); if result != 0 { events.push(5); } }
                                }
                                assert_eq!(queue.events, events);
                                let mut expected_objects = before;
                                if !null_candidate && !rejected && result == 0 { expected_objects.insert(0, candidate_ptr); }
                                assert_eq!(queue.objects, expected_objects);
                            }
                        }
                    }
                }
            }
            FRONT_OPERATIONS = saved;
        }
    }
}
