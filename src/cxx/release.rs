//! C++ object release and the NULL-guarded owner-field forwarder.
//!
//! `release_object` is retailOS `FUN_0837ee98` at `0x0837ee98` (200
//! bytes). Its raw ARM body begins `movs r5,r0`, so a NULL object returns
//! NULL without touching a context. A non-NULL object holds its context
//! pointer at +0x00 and a plain 16-bit refcount at +0x22. The function
//! acquires the context lease, decrements that count, and only on its
//! transition from one to zero detaches the object from one or two context
//! lists, invokes the optional context-owned destructor at +0xc4, and
//! decrements the context's child count at +0x48. A zero child count causes
//! the context cleanup at `0x082dd800` when its +0x17 flag is clear or its
//! signed 64-bit work count at +0x98 is positive. Every path releases the
//! context lease and returns NULL.
//!
//! `release_via_field_0x48` is `FUN_0836761c` at `0x0836761c` (16 bytes).
//! The raw body is exactly `cmp r0,#0; ldrne r0,[r0,#0x48]; bne
//! 0x0837ee98; bx lr`: it guards only its owner and then tail-calls
//! [`release_object`]. Ghidra incorrectly inlines the tail target into this
//! four-instruction forwarder.
//!
//! Deviation: on the firmware target the two still-unported context
//! helpers are direct calls to their retailOS load addresses (`0x082d7fdc`
//! and `0x082dd800`); the enter helper `0x082dd3d8` is ported as
//! `context_activity_enter` in `cxx/context_activity.rs` and called
//! directly. Host builds use private recording
//! boundaries for those helpers so the release function's transitions and
//! virtual dispatch can be exercised; this does not replace or bypass
//! `release_object` itself.

/// Width of a target pointer field: 4 on ARMv5TE and pointer-sized in the
/// host fixtures, so widened host pointers never overlap adjacent fields.
const WORD: usize = core::mem::size_of::<*mut u8>();

const OBJECT_CONTEXT: usize = 0;
const OBJECT_REFCOUNT: usize = 0x22;
const PRIMARY_NODE: usize = 0x10;
const SECONDARY_NODE: usize = 0x2c;
const OWNER_CHILD: usize = 0x48;

const CONTEXT_PRIMARY_LIST: usize = 0x7c;
const CONTEXT_DATA: usize = 0x40;
const CONTEXT_CHILDREN: usize = 0x48;
const CONTEXT_WORK_COUNT: usize = 0x98;
const CONTEXT_RELEASABLE: usize = 0x17;
const CONTEXT_SECONDARY_LIST_ENABLED: usize = 0x14;
const CONTEXT_ACTIVITY: usize = 0xe0;
const CONTEXT_DESTRUCTOR: usize = 0xc4;

/// Converts a target pointer slot offset into a host fixture offset.
#[inline(always)]
const fn pointer_offset(target_offset: usize) -> usize {
    target_offset / 4 * WORD
}

#[inline(always)]
unsafe fn read_pointer(base: *mut u8, target_offset: usize) -> *mut u8 {
    (base.add(pointer_offset(target_offset)) as *const *mut u8).read()
}

type ContextDestructor = unsafe extern "C" fn(*mut u8, *mut u8);

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn enter_context(context: *mut u8) {
    // Ported: context_activity_enter in cxx/context_activity.rs.
    unsafe { crate::cxx::context_activity::context_activity_enter(context) }
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn detach_context_list(list: *mut u8, node: *mut u8, object: *mut u8) {
    let detach: unsafe extern "C" fn(*mut u8, *mut u8, *mut u8) =
        core::mem::transmute(0x082d_7fdcusize);
    detach(list, node, object);
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn release_context(context: *mut u8) {
    let release: unsafe extern "C" fn(*mut u8) = core::mem::transmute(0x082d_d800usize);
    release(context);
}

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
struct ReleaseHostOps {
    enter_context: unsafe extern "C" fn(*mut u8),
    detach_context_list: unsafe extern "C" fn(*mut u8, *mut u8, *mut u8),
    release_context: unsafe extern "C" fn(*mut u8),
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_enter_context(context: *mut u8) {
    let activity = context.add(CONTEXT_ACTIVITY) as *mut u32;
    activity.write(activity.read().wrapping_add(1));
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_detach_context_list(_list: *mut u8, _node: *mut u8, _object: *mut u8) {}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_release_context(_context: *mut u8) {}

#[cfg(not(target_os = "none"))]
const DEFAULT_RELEASE_HOST_OPS: ReleaseHostOps = ReleaseHostOps {
    enter_context: host_enter_context,
    detach_context_list: host_detach_context_list,
    release_context: host_release_context,
};

#[cfg(not(target_os = "none"))]
static mut RELEASE_HOST_OPS: ReleaseHostOps = DEFAULT_RELEASE_HOST_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn host_ops() -> ReleaseHostOps {
    core::ptr::read_volatile(core::ptr::addr_of!(RELEASE_HOST_OPS))
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn enter_context(context: *mut u8) {
    (host_ops().enter_context)(context);
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn detach_context_list(list: *mut u8, node: *mut u8, object: *mut u8) {
    (host_ops().detach_context_list)(list, node, object);
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn release_context(context: *mut u8) {
    (host_ops().release_context)(context);
}

/// release_object — original: `FUN_0837ee98` @ `0x0837ee98` (200 bytes).
///
/// Drops `object`'s plain 16-bit reference count and returns NULL. The
/// object pointer is NULL-guarded; a non-NULL object and its context pointer
/// at +0x00 are preconditions, as in the raw `ldr r4,[r5,#0]`. The
/// destruction path runs only when the stored count becomes zero; underflow
/// wraps from zero to `0xffff`, matching `ldrh/sub/lsl/asr/strh`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn release_object(object: *mut u8) -> *mut u8 {
    if object.is_null() {
        return core::ptr::null_mut();
    }

    let context = read_pointer(object, OBJECT_CONTEXT);
    enter_context(context);

    let refcount = object.add(OBJECT_REFCOUNT) as *mut u16;
    let remaining = refcount.read().wrapping_sub(1);
    refcount.write(remaining);

    if remaining == 0 {
        detach_context_list(
            context.add(CONTEXT_PRIMARY_LIST),
            object.add(PRIMARY_NODE),
            object,
        );
        if context.add(CONTEXT_SECONDARY_LIST_ENABLED).read() == 0 {
            detach_context_list(0x0837_ef60usize as *mut u8, object.add(SECONDARY_NODE), object);
        }

        let destructor = read_pointer(context, CONTEXT_DESTRUCTOR);
        if !destructor.is_null() {
            let destructor: ContextDestructor = core::mem::transmute(destructor);
            destructor(object, read_pointer(context, CONTEXT_DATA));
        }

        let children = context.add(CONTEXT_CHILDREN) as *mut u32;
        let remaining_children = children.read().wrapping_sub(1);
        children.write(remaining_children);
        if remaining_children == 0
            && (context.add(CONTEXT_RELEASABLE).read() == 0
                || (context.add(CONTEXT_WORK_COUNT) as *const i64).read() > 0)
        {
            release_context(context);
        }
    }

    let activity = context.add(CONTEXT_ACTIVITY) as *mut u32;
    activity.write(activity.read().wrapping_sub(1));
    core::ptr::null_mut()
}

/// release_via_field_0x48 — original: `FUN_0836761c` @ `0x0836761c`
/// (16 bytes; 51 `bl` call sites).
///
/// NULL-guards `owner`; otherwise passes its child pointer at target offset
/// +0x48 to [`release_object`]. The child itself is deliberately not
/// guarded, because `release_object` owns that NULL behavior.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn release_via_field_0x48(owner: *mut u8) -> *mut u8 {
    if owner.is_null() {
        core::ptr::null_mut()
    } else {
        release_object(read_pointer(owner, OWNER_CHILD))
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::sync::atomic::{AtomicBool, Ordering};
    use std::vec::Vec;

    static OPS_LOCK: AtomicBool = AtomicBool::new(false);
    static mut EVENTS: Vec<Event> = Vec::new();

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Event {
        Enter(usize),
        Detach(usize, usize, usize),
        Destructor(usize, usize),
        ReleaseContext(usize),
    }

    unsafe extern "C" fn recording_enter(context: *mut u8) {
        EVENTS.push(Event::Enter(context as usize));
        let activity = context.add(CONTEXT_ACTIVITY) as *mut u32;
        activity.write(activity.read().wrapping_add(1));
    }

    unsafe extern "C" fn recording_detach(list: *mut u8, node: *mut u8, object: *mut u8) {
        EVENTS.push(Event::Detach(list as usize, node as usize, object as usize));
    }

    unsafe extern "C" fn recording_release_context(context: *mut u8) {
        EVENTS.push(Event::ReleaseContext(context as usize));
    }

    unsafe extern "C" fn recording_destructor(object: *mut u8, data: *mut u8) {
        EVENTS.push(Event::Destructor(object as usize, data as usize));
    }

    struct TestLock;

    fn lock_ops() -> TestLock {
        while OPS_LOCK
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            while OPS_LOCK.load(Ordering::Relaxed) {
                core::hint::spin_loop();
            }
        }
        TestLock
    }

    impl Drop for TestLock {
        fn drop(&mut self) {
            OPS_LOCK.store(false, Ordering::Release);
        }
    }

    struct Bench {
        _lock: TestLock,
    }

    fn bench() -> Bench {
        let lock = lock_ops();
        unsafe {
            EVENTS.clear();
            core::ptr::addr_of_mut!(RELEASE_HOST_OPS).write_volatile(ReleaseHostOps {
                enter_context: recording_enter,
                detach_context_list: recording_detach,
                release_context: recording_release_context,
            });
        }
        Bench { _lock: lock }
    }

    impl Drop for Bench {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(RELEASE_HOST_OPS).write_volatile(DEFAULT_RELEASE_HOST_OPS);
            }
        }
    }

    #[repr(align(8))]
    struct Fixture {
        object: [u8; 0x40],
        context: [u8; 0x200],
        data: [u8; 8],
    }

    impl Fixture {
        fn new(refcount: u16) -> Self {
            let mut fixture = Fixture {
                object: [0; 0x40],
                context: [0; 0x200],
                data: [0; 8],
            };
            unsafe {
                (fixture.object_ptr().add(OBJECT_REFCOUNT) as *mut u16).write(refcount);
                (fixture.context_ptr().add(CONTEXT_ACTIVITY) as *mut u32).write(7);
                (fixture.context_ptr().add(CONTEXT_CHILDREN) as *mut u32).write(1);
            }
            fixture
        }

        fn object_ptr(&mut self) -> *mut u8 {
            self.object.as_mut_ptr()
        }

        fn context_ptr(&mut self) -> *mut u8 {
            self.context.as_mut_ptr()
        }

        /// Wires self-referential fixture pointers after the fixture has
        /// reached its final stack address.
        fn wire(&mut self) {
            unsafe {
                write_pointer(self.object_ptr(), OBJECT_CONTEXT, self.context_ptr());
                write_pointer(self.context_ptr(), CONTEXT_DATA, self.data.as_mut_ptr());
            }
        }

        fn refcount(&self) -> u16 {
            unsafe { (self.object.as_ptr().add(OBJECT_REFCOUNT) as *const u16).read() }
        }

        fn activity(&self) -> u32 {
            unsafe { (self.context.as_ptr().add(CONTEXT_ACTIVITY) as *const u32).read() }
        }

        fn children(&self) -> u32 {
            unsafe { (self.context.as_ptr().add(CONTEXT_CHILDREN) as *const u32).read() }
        }

        fn set_children(&mut self, value: u32) {
            unsafe { (self.context_ptr().add(CONTEXT_CHILDREN) as *mut u32).write(value) };
        }

        fn set_secondary_list_enabled(&mut self, value: u8) {
            unsafe { self.context_ptr().add(CONTEXT_SECONDARY_LIST_ENABLED).write(value) };
        }

        fn set_releasable(&mut self, value: u8) {
            unsafe { self.context_ptr().add(CONTEXT_RELEASABLE).write(value) };
        }

        fn set_work_count(&mut self, value: i64) {
            unsafe { (self.context_ptr().add(CONTEXT_WORK_COUNT) as *mut i64).write(value) };
        }

        fn install_destructor(&mut self) {
            unsafe {
                write_pointer(
                    self.context_ptr(),
                    CONTEXT_DESTRUCTOR,
                    recording_destructor as *const () as *mut u8,
                );
            }
        }
    }

    unsafe fn write_pointer(base: *mut u8, target_offset: usize, value: *mut u8) {
        (base.add(pointer_offset(target_offset)) as *mut *mut u8).write(value);
    }

    fn events() -> Vec<Event> {
        unsafe { EVENTS.clone() }
    }

    #[test]
    fn null_inputs_return_null_without_entering_a_context() {
        let _bench = bench();
        assert!(unsafe { release_object(core::ptr::null_mut()) }.is_null());
        assert!(unsafe { release_via_field_0x48(core::ptr::null_mut()) }.is_null());
        assert!(events().is_empty());
    }

    #[test]
    fn a_nonterminal_drop_only_decrements_the_plain_u16_refcount() {
        let _bench = bench();
        let mut fixture = Fixture::new(2);
        fixture.install_destructor();
        fixture.wire();
        let object = fixture.object_ptr();
        let context = fixture.context_ptr();

        assert!(unsafe { release_object(object) }.is_null());
        assert_eq!(fixture.refcount(), 1);
        assert_eq!(fixture.children(), 1);
        assert_eq!(fixture.activity(), 7, "the enter/exit lease is balanced");
        assert_eq!(events(), std::vec![Event::Enter(context as usize)]);
    }

    #[test]
    fn the_zero_transition_detaches_dispatches_and_cascades_in_order() {
        let _bench = bench();
        let mut fixture = Fixture::new(1);
        fixture.install_destructor();
        fixture.set_releasable(0);
        fixture.set_work_count(0);
        fixture.wire();
        let object = fixture.object_ptr();
        let context = fixture.context_ptr();
        let data = fixture.data.as_mut_ptr();

        assert!(unsafe { release_object(object) }.is_null());
        assert_eq!(fixture.refcount(), 0);
        assert_eq!(fixture.children(), 0);
        assert_eq!(fixture.activity(), 7);
        assert_eq!(
            events(),
            std::vec![
                Event::Enter(context as usize),
                Event::Detach(
                    context.wrapping_add(CONTEXT_PRIMARY_LIST) as usize,
                    object.wrapping_add(PRIMARY_NODE) as usize,
                    object as usize,
                ),
                Event::Detach(0x0837_ef60, object.wrapping_add(SECONDARY_NODE) as usize, object as usize),
                Event::Destructor(object as usize, data as usize),
                Event::ReleaseContext(context as usize),
            ]
        );
    }

    #[test]
    fn context_flags_suppress_only_their_respective_terminal_actions() {
        let _bench = bench();
        let mut fixture = Fixture::new(1);
        fixture.install_destructor();
        fixture.set_secondary_list_enabled(1);
        fixture.set_releasable(1);
        fixture.set_work_count(0);
        fixture.set_children(2);
        fixture.wire();
        let object = fixture.object_ptr();
        let context = fixture.context_ptr();
        let data = fixture.data.as_mut_ptr();

        unsafe { release_object(object) };

        assert_eq!(fixture.children(), 1);
        assert_eq!(
            events(),
            std::vec![
                Event::Enter(context as usize),
                Event::Detach(
                    context.wrapping_add(CONTEXT_PRIMARY_LIST) as usize,
                    object.wrapping_add(PRIMARY_NODE) as usize,
                    object as usize,
                ),
                Event::Destructor(object as usize, data as usize),
            ]
        );
    }

    #[test]
    fn owner_forwarder_uses_the_ported_release_object_directly() {
        let _bench = bench();
        let mut fixture = Fixture::new(2);
        fixture.wire();
        let mut owner = [0u8; pointer_offset(OWNER_CHILD) + WORD];
        let object = fixture.object_ptr();
        let context = fixture.context_ptr();
        unsafe {
            write_pointer(owner.as_mut_ptr(), OWNER_CHILD, object);
            assert!(release_via_field_0x48(owner.as_mut_ptr()).is_null());
        }

        assert_eq!(fixture.refcount(), 1);
        assert_eq!(events(), std::vec![Event::Enter(context as usize)]);
    }
}
