//! `retain_object` — original: `FUN_0837e8dc` @ `0x0837e8dc` (68 bytes).
//!
//! Raw ARM body, decoded from `osos.dec`:
//!
//! ```text
//! push  {r4,lr}
//! mov   r4,r0
//! ldr   r0,[r0]             @ context = object->context
//! bl    0x082dd3d8          @ context_activity_enter(context)
//! ldrsh r0,[r4,#0x22]       @ signed 16-bit object reference count
//! cmp   r0,#0
//! addne r0,r0,#1
//! strhne r0,[r4,#0x22]
//! bne   done
//! mov   r0,r4
//! bl    0x082b1520          @ retain_object_reference(object)
//! done:
//! ldr   r0,[r4]
//! ldr   r1,[r0,#0xe0]       @ context activity lease release
//! sub   r1,r1,#1
//! str   r1,[r0,#0xe0]
//! mov   r0,#0
//! pop   {r4,pc}
//! ```
//!
//! The next separately linked function begins at `0x0837e920` (`push
//! {r3-r11,lr}`), so the 68-byte extent is exact; no trailing literal pool.
//! Decoding every ARM B/BL word in `osos.dec` finds six direct call sites:
//! four unconditional `bl` and two `blne`, with no tail `b`. The two
//! predicated callers gate retention on a nonzero object pointer. No aligned
//! image data word contains `0x0837e8dc`, so it is never dispatched
//! virtually.
//!
//! Algorithm: acquire the object's context activity lease, then retain the
//! object's plain 16-bit reference count. A nonzero count is incremented
//! inline; a zero count is delegated to `FUN_082b1520`, whose zero transition
//! performs the associated context bookkeeping before incrementing the count.
//! Finally release the activity lease and return zero. All arithmetic wraps at
//! the destination width as ARM `add`/`sub` and `strh` do. Deliberate
//! deviation: `FUN_082b1520` remains retailOS-owned, so target builds call
//! its fixed load address while host builds route that boundary through a
//! private testable operation.

const OBJECT_CONTEXT: usize = 0;
const OBJECT_REFCOUNT: usize = 0x22;
const CONTEXT_ACTIVITY: usize = 0xe0;

/// Signature of the zero-reference-count retain path at `0x082b1520`.
type RetainObjectReference = unsafe extern "C" fn(*mut u8);

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn retain_object_reference(object: *mut u8) {
    let retain: RetainObjectReference = core::mem::transmute(0x082b_1520usize);
    retain(object);
}

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
struct RetainHostOps {
    retain: RetainObjectReference,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_retain(_object: *mut u8) {}

#[cfg(not(target_os = "none"))]
const DEFAULT_RETAIN_HOST_OPS: RetainHostOps = RetainHostOps {
    retain: unavailable_retain,
};

#[cfg(not(target_os = "none"))]
static mut RETAIN_HOST_OPS: RetainHostOps = DEFAULT_RETAIN_HOST_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn retain_object_reference(object: *mut u8) {
    let ops = core::ptr::read_volatile(core::ptr::addr_of!(RETAIN_HOST_OPS));
    (ops.retain)(object);
}

/// retain_object — original: `FUN_0837e8dc` @ `0x0837e8dc` (68 bytes; six
/// direct call sites: four `bl`, two `blne`).
///
/// Acquires `object`'s context activity lease, increments its plain u16
/// reference count at +0x22 (delegating a zero count to `0x082b1520`),
/// releases the lease, and returns zero. No NULL checks: `object` and its
/// context pointer must be live, matching the first two raw `ldr` words.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.retain_object")]
#[inline(never)]
pub unsafe extern "C" fn retain_object(object: *mut u8) -> u32 {
    let context = (object.add(OBJECT_CONTEXT) as *const *mut u8).read();
    crate::cxx::context_activity::context_activity_enter(context);

    let refcount = object.add(OBJECT_REFCOUNT) as *mut u16;
    let count = refcount.read();
    if count == 0 {
        retain_object_reference(object);
    } else {
        refcount.write(count.wrapping_add(1));
    }

    let activity = context.add(CONTEXT_ACTIVITY) as *mut u32;
    activity.write_volatile(activity.read_volatile().wrapping_sub(1));
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::sync::atomic::{AtomicBool, Ordering};

    static OPS_LOCK: AtomicBool = AtomicBool::new(false);
    static mut RETAIN_CALLS: usize = 0;
    static mut RETAINED_OBJECT: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn recording_retain(object: *mut u8) {
        RETAIN_CALLS += 1;
        RETAINED_OBJECT = object;
        let refcount = object.add(OBJECT_REFCOUNT) as *mut u16;
        refcount.write(refcount.read().wrapping_add(1));
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
            RETAIN_CALLS = 0;
            RETAINED_OBJECT = core::ptr::null_mut();
            core::ptr::addr_of_mut!(RETAIN_HOST_OPS).write_volatile(RetainHostOps {
                retain: recording_retain,
            });
        }
        Bench { _lock: lock }
    }

    impl Drop for Bench {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(RETAIN_HOST_OPS)
                    .write_volatile(DEFAULT_RETAIN_HOST_OPS);
            }
        }
    }

    #[repr(align(4))]
    struct ContextFixture {
        bytes: [u8; 0x100],
    }

    impl ContextFixture {
        fn new(marked: u32, activity: u32) -> Self {
            let mut fixture = ContextFixture { bytes: [0xa5u8; 0x100] };
            fixture.set_word(0xdc, marked);
            fixture.set_word(CONTEXT_ACTIVITY, activity);
            fixture
        }

        fn set_word(&mut self, offset: usize, value: u32) {
            self.bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }

        fn word(&self, offset: usize) -> u32 {
            u32::from_le_bytes(self.bytes[offset..offset + 4].try_into().unwrap())
        }

        fn assert_untouched_except_activity(&self, before: &ContextFixture) {
            for offset in (0..0x100usize).step_by(4) {
                if offset == CONTEXT_ACTIVITY {
                    continue;
                }
                assert_eq!(
                    self.word(offset),
                    before.word(offset),
                    "word at {offset:#x} must not be modified"
                );
            }
        }
    }

    #[repr(C)]
    struct ObjectFixture {
        context: *mut u8,
        before_refcount: [u8; OBJECT_REFCOUNT - core::mem::size_of::<*mut u8>()],
        refcount: u16,
        after_refcount: [u8; 0x10],
    }

    impl ObjectFixture {
        fn new(context: *mut u8, refcount: u16) -> Self {
            ObjectFixture {
                context,
                before_refcount: [0xa5; OBJECT_REFCOUNT - core::mem::size_of::<*mut u8>()],
                refcount,
                after_refcount: [0xa5; 0x10],
            }
        }

        fn object(&mut self) -> *mut u8 {
            self as *mut ObjectFixture as *mut u8
        }

        fn assert_untouched_except_refcount(&self, before: &ObjectFixture) {
            assert_eq!(self.context, before.context);
            assert_eq!(self.before_refcount, before.before_refcount);
            assert_eq!(self.after_refcount, before.after_refcount);
        }
    }

    #[test]
    fn zero_count_delegates_before_releasing_its_context_lease() {
        let _bench = bench();
        let mut context = ContextFixture::new(1, 7);
        let before_context = ContextFixture::new(1, 7);
        let mut object = ObjectFixture::new(context.bytes.as_mut_ptr(), 0);
        let before_object = ObjectFixture::new(context.bytes.as_mut_ptr(), 0);

        let result = unsafe { retain_object(object.object()) };

        assert_eq!(result, 0);
        assert_eq!(object.refcount, 1, "the delegated zero path retains once");
        assert_eq!(unsafe { RETAIN_CALLS }, 1);
        assert_eq!(unsafe { RETAINED_OBJECT }, object.object());
        assert_eq!(context.word(CONTEXT_ACTIVITY), 7, "lease nets to zero change");
        context.assert_untouched_except_activity(&before_context);
        object.assert_untouched_except_refcount(&before_object);
    }

    #[test]
    fn nonzero_count_increments_inline_without_delegating() {
        let _bench = bench();
        for initial in [1u16, 0x7fff, 0x8000, u16::MAX] {
            let mut context = ContextFixture::new(0, 3);
            let mut object = ObjectFixture::new(context.bytes.as_mut_ptr(), initial);

            assert_eq!(unsafe { retain_object(object.object()) }, 0);
            assert_eq!(object.refcount, initial.wrapping_add(1), "initial {initial:#x}");
            assert_eq!(context.word(CONTEXT_ACTIVITY), 3);
        }
        assert_eq!(unsafe { RETAIN_CALLS }, 0, "only zero may call 0x082b1520");
    }

    #[test]
    fn activity_count_wraps_through_the_acquire_release_pair() {
        let _bench = bench();
        let mut context = ContextFixture::new(1, u32::MAX);
        let mut object = ObjectFixture::new(context.bytes.as_mut_ptr(), 1);

        unsafe { retain_object(object.object()) };

        assert_eq!(object.refcount, 2);
        assert_eq!(context.word(CONTEXT_ACTIVITY), u32::MAX);
        assert_eq!(context.word(0xdc), 1, "retain never writes the mark flag");
    }
}
