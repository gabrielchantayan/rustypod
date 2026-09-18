//! `resource_child_size_lookup` — original: `FUN_0813e7f8` @
//! `0x0813e7f8` (96 bytes).
//!
//! Raw ARM establishes the exact extent `0x0813e7f8..0x0813e858`: the next
//! separately linked function begins at `0x0813e858`. The body contains two
//! unconditional plain `bl` words (`0x0813e810` and `0x0813e820`), with no
//! predicated `bl`.
//!
//! # Algorithm
//!
//! Look up the context's resource collection at +0x40, select its child by
//! `selector`, then write the signed height (+0x16 - +0x12) and width
//! (+0x14 - +0x10) to the two output words. Either failed lookup returns zero
//! without modifying either output; success returns one.
//!
//! Deliberate deviations: the two unported lookup calls retain their fixed
//! retail load addresses on target builds and use injectable host boundaries
//! for tests. Their collection and child types remain opaque.

const CONTEXT_COLLECTION_OFFSET: usize = 0x40;
const CHILD_LEFT_OFFSET: usize = 0x10;
const CHILD_TOP_OFFSET: usize = 0x12;
const CHILD_RIGHT_OFFSET: usize = 0x14;
const CHILD_BOTTOM_OFFSET: usize = 0x16;

type RetailDirectLookup = unsafe extern "C" fn(*mut u8) -> *const u8;
type RetailChildLookup = unsafe extern "C" fn(*const u8, u32) -> *const u8;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn retail_direct_lookup(collection: *mut u8) -> *const u8 {
    let lookup: RetailDirectLookup = unsafe { core::mem::transmute(0x0805_0418usize) };
    unsafe { lookup(collection) }
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn retail_child_lookup(resource: *const u8, selector: u32) -> *const u8 {
    let lookup: RetailChildLookup = unsafe { core::mem::transmute(0x0805_0708usize) };
    unsafe { lookup(resource, selector) }
}

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
struct LookupHostOps {
    direct: RetailDirectLookup,
    child: RetailChildLookup,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_direct_lookup(_collection: *mut u8) -> *const u8 {
    core::ptr::null()
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_child_lookup(_resource: *const u8, _selector: u32) -> *const u8 {
    core::ptr::null()
}

#[cfg(not(target_os = "none"))]
const DEFAULT_LOOKUP_HOST_OPS: LookupHostOps = LookupHostOps {
    direct: unavailable_direct_lookup,
    child: unavailable_child_lookup,
};

#[cfg(not(target_os = "none"))]
static mut LOOKUP_HOST_OPS: LookupHostOps = DEFAULT_LOOKUP_HOST_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn retail_direct_lookup(collection: *mut u8) -> *const u8 {
    unsafe { (LOOKUP_HOST_OPS.direct)(collection) }
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn retail_child_lookup(resource: *const u8, selector: u32) -> *const u8 {
    unsafe { (LOOKUP_HOST_OPS.child)(resource, selector) }
}

/// Looks up a resource child and returns its signed width and height.
///
/// # Safety
///
/// `context` must be readable at +0x40. On a successful lookup, the returned
/// child must be half-word aligned and readable at offsets +0x10 through
/// +0x17. Both outputs must be valid, four-byte aligned writable words. The
/// original validates none of these pointers.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.resource_child_size_lookup")]
#[inline(never)]
pub unsafe extern "C" fn resource_child_size_lookup(
    context: *mut u8,
    _unused: u32,
    selector: u32,
    out_height: *mut i32,
    out_width: *mut i32,
) -> u32 {
    unsafe {
        let resource = retail_direct_lookup(context.add(CONTEXT_COLLECTION_OFFSET));
        if resource.is_null() {
            return 0;
        }
        let child = retail_child_lookup(resource, selector);
        if child.is_null() {
            return 0;
        }
        let height = i32::from(child.add(CHILD_BOTTOM_OFFSET).cast::<i16>().read())
            - i32::from(child.add(CHILD_TOP_OFFSET).cast::<i16>().read());
        let width = i32::from(child.add(CHILD_RIGHT_OFFSET).cast::<i16>().read())
            - i32::from(child.add(CHILD_LEFT_OFFSET).cast::<i16>().read());
        out_height.write(height);
        out_width.write(width);
        1
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::sync::atomic::{AtomicBool, Ordering};

    static OPS_LOCK: AtomicBool = AtomicBool::new(false);
    static mut DIRECT_RESULT: *const u8 = core::ptr::null();
    static mut CHILD_RESULT: *const u8 = core::ptr::null();
    static mut DIRECT_ARGUMENT: *mut u8 = core::ptr::null_mut();
    static mut CHILD_ARGUMENT: Option<(*const u8, u32)> = None;

    unsafe extern "C" fn recording_direct_lookup(collection: *mut u8) -> *const u8 {
        unsafe {
            DIRECT_ARGUMENT = collection;
            DIRECT_RESULT
        }
    }

    unsafe extern "C" fn recording_child_lookup(resource: *const u8, selector: u32) -> *const u8 {
        unsafe {
            CHILD_ARGUMENT = Some((resource, selector));
            CHILD_RESULT
        }
    }

    struct TestLock;

    fn lock_ops() -> TestLock {
        while OPS_LOCK.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
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

    fn bench(direct: *const u8, child: *const u8) -> Bench {
        let lock = lock_ops();
        unsafe {
            DIRECT_RESULT = direct;
            CHILD_RESULT = child;
            DIRECT_ARGUMENT = core::ptr::null_mut();
            CHILD_ARGUMENT = None;
            core::ptr::addr_of_mut!(LOOKUP_HOST_OPS).write_volatile(LookupHostOps {
                direct: recording_direct_lookup,
                child: recording_child_lookup,
            });
        }
        Bench { _lock: lock }
    }

    impl Drop for Bench {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(LOOKUP_HOST_OPS).write_volatile(DEFAULT_LOOKUP_HOST_OPS);
            }
        }
    }

    #[repr(align(4))]
    struct ContextFixture {
        bytes: [u8; 0x44],
    }

    #[repr(align(2))]
    struct ChildFixture {
        bytes: [u8; 0x18],
    }

    fn write_i16(bytes: &mut [u8], offset: usize, value: i16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn writes_signed_child_dimensions_after_both_lookups() {
        let mut context = ContextFixture { bytes: [0; 0x44] };
        let mut child = ChildFixture { bytes: [0; 0x18] };
        write_i16(&mut child.bytes, CHILD_LEFT_OFFSET, -200);
        write_i16(&mut child.bytes, CHILD_TOP_OFFSET, 300);
        write_i16(&mut child.bytes, CHILD_RIGHT_OFFSET, 100);
        write_i16(&mut child.bytes, CHILD_BOTTOM_OFFSET, -400);
        let resource = 0x1234usize as *const u8;
        let _bench = bench(resource, child.bytes.as_ptr());
        let mut height = 0;
        let mut width = 0;

        let result = unsafe {
            resource_child_size_lookup(context.bytes.as_mut_ptr(), 0xfeed_face, 0xdead_beef, &mut height, &mut width)
        };

        assert_eq!(result, 1);
        assert_eq!(unsafe { DIRECT_ARGUMENT }, unsafe { context.bytes.as_mut_ptr().add(0x40) });
        assert_eq!(unsafe { CHILD_ARGUMENT }, Some((resource, 0xdead_beef)));
        assert_eq!(height, -700);
        assert_eq!(width, 300);
    }

    #[test]
    fn preserves_both_outputs_when_either_lookup_fails() {
        let mut context = ContextFixture { bytes: [0; 0x44] };
        let mut height = 0x1234_5678;
        let mut width = -0x1234_567;
        let _bench = bench(core::ptr::null(), core::ptr::null());

        assert_eq!(unsafe { resource_child_size_lookup(context.bytes.as_mut_ptr(), 0, 9, &mut height, &mut width) }, 0);
        assert_eq!(unsafe { CHILD_ARGUMENT }, None);
        assert_eq!((height, width), (0x1234_5678, -0x1234_567));

        unsafe {
            DIRECT_RESULT = 0x1234usize as *const u8;
        }
        assert_eq!(unsafe { resource_child_size_lookup(context.bytes.as_mut_ptr(), 0, 10, &mut height, &mut width) }, 0);
        assert_eq!(unsafe { CHILD_ARGUMENT }, Some((0x1234usize as *const u8, 10)));
        assert_eq!((height, width), (0x1234_5678, -0x1234_567));
    }
}
