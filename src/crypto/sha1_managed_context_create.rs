//! RetailOS heap-backed SHA-1 context constructor.

use crate::heap::veneers::operator_new;

const SHA1_CONTEXT_BYTES: usize = 0x106c;
const HEAP_TAG: u32 = 3;
const SHA1_STATE_OFFSET: usize = 0x54;
const SHA1_BUFFER_OFFSET: usize = 0x4c;
const SHA1_LENGTH_OFFSET: usize = 0x68;
const SHA1_COUNTER_HIGH_OFFSET: usize = 0x40;
const SHA1_COUNTER_LOW_OFFSET: usize = 0x44;
const SHA1_FLAGS_OFFSET: usize = 0x50;

/// Stock `FUN_0839e0e8(handle, size, tag)` entry point.
pub type ManagedBufferCreateFn = unsafe extern "C" fn(*mut u32, u32, u32) -> *mut u32;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_managed_buffer_create(handle: *mut u32, size: u32, tag: u32) -> *mut u32 {
    let create: ManagedBufferCreateFn = unsafe { core::mem::transmute(0x0839_e0e8usize) };
    unsafe { create(handle, size, tag) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_managed_buffer_create(_handle: *mut u32, _size: u32, _tag: u32) -> *mut u32 {
    panic!("sha1_managed_context_create requires managed-buffer constructor 0x0839e0e8")
}

/// Active managed-buffer construction seam. Host tests replace it with a
/// layout-faithful recorder; target builds call the retained retailOS entry.
#[cfg(target_os = "none")]
pub static mut MANAGED_BUFFER_CREATE: ManagedBufferCreateFn = firmware_managed_buffer_create;
#[cfg(not(target_os = "none"))]
pub static mut MANAGED_BUFFER_CREATE: ManagedBufferCreateFn = missing_managed_buffer_create;

#[inline(always)]
unsafe fn managed_buffer_create() -> ManagedBufferCreateFn {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(MANAGED_BUFFER_CREATE)) }
}

/// `sha1_managed_context_create` — original: `FUN_0804bdb0` @ 0x0804bdb0
/// (116 bytes; two plain unconditional `bl` calls, zero predicated calls).
///
/// Raw words establish the complete body at `0x0804bdb0..0x0804be23`; the
/// SHA-1 IV literal pool begins at `0x0804be24`, and the next function begins
/// at `0x0804be3c`. Allocates the 16-byte managed-buffer handle, constructs a
/// 0x106c-byte tag-3 backing buffer, then seeds its SHA-1 state and counters.
/// It stores the resulting handle through `out` without NULL checks.
///
/// Deliberate deviation: the unported managed-buffer constructor remains a
/// volatile stock-entry seam at `0x0839e0e8`; the target call is indirect so
/// host tests can verify its ABI.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn sha1_managed_context_create(out: *mut *mut u32) {
    let handle = unsafe { operator_new(0x10).cast::<u32>() };
    let constructed = unsafe { managed_buffer_create()(handle, SHA1_CONTEXT_BYTES as u32, HEAP_TAG) };
    let context = unsafe { constructed.add(1).read() as usize as *mut u8 };

    unsafe {
        context.add(SHA1_STATE_OFFSET).cast::<u32>().write(0x0123_4567);
        context.add(SHA1_STATE_OFFSET + 4).cast::<u32>().write(0x89ab_cdef);
        context.add(SHA1_STATE_OFFSET + 8).cast::<u32>().write(0xfedc_ba98);
        context.add(SHA1_STATE_OFFSET + 12).cast::<u32>().write(0x7654_3210);
        context.add(SHA1_STATE_OFFSET + 16).cast::<u32>().write(0xf0e1_d2c3);
        context.add(SHA1_BUFFER_OFFSET).cast::<u32>().write(context.add(SHA1_STATE_OFFSET) as usize as u32);
        context.add(SHA1_LENGTH_OFFSET).cast::<u32>().write(0);
        context.add(SHA1_COUNTER_HIGH_OFFSET).cast::<u32>().write(0);
        context.add(SHA1_COUNTER_LOW_OFFSET).cast::<u32>().write(0);
        context.add(SHA1_FLAGS_OFFSET).cast::<u32>().write(1);
        out.write(constructed);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::types::{HeapDescriptorDescriptor, DEFAULT_HEAP};
    use crate::heap::veneers::{HeapVeneerOps, DEFAULT_HEAP_OPS, HEAP_OPS};
    use crate::testing::{hints, try_map_u32_slab};
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut HANDLE: [u32; 4] = [0; 4];
    static mut FAKE_HEAP: u8 = 0;
    static mut CONTEXT: *mut u32 = core::ptr::null_mut();
    static mut CREATE_ARGS: (*mut u32, u32, u32) = (core::ptr::null_mut(), 0, 0);

    unsafe extern "C" fn alloc(_heap: *mut HeapDescriptorDescriptor, size: usize, tag: usize) -> *mut u8 {
        assert_eq!((size, tag), (0x10, 2));
        core::ptr::addr_of_mut!(HANDLE).cast()
    }
    unsafe extern "C" fn record_create(handle: *mut u32, size: u32, tag: u32) -> *mut u32 {
        CREATE_ARGS = (handle, size, tag);
        handle.add(1).write(CONTEXT as usize as u32);
        handle
    }

    struct Reset(HeapVeneerOps, ManagedBufferCreateFn, *mut HeapDescriptorDescriptor);
    impl Drop for Reset {
        fn drop(&mut self) { unsafe { HEAP_OPS = self.0; MANAGED_BUFFER_CREATE = self.1; DEFAULT_HEAP = self.2; } }
    }

    #[test]
    fn allocates_and_initializes_the_complete_sha1_prefix() {
        let _lock = TEST_LOCK.lock();
        unsafe {
            let saved = core::ptr::read_volatile(core::ptr::addr_of!(HEAP_OPS));
            let seam = core::ptr::read_volatile(core::ptr::addr_of!(MANAGED_BUFFER_CREATE));
            let heap = DEFAULT_HEAP;
            let _reset = Reset(saved, seam, heap);
            let Some(context) = try_map_u32_slab(hints::SHA1_MANAGED_CONTEXT_CREATE, SHA1_CONTEXT_BYTES) else {
                return;
            };
            let context = context.cast::<u32>();
            HANDLE = [0; 4];
            core::ptr::write_bytes(context, 0xff, SHA1_CONTEXT_BYTES / core::mem::size_of::<u32>());
            CONTEXT = context;
            let mut ops = DEFAULT_HEAP_OPS;
            ops.alloc = alloc;
            HEAP_OPS = ops;
            DEFAULT_HEAP = core::ptr::addr_of_mut!(FAKE_HEAP).cast();
            MANAGED_BUFFER_CREATE = record_create;

            let mut out = core::ptr::null_mut();
            sha1_managed_context_create(&mut out);

            assert_eq!(out, core::ptr::addr_of_mut!(HANDLE).cast());
            assert_eq!(CREATE_ARGS, (out, 0x106c, 3));
            assert_eq!(core::slice::from_raw_parts(context.add(0x54 / 4), 5), &[0x0123_4567, 0x89ab_cdef, 0xfedc_ba98, 0x7654_3210, 0xf0e1_d2c3]);
            assert_eq!(context.add(0x4c / 4).read(), context.cast::<u8>().add(0x54) as usize as u32);
            assert_eq!((context.add(0x40 / 4).read(), context.add(0x44 / 4).read(), context.add(0x50 / 4).read(), context.add(0x68 / 4).read()), (0, 0, 1, 0));
        }
    }
}
