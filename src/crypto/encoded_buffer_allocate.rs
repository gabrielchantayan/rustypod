//! Allocation helper used by the proprietary digest input encoder.

use crate::runtime::malloc_rt::{free, malloc};

const INVALID_ARGUMENT: u32 = 0xffff_5bd9;
const OUT_OF_MEMORY: u32 = 0xffff_5bd4;
const ALLOCATION_FACTOR: u32 = 0xfc05_a7ff;

/// Allocates an encoded-buffer descriptor — original: `FUN_082fafac` @
/// **0x082fafac** (196 bytes, `0x082fafac..0x082fb070`). Raw ARM words place
/// the next separately linked function at `0x082fb07c`; `0x082fb070..78` is
/// this function's literal pool. The body has three plain `bl` instructions
/// (two `malloc` calls @ `0x0802edac`, one `free` @ `0x0802edc8`) and zero
/// predicated `bl` instructions (two unique callees).
///
/// Validates the target-width output word and a minimum count of 20. It then
/// allocates `0xfc05a7ff * (count + 12)` bytes, followed by a 12-byte
/// descriptor. The descriptor is `{data, scaled_capacity, 0}` and the first
/// twelve data bytes are zeroed. If descriptor allocation fails, it frees the
/// data allocation before returning the out-of-memory status.
///
/// Deliberate deviations: target pointers remain `u32` words rather than host
/// pointers, and the retail allocator calls use the existing Rust `malloc` /
/// `free` ports so host tests can replace their shared heap seam.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn encoded_buffer_allocate(count: u32, output: *mut u32) -> u32 {
    if output.is_null() || count < 20 {
        return INVALID_ARGUMENT;
    }

    let scaled_capacity = ALLOCATION_FACTOR.wrapping_mul(count.wrapping_add(12));
    let data = malloc(scaled_capacity as usize);
    if data.is_null() {
        return OUT_OF_MEMORY;
    }

    let descriptor = malloc(12);
    if descriptor.is_null() {
        free(data);
        return OUT_OF_MEMORY;
    }

    core::ptr::write_bytes(data, 0, 12);
    let descriptor_words = descriptor.cast::<u32>();
    descriptor_words.write(data as usize as u32);
    descriptor_words.add(1).write(scaled_capacity);
    descriptor_words.add(2).write(0);
    output.write(descriptor as usize as u32);
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use crate::runtime::malloc_rt::{HeapOps, DEFAULT_MALLOC_RT_OPS, HEAP_OPS};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr;
    use std::sync::{LazyLock, Mutex, MutexGuard};

    const FIXTURE_LEN: usize = 0x1000;
    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static BASE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::ENCODED_BUFFER_ALLOCATE, FIXTURE_LEN).map(|pointer| pointer as usize)
    });
    static mut ALLOC_CALLS: [(usize, *mut u8); 2] = [(0, ptr::null_mut()); 2];
    static mut ALLOC_COUNT: usize = 0;
    static mut FAIL_SECOND_ALLOC: bool = false;
    static mut FREED: *mut u8 = ptr::null_mut();

    unsafe extern "C" fn alloc(size: usize) -> *mut u8 {
        let index = ALLOC_COUNT;
        ALLOC_COUNT += 1;
        if FAIL_SECOND_ALLOC && index == 1 {
            return ptr::null_mut();
        }
        let pointer = (*BASE).unwrap() as *mut u8;
        let pointer = pointer.add(0x100 + index * 0x100);
        ALLOC_CALLS[index] = (size, pointer);
        pointer
    }

    unsafe extern "C" fn record_free(pointer: *mut u8) {
        FREED = pointer;
    }

    struct HeapOpsReset(HeapOps);

    impl Drop for HeapOpsReset {
        fn drop(&mut self) {
            unsafe { ptr::addr_of_mut!(HEAP_OPS).write(self.0); }
        }
    }

    fn install_allocator() -> Option<(MutexGuard<'static, ()>, HeapOpsReset)> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        if BASE.is_none() {
            assert!(note_missing_u32_fixture("crypto/encoded_buffer_allocate"));
            return None;
        }
        unsafe {
            ALLOC_CALLS = [(0, ptr::null_mut()); 2];
            ALLOC_COUNT = 0;
            FAIL_SECOND_ALLOC = false;
            FREED = ptr::null_mut();
            let old_ops = ptr::addr_of!(HEAP_OPS).read_volatile();
            ptr::addr_of_mut!(HEAP_OPS).write(HeapOps { alloc, free: record_free, ..DEFAULT_MALLOC_RT_OPS });
            Some((guard, HeapOpsReset(old_ops)))
        }
    }

    #[test]
    fn allocates_zeroed_data_and_target_width_descriptor() {
        let Some((_guard, _reset)) = install_allocator() else { return; };
        let base = (*BASE).unwrap() as *mut u8;
        unsafe { ptr::write_bytes(base.add(0x100), 0xa5, 12); }
        let output = unsafe { base.add(0x20).cast::<u32>() };

        assert_eq!(unsafe { encoded_buffer_allocate(20, output) }, 0);
        let capacity = ALLOCATION_FACTOR.wrapping_mul(32);
        assert_eq!(unsafe { ALLOC_CALLS }, [(capacity as usize, base.wrapping_add(0x100)), (12, base.wrapping_add(0x200))]);
        assert_eq!(unsafe { core::slice::from_raw_parts(base.add(0x100), 12) }, &[0; 12]);
        assert_eq!(unsafe { output.read() }, base.wrapping_add(0x200) as usize as u32);
        assert_eq!(unsafe { core::slice::from_raw_parts(base.add(0x200).cast::<u32>(), 3) }, &[base.wrapping_add(0x100) as usize as u32, capacity, 0]);
    }

    #[test]
    fn rejects_invalid_input_without_allocating() {
        let Some((_guard, _reset)) = install_allocator() else { return; };
        let base = (*BASE).unwrap() as *mut u8;
        assert_eq!(unsafe { encoded_buffer_allocate(20, ptr::null_mut()) }, INVALID_ARGUMENT);
        assert_eq!(unsafe { encoded_buffer_allocate(19, base.cast()) }, INVALID_ARGUMENT);
        assert_eq!(unsafe { ALLOC_COUNT }, 0);
    }

    #[test]
    fn frees_data_when_descriptor_allocation_fails() {
        let Some((_guard, _reset)) = install_allocator() else { return; };
        unsafe { FAIL_SECOND_ALLOC = true; }
        let output = unsafe { (*BASE).unwrap() as *mut u8 }.cast::<u32>();

        assert_eq!(unsafe { encoded_buffer_allocate(20, output) }, OUT_OF_MEMORY);
        assert_eq!(unsafe { ALLOC_COUNT }, 2);
        assert_eq!(unsafe { FREED }, unsafe { ALLOC_CALLS[0].1 });
    }
}
