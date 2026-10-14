//! `opaque_header_089a8a0c_create` — `FUN_083b6c64` @ `0x083b6c64`.
//!
//! True extent [0x083b6c64, 0x083b6c88): 36 bytes, nine A32 instructions,
//! no literals; the next instruction starts an independent PUSH. Raw aligned
//! whole-image BL decoding finds one plain incoming BL at 0x083b6310 and no
//! predicated incoming BLs. Body has two plain BLs (0x082aadd4, 0x082a8c64)
//! and no predicated BLs.
//!
//! Allocate 16 bytes, construct the opaque four-word header with payload zero,
//! then replace word 3 with the third argument. Return the constructed pointer:
//! STR and POP preserve r0 despite Ghidra's void signature. First two arguments
//! are unused. Deliberate deviations: none; no allocation failure check is added.

use super::opaque_header_089a8a0c_construct::opaque_header_089a8a0c_construct;
use crate::heap::veneers::operator_new;

/// # Safety
/// The installed heap must return writable, word-aligned storage for 16 bytes
/// or terminate on failure; the firmware dereferences allocation unconditionally.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn opaque_header_089a8a0c_create(
    _unused_first: u32,
    _unused_second: u32,
    payload: u32,
) -> *mut u32 {
    let storage = unsafe { operator_new(16) }.cast::<u32>();
    let record = unsafe { opaque_header_089a8a0c_construct(storage, 0) };
    unsafe { record.add(3).write(payload) };
    record
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::types::{DEFAULT_HEAP, HeapDescriptorDescriptor};
    use crate::heap::veneers::{DEFAULT_HEAP_OPS, HEAP_OPS, HeapVeneerOps};
    use super::super::opaque_header_089a8a0c_construct::OPAQUE_HEADER_089A8A0C;

    static mut BLOCK: [u32; 6] = [0; 6];

    unsafe extern "C" fn allocate(
        _heap: *mut HeapDescriptorDescriptor, size: usize, tag: usize,
    ) -> *mut u8 {
        assert_eq!((size, tag), (16, 2));
        unsafe { core::ptr::addr_of_mut!(BLOCK).cast::<u32>().add(1).cast() }
    }

    #[test]
    fn payload_edges_and_allocation_boundaries() {
        // Isolate the existing global heap seam from concurrent suite tests.
        const CHILD: &str = "RUSTYPOD_OPAQUE_HEADER_089A8A0C_CREATE_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "cxx::opaque_header_089a8a0c_create::tests::payload_edges_and_allocation_boundaries", "--nocapture"])
                .env(CHILD, "1").status().unwrap();
            assert!(status.success());
            return;
        }
        unsafe {
            DEFAULT_HEAP = core::ptr::NonNull::<HeapDescriptorDescriptor>::dangling().as_ptr();
            HEAP_OPS = HeapVeneerOps { alloc: allocate, ..DEFAULT_HEAP_OPS };
            for payload in [0, 1, 0x8000_0000, u32::MAX] {
                core::ptr::addr_of_mut!(BLOCK).write([0xa5a5_a5a5; 6]);
                let record = opaque_header_089a8a0c_create(u32::MAX, 0x1234_5678, payload);
                assert_eq!(record, core::ptr::addr_of_mut!(BLOCK).cast::<u32>().add(1));
                assert_eq!(core::ptr::addr_of!(BLOCK).read(),
                    [0xa5a5_a5a5, OPAQUE_HEADER_089A8A0C, 32, 0, payload, 0xa5a5_a5a5]);
            }
        }
    }
}
