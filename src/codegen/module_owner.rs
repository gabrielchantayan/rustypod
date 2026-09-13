//! Initializes the small IR-module owner records used by six renderer drivers.
//!
//! `cg_module_owner_initialize` — original: `FUN_082432ac` @ `0x082432ac`
//! (28 bytes; **6 unconditional `bl` call sites**, binary-scanned from
//! `osos.dec`: 0x08246598, 0x0824855c, 0x082493d8, 0x0824a454, 0x0824af70,
//! and 0x0824bd58).
//!
//! The routine creates a 0x1000-byte [`CgHeap`] and carves an eight-byte
//! `cg_module_t` from it. Its sole recovered field is the heap pointer at
//! module offset 0; the module pointer is installed at owner offset 4.
//!
//! Deliberate deviation: retailOS delegates the eight-byte carve and first
//! field store to unported `FUN_082c1dc4`. That exact sequence is expressed
//! directly through the already-ported [`cg_heap_alloc`] so this one port
//! introduces no duplicate dispatch seam.

use super::heap::{cg_heap_alloc, cg_heap_create, CgHeap};
use super::ir::{record_size, CgModule, CG_MODULE_HEAP};

/// Target size of the first code-generator heap block.
const CG_MODULE_INITIAL_HEAP_BYTES: usize = 0x1000;

/// The recovered prefix of each renderer-owned module holder.
///
/// On target, `module` occupies byte offset 4. `#[repr(C)]` lets the two
/// pointer fields remain disjoint on 64-bit hosts while preserving the two
/// target words on ARMv5TE.
#[repr(C)]
pub struct CgModuleOwner {
    /// An owner-specific field not touched by this initializer.
    pub opaque: *mut u8,
    /// The IR module allocated by [`cg_module_owner_initialize`].
    pub module: *mut CgModule,
}

/// cg_module_owner_initialize — original: `FUN_082432ac` @ `0x082432ac`
/// (28 bytes; 6 `bl` call sites).
///
/// Creates the owner's 4 KiB IR arena, allocates the two-word module record
/// from it, and makes the module's first word point back at its arena.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_module_owner_initialize(owner: *mut CgModuleOwner) {
    let heap = cg_heap_create(CG_MODULE_INITIAL_HEAP_BYTES);
    let module = cg_heap_alloc(heap, record_size(8)) as *mut CgModule;
    (module as *mut *mut CgHeap).add(CG_MODULE_HEAP).write(heap);
    (*owner).module = module;
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::codegen::heap::{cg_heap_destroy, CgHeapOps, CG_HEAP_OPS, DEFAULT_CG_HEAP_OPS};
    use parking_lot::{Mutex, MutexGuard};
    use std::alloc::{alloc, dealloc, Layout};

    static LOCK: Mutex<()> = Mutex::new(());
    const HEADER_BYTES: usize = core::mem::size_of::<usize>();

    unsafe extern "C" fn test_alloc(size: usize) -> *mut u8 {
        let layout = Layout::from_size_align(size + HEADER_BYTES, 16).unwrap();
        let raw = alloc(layout);
        assert!(!raw.is_null());
        (raw as *mut usize).write(size);
        raw.add(HEADER_BYTES)
    }

    unsafe extern "C" fn test_free(ptr: *mut u8) {
        let raw = ptr.sub(HEADER_BYTES);
        let size = (raw as *const usize).read();
        dealloc(raw, Layout::from_size_align(size + HEADER_BYTES, 16).unwrap());
    }

    unsafe fn install_test_ops() -> MutexGuard<'static, ()> {
        let guard = LOCK.lock();
        core::ptr::addr_of_mut!(CG_HEAP_OPS).write(CgHeapOps {
            alloc: test_alloc,
            free: test_free,
            zero: DEFAULT_CG_HEAP_OPS.zero,
        });
        guard
    }

    unsafe fn restore_default_ops() {
        core::ptr::addr_of_mut!(CG_HEAP_OPS).write(DEFAULT_CG_HEAP_OPS);
    }

    #[test]
    fn initializes_module_with_a_4k_heap_and_preserves_owner_prefix() {
        unsafe {
            let _guard = install_test_ops();
            let sentinel = 0xdead_beefusize as *mut u8;
            let mut owner = CgModuleOwner {
                opaque: sentinel,
                module: core::ptr::null_mut(),
            };

            cg_module_owner_initialize(&mut owner);

            let module_words = owner.module as *mut *mut CgHeap;
            let heap = module_words.add(CG_MODULE_HEAP).read();
            assert_eq!(owner.opaque, sentinel);
            assert!(!owner.module.is_null());
            assert_eq!((*heap).block_size, CG_MODULE_INITIAL_HEAP_BYTES);
            assert_eq!((*(*heap).current).current, record_size(8));

            cg_heap_destroy(heap);
            restore_default_ops();
        }
    }
}
