//! Buffer-pool owner teardown, `FUN_08297458` @ 0x08297458.
//!
//! True extent: 88 bytes, 0x08297458..0x082974b0 (84 executable bytes
//! and the vtable literal at 0x082974ac). Raw-word scanning finds two
//! unconditional inbound BLs (0x081efc80, 0x0829744c), no predicated BLs.
//! The body has three plain BLs, no predicated BLs, and one indirect BLX.
//! Install vtable 0x089a7378; release the optional child through slot +4,
//! clear it after release, reset the +0x50 aligned buffer, delete the +0x44
//! counted mutex, and destroy the +0x24 pool, rebasing its returned pointer.
//!
//! Deliberate deviations: pointers widen on hosts using repr(C) fields.
//! The unported pool destructor at 0x081e20dc remains a verified-address
//! seam on ARM and an explicitly installed operation on hosts. Raw decoding
//! establishes its single pointer argument and pointer return: it preserves
//! r1-r5, drains pool allocations if word +0x10 is nonzero, and returns r0.
//! Ghidra's four-argument/u64 signature is not used. The object's concrete
//! class name is unrecovered; the name describes its owned members.
//!
//! Codegen review: match.py exits 1 (structural diff). LLVM preserves the
//! child guard, slot +4 dispatch, post-release clear, target member offsets,
//! and final -0x24 rebase. It inlines counted-mutex teardown and eliminates
//! the aligned-buffer return rebase because that port always returns its
//! input. The pool address is called through BLX rather than a direct BL.

use crate::heap::aligned_buffer::aligned_buffer_reset;
use crate::kernel::sync_mutex::{mutex_delete_counted, CountedMutex};

#[repr(C)]
pub struct ReleaseVtable {
    pub primary: usize,
    pub release: unsafe extern "C" fn(*mut ReleaseObject),
}

#[repr(C)]
pub struct ReleaseObject {
    pub vtable: *const ReleaseVtable,
}

#[repr(C)]
pub struct BufferPoolOwner {
    pub vtable: u32,
    pub unknown: u32,
    pub child: *mut ReleaseObject,
    pub reserved: [u32; 6],
    pub pool: [u32; 8],
    pub lock: CountedMutex,
    pub buffer: [u32; 2],
}

type PoolDestruct = unsafe extern "C" fn(*mut u32) -> *mut u32;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_pool_destruct(_: *mut u32) -> *mut u32 {
    panic!("install buffer-pool owner host pool destructor")
}

#[cfg(not(target_os = "none"))]
pub static mut BUFFER_POOL_DESTRUCT: PoolDestruct = missing_pool_destruct;

#[inline(always)]
unsafe fn destruct_pool(pool: *mut u32) -> *mut u32 {
    #[cfg(target_os = "none")]
    { core::mem::transmute::<usize, PoolDestruct>(0x081e_20dc)(pool) }
    #[cfg(not(target_os = "none"))]
    { (core::ptr::addr_of!(BUFFER_POOL_DESTRUCT).read())(pool) }
}

/// Destroy a live owner without freeing its enclosing allocation.
///
/// # Safety
/// `owner` must be writable, with valid owned members and child dispatch.
/// On hosts, install the pool destructor before calling.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn buffer_pool_owner_destruct(owner: *mut BufferPoolOwner) -> *mut BufferPoolOwner {
    core::ptr::addr_of_mut!((*owner).vtable).write_volatile(0x089a_7378);
    let child = core::ptr::addr_of!((*owner).child).read();
    if !child.is_null() {
        ((*(*child).vtable).release)(child);
        core::ptr::addr_of_mut!((*owner).child).write(core::ptr::null_mut());
    }
    let buffer = core::ptr::addr_of_mut!((*owner).buffer).cast::<u8>();
    let returned = aligned_buffer_reset(buffer);
    let owner = returned.sub(core::mem::offset_of!(BufferPoolOwner, buffer)).cast::<BufferPoolOwner>();
    mutex_delete_counted(core::ptr::addr_of_mut!((*owner).lock));
    destruct_pool(core::ptr::addr_of_mut!((*owner).pool).cast())
        .cast::<u8>().sub(core::mem::offset_of!(BufferPoolOwner, pool)).cast()
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::kernel::sync_mutex::Mutex;
    use core::sync::atomic::{AtomicPtr, Ordering};

    static OWNER: AtomicPtr<BufferPoolOwner> = AtomicPtr::new(core::ptr::null_mut());

    unsafe extern "C" fn release(child: *mut ReleaseObject) {
        let owner = OWNER.load(Ordering::Relaxed);
        assert_eq!((*owner).vtable, 0x089a_7378);
        assert_eq!((*owner).child, child, "ownership cleared only after release");
        assert_eq!((*owner).buffer, [0x1234, 0]);
        assert_eq!((*owner).lock.hold_count, 7, "child released before lock teardown");
        (*owner).reserved[0] += 1;
    }

    unsafe extern "C" fn pool_destruct(pool: *mut u32) -> *mut u32 {
        let owner = OWNER.load(Ordering::Relaxed);
        assert!((*owner).child.is_null());
        assert_eq!((*owner).buffer, [0, 0]);
        assert!((*owner).lock.mutex.sem_cell.is_null());
        assert_eq!((*owner).lock.mutex.unused, 0);
        assert_eq!((*owner).lock.hold_count, 0);
        assert_eq!((*owner).pool, [0x55; 8], "pool untouched until its teardown");
        // This test pool has no allocations; mark its destruction explicitly.
        pool.write(0);
        pool
    }

    #[test]
    fn optional_child_and_repeated_teardown_preserve_unowned_state() {
        let vtable = ReleaseVtable { primary: 0, release };
        let mut child = ReleaseObject { vtable: &vtable };
        let old = unsafe { BUFFER_POOL_DESTRUCT };
        unsafe { BUFFER_POOL_DESTRUCT = pool_destruct; }
        for has_child in [false, true] {
            let mut owner = BufferPoolOwner {
                vtable: 0, unknown: 0xdead_beef,
                child: if has_child { &mut child } else { core::ptr::null_mut() },
                reserved: [0; 6], pool: [0x55; 8],
                lock: CountedMutex { mutex: Mutex { sem_cell: core::ptr::null_mut(), unused: 9 }, hold_count: 7 },
                buffer: [0x1234, 0],
            };
            OWNER.store(&mut owner, Ordering::Relaxed);
            assert_eq!(unsafe { buffer_pool_owner_destruct(&mut owner) }, &mut owner as *mut _);
            assert_eq!(owner.reserved[0], u32::from(has_child));
            assert_eq!(owner.unknown, 0xdead_beef);
            assert_eq!(owner.pool[0], 0);
            owner.pool = [0x55; 8];
            unsafe { buffer_pool_owner_destruct(&mut owner); }
            assert_eq!(owner.reserved[0], u32::from(has_child), "no double release");
        }
        unsafe { BUFFER_POOL_DESTRUCT = old; }
    }
}
