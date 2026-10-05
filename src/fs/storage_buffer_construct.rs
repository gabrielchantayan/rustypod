//! Extent-backed storage buffer constructor at retailOS 0x081c01e4.
//!
//! True extent: 156 bytes through 0x081c0280 (152 instruction bytes plus
//! the vtable literal at 0x081c027c). Raw words contain five plain BL calls
//! and no predicated BL calls; two inbound BL sites are in 0x08161e74.
//! Constructs the base with mode 2 and flags 0, installs vtable 0x0898ccb8,
//! clears the derived fields, and reads block zero into a 512-byte temporary.
//! On success, byte-swaps the halfword at byte 32, divides by 512, stores
//! that block count, and initializes the buffer pool, ignoring its status.
//!
//! Deviations: unported base/pool helpers retain verified firmware-address
//! seams; the existing storage_extent_read and bswap16 ports are reused.
//! Private callback parameters isolate host tests without global seam state.
//! Host calls to the exported constructor reject unavailable firmware helpers.
//! Object fields remain target-width words on all hosts.

use super::storage_extent_read::storage_extent_read;
use crate::util::bswap::bswap16;

type BaseConstruct = unsafe extern "C" fn(*mut u32, u32, *const u32, u32, u32, u32) -> *mut u32;
type Read = unsafe extern "C" fn(*mut u8, u32, u32, *mut u32, *mut u8, u32) -> i32;
type PoolInitialize = unsafe extern "C" fn(*mut u32) -> i32;

#[inline(always)]
unsafe fn construct_with(
    object: *mut u32, owner: u32, descriptor: *const u32, kind: u32,
    base: BaseConstruct, read: Read, pool: PoolInitialize,
) -> *mut u32 {
    let object = base(object, owner, descriptor, kind, 2, 0);
    object.write(0x0898_ccb8);
    object.add(0x42).write(0);
    object.add(0x5d).write(0);
    let zero = core::ptr::read_volatile(
        &(crate::libc::memzero::memzero_aligned as unsafe extern "C" fn(*mut u8, usize) -> *mut u8),
    );
    zero(object.add(0x43).cast(), 0x68);
    let mut completed = core::mem::MaybeUninit::<u32>::uninit();
    let mut block = core::mem::MaybeUninit::<[u32; 128]>::uninit();
    let buffer = block.as_mut_ptr().cast::<u8>();
    if read(object.cast(), 0, 1, completed.as_mut_ptr(), buffer, 0) == 0 {
        let bytes = buffer.add(32).cast::<u16>().read();
        object.add(0x42).write(bswap16(bytes as u32) >> 9);
        let _ = pool(object);
    }
    object
}

/// Constructs a 0x178-byte extent-backed storage object with a buffer pool.
///
/// # Safety
/// Inputs must satisfy the stock base constructor's owner/descriptor contract;
/// object must be aligned, writable storage of at least 0x178 bytes. Firmware
/// read and pool helpers must be available. No allocation failure is checked.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn storage_buffer_construct(
    object: *mut u32, owner: u32, descriptor: *const u32, kind: u32,
) -> *mut u32 {
    #[cfg(target_os = "none")]
    {
        let base: BaseConstruct = core::mem::transmute(0x0813_6dd0usize);
        let pool: PoolInitialize = core::mem::transmute(0x081c_007cusize);
        construct_with(object, owner, descriptor, kind, base, storage_extent_read, pool)
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = (object, owner, descriptor, kind, storage_extent_read as Read);
        panic!("storage_buffer_construct requires retailOS base/pool helpers")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn base(
        object: *mut u32, owner: u32, descriptor: *const u32, kind: u32, mode: u32, flags: u32,
    ) -> *mut u32 {
        assert_eq!((owner, kind, mode, flags), (7, 4, 2, 0));
        assert!(descriptor.is_null());
        object
    }

    unsafe extern "C" fn read_success(
        object: *mut u8, start: u32, count: u32, completed: *mut u32, buffer: *mut u8, flags: u32,
    ) -> i32 {
        assert_eq!((start, count, flags), (0, 1, 0));
        let object = object.cast::<u32>();
        assert_eq!(object.read(), 0x0898_ccb8);
        assert_eq!(object.add(0x42).read(), 0);
        assert_eq!(object.add(0x5d).read(), 0);
        for i in 0x43..0x5d { assert_eq!(object.add(i).read(), 0); }
        core::ptr::write_bytes(buffer, 0, 512);
        let size = object.add(1).read() as u16;
        let bytes = size.to_be_bytes();
        buffer.add(32).write(bytes[0]);
        buffer.add(33).write(bytes[1]);
        completed.write(1);
        0
    }

    unsafe extern "C" fn pool(object: *mut u32) -> i32 {
        assert_eq!(object.add(0x42).read(), (object.add(1).read() & 0xffff) >> 9);
        object.add(0x5d).write(0x1234);
        -25 // The constructor must ignore pool failure.
    }

    unsafe extern "C" fn read_failure(
        _: *mut u8, _: u32, _: u32, _: *mut u32, _: *mut u8, _: u32,
    ) -> i32 { -7 }

    unsafe extern "C" fn forbidden_pool(_: *mut u32) -> i32 {
        panic!("pool must not run after a failed read")
    }

    #[test]
    fn successful_read_truncates_to_blocks_and_ignores_pool_error() {
        for size in [0, 1, 511, 512, 513, 1024, 0xff00, 0xffff] {
            let mut object = [0xa5a5_a5a5u32; 0x60];
            object[1] = size;
            let ptr = object.as_mut_ptr();
            assert_eq!(unsafe { construct_with(ptr, 7, core::ptr::null(), 4, base, read_success, pool) }, ptr);
            assert_eq!(object[0x42], size >> 9);
            assert_eq!(object[0x5d], 0x1234);
            assert_eq!(object[2], 0xa5a5_a5a5);
            assert_eq!(&object[0x5e..], &[0xa5a5_a5a5; 2]);
        }
    }

    #[test]
    fn failed_read_leaves_cleared_derived_fields_without_consuming_uninitialized_buffer() {
        let mut object = [0xa5a5_a5a5u32; 0x60];
        let ptr = object.as_mut_ptr();
        assert_eq!(unsafe { construct_with(ptr, 7, core::ptr::null(), 4, base, read_failure, forbidden_pool) }, ptr);
        assert_eq!(&object[0x42..0x5e], &[0; 0x1c]);
        assert_eq!(object[0x41], 0xa5a5_a5a5);
        assert_eq!(object[0x5e], 0xa5a5_a5a5);
    }
}
