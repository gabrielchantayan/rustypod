//! Indexed-handle owner factory — FUN_0814a9c4 @ 0x0814a9c4.
//! True extent [0x0814a9c4,0x0814aa40): 124 bytes, 120 instruction
//! bytes plus the vtable literal 0x089866e8. Next entry starts with PUSH.
//! Two incoming plain BLs (0x081435c8,0x081cc7f4), no predicated incoming
//! BLs. Outbound: three plain BLs, one BLEQ, and one virtual BLX.
//!
//! Allocate seven words; install the vtable, invalid index, and two null
//! child pointers. Construct the embedded handle at +20 with zero value
//! and tag. Recover the owner from the returned handle, panic if null,
//! then initialize it with the requested mode and index. On zero status,
//! invoke deleting-destructor slot +4 and return null; otherwise return it.
//!
//! Deliberate deviations: unported handle construction (0x081070a8) and
//! owner setup (0x0814a904) call verified firmware addresses on target;
//! host-only seams fail loudly unless configured. Host destruction uses
//! a seam instead of dereferencing a firmware vtable. The object remains
//! seven u32 words on every architecture. Untouched word +8 and handle
//! padding +25..27 remain untouched. No physical-device verification.

pub type Allocate = unsafe extern "C" fn(usize) -> *mut u32;
pub type HandleConstruct = unsafe extern "C" fn(*mut u32, u32, u32) -> *mut u32;
pub type OwnerSetup = unsafe extern "C" fn(*mut u32, u32, u32) -> u32;
pub type Destroy = unsafe extern "C" fn(*mut u32);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_allocate(_: usize) -> *mut u32 { panic!("configure owner allocator") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_construct(_: *mut u32, _: u32, _: u32) -> *mut u32 { panic!("configure handle constructor") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_setup(_: *mut u32, _: u32, _: u32) -> u32 { panic!("configure owner setup") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_destroy(_: *mut u32) { panic!("configure owner destructor") }

#[cfg(not(target_os = "none"))]
pub static mut OWNER_ALLOCATE: Allocate = missing_allocate;
#[cfg(not(target_os = "none"))]
pub static mut HANDLE_CONSTRUCT: HandleConstruct = missing_construct;
#[cfg(not(target_os = "none"))]
pub static mut OWNER_SETUP: OwnerSetup = missing_setup;
#[cfg(not(target_os = "none"))]
pub static mut OWNER_DESTROY: Destroy = missing_destroy;

/// Create an indexed-handle owner, destroying it if setup returns zero.
///
/// # Safety
/// The allocator must return writable aligned storage for seven words.
/// Constructor results and mode/index must satisfy retailOS setup's contract.
/// Host seams must be configured and externally synchronized.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn indexed_handle_owner_create(mode: u32, index: u32) -> *mut u32 {
    #[cfg(target_os = "none")]
    let storage = crate::heap::veneers::operator_new(28).cast::<u32>();
    #[cfg(not(target_os = "none"))]
    let storage = OWNER_ALLOCATE(28);
    storage.write(0x0898_66e8);
    storage.add(1).write(u32::MAX);
    storage.add(3).write(0);
    storage.add(4).write(0);
    #[cfg(target_os = "none")]
    let construct: HandleConstruct = core::mem::transmute(0x0810_70a8usize);
    #[cfg(not(target_os = "none"))]
    let construct = HANDLE_CONSTRUCT;
    let handle = construct(storage.add(5), 0, 0);
    let owner = (handle as usize).wrapping_sub(20) as *mut u32;
    if owner.is_null() {
        crate::heap::veneers::heap_panic();
    }
    #[cfg(target_os = "none")]
    let setup: OwnerSetup = core::mem::transmute(0x0814_a904usize);
    #[cfg(not(target_os = "none"))]
    let setup = OWNER_SETUP;
    if setup(owner, mode, index) == 0 {
        #[cfg(target_os = "none")]
        {
            let vtable = owner.read() as usize as *const u32;
            let destroy: Destroy = core::mem::transmute(vtable.add(1).read() as usize);
            destroy(owner);
        }
        #[cfg(not(target_os = "none"))]
        OWNER_DESTROY(owner);
        core::ptr::null_mut()
    } else {
        owner
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    static LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    static mut STORAGE: [u32; 7] = [0; 7];
    static mut STATUS: u32 = 0;
    static mut DESTROYED: bool = false;

    unsafe extern "C" fn allocate(size: usize) -> *mut u32 {
        assert_eq!(size, 28);
        STORAGE.as_mut_ptr()
    }
    unsafe extern "C" fn construct(handle: *mut u32, value: u32, tag: u32) -> *mut u32 {
        handle.write(value);
        handle.add(1).cast::<u8>().write(tag as u8);
        handle
    }
    unsafe extern "C" fn setup(owner: *mut u32, mode: u32, index: u32) -> u32 {
        assert_eq!(owner.read(), 0x0898_66e8);
        assert_eq!(owner.add(1).read(), u32::MAX);
        assert_eq!(owner.add(2).read(), 0xa5a5_a5a5);
        assert_eq!(owner.add(3).read(), 0);
        assert_eq!(owner.add(4).read(), 0);
        assert_eq!(owner.add(5).read(), 0);
        assert_eq!(owner.add(6).read(), 0xa5a5_a500);
        owner.add(1).write(index);
        owner.add(2).write(mode);
        STATUS
    }
    unsafe extern "C" fn destroy(owner: *mut u32) {
        assert_eq!(owner, STORAGE.as_mut_ptr());
        DESTROYED = true;
        owner.write(0xdead_dead);
    }

    #[test]
    fn setup_status_controls_lifetime_and_preserves_partial_initialization() {
        let _guard = LOCK.lock();
        unsafe {
            OWNER_ALLOCATE = allocate;
            HANDLE_CONSTRUCT = construct;
            OWNER_SETUP = setup;
            OWNER_DESTROY = destroy;
            for status in [0, 1, 0x8000_0000, u32::MAX] {
                for (mode, index) in [(0, 0), (2, 10001), (u32::MAX, u32::MAX)] {
                    STORAGE = [0xa5a5_a5a5; 7];
                    STATUS = status;
                    DESTROYED = false;
                    let result = indexed_handle_owner_create(mode, index);
                    assert_eq!(STORAGE[1], index);
                    assert_eq!(STORAGE[2], mode);
                    assert_eq!(DESTROYED, status == 0);
                    if status == 0 {
                        assert!(result.is_null());
                        assert_eq!(STORAGE[0], 0xdead_dead);
                    } else {
                        assert_eq!(result, STORAGE.as_mut_ptr());
                        assert_eq!(STORAGE[0], 0x0898_66e8);
                    }
                }
            }
            OWNER_ALLOCATE = missing_allocate;
            HANDLE_CONSTRUCT = missing_construct;
            OWNER_SETUP = missing_setup;
            OWNER_DESTROY = missing_destroy;
        }
    }
}
