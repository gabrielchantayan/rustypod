//! Resource-record lookup through a matching owner or a temporary CROS list.
//!
//! `resource_record_find` — original: `FUN_08218604` @ `0x08218604`.
//! Raw firmware establishes the true extent as `0x08218604..0x08218688` (132
//! bytes): `pop {r3,r4,r5,pc}` ends the body and the next code starts at
//! `0x08218688`. It has three plain `bl` calls (`0x081d0b48`, `0x08184b24`,
//! and `0x08184cf4`) and one predicated indirect `blxne` virtual release.
//!
//! # Algorithm
//!
//! If `owner[+0x17c]` is `resource`, forwards `owner[+0x178]`, `key` twice,
//! `resource`, and `extra` to the owner-specific lookup. Otherwise it creates
//! a temporary CROS resource list from `resource[+0x68]`, returns entry zero's
//! `+8` data word only when its target-word vector is non-empty, then releases
//! the temporary object through vtable slot `+4`.
//!
//! # Deliberate deviations
//!
//! `FUN_081d0b48` remains unported, so the target calls its verified retail
//! address and host tests install a seam. Host temporary owners use native
//! pointers rather than target-width vtable words; the target path retains the
//! exact word offsets and virtual dispatch.

#[cfg(target_os = "none")]
use crate::app::opaque_collection_entry_data_at::opaque_collection_entry_data_at;
#[cfg(target_os = "none")]
use crate::util::resource_list::{load_cros_resource_list, ResourceList};

type OwnerLookup = unsafe extern "C" fn(u32, u32, u32, u32, u32) -> u32;
const OWNER_LOOKUP_ADDRESS: usize = 0x081d_0b48;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn owner_lookup() -> OwnerLookup {
    unsafe { core::mem::transmute(OWNER_LOOKUP_ADDRESS) }
}

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostResourceOwner {
    pub context: *mut u8,
    pub resource: *mut u8,
}

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostTemporaryResourceList {
    pub count: u32,
    pub first_data: u32,
    pub release: unsafe extern "C" fn(*mut HostTemporaryResourceList),
}

#[cfg(not(target_os = "none"))]
pub type HostOwnerLookup = unsafe extern "C" fn(*mut u8, *mut u8, u32, u32) -> u32;
#[cfg(not(target_os = "none"))]
pub type HostResourceListLoad = unsafe extern "C" fn(u32) -> *mut HostTemporaryResourceList;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_owner_lookup(_owner: *mut u8, _resource: *mut u8, _key: u32, _extra: u32) -> u32 {
    panic!("resource_record_find requires owner lookup 0x081d0b48")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_resource_list_load(_resource_data: u32) -> *mut HostTemporaryResourceList {
    panic!("resource_record_find requires temporary CROS list")
}

/// Host seams for the unported owner lookup and host-width temporary list.
#[cfg(not(target_os = "none"))]
pub static mut OWNER_LOOKUP: HostOwnerLookup = missing_owner_lookup;
#[cfg(not(target_os = "none"))]
pub static mut RESOURCE_LIST_LOAD: HostResourceListLoad = missing_resource_list_load;

/// Finds a resource record's data word, or zero when the temporary list is empty.
///
/// # Safety
///
/// On target, `owner` and `resource` must satisfy the retail layouts through
/// offsets `0x17c` and `0x68`, respectively. The matching owner lookup and
/// temporary object's vtable slot must be callable.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn resource_record_find(
    owner: *mut u8,
    resource: *mut u8,
    key: u32,
    extra: u32,
) -> u32 {
    #[cfg(target_os = "none")]
    unsafe {
        let owner_resource = owner.add(0x17c).cast::<u32>().read();
        if owner_resource == resource as usize as u32 {
            return owner_lookup()(owner.add(0x178).cast::<u32>().read(), key, key, owner_resource, extra);
        }

        let list = load_cros_resource_list(resource.add(0x68).cast::<u32>().read());
        let begin = list.cast::<u32>().add(5).read();
        let end = list.cast::<u32>().add(6).read();
        let result = if (end.wrapping_sub(begin) as i32 >> 2) > 0 {
            let data = opaque_collection_entry_data_at(list.cast(), 0);
            core::ptr::read_volatile((data as usize as *const u8).add(8));
            data
        } else {
            0
        };
        let vtable = list.cast::<u32>().read() as *const u32;
        let release: unsafe extern "C" fn(*mut ResourceList) = core::mem::transmute(vtable.add(1).read() as usize);
        release(list);
        result
    }

    #[cfg(not(target_os = "none"))]
    unsafe {
        let host_owner = &*owner.cast::<HostResourceOwner>();
        if host_owner.resource == resource {
            return core::ptr::read_volatile(core::ptr::addr_of!(OWNER_LOOKUP))(owner, resource, key, extra);
        }

        let list = core::ptr::read_volatile(core::ptr::addr_of!(RESOURCE_LIST_LOAD))(
            resource.add(0x68).cast::<u32>().read(),
        );
        let result = if (*list).count != 0 { (*list).first_data } else { 0 };
        ((*list).release)(list);
        result
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::sync::atomic::{AtomicU32, Ordering};
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static LOOKUP_CALLS: AtomicU32 = AtomicU32::new(0);
    static LIST_DATA: AtomicU32 = AtomicU32::new(0);
    static RELEASE_CALLS: AtomicU32 = AtomicU32::new(0);
    static mut LIST: HostTemporaryResourceList = HostTemporaryResourceList { count: 0, first_data: 0, release };

    unsafe extern "C" fn lookup(owner: *mut u8, resource: *mut u8, key: u32, extra: u32) -> u32 {
        LOOKUP_CALLS.fetch_add(1, Ordering::SeqCst);
        (owner as usize ^ resource as usize ^ key as usize ^ extra as usize) as u32
    }
    unsafe extern "C" fn release(_list: *mut HostTemporaryResourceList) {
        RELEASE_CALLS.fetch_add(1, Ordering::SeqCst);
    }
    unsafe extern "C" fn load(resource_data: u32) -> *mut HostTemporaryResourceList {
        LIST_DATA.store(resource_data, Ordering::SeqCst);
        core::ptr::addr_of_mut!(LIST)
    }

    #[test]
    fn matching_owner_uses_owner_lookup_without_temporary_list() {
        let _lock = TEST_LOCK.lock();
        unsafe {
            OWNER_LOOKUP = lookup;
            RESOURCE_LIST_LOAD = load;
            LOOKUP_CALLS.store(0, Ordering::SeqCst);
            let resource = [0u8; 0x6c];
            let owner = HostResourceOwner { context: core::ptr::null_mut(), resource: resource.as_ptr() as *mut u8 };
            let got = resource_record_find((&owner as *const HostResourceOwner).cast_mut().cast(), resource.as_ptr() as *mut u8, 0x12, 0x34);
            assert_eq!(got, ((&owner as *const _ as usize) ^ (resource.as_ptr() as usize) ^ 0x12 ^ 0x34) as u32);
            assert_eq!(LOOKUP_CALLS.load(Ordering::SeqCst), 1);
            assert_eq!(RELEASE_CALLS.load(Ordering::SeqCst), 0);
        }
    }

    #[test]
    fn temporary_list_returns_first_data_and_releases_even_when_empty() {
        let _lock = TEST_LOCK.lock();
        unsafe {
            OWNER_LOOKUP = lookup;
            RESOURCE_LIST_LOAD = load;
            let mut resource = [0u8; 0x6c];
            resource[0x68..0x6c].copy_from_slice(&0xfeed_beefu32.to_le_bytes());
            let owner = HostResourceOwner { context: core::ptr::null_mut(), resource: core::ptr::null_mut() };
            LIST.count = 1;
            LIST.first_data = 0x1234_5678;
            RELEASE_CALLS.store(0, Ordering::SeqCst);
            assert_eq!(resource_record_find((&owner as *const HostResourceOwner).cast_mut().cast(), resource.as_mut_ptr(), 0, 0), 0x1234_5678);
            assert_eq!(LIST_DATA.load(Ordering::SeqCst), 0xfeed_beef);
            assert_eq!(RELEASE_CALLS.load(Ordering::SeqCst), 1);
            LIST.count = 0;
            assert_eq!(resource_record_find((&owner as *const HostResourceOwner).cast_mut().cast(), resource.as_mut_ptr(), 0, 0), 0);
            assert_eq!(RELEASE_CALLS.load(Ordering::SeqCst), 2);
        }
    }
}
