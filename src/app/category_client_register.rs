//! Synchronized category-client registration — `FUN_08161270` @ 0x08161270.
//!
//! True extent: [0x08161270,0x081612a4), 52 bytes; the next constructor
//! starts with an independent push. Raw words verify three outbound plain BLs,
//! zero predicated BLs; two inbound plain BLs, zero predicated inbound BLs.
//! Lock the mutex at registry+0x10, invoke registration at 0x08161068 with
//! the unchanged registry/client arguments, unlock, and return its status.
//! That callee rejects NULL (1), unsupported categories (7), and failed client
//! activation (4); successful activation stores the client in its category slot.
//!
//! Deviations: the unported registration body remains a fixed-address call.
//! Hosts inject the three operations, following the condition-queue wrapper
//! convention; objects retain target u32 word offsets rather than host pointer
//! offsets. Target locking reuses the existing ported mutex implementation.
//! ARM comparison preserves lock/register/unlock and the saved result; LLVM
//! adds frame setup and uses a literal-loaded BLX for the fixed registration
//! address instead of the original immediate BL. No target behavior deviation.

#[cfg(target_os = "none")]
use crate::kernel::sync_mutex::{mutex_lock, mutex_unlock, Mutex};

type Register = unsafe extern "C" fn(*mut u32, *mut u8) -> u32;
type MutexCall = unsafe extern "C" fn(*mut u32);

#[cfg(not(target_os = "none"))]
pub struct CategoryClientRegisterOps {
    pub lock: MutexCall,
    pub register: Register,
    pub unlock: MutexCall,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_lock(_mutex: *mut u32) {
    panic!("category client mutex operation not installed")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_register(_registry: *mut u32, _client: *mut u8) -> u32 {
    panic!("category client registration operation not installed")
}
#[cfg(not(target_os = "none"))]
pub static mut CATEGORY_CLIENT_REGISTER_OPS: CategoryClientRegisterOps = CategoryClientRegisterOps {
    lock: missing_lock,
    register: missing_register,
    unlock: missing_lock,
};

/// # Safety
/// `registry` must be a live retail registry with an embedded mutex at word
/// index 4; `client` must satisfy the retail registration callee's contract
/// (NULL is permitted). Host operation installation requires synchronization.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn category_client_register(registry: *mut u32, client: *mut u8) -> u32 {
    let mutex = registry.add(4);
    #[cfg(target_os = "none")]
    {
        mutex_lock(mutex.cast::<Mutex>());
        let register: Register = core::mem::transmute(0x0816_1068usize);
        let status = register(registry, client);
        mutex_unlock(mutex.cast::<Mutex>());
        status
    }
    #[cfg(not(target_os = "none"))]
    {
        let lock = core::ptr::read_volatile(core::ptr::addr_of!(CATEGORY_CLIENT_REGISTER_OPS.lock));
        lock(mutex);
        let register = core::ptr::read_volatile(core::ptr::addr_of!(CATEGORY_CLIENT_REGISTER_OPS.register));
        let status = register(registry, client);
        let unlock = core::ptr::read_volatile(core::ptr::addr_of!(CATEGORY_CLIENT_REGISTER_OPS.unlock));
        unlock(mutex);
        status
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut EXPECTED_REGISTRY: *mut u32 = core::ptr::null_mut();
    static mut SLOTS: [*mut u8; 3] = [core::ptr::null_mut(); 3];

    #[repr(C)]
    struct Client { category: u32, activation_succeeds: u32, activations: u32 }

    unsafe extern "C" fn acquire(mutex: *mut u32) {
        assert_eq!(mutex, EXPECTED_REGISTRY.add(4));
        assert_eq!(*mutex, 1);
        *mutex = 0;
    }
    unsafe extern "C" fn release(mutex: *mut u32) {
        assert_eq!(mutex, EXPECTED_REGISTRY.add(4));
        assert_eq!(*mutex, 0);
        *mutex = 1;
    }
    // Host reference for the raw callee's category/activation algorithm.
    unsafe extern "C" fn register(registry: *mut u32, client: *mut u8) -> u32 {
        assert_eq!(registry, EXPECTED_REGISTRY);
        assert_eq!(*registry.add(4), 0, "registration must run while locked");
        if client.is_null() { return 1; }
        let object = &mut *client.cast::<Client>();
        if object.category > 2 { return 7; }
        object.activations += 1;
        if object.activation_succeeds == 0 { return 4; }
        SLOTS[object.category as usize] = client;
        0
    }

    #[test]
    fn registration_errors_release_lock_without_changing_slots() {
        let _guard = TEST_LOCK.lock();
        unsafe {
            let mut registry = [0u32; 6];
            registry[4] = 1;
            EXPECTED_REGISTRY = registry.as_mut_ptr();
            SLOTS = [core::ptr::null_mut(); 3];
            core::ptr::addr_of_mut!(CATEGORY_CLIENT_REGISTER_OPS).write(CategoryClientRegisterOps {
                lock: acquire, register, unlock: release,
            });
            assert_eq!(category_client_register(registry.as_mut_ptr(), core::ptr::null_mut()), 1);
            assert_eq!(registry[4], 1);
            for category in [0, 1, 2, 3, u32::MAX] {
                let mut client = Client { category, activation_succeeds: 0, activations: 0 };
                assert_eq!(category_client_register(registry.as_mut_ptr(), core::ptr::addr_of_mut!(client).cast()),
                    if category < 3 { 4 } else { 7 });
                assert_eq!(client.activations, if category < 3 { 1 } else { 0 });
                assert_eq!(registry[4], 1);
                assert_eq!(SLOTS, [core::ptr::null_mut(); 3]);
            }
        }
    }

    #[test]
    fn successful_registration_replaces_only_selected_slot_and_unlocks() {
        let _guard = TEST_LOCK.lock();
        unsafe {
            let mut registry = [0u32; 6];
            registry[4] = 1;
            EXPECTED_REGISTRY = registry.as_mut_ptr();
            SLOTS = [core::ptr::null_mut(); 3];
            core::ptr::addr_of_mut!(CATEGORY_CLIENT_REGISTER_OPS).write(CategoryClientRegisterOps {
                lock: acquire, register, unlock: release,
            });
            let mut clients = [
                Client { category: 0, activation_succeeds: 1, activations: 0 },
                Client { category: 1, activation_succeeds: 1, activations: 0 },
                Client { category: 2, activation_succeeds: 1, activations: 0 },
                Client { category: 1, activation_succeeds: 1, activations: 0 },
            ];
            let mut expected = [core::ptr::null_mut(); 3];
            for client in &mut clients {
                let pointer = core::ptr::from_mut(client).cast::<u8>();
                assert_eq!(category_client_register(registry.as_mut_ptr(), pointer), 0);
                expected[client.category as usize] = pointer;
                assert_eq!(SLOTS, expected);
                assert_eq!(client.activations, 1);
                assert_eq!(registry[4], 1);
            }
        }
    }
}
