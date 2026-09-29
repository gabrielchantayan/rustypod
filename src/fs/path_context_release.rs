//! Path-resolution context release.
//!
//! `path_context_release` is retailOS `FUN_082e1cd0` at `0x082e1cd0`.

#[cfg(target_os = "none")]
use crate::drivers::ata_semaphore;
#[cfg(target_os = "none")]
use crate::fs::{drive_slot, path_node};

const RETAIL_STORAGE_POOLS_INITIALIZE: usize = 0x082b_155c;
const CONTEXT_DRIVE_INDEX: usize = 0x128;
const CONTEXT_PRIMARY_NODE: usize = 0x240;
const CONTEXT_SECONDARY_NODE: usize = 0x244;
const DRIVE_SLOT_ATA_INDEX: usize = 0x78;

type InitializeStoragePools = unsafe extern "C" fn() -> u32;
type DriveSlotLookup = unsafe extern "C" fn(u32) -> *mut u8;
type SemaphoreWait = unsafe extern "C" fn(usize) -> usize;
type PathNodeRelease = unsafe extern "C" fn(*mut u8) -> *mut u8;
type SemaphoreSignal = unsafe extern "C" fn(usize) -> usize;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn initialize_storage_pools() -> u32 {
    core::mem::transmute::<usize, InitializeStoragePools>(RETAIL_STORAGE_POOLS_INITIALIZE)()
}

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct PathContextReleaseOps {
    pub initialize_storage_pools: InitializeStoragePools,
    pub drive_slot_lookup: DriveSlotLookup,
    pub semaphore_wait: SemaphoreWait,
    pub path_node_release: PathNodeRelease,
    pub semaphore_signal: SemaphoreSignal,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_initialize_storage_pools() -> u32 {
    panic!("path_context_release requires retail helper 0x082b155c")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_drive_slot_lookup(_: u32) -> *mut u8 {
    panic!("path_context_release requires drive-slot lookup")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_semaphore_wait(_: usize) -> usize {
    panic!("path_context_release requires ATA semaphore wait")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_path_node_release(_: *mut u8) -> *mut u8 {
    panic!("path_context_release requires path-node release")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_semaphore_signal(_: usize) -> usize {
    panic!("path_context_release requires ATA semaphore signal")
}

#[cfg(not(target_os = "none"))]
pub const DEFAULT_PATH_CONTEXT_RELEASE_OPS: PathContextReleaseOps = PathContextReleaseOps {
    initialize_storage_pools: missing_initialize_storage_pools,
    drive_slot_lookup: missing_drive_slot_lookup,
    semaphore_wait: missing_semaphore_wait,
    path_node_release: missing_path_node_release,
    semaphore_signal: missing_semaphore_signal,
};

#[cfg(not(target_os = "none"))]
pub static mut PATH_CONTEXT_RELEASE_OPS: PathContextReleaseOps = DEFAULT_PATH_CONTEXT_RELEASE_OPS;

#[inline(always)]
unsafe fn read_target_pointer(base: *mut u8, offset: usize) -> *mut u8 {
    (base.add(offset) as *const u32).read_volatile() as usize as *mut u8
}

/// path_context_release — original: `FUN_082e1cd0` @ `0x082e1cd0`.
///
/// Load address: `0x082e1cd0`; true size: 92 bytes (`0x5c`), from `push
/// {r4,r5,r6,lr}` through the tail branch at `0x082e1d28`; the next separate
/// function starts with `push {r4-r8,lr}` at `0x082e1d2c`. Raw whole-image ARM
/// decoding finds two inbound plain `bl` calls (`0x081bd2fc`, `0x081bda70`)
/// and no predicated `bl` calls. Its body has three plain `bl` instructions
/// and two predicated `blne` instructions.
///
/// Ensures the storage pools are initialized, validates the context's drive,
/// then reads the ATA controller through the secondary node's first word and
/// brackets releases of its two optional path nodes with that drive's semaphore.
/// A failed initialization or missing drive returns before locking.
///
/// Deliberate deviation: the initialization helper at `0x082b155c` has no
/// established identity, so target builds retain it as an address-verified
/// seam; host builds inject all calls. The port invokes the known lookup,
/// semaphore, and node-release ports directly on target rather than preserving
/// the original call and tail-branch encodings.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn path_context_release(context: *mut u8) {
    #[cfg(target_os = "none")]
    if initialize_storage_pools() == 0 {
        return;
    }
    #[cfg(not(target_os = "none"))]
    if (PATH_CONTEXT_RELEASE_OPS.initialize_storage_pools)() == 0 {
        return;
    }

    let drive_index = (context.add(CONTEXT_DRIVE_INDEX) as *const u32).read_volatile();
    #[cfg(target_os = "none")]
    let slot = drive_slot::drive_slot_lookup(drive_index);
    #[cfg(not(target_os = "none"))]
    let slot = (PATH_CONTEXT_RELEASE_OPS.drive_slot_lookup)(drive_index);
    if slot.is_null() {
        return;
    }

    let ata_device = read_target_pointer(read_target_pointer(context, CONTEXT_SECONDARY_NODE), 0);
    let ata_index = (ata_device.add(DRIVE_SLOT_ATA_INDEX) as *const u16).read_volatile() as usize;
    #[cfg(target_os = "none")]
    ata_semaphore::ata_semaphore_wait(ata_index);
    #[cfg(not(target_os = "none"))]
    (PATH_CONTEXT_RELEASE_OPS.semaphore_wait)(ata_index);

    let primary_node = read_target_pointer(context, CONTEXT_PRIMARY_NODE);
    if !primary_node.is_null() {
        #[cfg(target_os = "none")]
        path_node::path_node_release(primary_node);
        #[cfg(not(target_os = "none"))]
        (PATH_CONTEXT_RELEASE_OPS.path_node_release)(primary_node);
    }
    let secondary_node = read_target_pointer(context, CONTEXT_SECONDARY_NODE);
    if !secondary_node.is_null() {
        #[cfg(target_os = "none")]
        path_node::path_node_release(secondary_node);
        #[cfg(not(target_os = "none"))]
        (PATH_CONTEXT_RELEASE_OPS.path_node_release)(secondary_node);
    }

    #[cfg(target_os = "none")]
    ata_semaphore::ata_semaphore_signal(ata_index);
    #[cfg(not(target_os = "none"))]
    (PATH_CONTEXT_RELEASE_OPS.semaphore_signal)(ata_index);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut INITIALIZED: u32 = 1;
    static mut SLOT: *mut u8 = core::ptr::null_mut();
    static mut EVENTS: [usize; 4] = [0; 4];
    static mut EVENT_COUNT: usize = 0;

    unsafe extern "C" fn initialize() -> u32 { INITIALIZED }
    unsafe extern "C" fn lookup(_: u32) -> *mut u8 { SLOT }
    unsafe fn record(event: usize) { EVENTS[EVENT_COUNT] = event; EVENT_COUNT += 1; }
    unsafe extern "C" fn wait(index: usize) -> usize { record(0x1000 | index); 0 }
    unsafe extern "C" fn release(node: *mut u8) -> *mut u8 { record(node as usize); core::ptr::null_mut() }
    unsafe extern "C" fn signal(index: usize) -> usize { record(0x2000 | index); 0 }

    struct Restore(PathContextReleaseOps);
    impl Drop for Restore {
        fn drop(&mut self) { unsafe { PATH_CONTEXT_RELEASE_OPS = self.0; } }
    }

    fn setup(slot: *mut u8) -> Restore {
        unsafe {
            let previous = PATH_CONTEXT_RELEASE_OPS;
            PATH_CONTEXT_RELEASE_OPS = PathContextReleaseOps {
                initialize_storage_pools: initialize, drive_slot_lookup: lookup,
                semaphore_wait: wait, path_node_release: release, semaphore_signal: signal,
            };
            SLOT = slot;
            EVENT_COUNT = 0;
            Restore(previous)
        }
    }

    #[test]
    fn initialization_or_lookup_failure_does_not_lock() {
        let _lock = TEST_LOCK.lock();
        let mut context = [0u8; CONTEXT_DRIVE_INDEX + 4];
        let _restore = setup(core::ptr::null_mut());
        unsafe { INITIALIZED = 0; path_context_release(context.as_mut_ptr()); }
        assert_eq!(unsafe { EVENT_COUNT }, 0);
        unsafe { INITIALIZED = 1; path_context_release(context.as_mut_ptr()); }
        assert_eq!(unsafe { EVENT_COUNT }, 0);
    }

    #[test]
    fn releases_nonnull_nodes_between_drive_semaphore_operations() {
        let _lock = TEST_LOCK.lock();
        let Some(context) = crate::testing::try_map_u32_slab(crate::testing::hints::PATH_CONTEXT_RELEASE, 0x400) else { return; };
        let slot = unsafe { context.add(0x300) };
        let primary = unsafe { context.add(0x260) };
        let secondary = unsafe { context.add(0x280) };
        unsafe {
            (slot.add(DRIVE_SLOT_ATA_INDEX) as *mut u16).write_volatile(7);
            (context.add(CONTEXT_DRIVE_INDEX) as *mut u32).write_volatile(3);
            (secondary as *mut u32).write_volatile(slot as usize as u32);
            (context.add(CONTEXT_PRIMARY_NODE) as *mut u32).write_volatile(primary as usize as u32);
            (context.add(CONTEXT_SECONDARY_NODE) as *mut u32).write_volatile(secondary as usize as u32);
        }
        let _restore = setup(slot);
        unsafe { path_context_release(context); }
        assert_eq!(unsafe { EVENT_COUNT }, 4);
        assert_eq!(unsafe { EVENTS }, [0x1007, primary as usize, secondary as usize, 0x2007]);
    }
}
