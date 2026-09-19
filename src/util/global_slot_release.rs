//! `global_slot_release` — original: `FUN_08090b70` @ `0x08090b70` (20
//! bytes; four verified inbound plain `bl` call sites and no predicated
//! inbound `bl` calls).
//!
//! Raw ARM establishes the true extent from `push {r4,lr}` at `0x08090b70`
//! through `b 0x08149fa0` at `0x08090b84`; `0x08090b88` is a separately
//! entered function. The body has one plain direct `bl`, to the unported
//! global slot-table getter at `0x0814a08c`, and no predicated `bl` calls.
//! It preserves the caller's slot index across that getter, then tail-calls
//! the unported slot-release implementation at `0x08149fa0` with the table
//! in r0 and index in r1. The latter returns 2 for an invalid index, 18 for
//! a slot whose object is still active, or 0 after clearing and releasing a
//! releasable slot.
//!
//! Deliberate deviation: the ARM port reaches the two retail targets through
//! literal veneers because relocated payload code cannot encode their original
//! PC-relative branch displacements. The host build exposes recording seams.

/// Host signature of the retail global slot-table getter at `0x0814a08c`.
#[cfg(not(target_arch = "arm"))]
pub type GlobalSlotTableGet = unsafe extern "C" fn() -> *mut u8;

/// Host signature of the retail slot-release implementation at `0x08149fa0`.
#[cfg(not(target_arch = "arm"))]
pub type GlobalSlotRelease = unsafe extern "C" fn(*mut u8, u32) -> u32;

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_global_slot_table_get() -> *mut u8 {
    core::ptr::null_mut()
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_global_slot_release(_table: *mut u8, _index: u32) -> u32 {
    2
}

/// Host-only replacement for the retail getter at `0x0814a08c`.
#[cfg(not(target_arch = "arm"))]
pub static mut GLOBAL_SLOT_TABLE_GET: GlobalSlotTableGet = missing_global_slot_table_get;

/// Host-only replacement for the retail release body at `0x08149fa0`.
#[cfg(not(target_arch = "arm"))]
pub static mut GLOBAL_SLOT_RELEASE: GlobalSlotRelease = missing_global_slot_release;

/// Releases the global slot selected by `slot_index`.
#[cfg(not(target_arch = "arm"))]
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn global_slot_release(slot_index: u32) -> u32 {
    let get_table = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(GLOBAL_SLOT_TABLE_GET)) };
    let release = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(GLOBAL_SLOT_RELEASE)) };
    unsafe { release(get_table(), slot_index) }
}

#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl global_slot_release
    .type global_slot_release, %function
global_slot_release:
    push    {{r4, lr}}
    mov     r4, r0
    ldr     r12, 1f
    blx     r12
    mov     r1, r4
    pop     {{r4, lr}}
    ldr     pc, 2f
1:  .word   0x0814a08c
2:  .word   0x08149fa0
    .size global_slot_release, . - global_slot_release
"#
);

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut GET_CALLS: u32 = 0;
    static mut RELEASE_CALLS: u32 = 0;
    static mut RELEASE_ARGS: (*mut u8, u32) = (core::ptr::null_mut(), 0);
    static mut RELEASE_RESULT: u32 = 0;
    const TABLE: *mut u8 = 0x08a1_5000 as *mut u8;

    unsafe extern "C" fn recording_get() -> *mut u8 {
        GET_CALLS += 1;
        TABLE
    }

    unsafe extern "C" fn recording_release(table: *mut u8, index: u32) -> u32 {
        RELEASE_CALLS += 1;
        RELEASE_ARGS = (table, index);
        RELEASE_RESULT
    }

    struct Restore(GlobalSlotTableGet, GlobalSlotRelease);

    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe {
                GLOBAL_SLOT_TABLE_GET = self.0;
                GLOBAL_SLOT_RELEASE = self.1;
            }
        }
    }

    fn install(result: u32) -> Restore {
        unsafe {
            let restore = Restore(GLOBAL_SLOT_TABLE_GET, GLOBAL_SLOT_RELEASE);
            GLOBAL_SLOT_TABLE_GET = recording_get;
            GLOBAL_SLOT_RELEASE = recording_release;
            GET_CALLS = 0;
            RELEASE_CALLS = 0;
            RELEASE_ARGS = (core::ptr::null_mut(), 0);
            RELEASE_RESULT = result;
            restore
        }
    }

    #[test]
    fn obtains_table_then_forwards_invalid_slot_status() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _restore = install(2);

        assert_eq!(unsafe { global_slot_release(7) }, 2);
        assert_eq!(unsafe { GET_CALLS }, 1);
        assert_eq!(unsafe { RELEASE_CALLS }, 1);
        assert_eq!(unsafe { RELEASE_ARGS }, (TABLE, 7));
    }

    #[test]
    fn preserves_index_and_propagates_active_slot_status() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _restore = install(18);

        assert_eq!(unsafe { global_slot_release(u32::MAX) }, 18);
        assert_eq!(unsafe { GET_CALLS }, 1);
        assert_eq!(unsafe { RELEASE_CALLS }, 1);
        assert_eq!(unsafe { RELEASE_ARGS }, (TABLE, u32::MAX));
    }
}
