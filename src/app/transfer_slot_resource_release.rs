//! Releases the transfer slot's current resource.
//!
//! `transfer_slot_resource_release` is retailOS `FUN_080f5af8` at
//! **0x080f5af8**. Raw `osos.dec` words establish its 60-byte body from
//! 0x080f5af8 through 0x080f5b30; the next independently entered function
//! starts at 0x080f5b38, after the literal-pool word at 0x080f5b34. A complete
//! ARM B/BL decode finds four direct plain `bl` call sites, all unconditional,
//! at 0x080f5820, 0x080f588c, 0x080f5ab0, and 0x080f5ad0; there are no
//! predicated direct calls. The body makes one indirect `blx` through vtable
//! slot +0x04.
//!
//! # Algorithm
//!
//! Clears the resource's +0x5c state word, invokes its vtable slot +0x04 with
//! the resource in r0, increments the word at 0x08a09d40, then clears the
//! transfer slot's resource word at +0x3c.
//!
//! # Deliberate deviations
//!
//! The virtual target has no established identity. Host builds model it with a
//! typed vtable; the target build is the recovered ARM sequence and dispatches
//! the retail vtable word directly.

#[cfg(not(target_arch = "arm"))]
use core::ptr;

const RESOURCE_OFFSET: usize = 0x3c;
const RESOURCE_STATE_OFFSET: usize = 0x5c;

/// Prefix of the unlifted transfer resource's vtable.
#[repr(C)]
pub struct TransferSlotResourceVtable {
    pub unresolved_00: usize,
    pub release: unsafe extern "C" fn(*mut TransferSlotResource),
}

/// Observed fields of the unlifted transfer resource.
#[repr(C)]
pub struct TransferSlotResource {
    pub vtable: *const TransferSlotResourceVtable,
}

#[cfg(not(target_arch = "arm"))]
static mut TRANSFER_SLOT_RESOURCE_RELEASE_COUNT: u32 = 0;

/// transfer_slot_resource_release — original: `FUN_080f5af8` @ **0x080f5af8**
/// (60-byte body; literal pool at 0x080f5b34, next function at 0x080f5b38).
///
/// # Safety
///
/// `transfer_slot` must have a writable u32 resource word at +0x3c. That word
/// must identify a readable resource with a writable state word at +0x5c and
/// a callable vtable slot +0x04.
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn transfer_slot_resource_release(transfer_slot: *mut u8) {
    let resource_word = transfer_slot.add(RESOURCE_OFFSET).cast::<u32>();
    let resource = ptr::read(resource_word) as usize as *mut TransferSlotResource;
    ptr::write(resource.cast::<u8>().add(RESOURCE_STATE_OFFSET).cast::<u32>(), 0);
    let vtable = ptr::read(ptr::addr_of!((*resource).vtable));
    ((*vtable).release)(resource);
    TRANSFER_SLOT_RESOURCE_RELEASE_COUNT = TRANSFER_SLOT_RESOURCE_RELEASE_COUNT.wrapping_add(1);
    ptr::write(resource_word, 0);
}

#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl transfer_slot_resource_release
    .type transfer_slot_resource_release, %function
transfer_slot_resource_release:
    push    {{r4, r5, r6, lr}}
    mov     r4, r0
    ldr     r0, [r0, #60]
    mov     r5, #0
    str     r5, [r0, #92]
    ldr     r0, [r4, #60]
    ldr     r1, [r0]
    ldr     r1, [r1, #4]
    blx     r1
    ldr     r0, 1f
    ldr     r1, [r0, #4]
    add     r1, r1, #1
    str     r1, [r0, #4]
    str     r5, [r4, #60]
    pop     {{r4, r5, r6, pc}}
    .size transfer_slot_resource_release, . - transfer_slot_resource_release
1:  .word   0x08a09d3c
"#
);

#[cfg(target_arch = "arm")]
extern "C" {
    pub fn transfer_slot_resource_release(transfer_slot: *mut u8);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr::{addr_of, addr_of_mut};
    use core::sync::atomic::{AtomicUsize, Ordering};
    use parking_lot::Mutex;

    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static RELEASED_RESOURCE: AtomicUsize = AtomicUsize::new(0);
    static STATE_AT_RELEASE: AtomicUsize = AtomicUsize::new(usize::MAX);

    unsafe extern "C" fn record_release(resource: *mut TransferSlotResource) {
        RELEASED_RESOURCE.store(resource as usize, Ordering::SeqCst);
        STATE_AT_RELEASE.store(resource.cast::<u8>().add(RESOURCE_STATE_OFFSET).cast::<u32>().read() as usize, Ordering::SeqCst);
    }

    static VTABLE: TransferSlotResourceVtable = TransferSlotResourceVtable {
        unresolved_00: 0,
        release: record_release,
    };

    #[test]
    fn clears_resource_state_before_dispatch_then_releases_slot() {
        let _guard = TEST_LOCK.lock();
        let Some(storage) = try_map_u32_slab(hints::TRANSFER_SLOT_RESOURCE_RELEASE, 0x1000) else {
            note_missing_u32_fixture(module_path!());
            return;
        };
        let transfer_slot = unsafe { storage.add(0x100) };
        let resource = unsafe { storage.add(0x200).cast::<TransferSlotResource>() };

        unsafe {
            addr_of_mut!((*resource).vtable).write(&VTABLE);
            resource.cast::<u8>().add(RESOURCE_STATE_OFFSET).cast::<u32>().write(0xfeed_beef);
            transfer_slot.add(RESOURCE_OFFSET).cast::<u32>().write(resource as usize as u32);
            TRANSFER_SLOT_RESOURCE_RELEASE_COUNT = 9;
            RELEASED_RESOURCE.store(0, Ordering::SeqCst);
            STATE_AT_RELEASE.store(usize::MAX, Ordering::SeqCst);

            transfer_slot_resource_release(transfer_slot);

            assert_eq!(RELEASED_RESOURCE.load(Ordering::SeqCst), resource as usize);
            assert_eq!(STATE_AT_RELEASE.load(Ordering::SeqCst), 0);
            assert_eq!(transfer_slot.add(RESOURCE_OFFSET).cast::<u32>().read(), 0);
            assert_eq!(TRANSFER_SLOT_RESOURCE_RELEASE_COUNT, 10);
            assert!(addr_of!((*resource).vtable).read() == &VTABLE);
        }
    }
}
