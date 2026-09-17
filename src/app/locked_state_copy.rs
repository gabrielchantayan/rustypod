//! Locked copy of the controller's 18-record state block.
//!
//! `locked_state_copy` — original: `FUN_08214614` @ **0x08214614**
//! (**44 bytes**, 0x08214614..0x08214640). The next `push {r4,r5,r6,r7,r8,r9,lr}`
//! at 0x08214640 is an independent function. The body has three unconditional
//! plain `bl` calls and no predicated `bl` calls: mutex_handoff_lock,
//! the unported 0x081d6034 state-record copier, and mutex_handoff_unlock.
//! It locks the handoff, copies the 0x294-byte state block at +0x1c, unlocks,
//! and returns one. Deliberate deviation: 0x081d6034 has no established
//! semantic identity or Rust port, so target builds use its verified absolute
//! entry while host tests inject that sole operation.

use crate::kernel::mutex_handoff::{mutex_handoff_lock, mutex_handoff_unlock, MutexHandoff};

/// ABI of the unported 18-by-0x24-byte state-record copier at 0x081d6034.
pub type StateRecordsCopy = unsafe extern "C" fn(*mut u8, *const u8);

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_state_records_copy(_destination: *mut u8, _source: *const u8) {}

/// Host replacement for the unported state-record copy operation.
#[cfg(not(target_arch = "arm"))]
pub static mut STATE_RECORDS_COPY: StateRecordsCopy = missing_state_records_copy;

#[cfg(target_arch = "arm")]
extern "C" {
    fn retail_state_records_copy(destination: *mut u8, source: *const u8);
}

#[cfg(not(target_arch = "arm"))]
unsafe fn retail_state_records_copy(destination: *mut u8, source: *const u8) {
    core::ptr::read_volatile(core::ptr::addr_of!(STATE_RECORDS_COPY))(destination, source);
}

#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl retail_state_records_copy
    .type retail_state_records_copy, %function
retail_state_records_copy:
    ldr     pc, [pc, #-4]
    .word   0x081d6034
    .size retail_state_records_copy, . - retail_state_records_copy
"#
);

/// Copies `source` into the state records protected by `handoff`.
///
/// Original: `FUN_08214614` @ 0x08214614 (44 bytes; three unconditional plain
/// `bl` calls, no predicated calls). The target layout puts the copied records
/// at handoff+0x1c; byte addressing preserves that offset on 64-bit hosts.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn locked_state_copy(handoff: *mut MutexHandoff, source: *const u8) -> u32 {
    mutex_handoff_lock(handoff);
    retail_state_records_copy(handoff.cast::<u8>().add(0x1c), source);
    mutex_handoff_unlock(handoff);
    1
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::kernel::sync_mutex::Mutex;
    use core::sync::atomic::{AtomicUsize, Ordering};

    static DESTINATION: AtomicUsize = AtomicUsize::new(0);
    static SOURCE: AtomicUsize = AtomicUsize::new(0);
    static CALLS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn record_copy(destination: *mut u8, source: *const u8) {
        DESTINATION.store(destination as usize, Ordering::SeqCst);
        SOURCE.store(source as usize, Ordering::SeqCst);
        CALLS.fetch_add(1, Ordering::SeqCst);
    }

    #[repr(C)]
    struct Fixture {
        handoff: MutexHandoff,
        state_padding: [u8; 0x294],
    }

    #[test]
    fn copies_the_target_offset_once_and_returns_one() {
        let saved = unsafe { core::ptr::addr_of!(STATE_RECORDS_COPY).read_volatile() };
        unsafe { core::ptr::addr_of_mut!(STATE_RECORDS_COPY).write_volatile(record_copy) };
        CALLS.store(0, Ordering::SeqCst);
        let mut bootstrap_handle = 0;
        let mut fixture = Fixture {
            handoff: MutexHandoff {
                opaque: 0,
                bootstrap_mutex: Mutex { sem_cell: &mut bootstrap_handle, unused: 0 },
                current_mutex: core::ptr::null_mut(),
            },
            state_padding: [0; 0x294],
        };
        fixture.handoff.current_mutex = core::ptr::addr_of_mut!(fixture.handoff.bootstrap_mutex);
        let source = [0x5a_u8; 0x294];

        let result = unsafe { locked_state_copy(core::ptr::addr_of_mut!(fixture.handoff), source.as_ptr()) };

        assert_eq!(result, 1);
        assert_eq!(CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(DESTINATION.load(Ordering::SeqCst), unsafe { core::ptr::addr_of_mut!(fixture.handoff).cast::<u8>().add(0x1c) } as usize);
        assert_eq!(SOURCE.load(Ordering::SeqCst), source.as_ptr() as usize);
        unsafe { core::ptr::addr_of_mut!(STATE_RECORDS_COPY).write_volatile(saved) };
    }
}
