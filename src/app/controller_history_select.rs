//! Controller-history selection policy wrappers — originals: `FUN_08292d08`
//! @ `0x08292d08` (20 bytes: 16 bytes of code followed by the 4-byte
//! resource-id literal) and `FUN_08292e58` @ `0x08292e58` (20 bytes).
//!
//! # Verified call sites
//!
//! A raw scan of every ARM `B`/`BL` word in `osos.dec` finds 13 direct `bl`
//! callers of `FUN_08292d08`: 10 unconditional `bl`, two `bleq`, and one
//! `blne`; one further `bne` tail caller exists. The predicated calls are
//! gated by their callers rather than by a NULL guard in this wrapper.
//! `FUN_08292e58` has 25 direct `bl` callers, all unconditional, and no
//! predicated or tail-`b` callers.
//!
//! # Algorithms
//!
//! Both wrappers load private resource `0x0dad073a` then tail-branch to the
//! shared controller-history selection helper at `0x08292d1c`. The
//! `with_callback` wrapper passes `1, 0`, causing the helper to install its
//! `CntrlHistoryFn` callback after selection; `without_callback` passes `0, 1`
//! and suppresses that allocation.
//!
//! # Deliberate deviations
//!
//! The payload cannot retain the original PC-relative branch, so ARM builds
//! use a literal veneer to tail-enter the stock helper. Host builds expose a
//! volatile callback seam for the otherwise unmapped helper, proving the exact
//! identifier and policy flags.

/// Private controller resource selected by the stock literal pool.
pub const CONTROLLER_HISTORY_RESOURCE_ID: u32 = 0x0dad_073a;

/// ABI of the shared controller-history selection helper at `0x08292d1c`.
pub type ControllerHistorySelect = unsafe extern "C" fn(resource_id: u32, history_flag: u32, skip_callback: u32);

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_controller_history_select(_resource_id: u32, _history_flag: u32, _skip_callback: u32) {}

/// Host callback replacing the stock helper at `0x08292d1c`.
///
/// It is read volatily so test replacements cannot be folded away.
#[cfg(not(target_arch = "arm"))]
pub static mut CONTROLLER_HISTORY_SELECT: ControllerHistorySelect = missing_controller_history_select;

/// Selects the fixed controller-history resource without installing its
/// history callback.
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn controller_history_select_without_callback() {
    let select = core::ptr::read_volatile(core::ptr::addr_of!(CONTROLLER_HISTORY_SELECT));
    select(CONTROLLER_HISTORY_RESOURCE_ID, 0, 1);
}

/// Selects the fixed controller-history resource and installs its callback.
///
/// Original: `FUN_08292d08` at `0x08292d08`, 20 bytes including its literal
/// pool. The 212-byte Ghidra extent incorrectly absorbs following sibling
/// functions.
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn controller_history_select_with_callback() {
    let select = core::ptr::read_volatile(core::ptr::addr_of!(CONTROLLER_HISTORY_SELECT));
    select(CONTROLLER_HISTORY_RESOURCE_ID, 1, 0);
}

// The retail body has a direct PC-relative tail branch to 0x08292d1c. The
// payload is relocated, so preserve that transfer through a literal veneer.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl controller_history_select_without_callback
    .type controller_history_select_without_callback, %function
controller_history_select_without_callback:
    ldr     r0, 1f
    mov     r2, #1
    mov     r1, #0
    b       retail_controller_history_select
1:  .word   0x0dad073a
    .size controller_history_select_without_callback, . - controller_history_select_without_callback

retail_controller_history_select:
    ldr     pc, [pc, #-4]
    .word   0x08292d1c
    .size retail_controller_history_select, . - retail_controller_history_select
    .p2align 2
    .globl controller_history_select_with_callback
    .type controller_history_select_with_callback, %function
controller_history_select_with_callback:
    ldr     r0, 1f
    mov     r2, #0
    mov     r1, #1
    b       retail_controller_history_select_with_callback
1:  .word   0x0dad073a
    .size controller_history_select_with_callback, . - controller_history_select_with_callback

retail_controller_history_select_with_callback:
    ldr     pc, [pc, #-4]
    .word   0x08292d1c
    .size retail_controller_history_select_with_callback, . - retail_controller_history_select_with_callback
"#
);

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr;
    use std::sync::Mutex;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut CALL: Option<(u32, u32, u32)> = None;

    struct Reset;

    impl Drop for Reset {
        fn drop(&mut self) {
            unsafe {
                ptr::write(
                    ptr::addr_of_mut!(CONTROLLER_HISTORY_SELECT),
                    missing_controller_history_select,
                );
                ptr::write(ptr::addr_of_mut!(CALL), None);
            }
        }
    }

    unsafe extern "C" fn record_controller_history_select(
        resource_id: u32,
        history_flag: u32,
        skip_callback: u32,
    ) {
        ptr::write(
            ptr::addr_of_mut!(CALL),
            Some((resource_id, history_flag, skip_callback)),
        );
    }

    #[test]
    fn selects_fixed_resource_and_skips_history_callback() {
        let _guard = OPS_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _reset = Reset;
        unsafe {
            ptr::write(ptr::addr_of_mut!(CALL), None);
            ptr::write(
                ptr::addr_of_mut!(CONTROLLER_HISTORY_SELECT),
                record_controller_history_select,
            );

            controller_history_select_without_callback();

            assert_eq!(
                ptr::read(ptr::addr_of!(CALL)),
                Some((CONTROLLER_HISTORY_RESOURCE_ID, 0, 1)),
                "the wrapper keeps the retail resource id and skip-callback flags"
            );
        }
    }

    #[test]
    fn selects_fixed_resource_and_installs_history_callback() {
        let _guard = OPS_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _reset = Reset;
        unsafe {
            ptr::write(ptr::addr_of_mut!(CALL), None);
            ptr::write(
                ptr::addr_of_mut!(CONTROLLER_HISTORY_SELECT),
                record_controller_history_select,
            );

            controller_history_select_with_callback();

            assert_eq!(
                ptr::read(ptr::addr_of!(CALL)),
                Some((CONTROLLER_HISTORY_RESOURCE_ID, 1, 0)),
                "the wrapper keeps the retail resource id and install-callback flags"
            );
        }
    }
}
