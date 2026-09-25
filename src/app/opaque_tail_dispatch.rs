//! `opaque_tail_dispatch` — original: `thunk_FUN_080d43e0` at load address
//! `0x08003838` (4 bytes: `ldr pc, [pc, #-4]`; its literal target word at
//! `0x0800383c` is `0x080d43e0`, and `0x08003840` begins the next veneer).
//!
//! Full-image A32 branch decoding finds three inbound plain `bl` calls
//! (`0x08005f58`, `0x08005f60`, and `0x08006a98`) and zero predicated `bl`
//! calls.
//!
//! Algorithm: tail-dispatch to the opaque retail target at `0x080d43e0`.
//! The tail veneer preserves every incoming register and caller stack word;
//! only `r0` is established at each verified caller, so the target identity
//! and complete signature remain unrecovered.
//!
//! # Deliberate deviations
//!
//! Host builds expose a one-word callback seam solely to test the verified
//! `r0` forwarding contract. ARM builds retain the exact literal veneer,
//! including its tail-dispatch rather than a Rust call/return edge.

#[cfg(target_os = "none")]
core::arch::global_asm!(
    r#"
    .section .text.opaque_tail_dispatch,"ax",%progbits
    .p2align 2
    .globl opaque_tail_dispatch
    .type opaque_tail_dispatch,%function
opaque_tail_dispatch:
    ldr     pc, [pc, #-4]
    .size opaque_tail_dispatch, . - opaque_tail_dispatch
    .word   0x080d43e0
"#
);

#[cfg(not(target_os = "none"))]
pub type OpaqueTailTarget = unsafe extern "C" fn(u32);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_opaque_tail_target(_first_argument: u32) {
    panic!("opaque_tail_dispatch target is unavailable on the host");
}

#[cfg(not(target_os = "none"))]
pub static mut OPAQUE_TAIL_TARGET: OpaqueTailTarget = missing_opaque_tail_target;

#[cfg(not(target_os = "none"))]
#[inline(never)]
pub unsafe extern "C" fn opaque_tail_dispatch(first_argument: u32) {
    core::ptr::read_volatile(core::ptr::addr_of!(OPAQUE_TAIL_TARGET))(first_argument);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{opaque_tail_dispatch, OpaqueTailTarget, OPAQUE_TAIL_TARGET};
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::{Mutex, MutexGuard};

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut SEEN_ARGUMENT: u32 = 0;

    unsafe extern "C" fn record_target(first_argument: u32) {
        addr_of_mut!(SEEN_ARGUMENT).write(first_argument);
    }

    fn install_target() -> MutexGuard<'static, ()> {
        let guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            addr_of_mut!(SEEN_ARGUMENT).write(0);
            addr_of_mut!(OPAQUE_TAIL_TARGET).write(record_target as OpaqueTailTarget);
        }
        guard
    }

    fn restore_target(guard: MutexGuard<'static, ()>) {
        unsafe {
            addr_of_mut!(OPAQUE_TAIL_TARGET).write(super::missing_opaque_tail_target);
        }
        drop(guard);
    }

    #[test]
    fn forwards_observed_first_argument_bits() {
        let guard = install_target();
        for value in [0, 1, 0x8000_0000, 0xffff_ffff, 0x080d_43e0] {
            unsafe {
                opaque_tail_dispatch(value);
                assert_eq!(addr_of!(SEEN_ARGUMENT).read(), value);
            }
        }
        restore_target(guard);
    }
}
