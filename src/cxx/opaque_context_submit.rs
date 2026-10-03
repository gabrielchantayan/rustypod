//! `opaque_context_submit` — `FUN_08257818` @ **0x08257818**.
//! True size: **20 bytes**, ending at the independent push at 0x0825782c.
//! Raw A32 scan: two incoming plain BLs (0x081d6f3c, 0x081d7fb8), zero
//! predicated incoming BLs; body: zero BLs, two conditional tail branches.
//!
//! Advance the owner to its context at +4, XOR the full flag word with one,
//! and submit through the mode-zero boundary when mode is zero, otherwise
//! the mode-one boundary. Both verified boundaries allocate a record from
//! context+0x38, return 0x14 on exhaustion, and share the enqueue body at
//! 0x082619e4. Deliberate deviation: unported bodies remain fixed-address
//! calls (LLVM may use BLX rather than conditional immediate tail branches).

pub type OpaqueContextSubmit = unsafe extern "C" fn(*mut u8, u32, u32) -> u32;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_submit(_context: *mut u8, _payload: u32, _flag: u32) -> u32 {
    panic!("opaque context submit requires installed firmware boundary")
}

#[cfg(not(target_os = "none"))]
pub static mut OPAQUE_CONTEXT_SUBMIT_ZERO: OpaqueContextSubmit = missing_submit;
#[cfg(not(target_os = "none"))]
pub static mut OPAQUE_CONTEXT_SUBMIT_ONE: OpaqueContextSubmit = missing_submit;

/// Submit a payload to the embedded context, preserving the callee status.
///
/// # Safety
/// `owner` must contain a live retail context at +4. The payload word and
/// selected firmware boundary must satisfy that context's ABI and lifetime.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn opaque_context_submit(owner: *mut u8, payload: u32, flag: u32, mode: u32) -> u32 {
    #[cfg(target_os = "none")]
    let submit: OpaqueContextSubmit = core::mem::transmute(if mode == 0 { 0x0826_1b14usize } else { 0x0826_19a0usize });
    #[cfg(not(target_os = "none"))]
    let submit = core::ptr::read_volatile(if mode == 0 {
        core::ptr::addr_of!(OPAQUE_CONTEXT_SUBMIT_ZERO)
    } else {
        core::ptr::addr_of!(OPAQUE_CONTEXT_SUBMIT_ONE)
    });
    submit(owner.add(4), payload, flag ^ 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr::{addr_of, addr_of_mut};
    static LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    static mut OBSERVED: (usize, u32, u32, u32) = (0, 0, 0, 0);
    unsafe extern "C" fn zero(context: *mut u8, payload: u32, flag: u32) -> u32 {
        OBSERVED = (context as usize, payload, flag, 0);
        0x14
    }
    unsafe extern "C" fn one(context: *mut u8, payload: u32, flag: u32) -> u32 {
        OBSERVED = (context as usize, payload, flag, 1);
        0x8765_4321
    }
    #[test]
    fn zero_and_nonzero_modes_preserve_word_flags_and_error_status() {
        let _guard = LOCK.lock();
        unsafe {
            let saved_zero = core::ptr::read_volatile(addr_of!(OPAQUE_CONTEXT_SUBMIT_ZERO));
            let saved_one = core::ptr::read_volatile(addr_of!(OPAQUE_CONTEXT_SUBMIT_ONE));
            core::ptr::write_volatile(addr_of_mut!(OPAQUE_CONTEXT_SUBMIT_ZERO), zero);
            core::ptr::write_volatile(addr_of_mut!(OPAQUE_CONTEXT_SUBMIT_ONE), one);
            let mut owner = [0u32; 0x40];
            let base = owner.as_mut_ptr().cast::<u8>();
            for mode in [0, 1, 2, 0x8000_0000, u32::MAX] {
                for flag in [0, 1, 2, 0x100, 0x8000_0000, u32::MAX] {
                    let result = opaque_context_submit(base, 0xfedc_ba98, flag, mode);
                    assert_eq!(result, if mode == 0 { 0x14 } else { 0x8765_4321 });
                    assert_eq!(core::ptr::read_volatile(addr_of!(OBSERVED)), (base.add(4) as usize, 0xfedc_ba98, flag ^ 1, u32::from(mode != 0)));
                    assert_eq!(owner, [0; 0x40]);
                }
            }
            core::ptr::write_volatile(addr_of_mut!(OPAQUE_CONTEXT_SUBMIT_ZERO), saved_zero);
            core::ptr::write_volatile(addr_of_mut!(OPAQUE_CONTEXT_SUBMIT_ONE), saved_one);
        }
    }
}
