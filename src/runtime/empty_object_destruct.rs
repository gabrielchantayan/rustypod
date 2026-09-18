//! Empty object destructor — `FUN_081211a8` @ 0x081211a8 (4 bytes).
//!
//! Raw `osos.dec` is a single `bx lr`; 0x081211ac begins the next independent
//! function with `strb r0,[r0,#0x1a]`. The destructor reads no memory, makes no
//! changes, and returns its incoming `r0` unchanged. Four plain direct `bl`
//! instructions target this address; no predicated direct `bl` instructions do.
//!
//! The paired initializer at 0x081211a4 is also `bx lr`, and callers construct
//! and destroy a four-byte stack slot around parser work. This identifies an
//! empty object lifetime operation, not a resource-release seam.
//!
//! Deliberate deviation: the host implementation returns `this` explicitly
//! for testing; the firmware target is naked and emits the original `bx lr`.

#[cfg(all(target_os = "none", target_arch = "arm"))]
#[unsafe(naked)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn empty_object_destruct(_this: u32) -> u32 {
    core::arch::naked_asm!("bx lr");
}

#[cfg(not(all(target_os = "none", target_arch = "arm")))]
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn empty_object_destruct(this: u32) -> u32 {
    this
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_null_pointer_word() {
        assert_eq!(empty_object_destruct(0), 0);
    }

    #[test]
    fn preserves_aligned_object_pointer_word() {
        assert_eq!(empty_object_destruct(0x0800_0000), 0x0800_0000);
    }

    #[test]
    fn preserves_unaligned_word_without_dereferencing() {
        assert_eq!(empty_object_destruct(0xffff_fffd), 0xffff_fffd);
    }
}
