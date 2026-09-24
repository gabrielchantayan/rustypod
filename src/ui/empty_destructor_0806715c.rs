//! Empty UI destructor — `FUN_0806715c` @ 0x0806715c (4 bytes).
//!
//! Raw `osos.dec` is a single `bx lr`; 0x08067160 begins the next independent
//! function with `ldr r2,[r0,#0xf00]`. The destructor reads no memory, makes no
//! changes, and preserves its incoming `r0`. Two plain direct `bl` instructions
//! (0x080613a8 and 0x0806a9f0) and one predicated `bleq` (0x08049350) target it.
//!
//! Callers use this as the final lifetime operation for UI elements, but its
//! empty body makes no observable use of the object pointer. Deliberate
//! deviation: the host implementation returns `this` explicitly for testing;
//! the ARM firmware target is naked and emits the original `bx lr`.

#[cfg(all(target_os = "none", target_arch = "arm"))]
#[unsafe(naked)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn empty_destructor_0806715c(_this: u32) -> u32 {
    core::arch::naked_asm!("bx lr");
}

#[cfg(not(all(target_os = "none", target_arch = "arm")))]
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn empty_destructor_0806715c(this: u32) -> u32 {
    this
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_null_pointer_word() {
        assert_eq!(empty_destructor_0806715c(0), 0);
    }

    #[test]
    fn preserves_aligned_object_pointer_word() {
        assert_eq!(empty_destructor_0806715c(0x0800_0000), 0x0800_0000);
    }

    #[test]
    fn preserves_unaligned_word_without_dereferencing() {
        assert_eq!(empty_destructor_0806715c(0xffff_fffd), 0xffff_fffd);
    }
}
