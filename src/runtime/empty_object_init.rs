//! Empty object initializer — `FUN_081211a4` @ 0x081211a4 (4 bytes).
//!
//! Raw word e12fff1e is `bx lr`; the next independent lifetime operation
//! begins at 0x081211a8. Whole-image A32 decoding finds two plain direct BL
//! callers (0x081672f0 and 0x0818db84), zero predicated BL callers, and no
//! address-word references. There are no outgoing calls or memory accesses.
//! Both callers pass a four-byte stack slot before parser work and later
//! invoke the paired empty_object_destruct operation. Initialization leaves
//! both the object storage and incoming r0 unchanged.
//!
//! Deliberate deviation: the host implementation explicitly returns the
//! incoming pointer word; the ARM target is naked to preserve the exact
//! register-only behavior and original single-instruction body.

#[cfg(all(target_os = "none", target_arch = "arm"))]
#[unsafe(naked)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn empty_object_init(_this: u32) -> u32 {
    core::arch::naked_asm!("bx lr");
}

#[cfg(not(all(target_os = "none", target_arch = "arm")))]
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn empty_object_init(this: u32) -> u32 {
    this
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_pointer_words_without_accessing_storage() {
        // NULL, aligned DRAM, unaligned, unmapped, and maximum target words.
        // None requires allocated storage: the original never dereferences r0.
        for this in [0, 0x0800_0000, 0x0800_0001, 0xffff_fffd, u32::MAX] {
            assert_eq!(empty_object_init(this), this);
        }
    }
}
