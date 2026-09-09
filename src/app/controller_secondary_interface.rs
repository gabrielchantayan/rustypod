//! `controller_secondary_interface_construct` — original: `FUN_0821599c` @
//! **0x0821599c** (12 bytes, 0x0821599c..0x082159a8; **14 `bl` call
//! sites, all unconditional**, no predicated calls, tail branches, or aligned
//! data-word references), verified by decoding every ARM B/BL word and every
//! aligned word in `osos.dec`.
//!
//! ```text
//! 0821599c  ldr r1, [pc, #4]     @ 0x08993258
//! 082159a0  str r1, [r0]         @ secondary_interface->vtable
//! 082159a4  bx  lr
//! 082159a8  .word 0x08993258     @ literal pool
//! 082159ac  bx  lr               @ next separately linked function
//! ```
//!
//! The constructor of the secondary interface embedded at +0xd0 in the
//! `kinded_controller` leaf hierarchy: it installs the interface's base
//! vtable word and returns the incoming subobject pointer unchanged. Each
//! direct caller immediately overwrites that word with its leaf-specific
//! secondary vtable (for example, the 0x0822519c constructor writes
//! `this + 0x164` after this helper), but the base-construction store is still
//! observable before that write.
//!
//! # Deliberate deviations
//!
//! The runtime vtable is represented as its raw 32-bit target address rather
//! than a Rust vtable. The decrypted image has no trustworthy static contents
//! for the relocated vtable page. The target's unguarded aligned `str` is
//! modeled by an unguarded aligned `u32` store; NULL or misaligned input is
//! invalid exactly as it is for the ARM instruction.

/// The secondary interface vtable literal loaded from 0x082159a8.
pub const CONTROLLER_SECONDARY_INTERFACE_VTABLE: u32 = 0x0899_3258;

/// `controller_secondary_interface_construct` — original: `FUN_0821599c` @
/// 0x0821599c (12 bytes; 14 unconditional `bl` call sites).
///
/// Installs [`CONTROLLER_SECONDARY_INTERFACE_VTABLE`] in the interface's
/// leading word and returns `secondary_interface`. No NULL guard exists.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn controller_secondary_interface_construct(
    secondary_interface: *mut u32,
) -> *mut u32 {
    core::ptr::write(secondary_interface, CONTROLLER_SECONDARY_INTERFACE_VTABLE);
    secondary_interface
}

#[cfg(test)]
mod tests {
    use super::{controller_secondary_interface_construct, CONTROLLER_SECONDARY_INTERFACE_VTABLE};

    #[test]
    fn installs_only_the_leading_interface_vtable_word() {
        let mut words = [0xa5a5_a5a5, 0x1122_3344, 0x5566_7788];
        let interface = unsafe { words.as_mut_ptr().add(1) };

        let returned = unsafe { controller_secondary_interface_construct(interface) };

        assert_eq!(returned, interface, "r0 falls through unchanged");
        assert_eq!(words[0], 0xa5a5_a5a5, "does not write before the interface");
        assert_eq!(words[1], CONTROLLER_SECONDARY_INTERFACE_VTABLE);
        assert_eq!(words[2], 0x5566_7788, "does not write past the vtable word");
    }

    #[test]
    fn replaces_an_existing_leaf_vtable() {
        let mut interface = 0x0899_33bc;

        let returned = unsafe { controller_secondary_interface_construct(&mut interface) };

        assert_eq!(returned, core::ptr::addr_of_mut!(interface));
        assert_eq!(interface, CONTROLLER_SECONDARY_INTERFACE_VTABLE);
    }
}
