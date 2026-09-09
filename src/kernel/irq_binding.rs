//! Port of the retailOS IRQ binding "attach and enable" combiner
//! `irq_binding_attach_enable` — original: `FUN_081669dc` @ 0x081669dc.
//!
//! The original is the front door of a small C++-style object family
//! living at 0x081669a4..0x08166a40 in osos. An `IrqBinding` is an 8-byte
//! POD (usually stack-allocated) tying a global interrupt number to a
//! handler closure:
//!
//! - ctor    @ 0x08166a2c: `binding->irq = n; binding->handler = NULL`
//! - set     @ 0x081669bc: `binding->handler = h`, then registers
//!           `binding->irq` in the IRAM dispatch table (via the
//!           `rtxc_irq_enter` veneer 0x08038090 -> 0x22004d7c, whose r0
//!           return is the table base 0x22010200, and the register helper
//!           veneer 0x080380a0 -> 0x22004d20, which first masks the source
//!           in the VIC INTENCLEAR, then stores the handler at
//!           `table + 8 + irq*4`). Both helpers ignore irqs >= 64.
//! - enable  @ 0x08166a14: re-enters the table and tail-calls the
//!           `irq_enable` veneer 0x080380b0 -> 0x22004dd4 (ported in
//!           `kernel/irq`), writing `1 << (irq & 31)` to the VIC INTENABLE
//!           register stored in the table header.
//! - disable @ 0x081669a4 / unbind @ 0x081669f4 / empty dtor @ 0x08166a3c:
//!           siblings, not ported here.
//!
//! This function (verified extent 0x081669dc..0x081669f4, 24 bytes; Ghidra
//! over-reports 28 by absorbing the first word of the 0x081669f4 sibling):
//!
//! ```text
//! 081669dc:  push {r4, lr}
//! 081669e0:  mov  r4, r0            ; save binding
//! 081669e4:  bl   0x081669bc        ; irq_binding_set_handler(binding, handler)
//! 081669e8:  mov  r0, r4
//! 081669ec:  pop  {r4, lr}
//! 081669f0:  b    0x08166a14        ; tail: irq_binding_enable(binding)
//! ```
//!
//! i.e. attach `handler` to `binding->irq`, then unmask that IRQ in the
//! VIC. Ghidra's C drops the r1 handler argument entirely
//! (`FUN_081669bc()`); the 15 verified call sites (all unconditional `bl`,
//! zero predicated forms — full osos.dec B/BL scan) pass the handler in r1
//! from a literal-pool word, e.g. the driver init @ 0x08058388 which builds
//! ten bindings (irqs 8, 0x15, 0x21, 3, 2, 1, 0, 0x10, 0x11, 0x18) with
//! ctor + attach_enable each, then runs the empty dtor over all ten.
//!
//! Deliberate deviations:
//!
//! - Both callees are unported, so they ride the
//!   [`IRQ_BINDING_ATTACH_OPS`] `read_volatile` dispatch seam (the
//!   `app/animation.rs` precedent): on target the defaults transmute the
//!   real firmware addresses 0x081669bc / 0x08166a14 and the port is
//!   hook-ready; on host the defaults are inert (the port then does
//!   nothing — NOT hook-ready on host) and tests install recording mocks.
//! - The original tail-calls the enable; the Rust body calls it normally,
//!   which is observationally identical (nothing follows it).

use super::irq::IrqHandler;

// ---------------------------------------------------------------------------
// The binding object (layout verified against the ctor 0x08166a2c and the
// setter 0x081669bc).
// ---------------------------------------------------------------------------

/// IRQ binding POD, 8 bytes on the 32-bit target. This port only forwards
/// the pointer; the fields are documented for the sibling functions that
/// own them.
#[repr(C)]
pub struct IrqBinding {
    /// +0x00: global interrupt number 0..63 (VIC0 sources 0..31, VIC1
    /// sources 32..63).
    pub irq: u8,
    /// +0x01..0x03: never written by the family; alignment padding.
    pub _pad: [u8; 3],
    /// +0x04: registered handler word (NULL after ctor / unbind).
    pub handler: Option<IrqHandler>,
}

// Pointer fields are 4 bytes on the 32-bit target, 8 on host — pin the
// layout where it is load-bearing.
#[cfg(target_arch = "arm")]
const _: () = {
    assert!(core::mem::size_of::<IrqBinding>() == 8);
    assert!(core::mem::offset_of!(IrqBinding, irq) == 0);
    assert!(core::mem::offset_of!(IrqBinding, handler) == 4);
};

// ---------------------------------------------------------------------------
// Dispatch seam for the two unported callees (see the module header).
// ---------------------------------------------------------------------------

/// Firmware load address of the unported handler-registration callee
/// (`FUN_081669bc`), kept beside the transmute below.
pub const IRQ_BINDING_SET_HANDLER_ADDRESS: usize = 0x0816_69bc;

/// Firmware load address of the unported VIC-unmask callee
/// (`FUN_08166a14`), kept beside the transmute below.
pub const IRQ_BINDING_ENABLE_ADDRESS: usize = 0x0816_6a14;

/// Indirect dispatch for the unported callees of
/// [`irq_binding_attach_enable`]. Host tests install recording models; the
/// sibling ports replace the defaults when they land.
#[derive(Clone, Copy)]
pub struct IrqBindingAttachOps {
    /// Original @ 0x081669bc: store `handler` into the binding and register
    /// it in the IRAM dispatch table (source masked in the VIC first).
    pub set_handler: unsafe extern "C" fn(binding: *mut IrqBinding, handler: Option<IrqHandler>),
    /// Original @ 0x08166a14: unmask `binding->irq` in the VIC.
    pub enable: unsafe extern "C" fn(binding: *mut IrqBinding),
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_binding_set_handler(
    binding: *mut IrqBinding,
    handler: Option<IrqHandler>,
) {
    let f: unsafe extern "C" fn(*mut IrqBinding, Option<IrqHandler>) =
        core::mem::transmute(IRQ_BINDING_SET_HANDLER_ADDRESS);
    f(binding, handler)
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_binding_enable(binding: *mut IrqBinding) {
    let f: unsafe extern "C" fn(*mut IrqBinding) =
        core::mem::transmute(IRQ_BINDING_ENABLE_ADDRESS);
    f(binding)
}

/// Host defaults: inert (see the module header's NOT-hook-ready note).
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_binding_set_handler(
    _binding: *mut IrqBinding,
    _handler: Option<IrqHandler>,
) {
}

/// Host default: inert.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_binding_enable(_binding: *mut IrqBinding) {}

/// Wired defaults: the real firmware addresses on target, inert stubs on
/// host.
pub const DEFAULT_IRQ_BINDING_ATTACH_OPS: IrqBindingAttachOps = IrqBindingAttachOps {
    set_handler: firmware_binding_set_handler,
    enable: firmware_binding_enable,
};

/// The active callee set, read through `read_volatile` so LLVM cannot fold
/// the indirect calls to the defaults.
pub static mut IRQ_BINDING_ATTACH_OPS: IrqBindingAttachOps = DEFAULT_IRQ_BINDING_ATTACH_OPS;

#[inline(always)]
fn attach_ops() -> IrqBindingAttachOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(IRQ_BINDING_ATTACH_OPS)) }
}

// ---------------------------------------------------------------------------
// The ported function.
// ---------------------------------------------------------------------------

/// irq_binding_attach_enable — original: `FUN_081669dc` @ 0x081669dc
/// (24 bytes; Ghidra says 28 — it absorbs the next function's `push`).
///
/// Attaches `handler` to `binding->irq` in the IRAM dispatch table
/// (`FUN_081669bc`), then unmasks that interrupt in the VIC
/// (`FUN_08166a14`, a tail call in the original). No NULL guard on either
/// argument; no irq-range guard here (the table helpers ignore >= 64).
/// 15 verified unconditional `bl` call sites, zero predicated forms.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn irq_binding_attach_enable(
    binding: *mut IrqBinding,
    handler: Option<IrqHandler>,
) {
    let ops = attach_ops();
    (ops.set_handler)(binding, handler);
    (ops.enable)(binding);
}

// ---------------------------------------------------------------------------
// Host tests: recording mocks prove call structure and argument forwarding.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// One recorded seam invocation, in call order.
    #[derive(Clone, PartialEq, Debug)]
    enum Call {
        SetHandler(*mut IrqBinding, Option<IrqHandler>),
        Enable(*mut IrqBinding),
    }

    static mut LOG: Vec<Call> = Vec::new();
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    unsafe extern "C" fn recording_set_handler(
        binding: *mut IrqBinding,
        handler: Option<IrqHandler>,
    ) {
        (*core::ptr::addr_of_mut!(LOG)).push(Call::SetHandler(binding, handler));
    }

    unsafe extern "C" fn recording_enable(binding: *mut IrqBinding) {
        (*core::ptr::addr_of_mut!(LOG)).push(Call::Enable(binding));
    }

    unsafe extern "C" fn mock_handler() {}

    /// Installs the recording seams and clears the log; restores the wired
    /// defaults when the returned guard drops.
    fn mock() -> MutexGuard<'static, ()> {
        let guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            core::ptr::addr_of_mut!(IRQ_BINDING_ATTACH_OPS).write_volatile(IrqBindingAttachOps {
                set_handler: recording_set_handler,
                enable: recording_enable,
            });
            (*core::ptr::addr_of_mut!(LOG)).clear();
        }
        guard
    }

    fn logged() -> Vec<Call> {
        unsafe { (*core::ptr::addr_of!(LOG)).clone() }
    }

    /// Restores the wired defaults (each test calls this explicitly before
    /// dropping its lock guard).
    fn restore() {
        unsafe {
            core::ptr::addr_of_mut!(IRQ_BINDING_ATTACH_OPS)
                .write_volatile(DEFAULT_IRQ_BINDING_ATTACH_OPS);
        }
    }

    #[test]
    fn attaches_then_enables_same_binding() {
        let _guard = mock();
        let mut binding = IrqBinding { irq: 0x15, _pad: [0; 3], handler: None };
        let binding_ptr = &mut binding as *mut IrqBinding;
        unsafe {
            irq_binding_attach_enable(binding_ptr, Some(mock_handler));
        }
        assert_eq!(
            logged(),
            std::vec![
                Call::SetHandler(binding_ptr, Some(mock_handler)),
                Call::Enable(binding_ptr),
            ]
        );
        restore();
    }

    #[test]
    fn forwards_null_handler_without_guard() {
        let _guard = mock();
        let mut binding = IrqBinding { irq: 0, _pad: [0; 3], handler: Some(mock_handler) };
        let binding_ptr = &mut binding as *mut IrqBinding;
        unsafe {
            irq_binding_attach_enable(binding_ptr, None);
        }
        // No NULL guard in the original: None is forwarded verbatim.
        assert_eq!(
            logged(),
            std::vec![
                Call::SetHandler(binding_ptr, None),
                Call::Enable(binding_ptr),
            ]
        );
        restore();
    }

    #[test]
    fn distinct_bindings_keep_identity() {
        let _guard = mock();
        let mut a = IrqBinding { irq: 3, _pad: [0; 3], handler: None };
        let mut b = IrqBinding { irq: 0x21, _pad: [0; 3], handler: None };
        let pa = &mut a as *mut IrqBinding;
        let pb = &mut b as *mut IrqBinding;
        unsafe {
            irq_binding_attach_enable(pa, Some(mock_handler));
            irq_binding_attach_enable(pb, None);
        }
        assert_eq!(
            logged(),
            std::vec![
                Call::SetHandler(pa, Some(mock_handler)),
                Call::Enable(pa),
                Call::SetHandler(pb, None),
                Call::Enable(pb),
            ]
        );
        restore();
    }

    #[test]
    fn host_defaults_are_inert() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            core::ptr::addr_of_mut!(IRQ_BINDING_ATTACH_OPS)
                .write_volatile(DEFAULT_IRQ_BINDING_ATTACH_OPS);
        }
        let mut binding = IrqBinding { irq: 8, _pad: [0xaa; 3], handler: Some(mock_handler) };
        unsafe {
            irq_binding_attach_enable(&mut binding, Some(mock_handler));
        }
        // Inert defaults touch nothing (documented: not hook-ready on host).
        assert_eq!(binding.irq, 8);
        assert_eq!(binding._pad, [0xaa; 3]);
        assert!(binding.handler == Some(mock_handler));
    }

}
