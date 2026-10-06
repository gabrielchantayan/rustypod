//! Ports of the retailOS IRQ binding setter, enable, and attach/enable combiner.
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
//! - enable  @ 0x08166a14: re-enters the table through veneer 0x08038090,
//!           loads `binding->irq`, then tail-calls veneer 0x080380b0. The
//!           veneer targets receive `(table_base, irq)`; their identities
//!           remain unproven.
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
//! - The IRQ-table base defaults to the established Rust IRQ-entry veneer.
//!   Registration and enable still call their verified stock veneers on
//!   target; host defaults are inert and tests install behavioral models.
//! - The original tail-calls the enable; the Rust body calls it normally,
//!   which is observationally identical (nothing follows it).

use super::irq::IrqHandler;

// ---------------------------------------------------------------------------
// The binding object (layout verified against the ctor 0x08166a2c and the
// setter 0x081669bc).
// ---------------------------------------------------------------------------

/// IRQ binding POD, 8 bytes on the 32-bit target. `repr(C)` preserves the
/// target field offsets while allowing native handler pointers on host.
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
// Dispatch seams for the table accessor and unported table operations.
// ---------------------------------------------------------------------------

pub const IRQ_REGISTER_FROM_TABLE_VENEER_ADDRESS: usize = 0x0803_80a0;
pub const IRQ_ENABLE_FROM_TABLE_VENEER_ADDRESS: usize = 0x0803_80b0;

/// Verified veneer ABIs. The table accessor defaults to its existing Rust
/// port; the remaining operations call stock firmware on target.
#[derive(Clone, Copy)]
pub struct IrqBindingOps {
    pub irq_table_base: unsafe extern "C" fn() -> *mut u32,
    pub register_from_table: unsafe extern "C" fn(*mut u32, u8, Option<IrqHandler>),
    pub enable_from_table: unsafe extern "C" fn(*mut u32, u8),
}

unsafe extern "C" fn irq_table_base() -> *mut u32 {
    super::irq::rtxc_irq_enter_veneer().cast()
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_register_from_table(
    table: *mut u32, irq: u8, handler: Option<IrqHandler>,
) {
    let f: unsafe extern "C" fn(*mut u32, u8, Option<IrqHandler>) =
        core::mem::transmute(IRQ_REGISTER_FROM_TABLE_VENEER_ADDRESS);
    f(table, irq, handler)
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_enable_from_table(table: *mut u32, irq: u8) {
    let f: unsafe extern "C" fn(*mut u32, u8) =
        core::mem::transmute(IRQ_ENABLE_FROM_TABLE_VENEER_ADDRESS);
    f(table, irq)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_register_from_table(
    _table: *mut u32, _irq: u8, _handler: Option<IrqHandler>,
) {}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_enable_from_table(_table: *mut u32, _irq: u8) {}

pub const DEFAULT_IRQ_BINDING_OPS: IrqBindingOps = IrqBindingOps {
    irq_table_base,
    register_from_table: firmware_register_from_table,
    enable_from_table: firmware_enable_from_table,
};

/// Active callees, read through `read_volatile` so LLVM cannot fold calls.
pub static mut IRQ_BINDING_OPS: IrqBindingOps = DEFAULT_IRQ_BINDING_OPS;

// ---------------------------------------------------------------------------
// The ported function.
// ---------------------------------------------------------------------------
/// irq_binding_set_handler — original: `FUN_081669bc` @ 0x081669bc.
/// True extent 0x081669bc..0x081669dc, 32 bytes (Ghidra's 36 includes
/// the next function's push). Two plain BL callers, zero predicated BLs;
/// the body has one plain BL and a tail B.
///
/// Store the handler, obtain the IRQ dispatch table via 0x08038090,
/// reload handler and byte IRQ from the binding, then register through
/// 0x080380a0 -> IRAM 0x22004d20 (osos mirror 0x08004d20). That helper
/// masks valid IRQs before storing the handler; IRQs >= 64 leave the table
/// unchanged, but the binding's handler is still updated here.
///
/// Deliberate deviations: use the established Rust table-accessor port
/// (Rust BSS table), a volatile-read seam for the unported registration
/// veneer, and an ordinary call in place of the final tail branch.
/// Native `repr(C)` pointer layout is used on host. No NULL binding guard.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn irq_binding_set_handler(
    binding: *mut IrqBinding,
    handler: Option<IrqHandler>,
) {
    (*binding).handler = handler;
    // Read only the two required pointers. Copying the whole three-field
    // ops struct miscompiled on LLVM 22.1.8 ARM (lost binding/branch-target
    // register moves); these scalar loads retain correct AAPCS codegen.
    let table_base = core::ptr::addr_of!(IRQ_BINDING_OPS.irq_table_base).read_volatile();
    let register = core::ptr::addr_of!(IRQ_BINDING_OPS.register_from_table).read_volatile();
    let table = table_base();
    register(table, (*binding).irq, (*binding).handler);
}


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
    irq_binding_set_handler(binding, handler);
    irq_binding_enable(binding);
}

/// irq_binding_enable — original: `FUN_08166a14` @ 0x08166a14 (24 bytes;
/// verified extent 0x08166a14..0x08166a2c).
///
/// Calls the existing Rust port of veneer 0x08038090 to obtain the IRQ
/// table base, loads the binding's byte-sized IRQ number, then calls
/// stock veneer 0x080380b0 with `(table, irq)`. The raw body has one BL;
/// four direct callers use plain BL, with zero predicated forms.
/// Deliberate deviations: Rust BSS table, indirect enable seam, and an
/// ordinary call in place of the final tail branch.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn irq_binding_enable(binding: *mut IrqBinding) {
    let table_base = core::ptr::addr_of!(IRQ_BINDING_OPS.irq_table_base).read_volatile();
    let enable = core::ptr::addr_of!(IRQ_BINDING_OPS.enable_from_table).read_volatile();
    enable(table_base(), (*binding).irq);
}

// ---------------------------------------------------------------------------
// Host tests: binding updates and registration ordering across edge cases.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut BINDING: *mut IrqBinding = core::ptr::null_mut();
    static mut REWRITE: bool = false;
    static mut REGISTERED: Option<IrqHandler> = None;
    static mut MASKED: bool = false;
    static mut ENABLED: bool = false;

    unsafe extern "C" fn first_handler() {}
    unsafe extern "C" fn second_handler() {}

    // Table entry can re-enter driver code: observe the store and alter
    // the binding before returning, forcing the setter to reload fields.
    unsafe extern "C" fn model_table_base() -> *mut u32 {
        assert!((*BINDING).handler.is_some());
        if REWRITE {
            (*BINDING).irq = 63;
            (*BINDING).handler = Some(second_handler);
        }
        core::ptr::null_mut()
    }

    unsafe extern "C" fn model_register(
        _table: *mut u32, irq: u8, handler: Option<IrqHandler>,
    ) {
        if irq < 64 {
            MASKED = true;
            REGISTERED = handler;
        }
    }

    unsafe extern "C" fn model_enable(_table: *mut u32, irq: u8) {
        if irq < 64 {
            assert!(MASKED);
            assert_eq!(REGISTERED.map(|f| f as usize), (*BINDING).handler.map(|f| f as usize));
            ENABLED = true;
        }
    }

    struct Restore;
    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(IRQ_BINDING_OPS).write_volatile(DEFAULT_IRQ_BINDING_OPS);
                BINDING = core::ptr::null_mut();
            }
        }
    }

    unsafe fn setup(binding: *mut IrqBinding, rewrite: bool) -> Restore {
        BINDING = binding;
        REWRITE = rewrite;
        REGISTERED = Some(second_handler);
        MASKED = false;
        ENABLED = false;
        core::ptr::addr_of_mut!(IRQ_BINDING_OPS).write_volatile(IrqBindingOps {
            irq_table_base: model_table_base,
            register_from_table: model_register,
            enable_from_table: model_enable,
        });
        Restore
    }

    #[test]
    fn stores_before_entry_and_reloads_after_entry() {
        let _lock = TEST_LOCK.lock();
        let mut binding = IrqBinding { irq: 255, _pad: [0xa5; 3], handler: None };
        unsafe {
            let _restore = setup(&mut binding, true);
            irq_binding_set_handler(&mut binding, Some(first_handler));
            assert_eq!(binding.irq, 63);
            assert_eq!(binding._pad, [0xa5; 3]);
            assert_eq!(binding.handler.map(|f| f as usize), Some(second_handler as *const () as usize));
            assert_eq!(core::ptr::addr_of!(REGISTERED).read().map(|f| f as usize),
                Some(second_handler as *const () as usize));
            assert!(core::ptr::addr_of!(MASKED).read());
        }
    }

    unsafe extern "C" fn table_without_reentry() -> *mut u32 {
        core::ptr::null_mut()
    }

    #[test]
    fn null_replacement_and_irq_boundaries_preserve_binding_padding() {
        let _lock = TEST_LOCK.lock();
        for irq in [0, 31, 32, 63, 64, 255] {
            let mut binding = IrqBinding { irq, _pad: [0x5a; 3], handler: Some(first_handler) };
            unsafe {
                let _restore = setup(&mut binding, false);
                (*core::ptr::addr_of_mut!(IRQ_BINDING_OPS)).irq_table_base = table_without_reentry;
                irq_binding_set_handler(&mut binding, None);
                assert!(binding.handler.is_none());
                assert_eq!(binding.irq, irq);
                assert_eq!(binding._pad, [0x5a; 3]);
                assert_eq!(core::ptr::addr_of!(MASKED).read(), irq < 64);
                assert_eq!(core::ptr::addr_of!(REGISTERED).read().map(|f| f as usize),
                    if irq < 64 { None } else { Some(second_handler as *const () as usize) });
            }
        }
    }

    #[test]
    fn attach_enable_registers_before_unmasking() {
        let _lock = TEST_LOCK.lock();
        let mut binding = IrqBinding { irq: 32, _pad: [0; 3], handler: None };
        unsafe {
            let _restore = setup(&mut binding, false);
            irq_binding_attach_enable(&mut binding, Some(first_handler));
            assert!(core::ptr::addr_of!(ENABLED).read());
            assert_eq!(binding.handler.map(|f| f as usize), Some(first_handler as *const () as usize));
        }
    }
}
