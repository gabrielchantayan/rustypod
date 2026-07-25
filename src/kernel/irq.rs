//! Port of the retailOS IRQ path: the IRQ vector entry stub and its C
//! dispatcher, with the small S5L8702 VIC helper cluster the dispatcher
//! relies on:
//!
//! - `irq_entry`       — original: vector stub @ 0x08003080 (0x78 bytes
//!   incl. literal pool). Reached from the ARM IRQ vector (0x18). Classic
//!   RTXC frame: fixes `lr`, spills the return pc / r0 / SPSR below the IRQ
//!   stack, switches to SVC mode (IRQ masked), pushes r1-r12+lr plus the
//!   saved SPSR/r0 into a 64-byte frame, bumps the IRQ nesting counter @
//!   0x22008a50 (ROM SRAM, RTXC kernel control block), switches to the
//!   interrupt stack @ 0x08b32b58 on the outermost interrupt, calls
//!   `irq_dispatch`, then unwinds via `ldm sp!, {r0-r12, lr, pc}^`.
//! - `irq_dispatch`    — original: `FUN_080080ac` @ 0x080080ac (0x20 bytes).
//!   Runs `rtxc_irq_enter`, then `vic_dispatch`, then tail-calls
//!   `irq_exit(frame, 0)`; returns `frame` in r0 (the entry stub reloads sp
//!   from it).
//! - `rtxc_irq_enter`  — original: `FUN_08004d7c` @ 0x08004d7c (0x48 bytes).
//!   Kernel-entry bookkeeping: unless the flag word @ 0x22008c70 has bit 0
//!   set, calls an RTXC ROM service through the RAM hook table; on success
//!   runs the one-time `vic_vector_init` and two more ROM services.
//! - `irq_enable`      — original: helper @ 0x08004dd4 (0x28 bytes). Writes
//!   `1 << (irq & 31)` to the VIC INTENABLE register of the right block.
//! - `vic_dispatch`    — original: `FUN_08004dfc` @ 0x08004dfc (0x64 bytes).
//!   The actual routing: reads the two VIC status registers, picks the
//!   busy block, reads its vector (address) register to get the interrupt
//!   number, calls the registered handler, clears the source and
//!   acknowledges the VIC.
//! - `vic_vector_init` — original: `FUN_08004e78` @ 0x08004e78 (0x5c bytes).
//!   One-time init: masks everything, clears the handler table, and
//!   programs each VIC vector slot with its own global interrupt number —
//!   which is why the dispatcher can read VICADDRESS and use the value
//!   directly as a 0..63 index.
//! - `irq_exit`        — original: `FUN_08001d10` @ 0x08001d10 (0x64 bytes).
//!   Tracks the nesting high-water mark, optionally pushes a value onto
//!   the kernel's interrupt value stack, and on the outermost interrupt
//!   stores the frame pointer into the current task's save area, re-enables
//!   IRQs and enters the RTXC scheduler (hook-table veneer 0x082db99c).
//!
//! Interrupt controller (addresses recovered from the binary): two
//! PL192-style VIC blocks at 0x38e00000 / 0x38e01000 plus a shared block
//! at 0x38e02000. Per block: +0x000 IRQSTATUS (nonzero = an IRQ pending),
//! +0x010 INTENABLE (write-1-to-set), +0x014 INTENCLEAR, +0x100..0x17c
//! per-source vector value table, +0xf00 ADDRESS (read: current vector
//! value = interrupt number; write: acknowledge). Shared: 0x38e02008 /
//! 0x38e0200c take `1 << n` to clear a VIC0 / VIC1 source.
//!
//! Simplifications vs the original (all verified behavior is identical):
//!
//! - The handler table lives in rustypod BSS (`IRQ_TABLE`) instead of ROM
//!   SRAM @ 0x22010200. Layout is kept (two leading words holding the VIC
//!   INTENABLE register addresses, then 64 slots at +8), but slots hold
//!   `Option<unsafe extern "C" fn()>` so host tests can install callable
//!   handlers. `irq_set_handler` is port-added registration plumbing.
//! - RTXC ROM services and the scheduler tail are reached through
//!   overridable hooks (`VENEER_CALL` / `SCHEDULER_HOOK`). On ARM the
//!   defaults read the real RAM hook-table words (0x082a0444, 0x082a02f0,
//!   0x082a0460, 0x082db99c) and call them, exactly like the original
//!   veneers @ 0x080036e0/0x080036e8/0x080036f0/0x080034e8; on host the
//!   defaults are inert and tests install mocks.
//! - All absolute-address accesses (VIC MMIO, ROM-SRAM kernel state) go
//!   through the `bus_read*/bus_write*` accessors (volatile at the
//!   documented address by default) so host tests can substitute a mock
//!   address space.
//! - `1 << vec` for vec in 32..63 wraps to 0, mirroring ARM register-shift
//!   semantics (the original writes 0 to the VIC1 clear register — likely
//!   an original bug, kept verbatim). The vector index is bounds-checked
//!   with `.get()`; the original trusts the hardware 0..63 range.
//! - The CPSR writes (`msr CPSR_c`) are ARM-only inline asm; on host they
//!   compile to nothing.
//!
//! Verification: host `cargo test` exercises dispatcher routing, lazy
//! init, `irq_enable`, and the nesting-counter/high-water logic against a
//! mock address space. The entry stub is naked ARM and cannot run on host;
//! `tools/match.py` (ipod-decomp) shows it matching the original nearly
//! instruction-for-instruction (only the `bl irq_dispatch` target differs,
//! as the Rust symbol sits at a different address).

use core::ptr::{addr_of, addr_of_mut};

// ---------------------------------------------------------------------------
// Hardware / firmware addresses (see module header for the register map).
// ---------------------------------------------------------------------------

/// VIC block 0 base (global irqs 0..31).
const VIC0_BASE: u32 = 0x38e0_0000;
/// VIC block 1 base (global irqs 32..63).
const VIC1_BASE: u32 = 0x38e0_1000;
/// Per-block offset: IRQ status, nonzero while any source is pending.
const VIC_IRQSTATUS: u32 = 0x000;
/// Per-block offset: interrupt enable (write-1-to-set).
const VIC_INTENABLE: u32 = 0x010;
/// Per-block offset: interrupt enable clear.
const VIC_INTENCLEAR: u32 = 0x014;
/// Per-block offset: per-source vector value table (32 entries).
const VIC_VECTADDR: u32 = 0x100;
/// Per-block offset: vector address register (read = current interrupt
/// number as programmed by `vic_vector_init`; write = acknowledge).
const VIC_ADDRESS: u32 = 0xf00;
/// Shared block: write `1 << n` to clear VIC0 source n.
const VIC0_CLEAR: u32 = 0x38e0_2008;
/// Shared block: write `1 << n` to clear VIC1 source n.
const VIC1_CLEAR: u32 = 0x38e0_200c;
/// Magic value the original writes to VICADDRESS to acknowledge.
const VIC_ACK_VALUE: u32 = 0x0101_0101;

/// Number of interrupt sources across both VIC blocks.
pub const NUM_IRQS: usize = 64;

/// ROM-SRAM flag word @ 0x22008c70; bit 0 set = lazy IRQ init already done
/// (or the RTXC anchor is otherwise claimed).
const ROM_IRQ_FLAG: u32 = 0x2200_8c70;
/// osos word @ 0x08001524 holding the RTXC kernel control block pointer
/// (0x22008a50: +0 nesting count, +1 high-water, +8 value-stack pointer,
/// +12 value-stack limit).
const KCB_PTR_ADDR: u32 = 0x0800_1524;
/// osos word @ 0x08001510 holding the RTXC task-state pointer
/// (0x2200acf0: +1 flag byte, +4 current task, whose +16 receives the
/// interrupted frame pointer).
const TASK_STATE_PTR_ADDR: u32 = 0x0800_1510;

/// RAM hook-table slots for the RTXC ROM services / scheduler (the original
/// reaches them through the veneers @ 0x080036e0/0x080036e8/0x080036f0 and
/// 0x080034e8). Their exact RTXC semantics are unidentified; they are
/// passed through verbatim.
mod hook_table {
    /// Called with the flag word address before lazy init.
    pub const IRQ_ENTER: u32 = 0x082a_0444;
    /// Called after `vic_vector_init` with (handler_table, obj_a, obj_b).
    pub const IRQ_REGISTER: u32 = 0x082a_02f0;
    /// Called with the flag word address after registration.
    pub const IRQ_FINISH: u32 = 0x082a_0460;
    /// RTXC scheduler, tail-entered from `irq_exit` on the outermost IRQ.
    pub const SCHEDULER: u32 = 0x082d_b99c;
}

/// Unidentified RTXC kernel objects handed to the IRQ_REGISTER service,
/// passed through verbatim from the original.
const RTXC_REGISTER_OBJ_A: u32 = 0x2200_4ee0;
const RTXC_REGISTER_OBJ_B: u32 = 0x089c_a09c;

// ---------------------------------------------------------------------------
// Address-space accessors (default: volatile at the absolute address; host
// tests substitute a mock address space).
// ---------------------------------------------------------------------------

unsafe fn hw_read32(addr: u32) -> u32 {
    (addr as *const u32).read_volatile()
}
unsafe fn hw_write32(addr: u32, val: u32) {
    (addr as *mut u32).write_volatile(val);
}
unsafe fn hw_read8(addr: u32) -> u8 {
    (addr as *const u8).read_volatile()
}
unsafe fn hw_write8(addr: u32, val: u8) {
    (addr as *mut u8).write_volatile(val);
}

static mut BUS_READ32: unsafe fn(u32) -> u32 = hw_read32;
static mut BUS_WRITE32: unsafe fn(u32, u32) = hw_write32;
static mut BUS_READ8: unsafe fn(u32) -> u8 = hw_read8;
static mut BUS_WRITE8: unsafe fn(u32, u8) = hw_write8;

unsafe fn bus_read32(addr: u32) -> u32 {
    (*addr_of!(BUS_READ32))(addr)
}
unsafe fn bus_write32(addr: u32, val: u32) {
    (*addr_of!(BUS_WRITE32))(addr, val);
}
unsafe fn bus_read8(addr: u32) -> u8 {
    (*addr_of!(BUS_READ8))(addr)
}
unsafe fn bus_write8(addr: u32, val: u8) {
    (*addr_of!(BUS_WRITE8))(addr, val);
}

// ---------------------------------------------------------------------------
// RTXC ROM service / scheduler hooks.
// ---------------------------------------------------------------------------

/// Calls an RTXC ROM service through a RAM hook-table slot. On ARM the
/// default loads the service pointer from `slot` and calls it with up to
/// three APCS arguments, mirroring the original veneers; the host default
/// is inert (returns 0) so tests can install a mock.
static mut VENEER_CALL: unsafe fn(slot: u32, a0: u32, a1: u32, a2: u32) -> u32 = default_veneer_call;

#[cfg(target_arch = "arm")]
unsafe fn default_veneer_call(slot: u32, a0: u32, a1: u32, a2: u32) -> u32 {
    let service: unsafe extern "C" fn(u32, u32, u32) -> u32 =
        core::mem::transmute(bus_read32(slot) as usize);
    service(a0, a1, a2)
}

#[cfg(not(target_arch = "arm"))]
unsafe fn default_veneer_call(slot: u32, a0: u32, a1: u32, a2: u32) -> u32 {
    let _ = (slot, a0, a1, a2);
    0
}

unsafe fn veneer_call(slot: u32, a0: u32, a1: u32, a2: u32) -> u32 {
    (*addr_of!(VENEER_CALL))(slot, a0, a1, a2)
}

/// Test/integration hook replacing the RTXC scheduler tail. On ARM, `None`
/// falls through to the real hook-table word 0x082db99c; on host, `None`
/// is a no-op.
static mut SCHEDULER_HOOK: Option<unsafe extern "C" fn()> = None;

unsafe fn call_scheduler() {
    if let Some(hook) = *addr_of!(SCHEDULER_HOOK) {
        hook();
        return;
    }
    #[cfg(target_arch = "arm")]
    {
        let scheduler: unsafe extern "C" fn() =
            core::mem::transmute(bus_read32(hook_table::SCHEDULER) as usize);
        scheduler();
    }
}

// ---------------------------------------------------------------------------
// Handler table (see module header: relocated from ROM SRAM to BSS, layout
// preserved).
// ---------------------------------------------------------------------------

/// Registered IRQ handler: no arguments, called in SVC mode with IRQs
/// masked.
pub type IrqHandler = unsafe extern "C" fn();

/// The interrupt handler table. Field layout mirrors the original's ROM
/// SRAM table @ 0x22010200: two leading words with the VIC INTENABLE
/// register addresses (used by `irq_enable`), then one slot per global
/// interrupt number.
#[repr(C)]
struct IrqTable {
    vic0_intenable: u32,
    vic1_intenable: u32,
    handlers: [Option<IrqHandler>; NUM_IRQS],
}

static mut IRQ_TABLE: IrqTable = IrqTable {
    vic0_intenable: 0,
    vic1_intenable: 0,
    handlers: [None; NUM_IRQS],
};

/// Port-added registration plumbing (the original wrote the ROM-SRAM table
/// from a driver-side helper). `vec` is the global interrupt number 0..63.
pub unsafe fn irq_set_handler(vec: usize, handler: Option<IrqHandler>) {
    if vec < NUM_IRQS {
        (*addr_of_mut!(IRQ_TABLE)).handlers[vec] = handler;
    }
}

// ---------------------------------------------------------------------------
// Mode switches (ARM-only; no-ops on host).
// ---------------------------------------------------------------------------

/// `msr CPSR_c, #0x93` — SVC mode, IRQ masked, FIQ open.
#[inline(always)]
fn svc_mode_irq_masked() {
    #[cfg(target_arch = "arm")]
    unsafe {
        core::arch::asm!("msr CPSR_c, #0x93", options(nomem, nostack));
    }
}

/// `msr CPSR_c, #0x13` — SVC mode, IRQ and FIQ open.
#[inline(always)]
fn svc_mode_irq_open() {
    #[cfg(target_arch = "arm")]
    unsafe {
        core::arch::asm!("msr CPSR_c, #0x13", options(nomem, nostack));
    }
}

// ---------------------------------------------------------------------------
// The ported functions.
// ---------------------------------------------------------------------------

/// irq_enable — original: helper @ 0x08004dd4 (0x28 bytes).
///
/// Enables one interrupt source: writes `1 << (irq & 31)` to the INTENABLE
/// register of VIC0 (irq < 32) or VIC1 (irq >= 32). Irqs >= 64 are ignored.
#[no_mangle]
pub unsafe extern "C" fn irq_enable(irq: u32) {
    if irq >= NUM_IRQS as u32 {
        return;
    }
    let table = &*addr_of!(IRQ_TABLE);
    let (enable_reg, bit) = if irq >= 32 {
        (table.vic1_intenable, irq - 32)
    } else {
        (table.vic0_intenable, irq)
    };
    bus_write32(enable_reg, 1 << bit);
}

/// vic_vector_init — original: `FUN_08004e78` @ 0x08004e78 (0x5c bytes).
///
/// One-time init of the handler table and both VIC blocks: stores the
/// INTENABLE register addresses in the table header, masks all 64 sources,
/// NULLs the handler slots, and programs every vector slot with its own
/// global interrupt number so that reading VICADDRESS later yields the
/// interrupt number directly.
unsafe fn vic_vector_init() {
    let table = &mut *addr_of_mut!(IRQ_TABLE);
    table.vic0_intenable = VIC0_BASE + VIC_INTENABLE;
    table.vic1_intenable = VIC1_BASE + VIC_INTENABLE;
    bus_write32(VIC0_BASE + VIC_INTENCLEAR, 0xffff_ffff);
    bus_write32(VIC1_BASE + VIC_INTENCLEAR, 0xffff_ffff);
    for irq in 0..NUM_IRQS as u32 {
        table.handlers[irq as usize] = None;
        if irq >= 32 {
            // Original address arithmetic: (VIC1_BASE + 0x80) + irq * 4,
            // i.e. VIC1's vector table programmed with values 32..63.
            bus_write32(VIC1_BASE + 0x80 + irq * 4, irq);
        } else {
            bus_write32(VIC0_BASE + VIC_VECTADDR + irq * 4, irq);
        }
    }
}

/// rtxc_irq_enter — original: `FUN_08004d7c` @ 0x08004d7c (0x48 bytes).
///
/// Kernel-entry bookkeeping. Unless bit 0 of the ROM-SRAM flag word @
/// 0x22008c70 is set, calls the IRQ_ENTER RTXC service through the hook
/// table; if that claims the anchor, runs the one-time VIC/table init and
/// the IRQ_REGISTER / IRQ_FINISH services.
unsafe fn rtxc_irq_enter() {
    if bus_read32(ROM_IRQ_FLAG) & 1 != 0 {
        return;
    }
    if veneer_call(hook_table::IRQ_ENTER, ROM_IRQ_FLAG, 0, 0) == 0 {
        return;
    }
    vic_vector_init();
    veneer_call(
        hook_table::IRQ_REGISTER,
        addr_of!(IRQ_TABLE) as u32,
        RTXC_REGISTER_OBJ_A,
        RTXC_REGISTER_OBJ_B,
    );
    veneer_call(hook_table::IRQ_FINISH, ROM_IRQ_FLAG, 0, 0);
}

/// vic_dispatch — original: `FUN_08004dfc` @ 0x08004dfc (0x64 bytes).
///
/// Routes the pending interrupt: reads both VIC status registers (VIC0
/// wins when both are busy), reads the busy block's VICADDRESS to get the
/// global interrupt number, calls the registered handler if any, clears
/// the source in the shared clear block, and acknowledges the VIC by
/// writing 0x01010101 to VICADDRESS.
unsafe fn vic_dispatch() {
    let vic0_pending = bus_read32(VIC0_BASE + VIC_IRQSTATUS);
    let vic1_pending = bus_read32(VIC1_BASE + VIC_IRQSTATUS);
    let (vector_reg, clear_reg) = if vic0_pending != 0 {
        (VIC0_BASE + VIC_ADDRESS, VIC0_CLEAR)
    } else {
        if vic1_pending == 0 {
            return;
        }
        (VIC1_BASE + VIC_ADDRESS, VIC1_CLEAR)
    };
    let vec = bus_read32(vector_reg) as usize;
    if let Some(Some(handler)) = (*addr_of!(IRQ_TABLE)).handlers.get(vec) {
        handler();
    }
    // `1 << vec` with vec in 32..63 is 0 on ARM (register shift); kept
    // verbatim via checked_shl (the original writes 0 for VIC1 sources).
    bus_write32(clear_reg, 1u32.checked_shl(vec as u32).unwrap_or(0));
    bus_write32(vector_reg, VIC_ACK_VALUE);
}

/// irq_exit — original: `FUN_08001d10` @ 0x08001d10 (0x64 bytes).
///
/// Interrupt epilogue. Tracks the nesting high-water mark in the RTXC
/// kernel control block; a nonzero `value` is pushed onto the kernel's
/// interrupt value stack (the dispatcher always passes 0 — that path
/// serves other callers). On the outermost interrupt (nesting count 1) it
/// stores the interrupted frame pointer into the current task's save area,
/// re-enables IRQs and enters the RTXC scheduler.
unsafe fn irq_exit(frame: *mut u32, value: u32) {
    let kcb = bus_read32(KCB_PTR_ADDR);
    let nesting = bus_read8(kcb);
    let high_water = bus_read8(kcb + 1);
    if nesting > high_water {
        bus_write8(kcb + 1, nesting);
    }
    svc_mode_irq_masked();
    if value != 0 {
        let stack_ptr = bus_read32(kcb + 8);
        bus_write32(stack_ptr, value);
        bus_write32(kcb + 8, stack_ptr + 4);
    }
    if nesting != 1 {
        return;
    }
    let stack_ptr = bus_read32(kcb + 8);
    let stack_limit = bus_read32(kcb + 12);
    let task_state = bus_read32(TASK_STATE_PTR_ADDR);
    if stack_ptr == stack_limit && bus_read8(task_state + 1) == 0 {
        return;
    }
    let current_task = bus_read32(task_state + 4);
    bus_write32(current_task + 16, frame as u32);
    svc_mode_irq_open();
    call_scheduler();
}

/// irq_dispatch — original: `FUN_080080ac` @ 0x080080ac (0x20 bytes).
///
/// C entry of the IRQ path, called from the `irq_entry` stub with the
/// saved-context frame pointer. Runs the kernel-entry hook, routes the
/// pending interrupt to its registered handler, and performs the epilogue
/// (the original tail-calls `irq_exit`). Returns `frame` in r0 — the entry
/// stub reloads sp from it.
#[no_mangle]
pub unsafe extern "C" fn irq_dispatch(frame: *mut u32) -> *mut u32 {
    rtxc_irq_enter();
    vic_dispatch();
    irq_exit(frame, 0);
    frame
}

// ---------------------------------------------------------------------------
// irq_entry — the IRQ vector stub (verbatim ARM; see module header).
// ---------------------------------------------------------------------------

// IRQ vector entry. ARM only; the body is the verbatim global_asm below.
#[cfg(target_arch = "arm")]
extern "C" {
    /// Never called from Rust — the CPU vectors here from 0x18.
    pub fn irq_entry() -> !;
}

/// Host-only shim; see the extern block above for the real contract.
#[cfg(not(target_arch = "arm"))]
pub unsafe extern "C" fn irq_entry() -> ! {
    unreachable!("irq_entry is provided by global_asm on ARM targets")
}

// Verbatim ARM body, mirrored instruction-for-instruction from the original
// @ 0x08003080. The literal pool holds the RTXC nesting counter address
// (0x22008a50, ROM SRAM) and the interrupt stack top (0x08b32b58).
// Register aliases are APCS: sl = r10, fp = r11.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl irq_entry
    .type irq_entry, %function
irq_entry:
    sub     lr, lr, #4
    str     lr, [sp, #-12]
    str     r0, [sp, #-4]
    mrs     r0, SPSR
    str     r0, [sp, #-8]
    mov     r0, sp
    msr     CPSR_c, #0x93
    sub     sp, sp, #4
    push    {{r1, r2, r3, r4, r5, r6, r7, r8, r9, sl, fp, ip, lr}}
    ldr     r1, [r0, #-8]
    ldr     r2, [r0, #-4]
    push    {{r1, r2}}
    ldr     lr, [r0, #-12]
    str     lr, [sp, #60]
    ldr     r4, =0x22008a50
    ldrb    r5, [r4]
    add     r5, r5, #1
    strb    r5, [r4]
    mov     r0, sp
    teq     r5, #1
    ldreq   sp, =0x08b32b58
    bl      irq_dispatch
    mov     sp, r0
    sub     r5, r5, #1
    strb    r5, [r4]
    ldmfd   sp!, {{r0}}
    msr     SPSR_fc, r0
    ldm     sp!, {{r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, sl, fp, ip, lr, pc}}^
    .ltorg
    .size irq_entry, . - irq_entry
"#
);

// ---------------------------------------------------------------------------
// Host tests: mock address space + hook capture.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Byte-addressable mock target memory (little-endian word assembly),
    /// plus a log of bus writes in order.
    struct MockBus {
        bytes: BTreeMap<u32, u8>,
        write_log: Vec<(u32, u32)>,
    }

    impl MockBus {
        fn new() -> Self {
            MockBus {
                bytes: BTreeMap::new(),
                write_log: Vec::new(),
            }
        }
        fn read8(&self, addr: u32) -> u8 {
            *self.bytes.get(&addr).unwrap_or(&0)
        }
        fn write8(&mut self, addr: u32, val: u8) {
            self.bytes.insert(addr, val);
        }
        fn read32(&self, addr: u32) -> u32 {
            (0..4).fold(0u32, |w, i| {
                w | (self.read8(addr + i) as u32) << (8 * i)
            })
        }
        fn write32(&mut self, addr: u32, val: u32) {
            for i in 0..4 {
                self.write8(addr + i, (val >> (8 * i)) as u8);
            }
            self.write_log.push((addr, val));
        }
    }

    // Test fixture state (process-global; guarded by TEST_LOCK).
    static mut BUS: Option<MockBus> = None;
    static mut VENEER_LOG: Vec<(u32, u32, u32, u32)> = Vec::new();
    static mut VENEER_RETURN: u32 = 0;
    static mut SCHEDULER_CALLS: usize = 0;
    static mut HANDLER_CALLS: usize = 0;
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    unsafe fn mock_read32(addr: u32) -> u32 {
        (*addr_of!(BUS)).as_ref().unwrap().read32(addr)
    }
    unsafe fn mock_write32(addr: u32, val: u32) {
        (*addr_of_mut!(BUS)).as_mut().unwrap().write32(addr, val);
    }
    unsafe fn mock_read8(addr: u32) -> u8 {
        (*addr_of!(BUS)).as_ref().unwrap().read8(addr)
    }
    unsafe fn mock_write8(addr: u32, val: u8) {
        (*addr_of_mut!(BUS)).as_mut().unwrap().write8(addr, val);
    }

    unsafe fn mock_veneer(slot: u32, a0: u32, a1: u32, a2: u32) -> u32 {
        (*addr_of_mut!(VENEER_LOG)).push((slot, a0, a1, a2));
        *addr_of!(VENEER_RETURN)
    }

    unsafe extern "C" fn mock_scheduler() {
        *addr_of_mut!(SCHEDULER_CALLS) += 1;
    }

    unsafe extern "C" fn mock_handler() {
        *addr_of_mut!(HANDLER_CALLS) += 1;
    }

    /// Serialized fixture: fresh mock bus + hooks for one test.
    struct Fixture {
        _guard: MutexGuard<'static, ()>,
    }

    impl Fixture {
        fn new() -> Self {
            let guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            unsafe {
                *addr_of_mut!(BUS) = Some(MockBus::new());
                (*addr_of_mut!(VENEER_LOG)).clear();
                *addr_of_mut!(VENEER_RETURN) = 0;
                *addr_of_mut!(SCHEDULER_CALLS) = 0;
                *addr_of_mut!(HANDLER_CALLS) = 0;
                *addr_of_mut!(BUS_READ32) = mock_read32;
                *addr_of_mut!(BUS_WRITE32) = mock_write32;
                *addr_of_mut!(BUS_READ8) = mock_read8;
                *addr_of_mut!(BUS_WRITE8) = mock_write8;
                *addr_of_mut!(VENEER_CALL) = mock_veneer;
                *addr_of_mut!(SCHEDULER_HOOK) = Some(mock_scheduler);
                // Point the kernel-state pointers at mock SRAM locations.
                bus_write32(KCB_PTR_ADDR, 0x2200_8a50);
                bus_write32(TASK_STATE_PTR_ADDR, 0x2200_acf0);
                // Lazy init considered done unless a test says otherwise.
                bus_write32(ROM_IRQ_FLAG, 1);
                // Setup writes above must not count as bus activity.
                (*addr_of_mut!(BUS)).as_mut().unwrap().write_log.clear();
            }
            Fixture { _guard: guard }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            unsafe {
                *addr_of_mut!(BUS) = None;
                *addr_of_mut!(SCHEDULER_HOOK) = None;
                // Restore hardware defaults for any non-fixture user.
                *addr_of_mut!(BUS_READ32) = hw_read32;
                *addr_of_mut!(BUS_WRITE32) = hw_write32;
                *addr_of_mut!(BUS_READ8) = hw_read8;
                *addr_of_mut!(BUS_WRITE8) = hw_write8;
                *addr_of_mut!(VENEER_CALL) = default_veneer_call;
                for slot in &mut (*addr_of_mut!(IRQ_TABLE)).handlers {
                    *slot = None;
                }
            }
        }
    }

    // -- helpers reading fixture state -------------------------------------

    fn bus() -> &'static MockBus {
        unsafe { (*addr_of!(BUS)).as_ref().unwrap() }
    }
    /// Test setup pokes: write mock memory without polluting the write log
    /// (which is reserved for writes made by the ported code).
    fn w32(addr: u32, val: u32) {
        let bus = unsafe { (*addr_of_mut!(BUS)).as_mut().unwrap() };
        for i in 0..4 {
            bus.write8(addr + i, (val >> (8 * i)) as u8);
        }
    }
    fn w8(addr: u32, val: u8) {
        unsafe { (*addr_of_mut!(BUS)).as_mut().unwrap().write8(addr, val) };
    }
    fn r32(addr: u32) -> u32 {
        bus().read32(addr)
    }
    fn r8(addr: u32) -> u8 {
        bus().read8(addr)
    }
    fn writes() -> &'static [(u32, u32)] {
        unsafe { &(*addr_of!(BUS)).as_ref().unwrap().write_log }
    }
    fn veneer_log() -> &'static [(u32, u32, u32, u32)] {
        unsafe { &(*addr_of!(VENEER_LOG)) }
    }
    fn scheduler_calls() -> usize {
        unsafe { *addr_of!(SCHEDULER_CALLS) }
    }
    fn handler_calls() -> usize {
        unsafe { *addr_of!(HANDLER_CALLS) }
    }

    const KCB: u32 = 0x2200_8a50;
    const TASK_STATE: u32 = 0x2200_acf0;

    // -- vic_dispatch routing ----------------------------------------------

    #[test]
    fn routes_vic0_irq_to_registered_handler() {
        let _f = Fixture::new();
        w32(VIC0_BASE + VIC_IRQSTATUS, 1 << 5); // something pending
        w32(VIC0_BASE + VIC_ADDRESS, 5); // current vector = irq 5
        unsafe {
            irq_set_handler(5, Some(mock_handler));
            irq_set_handler(6, Some(mock_handler));
            vic_dispatch();
        }
        assert_eq!(handler_calls(), 1, "exactly the irq-5 handler runs");
        assert_eq!(
            writes(),
            &[(VIC0_CLEAR, 1 << 5), (VIC0_BASE + VIC_ADDRESS, VIC_ACK_VALUE)],
            "source cleared, then VIC acknowledged"
        );
        assert_eq!(r32(VIC1_BASE + VIC_IRQSTATUS), 0, "VIC1 untouched");
    }

    #[test]
    fn routes_vic1_irq_when_vic0_idle() {
        let _f = Fixture::new();
        w32(VIC1_BASE + VIC_IRQSTATUS, 1);
        w32(VIC1_BASE + VIC_ADDRESS, 40); // global irq 40 (VIC1 source 8)
        unsafe {
            irq_set_handler(40, Some(mock_handler));
            vic_dispatch();
        }
        assert_eq!(handler_calls(), 1);
        // 1 << 40 wraps to 0 with ARM shift semantics (original quirk).
        assert_eq!(
            writes(),
            &[(VIC1_CLEAR, 0), (VIC1_BASE + VIC_ADDRESS, VIC_ACK_VALUE)]
        );
    }

    #[test]
    fn vic0_wins_when_both_pending() {
        let _f = Fixture::new();
        w32(VIC0_BASE + VIC_IRQSTATUS, 1);
        w32(VIC1_BASE + VIC_IRQSTATUS, 1);
        w32(VIC0_BASE + VIC_ADDRESS, 3);
        w32(VIC1_BASE + VIC_ADDRESS, 40);
        unsafe {
            irq_set_handler(3, Some(mock_handler));
            irq_set_handler(40, Some(mock_handler));
            vic_dispatch();
        }
        assert_eq!(handler_calls(), 1);
        assert!(writes().iter().all(|(addr, _)| *addr != VIC1_CLEAR));
    }

    #[test]
    fn no_pending_irq_is_noop() {
        let _f = Fixture::new();
        unsafe { vic_dispatch() };
        assert_eq!(handler_calls(), 0);
        assert!(writes().is_empty(), "no clear/ack when nothing pending");
    }

    #[test]
    fn null_handler_still_clears_and_acks() {
        let _f = Fixture::new();
        w32(VIC0_BASE + VIC_IRQSTATUS, 1);
        w32(VIC0_BASE + VIC_ADDRESS, 9);
        unsafe { vic_dispatch() };
        assert_eq!(handler_calls(), 0);
        assert_eq!(
            writes(),
            &[(VIC0_CLEAR, 1 << 9), (VIC0_BASE + VIC_ADDRESS, VIC_ACK_VALUE)]
        );
    }

    #[test]
    fn out_of_range_vector_is_tolerated() {
        let _f = Fixture::new();
        w32(VIC0_BASE + VIC_IRQSTATUS, 1);
        w32(VIC0_BASE + VIC_ADDRESS, 200); // hardware says 0..63; stay safe
        unsafe { vic_dispatch() };
        assert_eq!(handler_calls(), 0);
        assert_eq!(writes().len(), 2);
    }

    // -- irq_enable ----------------------------------------------------------

    #[test]
    fn enable_writes_the_matching_vic_register() {
        let _f = Fixture::new();
        unsafe { vic_vector_init() };
        // Skip the init writes so only the enable writes remain observable.
        let base = writes().len();
        unsafe {
            irq_enable(3);
            irq_enable(35);
            irq_enable(64); // out of range: ignored
            irq_enable(0);
        }
        assert_eq!(
            &writes()[base..],
            &[
                (VIC0_BASE + VIC_INTENABLE, 1 << 3),
                (VIC1_BASE + VIC_INTENABLE, 1 << 3),
                (VIC0_BASE + VIC_INTENABLE, 1 << 0),
            ]
        );
    }

    // -- vic_vector_init -----------------------------------------------------

    #[test]
    fn vector_init_programs_identity_vectors() {
        let _f = Fixture::new();
        unsafe { vic_vector_init() };
        assert_eq!(r32(VIC0_BASE + VIC_INTENCLEAR), 0xffff_ffff);
        assert_eq!(r32(VIC1_BASE + VIC_INTENCLEAR), 0xffff_ffff);
        for irq in 0..32u32 {
            assert_eq!(r32(VIC0_BASE + VIC_VECTADDR + irq * 4), irq);
            assert_eq!(r32(VIC1_BASE + VIC_VECTADDR + irq * 4), irq + 32);
        }
        let table = unsafe { &*addr_of!(IRQ_TABLE) };
        assert_eq!(table.vic0_intenable, VIC0_BASE + VIC_INTENABLE);
        assert_eq!(table.vic1_intenable, VIC1_BASE + VIC_INTENABLE);
        assert!(table.handlers.iter().all(|h| h.is_none()));
    }

    // -- rtxc_irq_enter lazy init --------------------------------------------

    #[test]
    fn enter_skips_rom_services_when_flag_set() {
        let _f = Fixture::new(); // fixture leaves flag = 1
        unsafe { rtxc_irq_enter() };
        assert!(veneer_log().is_empty());
    }

    #[test]
    fn enter_runs_lazy_init_and_registration() {
        let _f = Fixture::new();
        w32(ROM_IRQ_FLAG, 0);
        unsafe {
            *addr_of_mut!(VENEER_RETURN) = 1;
            rtxc_irq_enter();
        }
        assert_eq!(
            veneer_log(),
            &[
                (hook_table::IRQ_ENTER, ROM_IRQ_FLAG, 0, 0),
                (
                    hook_table::IRQ_REGISTER,
                    addr_of!(IRQ_TABLE) as u32,
                    RTXC_REGISTER_OBJ_A,
                    RTXC_REGISTER_OBJ_B
                ),
                (hook_table::IRQ_FINISH, ROM_IRQ_FLAG, 0, 0),
            ]
        );
        // Lazy init ran: vectors programmed.
        assert_eq!(r32(VIC0_BASE + VIC_VECTADDR), 0);
        assert_eq!(r32(VIC1_BASE + VIC_VECTADDR + 31 * 4), 63);
    }

    #[test]
    fn enter_aborts_when_rom_service_declines() {
        let _f = Fixture::new();
        w32(ROM_IRQ_FLAG, 0);
        unsafe {
            *addr_of_mut!(VENEER_RETURN) = 0;
            rtxc_irq_enter();
        }
        assert_eq!(
            veneer_log(),
            &[(hook_table::IRQ_ENTER, ROM_IRQ_FLAG, 0, 0)],
            "no init/register when the enter service returns 0"
        );
    }

    // -- irq_exit: nesting counter / high-water / scheduler ------------------

    /// Standard outermost-interrupt KCB state: nesting 1, value stack
    /// holding one word (ptr past limit => non-empty), one current task.
    fn setup_outermost_kcb() {
        w8(KCB, 1); // nesting count (already bumped by the entry stub)
        w8(KCB + 1, 0); // high-water
        w32(KCB + 8, 0x2200_8a84); // value-stack pointer
        w32(KCB + 12, 0x2200_8a80); // value-stack limit (ptr != limit)
        w32(TASK_STATE + 4, 0x2200_9000); // current task
    }

    #[test]
    fn outermost_irq_stores_frame_and_schedules() {
        let _f = Fixture::new();
        setup_outermost_kcb();
        unsafe { irq_exit(0x0800_4000 as *mut u32, 0) };
        assert_eq!(r8(KCB + 1), 1, "high-water raised to 1");
        assert_eq!(
            r32(0x2200_9000 + 16),
            0x0800_4000,
            "frame pointer stored into current task + 16"
        );
        assert_eq!(scheduler_calls(), 1);
    }

    #[test]
    fn nested_irq_only_tracks_high_water() {
        let _f = Fixture::new();
        setup_outermost_kcb();
        w8(KCB, 2); // nested
        unsafe { irq_exit(0x0800_4000 as *mut u32, 0) };
        assert_eq!(r8(KCB + 1), 2, "high-water raised to 2");
        assert_eq!(r32(0x2200_9000 + 16), 0, "no frame store when nested");
        assert_eq!(scheduler_calls(), 0);
    }

    #[test]
    fn high_water_never_lowered() {
        let _f = Fixture::new();
        setup_outermost_kcb();
        w8(KCB + 1, 3); // previous peak above current nesting
        unsafe { irq_exit(0x0800_4000 as *mut u32, 0) };
        assert_eq!(r8(KCB + 1), 3);
    }

    #[test]
    fn nonzero_value_is_pushed_on_value_stack() {
        let _f = Fixture::new();
        setup_outermost_kcb();
        w8(KCB, 2); // nested: push still happens, scheduler doesn't
        unsafe { irq_exit(0x0800_4000 as *mut u32, 0xdead_beef) };
        assert_eq!(r32(0x2200_8a84), 0xdead_beef, "value stored at stack ptr");
        assert_eq!(r32(KCB + 8), 0x2200_8a88, "stack ptr advanced by 4");
        assert_eq!(scheduler_calls(), 0);
    }

    #[test]
    fn outermost_with_empty_stack_and_clear_flag_returns_early() {
        let _f = Fixture::new();
        setup_outermost_kcb();
        w32(KCB + 8, 0x2200_8a80); // stack ptr == limit: empty
        w8(TASK_STATE + 1, 0); // flag byte clear
        unsafe { irq_exit(0x0800_4000 as *mut u32, 0) };
        assert_eq!(r32(0x2200_9000 + 16), 0);
        assert_eq!(scheduler_calls(), 0);
    }

    #[test]
    fn empty_stack_but_flag_set_still_schedules() {
        let _f = Fixture::new();
        setup_outermost_kcb();
        w32(KCB + 8, 0x2200_8a80); // empty stack
        w8(TASK_STATE + 1, 1); // flag set: proceed anyway
        unsafe { irq_exit(0x0800_4000 as *mut u32, 0) };
        assert_eq!(scheduler_calls(), 1);
    }

    // -- irq_dispatch end to end ---------------------------------------------

    #[test]
    fn dispatch_end_to_end() {
        let _f = Fixture::new();
        setup_outermost_kcb();
        w32(VIC0_BASE + VIC_IRQSTATUS, 1);
        w32(VIC0_BASE + VIC_ADDRESS, 7);
        unsafe {
            irq_set_handler(7, Some(mock_handler));
            let frame = 0x08b3_2b00 as *mut u32;
            let ret = irq_dispatch(frame);
            assert_eq!(ret, frame, "frame returned in r0 for the stub");
        }
        assert_eq!(handler_calls(), 1);
        assert_eq!(scheduler_calls(), 1);
        assert_eq!(r32(0x2200_9000 + 16), 0x08b3_2b00);
        assert!(veneer_log().is_empty(), "flag was set: no ROM services");
    }
}
