//! Ports of the raw ROM-thunk wrappers @ 0x08037e00..0x08037f00 in osos —
//! the 32-entry slice of the RTXC mask-ROM thunk table (0x08037db0..0x080382a0,
//! catalogued in kernel/thunks.rs) that contains the task-lock/scheduler-lock
//! pair:
//!
//! - `task_lock` — original: thunk @ 0x08037e48 (8 bytes: `ldr pc, [pc, #-4]`;
//!   .word 0x22003ea0). ROM target via the osos mirror @ 0x08003ea0:
//!   `ldr r1, =0x08a24108; ldr r0, [r1, r0, lsl #2]; bx lr` — a table-indexed
//!   kernel-id -> object-pointer lookup. 3 call sites: the mailbox helpers
//!   @ 0x080564b0 / 0x080564ec (result unused) and the mutex-delete helper
//!   @ 0x0809c79c, which accepts r0 = 0 or -1 (0xFFFFFFFF, the table's empty
//!   slot sentinel) and maps anything else to error 0x14.
//! - `task_unlock` — original: thunk @ 0x08037e50 (8 bytes; .word 0x2200408c).
//!   ROM target via the osos mirror @ 0x0800408c: builds a one-argument
//!   request frame {3, arg} on the stack and calls the kernel gateway
//!   (@ 0x08003660 in the mirror) with service 3; the gateway's result words
//!   land back in r0-r3. 8 call sites, most passing a kernel id (0x27, 0x23,
//!   0x1e, 0x3f or a semaphore/mutex object id).
//!
//! Naming caveat (project convention, see kernel/thunks.rs header): the pair
//! is invoked back-to-back around the semaphore/mutex critical sections at
//! 0x080564c0/c8, 0x080564f4/fc and 0x0809c7b4/c8, which is what the
//! task_lock/task_unlock names record — the ROM code behind them is the
//! id-lookup and gateway-service-3 stubs described above, not literally a
//! scheduler lock.
//!
//! ## Span survey: all 32 thunks in 0x08037e00..0x08037f00
//!
//! Every slot in the span is the same 8-byte ADS literal veneer
//! (`ldr pc, [pc, #-4]` + absolute ROM word; verified word-for-word against
//! osos.dec — see THUNK_CATALOG). ROM semantics below come from the osos
//! link-order mirror (ROM 0x22000XXX == osos 0x08000XXX; see thunks.rs) and
//! call-site evidence in osos.asm (caller counts as of firmware 2.0.4):
//!
//! - 0x08037e00 -> 0x220000d4 `rom_memmove` — the ROM's own copy of the ADS
//!   memmove (mirror = the routine ported in libc/memmove.rs). 24 callers
//!   use the ROM copy instead of the osos one. (dst, src, len) -> dst.
//! - 0x08037e08 -> 0x22003fd0 `rom_sem_wait` — kernel semaphore wait (the
//!   RAM wrapper sem_wait @ 0x08056510 tail-branches here; sync_sem.rs).
//!   24 callers, r0 = kernel semaphore id.
//! - 0x08037e10 -> 0x220042b4 `rom_sem_signal` — kernel semaphore signal
//!   (sem_signal @ 0x08056710 tail-branches here). 24 callers, r0 = id.
//! - 0x08037e18 -> 0x2200418c — gateway stub, service 4 (r0 arg plus r1/r2
//!   at call sites, e.g. (1, ptr, 5) from the alarm/timer create path
//!   @ 0x08047dd0). 11 callers.
//! - 0x08037e20 -> 0x22001edc `kernel_ticks` — returns the kernel tick
//!   counter (`ldr r0, =anchor; ldr r0, [r0, #0xb4]; bx lr`). 47 callers,
//!   several adding the result to a duration (deadline arithmetic).
//! - 0x08037e28 -> 0x22003b6c — gateway stub, service 23, no input args,
//!   returns a result word; called at the head of the kernel-object create
//!   helpers (sem create path @ 0x080563b8). 3 callers.
//! - 0x08037e30 -> 0x22003c98 — gateway stub; aligns its r2 size argument
//!   up to 8 and reads a FIFTH argument from the caller's stack
//!   (`ldr ip, [sp, #40]`). 3 callers (object init on the create path).
//! - 0x08037e38 -> 0x22003d00 — gateway stub, service 41, (r0, r1).
//!   2 callers (object registration on the create path).
//! - 0x08037e40 -> 0x22003dc8 `kernel_op_dispatch` — the object-op
//!   dispatcher (mirror frame {12, 6, op, arg, 0}); sync_sem's op_delete.
//!   9 callers, r0 = object-class opcode (1 = semaphore, 2, 4), r1 = slot.
//! - 0x08037e48 -> 0x22003ea0 `task_lock` — see above.
//! - 0x08037e50 -> 0x2200408c `task_unlock` — see above.
//! - 0x08037e58 -> 0x22003ec4 — gateway stub, service 40, r0 arg, returns a
//!   result word. 1 caller (@ 0x080565f8, r0 = 0).
//! - 0x08037e60 -> 0x22003eb0 `size_to_class` — UNVERIFIED (thunks.rs /
//!   heap/stats.rs): mirror is a 3-instruction pointer chase
//!   (`*(**0x2200acf4) + 0x20`), not an arithmetic mapping. 5 callers.
//! - 0x08037e68 -> 0x22003be8 — gateway stub, service 46, r0 arg plus a
//!   stack argument; call sites pass (id, 4, size) e.g. (1, 4, 0x200) from
//!   @ 0x08056680. 4 callers.
//! - 0x08037e70 -> 0x22003d70 `kernel_create_dispatch` — the object-create
//!   dispatcher (mirror frame {13, 7, op, slot, 0}); sync_sem's op_create.
//!   5 callers, r0 = object-class opcode, r1 = slot.
//! - 0x08037e78 -> 0x220041cc — gateway stub, service 2, r0 arg. 16 callers
//!   (r0 = small ids like 0x2e, or pointers).
//! - 0x08037e80 -> 0x22001cbc — a full ROM function (kernel lock, then a
//!   table walk), NOT a gateway stub. 0 callers in osos 2.0.4.
//! - 0x08037e88 -> 0x22003d44 — gateway stub, service 20, (r0, r1).
//!   15 callers, always r0 = 0, r1 = small count (1, 0x64) — delay-flavoured.
//! - 0x08037e90 -> 0x220043f4 — gateway stub, service 28 sub 13, returns a
//!   result word. 0 callers.
//! - 0x08037e98 -> 0x22004260 — gateway stub, service 25, r0 arg (0 at the
//!   single call site @ 0x08393acc, after stashing SP for the ROM).
//!   1 caller.
//! - 0x08037ea0 -> 0x220043c0 — gateway stub, service 1 sub 0, (r0, r1).
//!   5 callers, r0 = pointer, r1 = flag (0/1).
//! - 0x08037ea8 -> 0x22004368 — gateway stub, service 1 frame {1, 0, r0, 0}.
//!   8 callers, r0 = small id (0x3c, 0x24) or pointer.
//! - 0x08037eb0 -> 0x22003c28 — gateway stub, service 39, (r0, r1).
//!   3 callers, e.g. (3, 1) / (4, 1) from @ 0x08058508.
//! - 0x08037eb8 -> 0x22001ee8 `tick_elapsed` — tick deadline check:
//!   `(kernel_ticks() - start) >= span` -> 0/1 (mirror @ 0x08001ee8, right
//!   after kernel_ticks). 40 callers.
//! - 0x08037ec0 -> 0x22000364 — ADS-style error/status mapping function
//!   (cmp chain on r0), not a gateway stub. 1 caller (r0 = 0).
//! - 0x22003e44 via 0x08037ec8 — object/anchor field lookup:
//!   r0 = 0 -> `anchor->field_0x24`, else `table[id * 13]->field_0x24`.
//!   4 callers (r0 = 0 at all sampled sites).
//! - 0x08037ed0 -> 0x22003bcc — gateway stub, service 27, (r0, r1).
//!   5 callers, r0 = 0, r1 = 2/3 or a pointer.
//! - 0x08037ed8 -> 0x22001e70 `irq_fiq_disable` — interrupt lockout:
//!   `mrs r1, cpsr; and r0, r1, #0xc0; orr r1, r1, #0xc0; msr cpsr_c, r1;
//!   bx lr` — masks IRQ+FIQ, returns the previous I/F bits. (The paired
//!   restore @ 0x22001e84 is thunk 0x08037f00, outside this span.)
//!   2 callers.
//! - 0x08037ee0 -> 0x22003b00 — tail stub: `mov r0, #1; b gateway'` (the
//!   alternate gateway entry @ 0x08003640 in the mirror). 1 caller.
//! - 0x08037ee8 -> 0x220044c8 — compound ROM function: sem-waits on kernel
//!   semaphore 22, then irq_fiq_disable. 1 caller (init path @ 0x08067fb8).
//! - 0x08037ef0 -> 0x22001f78 `tick_delay` — busy-wait delay: spins calling
//!   tick_elapsed until `r0` ticks pass (mirror @ 0x08001f78). 23 callers,
//!   r0 = tick count (1, 10, 60, 100, 1000), typically after hardware
//!   register pokes (USB init @ 0x080923d8, etc.).
//! - 0x08037ef8 -> 0x22003b08 — gateway config call with fixed arguments
//!   (1, 500) then (1, 1) via the alternate gateway entries. 1 caller
//!   (init path @ 0x08068018).
//!
//! ## ROM-dispatch design (deviation, by necessity — same as sync_sem.rs)
//!
//! The original thunks tail-jump straight into the mask ROM. The port
//! cannot do that and stay testable/linkable, so every wrapper dispatches
//! indirectly through the `ROM_KERNEL` fn-pointer table (the ROM_KERNEL
//! hook pattern of sync_sem.rs / malloc_rt.rs). The table defaults to
//! documented stubs that spin: a ROM call made before the table is
//! installed can produce neither a value nor a side effect, and hanging
//! surfaces the misconfiguration (same philosophy as `missing_wait` in
//! sync_sem.rs). Host tests swap in a mock kernel. Consequences:
//!
//! - Codegen deviates from the original on purpose: an indirect call
//!   through the table instead of the 8-byte `ldr pc` veneer. match.py
//!   diffs are expected and structural, as with the heap veneers.
//! - The original veneer forwards ALL of r0-r3 to the ROM untouched; the
//!   port forwards only the documented arguments of each service. Where a
//!   ROM stub reads a stacked fifth argument (0x22003c98, 0x22003be8) the
//!   port models it as a fifth Rust argument, which the ARM ABI also
//!   passes on the stack.
//! - Every wrapper returns the r0 result word (`usize`) even where no
//!   caller consumes it — the veneer physically passes r0 back.
//! - Symbol exports (`#[no_mangle]`) are disabled in cfg(test) builds
//!   (sync_sem.rs precedent: avoids dyld interposition surprises when the
//!   host test binary exports kernel-flavoured names); ARM/release builds
//!   export normally for match.py and the firmware link.

/// Load address of the first thunk in this span (inclusive).
pub const SPAN_BASE: u32 = 0x08037e00;

/// First address past this span's last thunk target word (exclusive).
pub const SPAN_END: u32 = 0x08037f00;

/// Byte size of one thunk: 4-byte `ldr pc, [pc, #-4]` + 4-byte ROM word.
pub const THUNK_STRIDE: u32 = 8;

/// Number of thunk wrappers in the span (and in ROM_KERNEL / THUNK_CATALOG).
pub const WRAPPER_COUNT: usize = 32;

/// The full span catalog: (thunk address, ROM target, exported symbol),
/// in address order. Verified word-for-word against osos.dec.
pub static THUNK_CATALOG: [(u32, u32, &str); WRAPPER_COUNT] = [
    (0x08037e00, 0x220000d4, "rom_memmove"),
    (0x08037e08, 0x22003fd0, "rom_sem_wait"),
    (0x08037e10, 0x220042b4, "rom_sem_signal"),
    (0x08037e18, 0x2200418c, "rom_svc_2200418c"),
    (0x08037e20, 0x22001edc, "kernel_ticks"),
    (0x08037e28, 0x22003b6c, "rom_svc_22003b6c"),
    (0x08037e30, 0x22003c98, "rom_svc_22003c98"),
    (0x08037e38, 0x22003d00, "rom_svc_22003d00"),
    (0x08037e40, 0x22003dc8, "kernel_op_dispatch"),
    (0x08037e48, 0x22003ea0, "task_lock"),
    (0x08037e50, 0x2200408c, "task_unlock"),
    (0x08037e58, 0x22003ec4, "rom_svc_22003ec4"),
    (0x08037e60, 0x22003eb0, "size_to_class"),
    (0x08037e68, 0x22003be8, "rom_svc_22003be8"),
    (0x08037e70, 0x22003d70, "kernel_create_dispatch"),
    (0x08037e78, 0x220041cc, "rom_svc_220041cc"),
    (0x08037e80, 0x22001cbc, "rom_svc_22001cbc"),
    (0x08037e88, 0x22003d44, "rom_svc_22003d44"),
    (0x08037e90, 0x220043f4, "rom_svc_220043f4"),
    (0x08037e98, 0x22004260, "rom_svc_22004260"),
    (0x08037ea0, 0x220043c0, "rom_svc_220043c0"),
    (0x08037ea8, 0x22004368, "rom_svc_22004368"),
    (0x08037eb0, 0x22003c28, "rom_svc_22003c28"),
    (0x08037eb8, 0x22001ee8, "tick_elapsed"),
    (0x08037ec0, 0x22000364, "rom_svc_22000364"),
    (0x08037ec8, 0x22003e44, "rom_svc_22003e44"),
    (0x08037ed0, 0x22003bcc, "rom_svc_22003bcc"),
    (0x08037ed8, 0x22001e70, "irq_fiq_disable"),
    (0x08037ee0, 0x22003b00, "rom_svc_22003b00"),
    (0x08037ee8, 0x220044c8, "rom_svc_220044c8"),
    (0x08037ef0, 0x22001f78, "tick_delay"),
    (0x08037ef8, 0x22003b08, "rom_svc_22003b08"),
];

/// Indirect dispatch table for the 32 ROM services of this span (see the
/// module header for the design and the default-stub behavior). Field order
/// matches THUNK_CATALOG.
#[derive(Clone, Copy)]
pub struct RomThunkOps {
    /// ROM memmove @ 0x220000d4: (dst, src, len) -> dst.
    pub rom_memmove: unsafe extern "C" fn(dst: usize, src: usize, len: usize) -> usize,
    /// ROM semaphore wait @ 0x22003fd0: kernel semaphore id in r0.
    pub rom_sem_wait: unsafe extern "C" fn(sem: usize) -> usize,
    /// ROM semaphore signal @ 0x220042b4: kernel semaphore id in r0.
    pub rom_sem_signal: unsafe extern "C" fn(sem: usize) -> usize,
    /// ROM gateway service 4 @ 0x2200418c.
    pub rom_svc_2200418c: unsafe extern "C" fn(a0: usize, a1: usize, a2: usize) -> usize,
    /// Kernel tick counter @ 0x22001edc (anchor + 0xb4).
    pub kernel_ticks: unsafe extern "C" fn() -> usize,
    /// ROM gateway service 23 @ 0x22003b6c.
    pub rom_svc_22003b6c: unsafe extern "C" fn() -> usize,
    /// ROM gateway stub @ 0x22003c98; a4 rides the stack in the original.
    pub rom_svc_22003c98: unsafe extern "C" fn(
        a0: usize,
        a1: usize,
        a2: usize,
        a3: usize,
        a4: usize,
    ) -> usize,
    /// ROM gateway service 41 @ 0x22003d00.
    pub rom_svc_22003d00: unsafe extern "C" fn(a0: usize, a1: usize) -> usize,
    /// Object-op dispatcher @ 0x22003dc8: (class opcode, slot).
    pub kernel_op_dispatch: unsafe extern "C" fn(op: usize, arg: usize) -> usize,
    /// Kernel-id -> object lookup @ 0x22003ea0 (see module header).
    pub task_lock: unsafe extern "C" fn(id: usize) -> usize,
    /// Kernel gateway service 3 @ 0x2200408c (see module header).
    pub task_unlock: unsafe extern "C" fn(id: usize) -> usize,
    /// ROM gateway service 40 @ 0x22003ec4.
    pub rom_svc_22003ec4: unsafe extern "C" fn(a0: usize) -> usize,
    /// UNVERIFIED (thunks.rs): pointer chase @ 0x22003eb0.
    pub size_to_class: unsafe extern "C" fn() -> usize,
    /// ROM gateway service 46 @ 0x22003be8.
    pub rom_svc_22003be8: unsafe extern "C" fn(
        a0: usize,
        a1: usize,
        a2: usize,
        a3: usize,
    ) -> usize,
    /// Object-create dispatcher @ 0x22003d70: (class opcode, slot).
    pub kernel_create_dispatch: unsafe extern "C" fn(op: usize, slot: usize) -> usize,
    /// ROM gateway service 2 @ 0x220041cc.
    pub rom_svc_220041cc: unsafe extern "C" fn(a0: usize) -> usize,
    /// Full ROM function @ 0x22001cbc (lock + table walk; no osos callers).
    pub rom_svc_22001cbc: unsafe extern "C" fn(a0: usize) -> usize,
    /// ROM gateway service 20 @ 0x22003d44.
    pub rom_svc_22003d44: unsafe extern "C" fn(a0: usize, a1: usize) -> usize,
    /// ROM gateway service 28 sub 13 @ 0x220043f4.
    pub rom_svc_220043f4: unsafe extern "C" fn() -> usize,
    /// ROM gateway service 25 @ 0x22004260.
    pub rom_svc_22004260: unsafe extern "C" fn(a0: usize) -> usize,
    /// ROM gateway service 1 sub 0 @ 0x220043c0.
    pub rom_svc_220043c0: unsafe extern "C" fn(a0: usize, a1: usize) -> usize,
    /// ROM gateway service 1 @ 0x22004368.
    pub rom_svc_22004368: unsafe extern "C" fn(a0: usize) -> usize,
    /// ROM gateway service 39 @ 0x22003c28.
    pub rom_svc_22003c28: unsafe extern "C" fn(a0: usize, a1: usize) -> usize,
    /// Tick deadline check @ 0x22001ee8: (kernel_ticks() - start) >= span.
    pub tick_elapsed: unsafe extern "C" fn(start: usize, span: usize) -> usize,
    /// ADS-style error/status mapping @ 0x22000364.
    pub rom_svc_22000364: unsafe extern "C" fn(a0: usize) -> usize,
    /// Object/anchor field lookup @ 0x22003e44.
    pub rom_svc_22003e44: unsafe extern "C" fn(a0: usize) -> usize,
    /// ROM gateway service 27 @ 0x22003bcc.
    pub rom_svc_22003bcc: unsafe extern "C" fn(a0: usize, a1: usize) -> usize,
    /// IRQ+FIQ lockout @ 0x22001e70: masks both, returns previous I/F bits.
    pub irq_fiq_disable: unsafe extern "C" fn() -> usize,
    /// Alternate-gateway tail stub @ 0x22003b00.
    pub rom_svc_22003b00: unsafe extern "C" fn() -> usize,
    /// Compound ROM function @ 0x220044c8 (sem 22 wait + irq lockout).
    pub rom_svc_220044c8: unsafe extern "C" fn() -> usize,
    /// Busy-wait delay @ 0x22001f78, in kernel ticks.
    pub tick_delay: unsafe extern "C" fn(ticks: usize) -> usize,
    /// Gateway config call with fixed args @ 0x22003b08.
    pub rom_svc_22003b08: unsafe extern "C" fn() -> usize,
}

// Default stubs: without an installed ROM_KERNEL no wrapper can produce a
// value or a side effect — spin, so a missing install hangs loudly instead
// of silently corrupting state (sync_sem.rs `missing_wait` philosophy).
unsafe extern "C" fn missing0() -> usize {
    loop {}
}
unsafe extern "C" fn missing1(_a0: usize) -> usize {
    loop {}
}
unsafe extern "C" fn missing2(_a0: usize, _a1: usize) -> usize {
    loop {}
}
unsafe extern "C" fn missing3(_a0: usize, _a1: usize, _a2: usize) -> usize {
    loop {}
}
unsafe extern "C" fn missing4(_a0: usize, _a1: usize, _a2: usize, _a3: usize) -> usize {
    loop {}
}
unsafe extern "C" fn missing5(
    _a0: usize,
    _a1: usize,
    _a2: usize,
    _a3: usize,
    _a4: usize,
) -> usize {
    loop {}
}

/// The active ROM-kernel implementation for this span. Defaults to the
/// documented spin stubs above; replaced by host tests (mock kernel) and on
/// target by the real ROM veneers at install time. Written once at init on
/// target; tests serialize access.
pub static mut ROM_KERNEL: RomThunkOps = RomThunkOps {
    rom_memmove: missing3,
    rom_sem_wait: missing1,
    rom_sem_signal: missing1,
    rom_svc_2200418c: missing3,
    kernel_ticks: missing0,
    rom_svc_22003b6c: missing0,
    rom_svc_22003c98: missing5,
    rom_svc_22003d00: missing2,
    kernel_op_dispatch: missing2,
    task_lock: missing1,
    task_unlock: missing1,
    rom_svc_22003ec4: missing1,
    size_to_class: missing0,
    rom_svc_22003be8: missing4,
    kernel_create_dispatch: missing2,
    rom_svc_220041cc: missing1,
    rom_svc_22001cbc: missing1,
    rom_svc_22003d44: missing2,
    rom_svc_220043f4: missing0,
    rom_svc_22004260: missing1,
    rom_svc_220043c0: missing2,
    rom_svc_22004368: missing1,
    rom_svc_22003c28: missing2,
    tick_elapsed: missing2,
    rom_svc_22000364: missing1,
    rom_svc_22003e44: missing1,
    rom_svc_22003bcc: missing2,
    irq_fiq_disable: missing0,
    rom_svc_22003b00: missing0,
    rom_svc_220044c8: missing0,
    tick_delay: missing1,
    rom_svc_22003b08: missing0,
};

/// Reads one hook slot. The read is volatile: the table is meant to be
/// swapped at runtime, and otherwise LLVM would constant-fold the loads to
/// the default stubs and inline their `loop {}` bodies (observed in
/// malloc_rt.rs: `malloc` collapsed to a branch-to-self in ARM release).
/// Only the needed field is read — reading the whole 32-slot struct per
/// call compiled to 16 `ldrd`s of dead table data.
macro_rules! hook {
    ($field:ident) => {
        core::ptr::addr_of!(ROM_KERNEL.$field).read_volatile()
    };
}

/// rom_memmove — original: thunk @ 0x08037e00 -> ROM 0x220000d4, the mask
/// ROM's own copy of the ADS memmove (24 osos callers use it instead of the
/// osos copy). (dst, src, len) -> dst.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn rom_memmove(dst: usize, src: usize, len: usize) -> usize {
    (hook!(rom_memmove))(dst, src, len)
}

/// rom_sem_wait — original: thunk @ 0x08037e08 -> ROM 0x22003fd0, kernel
/// semaphore wait. `sem` is the kernel semaphore id (`*slot` in RAM terms;
/// see sync_sem.rs).
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn rom_sem_wait(sem: usize) -> usize {
    (hook!(rom_sem_wait))(sem)
}

/// rom_sem_signal — original: thunk @ 0x08037e10 -> ROM 0x220042b4, kernel
/// semaphore signal.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn rom_sem_signal(sem: usize) -> usize {
    (hook!(rom_sem_signal))(sem)
}

/// rom_svc_2200418c — original: thunk @ 0x08037e18 -> ROM gateway stub,
/// service 4. Args per call sites, e.g. (1, ptr, 5) from the create path
/// @ 0x08047dd0.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn rom_svc_2200418c(a0: usize, a1: usize, a2: usize) -> usize {
    (hook!(rom_svc_2200418c))(a0, a1, a2)
}

/// kernel_ticks — original: thunk @ 0x08037e20 -> ROM 0x22001edc. Returns
/// the kernel tick counter (kernel anchor + 0xb4). No input args: the ROM
/// stub overwrites r0 immediately.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn kernel_ticks() -> usize {
    (hook!(kernel_ticks))()
}

/// rom_svc_22003b6c — original: thunk @ 0x08037e28 -> ROM gateway stub,
/// service 23. No input args; returns a result word. Called at the head of
/// the kernel-object create helpers.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn rom_svc_22003b6c() -> usize {
    (hook!(rom_svc_22003b6c))()
}

/// rom_svc_22003c98 — original: thunk @ 0x08037e30 -> ROM gateway stub.
/// Aligns a2 up to 8 in the original; the ROM stub reads a fifth argument
/// from the caller's stack, modeled here as `a4` (the ARM ABI also passes
/// it on the stack).
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn rom_svc_22003c98(
    a0: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
) -> usize {
    (hook!(rom_svc_22003c98))(a0, a1, a2, a3, a4)
}

/// rom_svc_22003d00 — original: thunk @ 0x08037e38 -> ROM gateway stub,
/// service 41, (a0, a1). Object registration on the create path.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn rom_svc_22003d00(a0: usize, a1: usize) -> usize {
    (hook!(rom_svc_22003d00))(a0, a1)
}

/// kernel_op_dispatch — original: thunk @ 0x08037e40 -> ROM 0x22003dc8,
/// the object-op dispatcher (mirror frame {12, 6, op, arg, 0}): r0 =
/// object-class opcode (1 = semaphore, 2, 4 observed), r1 = handle slot.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn kernel_op_dispatch(op: usize, arg: usize) -> usize {
    (hook!(kernel_op_dispatch))(op, arg)
}

/// task_lock — original: thunk @ 0x08037e48 -> ROM 0x22003ea0, the
/// kernel-id -> object-pointer table lookup (table @ 0x08a24108; empty
/// slots read back as 0/-1 — see the module header for the naming caveat).
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn task_lock(id: usize) -> usize {
    (hook!(task_lock))(id)
}

/// task_unlock — original: thunk @ 0x08037e50 -> ROM 0x2200408c, the
/// kernel gateway's service-3 stub with `id` as its argument (see the
/// module header for the naming caveat).
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn task_unlock(id: usize) -> usize {
    (hook!(task_unlock))(id)
}

/// rom_svc_22003ec4 — original: thunk @ 0x08037e58 -> ROM gateway stub,
/// service 40. Single call site passes r0 = 0; returns a result word.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn rom_svc_22003ec4(a0: usize) -> usize {
    (hook!(rom_svc_22003ec4))(a0)
}

/// size_to_class — original: thunk @ 0x08037e60 -> ROM 0x22003eb0.
/// UNVERIFIED (kernel/thunks.rs): the mirror is a pointer chase
/// (`*(**0x2200acf4) + 0x20`), not an arithmetic size->class mapping.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn size_to_class() -> usize {
    (hook!(size_to_class))()
}

/// rom_svc_22003be8 — original: thunk @ 0x08037e68 -> ROM gateway stub,
/// service 46. Call sites pass (id, 4, size), e.g. (1, 4, 0x200); the ROM
/// stub also reads a stack argument.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn rom_svc_22003be8(
    a0: usize,
    a1: usize,
    a2: usize,
    a3: usize,
) -> usize {
    (hook!(rom_svc_22003be8))(a0, a1, a2, a3)
}

/// kernel_create_dispatch — original: thunk @ 0x08037e70 -> ROM 0x22003d70,
/// the object-create dispatcher (mirror frame {13, 7, op, slot, 0}): r0 =
/// object-class opcode, r1 = handle slot (sync_sem's op_create).
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn kernel_create_dispatch(op: usize, slot: usize) -> usize {
    (hook!(kernel_create_dispatch))(op, slot)
}

/// rom_svc_220041cc — original: thunk @ 0x08037e78 -> ROM gateway stub,
/// service 2. Callers pass small ids (0x2e) or pointers.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn rom_svc_220041cc(a0: usize) -> usize {
    (hook!(rom_svc_220041cc))(a0)
}

/// rom_svc_22001cbc — original: thunk @ 0x08037e80 -> ROM 0x22001cbc, a
/// full ROM function (kernel lock, then a table walk). No callers in osos
/// 2.0.4; signature from the mirror's prologue.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn rom_svc_22001cbc(a0: usize) -> usize {
    (hook!(rom_svc_22001cbc))(a0)
}

/// rom_svc_22003d44 — original: thunk @ 0x08037e88 -> ROM gateway stub,
/// service 20. All sampled call sites pass r0 = 0, r1 = a small count
/// (1, 0x64) — delay-flavoured.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn rom_svc_22003d44(a0: usize, a1: usize) -> usize {
    (hook!(rom_svc_22003d44))(a0, a1)
}

/// rom_svc_220043f4 — original: thunk @ 0x08037e90 -> ROM gateway stub,
/// service 28 sub 13. No input args; returns a result word. No callers in
/// osos 2.0.4.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn rom_svc_220043f4() -> usize {
    (hook!(rom_svc_220043f4))()
}

/// rom_svc_22004260 — original: thunk @ 0x08037e98 -> ROM gateway stub,
/// service 25. Single call site (r0 = 0) stashes SP for the ROM first.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn rom_svc_22004260(a0: usize) -> usize {
    (hook!(rom_svc_22004260))(a0)
}

/// rom_svc_220043c0 — original: thunk @ 0x08037ea0 -> ROM gateway stub,
/// service 1 sub 0, (a0, a1): pointer + flag at call sites.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn rom_svc_220043c0(a0: usize, a1: usize) -> usize {
    (hook!(rom_svc_220043c0))(a0, a1)
}

/// rom_svc_22004368 — original: thunk @ 0x08037ea8 -> ROM gateway stub,
/// service 1 (frame {1, 0, arg, 0}). Callers pass small ids or pointers.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn rom_svc_22004368(a0: usize) -> usize {
    (hook!(rom_svc_22004368))(a0)
}

/// rom_svc_22003c28 — original: thunk @ 0x08037eb0 -> ROM gateway stub,
/// service 39. Call sites pass e.g. (3, 1) / (4, 1).
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn rom_svc_22003c28(a0: usize, a1: usize) -> usize {
    (hook!(rom_svc_22003c28))(a0, a1)
}

/// tick_elapsed — original: thunk @ 0x08037eb8 -> ROM 0x22001ee8. Returns
/// 1 when `(kernel_ticks() - start) >= span`, else 0 (mirror @ 0x08001ee8).
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn tick_elapsed(start: usize, span: usize) -> usize {
    (hook!(tick_elapsed))(start, span)
}

/// rom_svc_22000364 — original: thunk @ 0x08037ec0 -> ROM 0x22000364, an
/// ADS-style error/status mapping function (cmp chain on r0). Single call
/// site passes r0 = 0.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn rom_svc_22000364(a0: usize) -> usize {
    (hook!(rom_svc_22000364))(a0)
}

/// rom_svc_22003e44 — original: thunk @ 0x08037ec8 -> ROM 0x22003e44, an
/// object/anchor field lookup: r0 = 0 returns `anchor->field_0x24`, else
/// `table[id * 13]->field_0x24`.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn rom_svc_22003e44(a0: usize) -> usize {
    (hook!(rom_svc_22003e44))(a0)
}

/// rom_svc_22003bcc — original: thunk @ 0x08037ed0 -> ROM gateway stub,
/// service 27, (a0, a1). Call sites pass r0 = 0, r1 = 2/3 or a pointer.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn rom_svc_22003bcc(a0: usize, a1: usize) -> usize {
    (hook!(rom_svc_22003bcc))(a0, a1)
}

/// irq_fiq_disable — original: thunk @ 0x08037ed8 -> ROM 0x22001e70. Masks
/// IRQ+FIQ in CPSR and returns the previous I/F bits (restore lives at ROM
/// 0x22001e84, thunk 0x08037f00 — outside this span).
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn irq_fiq_disable() -> usize {
    (hook!(irq_fiq_disable))()
}

/// rom_svc_22003b00 — original: thunk @ 0x08037ee0 -> ROM 0x22003b00, a
/// tail stub: `mov r0, #1; b` alternate gateway entry.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn rom_svc_22003b00() -> usize {
    (hook!(rom_svc_22003b00))()
}

/// rom_svc_220044c8 — original: thunk @ 0x08037ee8 -> ROM 0x220044c8, a
/// compound ROM function (waits on kernel semaphore 22, then IRQ lockout).
/// Single caller on an init path.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn rom_svc_220044c8() -> usize {
    (hook!(rom_svc_220044c8))()
}

/// tick_delay — original: thunk @ 0x08037ef0 -> ROM 0x22001f78. Busy-waits
/// until `ticks` kernel ticks have elapsed (spins on tick_elapsed; mirror
/// @ 0x08001f78). 23 callers, typically right after hardware register
/// pokes.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn tick_delay(ticks: usize) -> usize {
    (hook!(tick_delay))(ticks)
}

/// rom_svc_22003b08 — original: thunk @ 0x08037ef8 -> ROM 0x22003b08, a
/// gateway config call with fixed arguments ((1, 500) then (1, 1)). Single
/// caller on an init path.
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn rom_svc_22003b08() -> usize {
    (hook!(rom_svc_22003b08))()
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::Mutex;
    use std::vec::Vec;

    /// Serializes tests that swap the global ROM_KERNEL table.
    static OPS_LOCK: Mutex<()> = Mutex::new(());

    /// Per-slot call log: how often each hook fired and with what args.
    static mut CALLS: [usize; WRAPPER_COUNT] = [0; WRAPPER_COUNT];
    static mut LAST_ARGS: [[usize; 5]; WRAPPER_COUNT] = [[0; 5]; WRAPPER_COUNT];

    /// Each mock returns MAGIC | slot, so a wrapper wired to the wrong slot
    /// fails the return-value assertion.
    const MAGIC: usize = 0x5A5A_0000;

    fn record(slot: usize, args: &[usize]) -> usize {
        unsafe {
            CALLS[slot] += 1;
            LAST_ARGS[slot] = [0; 5];
            LAST_ARGS[slot][..args.len()].copy_from_slice(args);
        }
        MAGIC | slot
    }

    macro_rules! mock0 {
        ($name:ident, $slot:expr) => {
            unsafe extern "C" fn $name() -> usize {
                record($slot, &[])
            }
        };
    }
    macro_rules! mock1 {
        ($name:ident, $slot:expr) => {
            unsafe extern "C" fn $name(a0: usize) -> usize {
                record($slot, &[a0])
            }
        };
    }
    macro_rules! mock2 {
        ($name:ident, $slot:expr) => {
            unsafe extern "C" fn $name(a0: usize, a1: usize) -> usize {
                record($slot, &[a0, a1])
            }
        };
    }
    macro_rules! mock3 {
        ($name:ident, $slot:expr) => {
            unsafe extern "C" fn $name(a0: usize, a1: usize, a2: usize) -> usize {
                record($slot, &[a0, a1, a2])
            }
        };
    }
    macro_rules! mock4 {
        ($name:ident, $slot:expr) => {
            unsafe extern "C" fn $name(
                a0: usize,
                a1: usize,
                a2: usize,
                a3: usize,
            ) -> usize {
                record($slot, &[a0, a1, a2, a3])
            }
        };
    }
    macro_rules! mock5 {
        ($name:ident, $slot:expr) => {
            unsafe extern "C" fn $name(
                a0: usize,
                a1: usize,
                a2: usize,
                a3: usize,
                a4: usize,
            ) -> usize {
                record($slot, &[a0, a1, a2, a3, a4])
            }
        };
    }

    mock3!(m00, 0); // rom_memmove
    mock1!(m01, 1); // rom_sem_wait
    mock1!(m02, 2); // rom_sem_signal
    mock3!(m03, 3); // rom_svc_2200418c
    mock0!(m04, 4); // kernel_ticks
    mock0!(m05, 5); // rom_svc_22003b6c
    mock5!(m06, 6); // rom_svc_22003c98
    mock2!(m07, 7); // rom_svc_22003d00
    mock2!(m08, 8); // kernel_op_dispatch
    mock1!(m09, 9); // task_lock
    mock1!(m10, 10); // task_unlock
    mock1!(m11, 11); // rom_svc_22003ec4
    mock0!(m12, 12); // size_to_class
    mock4!(m13, 13); // rom_svc_22003be8
    mock2!(m14, 14); // kernel_create_dispatch
    mock1!(m15, 15); // rom_svc_220041cc
    mock1!(m16, 16); // rom_svc_22001cbc
    mock2!(m17, 17); // rom_svc_22003d44
    mock0!(m18, 18); // rom_svc_220043f4
    mock1!(m19, 19); // rom_svc_22004260
    mock2!(m20, 20); // rom_svc_220043c0
    mock1!(m21, 21); // rom_svc_22004368
    mock2!(m22, 22); // rom_svc_22003c28
    mock2!(m23, 23); // tick_elapsed
    mock1!(m24, 24); // rom_svc_22000364
    mock1!(m25, 25); // rom_svc_22003e44
    mock2!(m26, 26); // rom_svc_22003bcc
    mock0!(m27, 27); // irq_fiq_disable
    mock0!(m28, 28); // rom_svc_22003b00
    mock0!(m29, 29); // rom_svc_220044c8
    mock1!(m30, 30); // tick_delay
    mock0!(m31, 31); // rom_svc_22003b08

    const MOCK_OPS: RomThunkOps = RomThunkOps {
        rom_memmove: m00,
        rom_sem_wait: m01,
        rom_sem_signal: m02,
        rom_svc_2200418c: m03,
        kernel_ticks: m04,
        rom_svc_22003b6c: m05,
        rom_svc_22003c98: m06,
        rom_svc_22003d00: m07,
        kernel_op_dispatch: m08,
        task_lock: m09,
        task_unlock: m10,
        rom_svc_22003ec4: m11,
        size_to_class: m12,
        rom_svc_22003be8: m13,
        kernel_create_dispatch: m14,
        rom_svc_220041cc: m15,
        rom_svc_22001cbc: m16,
        rom_svc_22003d44: m17,
        rom_svc_220043f4: m18,
        rom_svc_22004260: m19,
        rom_svc_220043c0: m20,
        rom_svc_22004368: m21,
        rom_svc_22003c28: m22,
        tick_elapsed: m23,
        rom_svc_22000364: m24,
        rom_svc_22003e44: m25,
        rom_svc_22003bcc: m26,
        irq_fiq_disable: m27,
        rom_svc_22003b00: m28,
        rom_svc_220044c8: m29,
        tick_delay: m30,
        rom_svc_22003b08: m31,
    };

    /// Resets the call log, installs the mock table, returns the lock guard.
    fn mock_kernel() -> std::sync::MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap();
        unsafe {
            CALLS = [0; WRAPPER_COUNT];
            LAST_ARGS = [[0; 5]; WRAPPER_COUNT];
            *core::ptr::addr_of_mut!(ROM_KERNEL) = MOCK_OPS;
        }
        guard
    }

    /// Checks one wrapper call: exactly its own slot fired, once, with the
    /// expected args, and the slot's magic came back.
    fn check(slot: usize, ret: usize, args: &[usize]) {
        unsafe {
            assert_eq!(ret, MAGIC | slot, "slot {slot}: wrong return value");
            assert_eq!(CALLS[slot], 1, "slot {slot}: hook call count");
            assert_eq!(
                CALLS.iter().sum::<usize>(),
                1,
                "slot {slot}: another hook fired too ({CALLS:?})"
            );
            assert_eq!(&LAST_ARGS[slot][..args.len()], args, "slot {slot}: args");
        }
        unsafe {
            CALLS = [0; WRAPPER_COUNT];
        }
    }

    /// The catalog holds every 8-byte slot in 0x08037e00..0x08037f00, in
    /// order, with a ported wrapper name for each — the completeness lock:
    /// the disassembly found exactly 32 thunks and all 32 are ported.
    #[test]
    fn catalog_covers_the_whole_span() {
        assert_eq!(THUNK_CATALOG.len(), WRAPPER_COUNT);
        assert_eq!(SPAN_END - SPAN_BASE, WRAPPER_COUNT as u32 * THUNK_STRIDE);
        let mut names: Vec<&str> = Vec::new();
        for (i, &(thunk, rom, name)) in THUNK_CATALOG.iter().enumerate() {
            assert_eq!(thunk, SPAN_BASE + i as u32 * THUNK_STRIDE, "slot {i} addr");
            assert!(
                (0x2200_0000..0x2201_0000).contains(&rom),
                "slot {i}: ROM target {rom:#x} outside mask ROM"
            );
            assert_eq!(rom & 3, 0, "slot {i}: ROM target not word aligned");
            assert!(!name.is_empty(), "slot {i} not ported");
            names.push(name);
        }
        let mut dedup = names.clone();
        dedup.sort_unstable();
        dedup.dedup();
        assert_eq!(dedup.len(), names.len(), "duplicate wrapper names");
    }

    /// The catalog's ROM targets match the disassembly of osos.dec exactly.
    #[test]
    fn catalog_matches_osos_disassembly() {
        let expected: [u32; WRAPPER_COUNT] = [
            0x220000d4, 0x22003fd0, 0x220042b4, 0x2200418c, 0x22001edc, 0x22003b6c, 0x22003c98,
            0x22003d00, 0x22003dc8, 0x22003ea0, 0x2200408c, 0x22003ec4, 0x22003eb0, 0x22003be8,
            0x22003d70, 0x220041cc, 0x22001cbc, 0x22003d44, 0x220043f4, 0x22004260, 0x220043c0,
            0x22004368, 0x22003c28, 0x22001ee8, 0x22000364, 0x22003e44, 0x22003bcc, 0x22001e70,
            0x22003b00, 0x220044c8, 0x22001f78, 0x22003b08,
        ];
        for (i, &rom) in expected.iter().enumerate() {
            assert_eq!(THUNK_CATALOG[i].1, rom, "slot {i} ROM target");
        }
    }

    /// The table really holds 32 independent fn pointers.
    #[test]
    fn ops_table_has_32_slots() {
        assert_eq!(
            core::mem::size_of::<RomThunkOps>(),
            WRAPPER_COUNT * core::mem::size_of::<usize>()
        );
    }

    /// task_lock (thunk 0x08037e48 -> ROM 0x22003ea0): the kernel id in r0
    /// reaches the ROM hook and the r0 result word comes back.
    #[test]
    fn task_lock_passes_id_through() {
        let _lock = mock_kernel();
        unsafe {
            let ret = task_lock(0x27);
            check(9, ret, &[0x27]);
            let ret = task_lock(0xdead_beef);
            check(9, ret, &[0xdead_beef]);
        }
    }

    /// task_unlock (thunk 0x08037e50 -> ROM 0x2200408c): same contract.
    #[test]
    fn task_unlock_passes_id_through() {
        let _lock = mock_kernel();
        unsafe {
            let ret = task_unlock(0x3f);
            check(10, ret, &[0x3f]);
            let ret = task_unlock(usize::MAX); // the -1 sentinel seen at 0x0809c7b8
            check(10, ret, &[usize::MAX]);
        }
    }

    /// Every remaining wrapper: args pass through to its ROM hook and the
    /// hook's r0 result comes back, with no cross-slot wiring.
    #[test]
    fn all_wrappers_pass_args_through() {
        let _lock = mock_kernel();
        unsafe {
            check(0, rom_memmove(0x1000, 0x2000, 0x40), &[0x1000, 0x2000, 0x40]);
            check(1, rom_sem_wait(0x11), &[0x11]);
            check(2, rom_sem_signal(0x12), &[0x12]);
            check(3, rom_svc_2200418c(1, 0x3000, 5), &[1, 0x3000, 5]);
            check(4, kernel_ticks(), &[]);
            check(5, rom_svc_22003b6c(), &[]);
            check(6, rom_svc_22003c98(1, 2, 3, 4, 5), &[1, 2, 3, 4, 5]);
            check(7, rom_svc_22003d00(6, 0x4000), &[6, 0x4000]);
            check(8, kernel_op_dispatch(1, 0x5000), &[1, 0x5000]);
            check(9, task_lock(0x27), &[0x27]);
            check(10, task_unlock(0x27), &[0x27]);
            check(11, rom_svc_22003ec4(0), &[0]);
            check(12, size_to_class(), &[]);
            check(13, rom_svc_22003be8(1, 4, 0x200, 0), &[1, 4, 0x200, 0]);
            check(14, kernel_create_dispatch(1, 0x6000), &[1, 0x6000]);
            check(15, rom_svc_220041cc(0x2e), &[0x2e]);
            check(16, rom_svc_22001cbc(0), &[0]);
            check(17, rom_svc_22003d44(0, 100), &[0, 100]);
            check(18, rom_svc_220043f4(), &[]);
            check(19, rom_svc_22004260(0), &[0]);
            check(20, rom_svc_220043c0(0x7000, 1), &[0x7000, 1]);
            check(21, rom_svc_22004368(0x3c), &[0x3c]);
            check(22, rom_svc_22003c28(3, 1), &[3, 1]);
            check(23, tick_elapsed(1000, 50), &[1000, 50]);
            check(24, rom_svc_22000364(0), &[0]);
            check(25, rom_svc_22003e44(0), &[0]);
            check(26, rom_svc_22003bcc(0, 2), &[0, 2]);
            check(27, irq_fiq_disable(), &[]);
            check(28, rom_svc_22003b00(), &[]);
            check(29, rom_svc_220044c8(), &[]);
            check(30, tick_delay(10), &[10]);
            check(31, rom_svc_22003b08(), &[]);
        }
    }

    /// The catalog's slot order matches the RomThunkOps field order: the
    /// name in slot i is the wrapper that calls hook i (spot-checked here
    /// against the semantic anchors; the mock table construction covers the
    /// rest at compile time).
    #[test]
    fn catalog_names_match_exported_wrappers() {
        assert_eq!(THUNK_CATALOG[9], (0x08037e48, 0x22003ea0, "task_lock"));
        assert_eq!(THUNK_CATALOG[10], (0x08037e50, 0x2200408c, "task_unlock"));
        assert_eq!(THUNK_CATALOG[4], (0x08037e20, 0x22001edc, "kernel_ticks"));
        assert_eq!(THUNK_CATALOG[23], (0x08037eb8, 0x22001ee8, "tick_elapsed"));
        assert_eq!(THUNK_CATALOG[27], (0x08037ed8, 0x22001e70, "irq_fiq_disable"));
        assert_eq!(THUNK_CATALOG[30], (0x08037ef0, 0x22001f78, "tick_delay"));
    }
}
