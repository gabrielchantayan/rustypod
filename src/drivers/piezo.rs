//! Piezo (clicker/beeper) note post helper.
//!
//! `piezo_note_post` — original: `FUN_08087554` @ `0x08087554` (64 bytes,
//! `0x08087554..0x08087594`; the sibling at `0x08087594` is a separate
//! function, binary-verified by its own `push` prologue).
//!
//! # What it does
//!
//! Allocates a 24-byte RTXC message block (`malloc` @ `0x0802edac`,
//! ported in `runtime/malloc_rt`), zero-fills it through the IRAM
//! memzero veneer `0x08037db8` (-> `0x2200027c`, the relocated copy of
//! `memzero_aligned` @ `0x0800027c`, ported in `libc/memzero` — the port
//! calls `memzero_aligned` directly, the established idiom), stores the
//! two arguments at `+0x10` / `+0x14`, then tail-branches through the
//! veneer `0x08037f30` (-> IRAM `0x22004154`) to `mailbox_send_gateway`
//! @ `0x08004154` (ported in `heap/mailbox_send_gateway`), posting the
//! block to RTXC mailbox 2 at priority 5 with no semaphore:
//!
//! ```text
//! push {r4, r5, r6, lr}
//! mov  r5, r0            ; period_ticks
//! mov  r0, #24
//! mov  r6, r1            ; duration_ticks
//! bl   0x0802edac        ; malloc(24)
//! mov  r4, r0
//! mov  r1, #24
//! bl   0x08037db8        ; memzero_aligned(block, 24)
//! str  r5, [r4, #16]     ; block->period_ticks
//! mov  r1, r4
//! str  r6, [r4, #20]     ; block->duration_ticks
//! pop  {r4, r5, r6, lr}
//! mov  r3, #0            ; semaphore = 0
//! mov  r2, #5            ; priority = 5
//! mov  r0, #2            ; mailbox = 2
//! b    0x08037f30        ; -> mailbox_send_gateway(2, block, 5, 0)
//! ```
//!
//! # Semantics (from the consumer)
//!
//! Mailbox 2 is the piezo-manager command mailbox: its receiver task @
//! `0x083938f4` loops on `mailbox_receive_gateway(2, 0)` and reads the
//! message's `+0x10`/`+0x14` words as tick counts for two hardware timer
//! channels (S5L8702 timer block at `0x3c700020 + channel * 0x20`).
//! `+0x10` arms the tone channel through `timer_channel_arm` @
//! `0x0836dc14` and is SKIPPED when zero; `+0x14` always arms the second
//! channel (`0x0836dbb0`: stop, program data register, prescaler 749,
//! control `0x240`) whose expiry callback ends the note. The freemyipod
//! RetailOS page names the mailbox set `M_PIEZOMGR`/`PIEZOMGRSEND` and
//! the tasks `S_PIEZOMGR`/`S_PIEZOMGRSNDR`/`S_PIEZODONE`. Call sites
//! confirm the reading: `0x08392f10` posts the boot-chime pairs
//! (540,200) then (676,400); `0x0804958c` posts (223,50), a rest
//! (0,10), (250,50); `0x081b111c` posts (500,2) behind a flag check.
//!
//! # Call sites (binary-verified)
//!
//! Decoding every B/BL word in `osos.dec` finds 19 sites: 13 plain `bl`,
//! 4 tail `b`, 1 tail `bne` @ `0x0805bc14` and 1 `blne` @ `0x081b1178`
//! (the two predicated forms are callers gating the post on their own
//! state — the callee itself has no condition). Ghidra's "14 bl" both
//! misses the tail branches and double-counts the thunk `0x08061054`
//! (a lone `b 0x08087554`) as a separate caller.
//!
//! # Deviations
//!
//! - The original has NO malloc-failure check: a NULL return would be
//!   zero-filled at address 0 and posted anyway. The port returns early
//!   on NULL (documented-deviation precedent: `0x08030300`'s slot append
//!   in `stdio`).
//! - `memzero_aligned` is called through a `read_volatile` fn-pointer
//!   load so LLVM neither inlines it nor re-lowers the fixed 24-byte
//!   zero-fill to `__aeabi_memclr4`; the original is a real `bl`.
//!
//! Host tests: a recording heap-ops alloc and a recording ROM gateway
//! dispatch prove the 24-byte zero-fill, the two payload stores, the
//! (mailbox 2, priority 5, semaphore 0) send arguments, the single
//! delegation, and the malloc-failure early return.

use crate::heap::mailbox_send_gateway::mailbox_send_gateway;
use crate::libc::memzero::memzero_aligned;
use crate::runtime::malloc_rt::malloc;

/// RTXC mailbox the piezo manager task (`0x083938f4`) receives on.
const PIEZO_MAILBOX: u32 = 2;
/// KS_send priority every caller of the original posts with.
const PIEZO_PRIORITY: u32 = 5;
/// Message block size in bytes: 16-byte zeroed RTXC header + 2 payload
/// words.
const PIEZO_MESSAGE_BYTES: usize = 24;

/// Piezo-manager command message (24 bytes, original layout). The first
/// four words are the RTXC message header the send service owns; the
/// receiver task consumes only the two payload words.
#[repr(C)]
pub struct PiezoNote {
    /// +0x00..+0x0f: RTXC header, zeroed by the post helper.
    pub header: [u32; 4],
    /// +0x10: tone-channel period in timer ticks; 0 suppresses the tone
    /// channel entirely (the receiver arms it only when nonzero) — a
    /// rest.
    pub period_ticks: u32,
    /// +0x14: note length in timer ticks on the second channel, whose
    /// expiry callback ends the note.
    pub duration_ticks: u32,
}

const _: [u8; 24] = [0; core::mem::size_of::<PiezoNote>()];

/// Posts a `(period_ticks, duration_ticks)` piezo note command to the
/// piezo-manager mailbox. `period_ticks == 0` posts a rest (tone channel
/// left disarmed by the receiver). Returns without posting if the
/// 24-byte message block cannot be allocated (see Deviations).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn piezo_note_post(period_ticks: u32, duration_ticks: u32) {
    let message = malloc(PIEZO_MESSAGE_BYTES).cast::<PiezoNote>();
    if message.is_null() {
        return;
    }
    // Volatile fn-pointer load: keeps the zero-fill a real call to the
    // ported body (see Deviations).
    let zero =
        core::ptr::read_volatile(&(memzero_aligned as unsafe extern "C" fn(*mut u8, usize) -> *mut u8));
    zero(message.cast::<u8>(), PIEZO_MESSAGE_BYTES);
    (*message).period_ticks = period_ticks;
    (*message).duration_ticks = duration_ticks;
    mailbox_send_gateway(PIEZO_MAILBOX, message as u32, PIEZO_PRIORITY, 0);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::rom_task_start::{RomGatewayOps, DEFAULT_ROM_GATEWAY_OPS, ROM_GATEWAY_OPS};
    use crate::runtime::malloc_rt::{HeapOps, DEFAULT_MALLOC_RT_OPS, HEAP_OPS};
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::{Mutex, MutexGuard};

    /// Serializes both seams (heap ops and ROM gateway) across tests.
    static SEAM_LOCK: Mutex<()> = Mutex::new(());

    static mut MESSAGE: PiezoNote = PiezoNote {
        header: [0xdead_beef; 4],
        period_ticks: 0xdead_beef,
        duration_ticks: 0xdead_beef,
    };
    static mut ALLOC_CALLS: u32 = 0;
    static mut ALLOC_SIZE: usize = 0;
    static mut ALLOC_FAILS: bool = false;
    static mut SEND_CALLS: u32 = 0;
    /// The six initialized words of the service-4 request frame
    /// `{selector, semaphore, mailbox, priority, message, output}`.
    static mut SEND_REQUEST: [u32; 6] = [0; 6];

    unsafe extern "C" fn mock_alloc(size: usize) -> *mut u8 {
        addr_of_mut!(ALLOC_CALLS).write(addr_of!(ALLOC_CALLS).read() + 1);
        addr_of_mut!(ALLOC_SIZE).write(size);
        if addr_of!(ALLOC_FAILS).read() {
            core::ptr::null_mut()
        } else {
            addr_of_mut!(MESSAGE).cast::<u8>()
        }
    }

    unsafe extern "C" fn record_send(request: *mut u32) {
        addr_of_mut!(SEND_CALLS).write(addr_of!(SEND_CALLS).read() + 1);
        // Words 1 and 4 are deliberately uninitialized in the gateway ABI.
        addr_of_mut!(SEND_REQUEST).write([
            request.read(),
            request.add(2).read(),
            request.add(3).read(),
            request.add(5).read(),
            request.add(6).read(),
            request.add(7).read(),
        ]);
    }

    fn install() -> MutexGuard<'static, ()> {
        let guard = SEAM_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        unsafe {
            addr_of_mut!(ALLOC_CALLS).write(0);
            addr_of_mut!(ALLOC_SIZE).write(0);
            addr_of_mut!(ALLOC_FAILS).write(false);
            addr_of_mut!(SEND_CALLS).write(0);
            addr_of_mut!(SEND_REQUEST).write([0; 6]);
            // Poison the block: the port must zero every byte before the
            // payload stores.
            (addr_of_mut!(MESSAGE).cast::<u32>()).write_bytes(0xa5, 6);
            addr_of_mut!(HEAP_OPS).write(HeapOps {
                alloc: mock_alloc,
                ..DEFAULT_MALLOC_RT_OPS
            });
            addr_of_mut!(ROM_GATEWAY_OPS).write(RomGatewayOps {
                dispatch: record_send,
            });
        }
        guard
    }

    fn restore(guard: MutexGuard<'static, ()>) {
        unsafe {
            addr_of_mut!(HEAP_OPS).write(DEFAULT_MALLOC_RT_OPS);
            addr_of_mut!(ROM_GATEWAY_OPS).write(DEFAULT_ROM_GATEWAY_OPS);
        }
        drop(guard);
    }

    #[test]
    fn posts_zeroed_note_block_to_mailbox_two() {
        let guard = install();
        unsafe {
            piezo_note_post(540, 200);

            assert_eq!(addr_of!(ALLOC_CALLS).read(), 1, "one malloc");
            assert_eq!(addr_of!(ALLOC_SIZE).read(), 24, "24-byte message block");
            assert_eq!(
                addr_of!(MESSAGE.header).read(),
                [0; 4],
                "16-byte RTXC header zero-filled"
            );
            assert_eq!(addr_of!(MESSAGE.period_ticks).read(), 540);
            assert_eq!(addr_of!(MESSAGE.duration_ticks).read(), 200);
            assert_eq!(addr_of!(SEND_CALLS).read(), 1, "one gateway dispatch");
            assert_eq!(
                addr_of!(SEND_REQUEST).read(),
                [
                    4,
                    0,
                    PIEZO_MAILBOX,
                    PIEZO_PRIORITY,
                    addr_of_mut!(MESSAGE) as u32,
                    0
                ],
                "KS_send(mailbox 2, block, priority 5, semaphore 0)"
            );
        }
        restore(guard);
    }

    #[test]
    fn rest_note_still_posts_with_zero_period() {
        let guard = install();
        unsafe {
            // The (0, 10) caller pattern: word 0 = 0 is a valid message —
            // the RECEIVER skips the tone-channel arm, the post must go
            // through unchanged.
            piezo_note_post(0, 10);
            assert_eq!(addr_of!(MESSAGE.period_ticks).read(), 0);
            assert_eq!(addr_of!(MESSAGE.duration_ticks).read(), 10);
            assert_eq!(addr_of!(SEND_CALLS).read(), 1);
            assert_eq!(addr_of!(SEND_REQUEST).read()[2], PIEZO_MAILBOX);
        }
        restore(guard);
    }

    #[test]
    fn malloc_failure_returns_without_posting() {
        let guard = install();
        unsafe {
            addr_of_mut!(ALLOC_FAILS).write(true);
            piezo_note_post(676, 400);
            assert_eq!(addr_of!(ALLOC_CALLS).read(), 1);
            assert_eq!(
                addr_of!(SEND_CALLS).read(),
                0,
                "documented deviation: no zero-fill of address 0, no send"
            );
        }
        restore(guard);
    }
}
