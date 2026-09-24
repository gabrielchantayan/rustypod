//! The **iAP packet factory** — allocate, construct and initialize one
//! iPod Accessory Protocol message object.
//!
//! # Identifying the subsystem
//!
//! The 0x080f6xxx..0x080f7xxx cluster is the iAP message class. Three
//! independent pieces of evidence pin it down:
//!
//! 1. The header parser that feeds this factory, `FUN_080f6d34` @
//!    0x080f6d34, splits the command field by the first byte:
//!
//!    ```text
//!    header = (raw[0] == 4) ? 3 : 2;
//!    command = (header == 3) ? bswap16(*(u16 *)&raw[1]) : raw[1];
//!    iap_packet_create(owner, NULL, raw[0], command, raw + header,
//!                      (length - header) & 0xffff);
//!    ```
//!
//!    A one-byte id where id 4 alone carries a **big-endian 16-bit**
//!    command is the iAP lingo rule: lingo 0x04 (Extended Interface) uses
//!    16-bit command ids, every other lingo uses 8-bit ones.
//! 2. Decoding the third argument at all 59 `bl` sites yields the
//!    immediates 0,1,2,3,4,5,6,7,8,9,10 and nothing else — exactly the
//!    allocated iAP lingo id range.
//! 3. The default constructor `FUN_080f745c` @ 0x080f745c arms +0x0e with
//!    0xff and +0x10 with 0xffff: the "no lingo" / "no command" sentinels.
//!
//! The wire-length helper `FUN_080f6e08` @ 0x080f6e08 closes it — it
//! returns `3 + payload_len + (lingo == 4 ? 2 : 1) + (payload_len > 0xfd ?
//! 3 : 1) + …`, i.e. sync byte + length field (one byte, or the 0x00 escape
//! plus a 16-bit length once the body exceeds 0xfd) + lingo + command +
//! payload + checksum. That is the iAP frame.
//!
//! # Why this lives under `app/`
//!
//! The address band (0x080fxxxx) is otherwise driver territory, but iAP is
//! a protocol layer, and the crate already files it under `app/` —
//! `app/iap_incoming_process_thread.rs` ports the accessor for the
//! `CIapIncomingProcessThread` singleton that consumes these packets. The
//! producer belongs beside the consumer.
//!
//! # The packet object (0x24 = 36 bytes)
//!
//! Recovered from the constructor @ 0x080f745c, the initializer @
//! 0x080f73a0 and the payload release @ 0x080f7420:
//!
//! ```text
//! +0x00  ptr  owner — the object the packet is bound to; the lone field
//!             the sibling factory FUN_080f6f8c @ 0x080f6f8c sets
//! +0x04  ptr  a second opaque word; NULL at all 59 call sites
//! +0x08  ptr  payload buffer, tag-3 `operator_new` (0x082aad74),
//!             released through 0x082aad14
//! +0x0c  u16  payload length
//! +0x0e  u8   lingo id           (constructor default 0xff)
//! +0x10  u16  command id         (constructor default 0xffff)
//! +0x14  ptr  a second buffer, released the same way
//! +0x18  u16  its length
//! +0x1a  u8   flag
//! +0x1c  u32  zeroed by the initializer
//! +0x20  u32  zeroed by the initializer
//! ```
//!
//! The constructor and destructor also bump a live-packet counter at the
//! global word 0x089ccc24 (up in 0x080f745c, down in 0x080f74ac).

use crate::heap::veneers::{operator_delete, operator_new};

/// Allocation size of an iAP packet — the `mov r0, #0x24` feeding
/// `operator_new` in [`iap_packet_create`].
pub const IAP_PACKET_SIZE: usize = 0x24;

/// Lingo 0x04, Extended Interface: the one lingo whose command ids are
/// 16-bit, which is why [`iap_packet_create`] takes a `u16` command.
/// Not read here — recorded because it is what makes the parameter's
/// width meaningful.
pub const LINGO_EXTENDED_INTERFACE: u8 = 0x04;

/// Indirect dispatch for this cluster's unported payload-release helper (the
/// house pattern — see `drivers/display_layer.rs` and `heap/alloc_core.rs`).
#[derive(Clone, Copy)]
pub struct IapPacketOps {
    /// `FUN_080f7420` @ 0x080f7420: the payload release helper. Runs the
    /// conditional second-buffer release @ 0x080f6af8, releases +0x08 and
    /// +0x14 through tag-3 `operator_delete` @ 0x082aad14, and zeroes both
    /// pointer/length pairs. No NULL guard on `packet` itself.
    ///
    /// Default: no-op, releases nothing.
    pub release: unsafe extern "C" fn(packet: *mut u8),
}


unsafe extern "C" fn release_stub(_packet: *mut u8) {}

/// Wired default for the unported release helper.
pub(crate) const DEFAULT_IAP_PACKET_OPS: IapPacketOps = IapPacketOps {
    release: release_stub,
};

/// The active release op. Host tests swap in a recording mock and restore.
pub static mut IAP_PACKET_OPS: IapPacketOps = DEFAULT_IAP_PACKET_OPS;

/// Volatile read so LLVM cannot fold the default stub in and delete the
/// dispatch (the `alloc_core.rs` rationale).
#[inline(always)]
unsafe fn iap_packet_ops() -> IapPacketOps {
    core::ptr::read_volatile(core::ptr::addr_of!(IAP_PACKET_OPS))
}

/// The live-packet counter (original: the word @ 0x089ccc24, held in the
/// literal pool of both the constructor @ 0x080f745c — pool word @
/// 0x080f74a8 — and the destructor @ 0x080f74ac — pool word @
/// 0x080f74d0).
///
/// A fixed address on target, not a crate static: both the ported
/// constructor and destructor must update the same word.
#[cfg(target_os = "none")]
const IAP_PACKET_LIVE_COUNT: *mut u32 = 0x089c_cc24 as *mut u32;

/// Host stand-in for the counter word (the buffer_refill_request.rs
/// pattern).
#[cfg(not(target_os = "none"))]
pub static mut IAP_PACKET_LIVE_COUNT: u32 = 0;

#[inline(always)]
fn iap_packet_live_count_ptr() -> *mut u32 {
    #[cfg(target_os = "none")]
    {
        IAP_PACKET_LIVE_COUNT
    }

    #[cfg(not(target_os = "none"))]
    {
        core::ptr::addr_of_mut!(IAP_PACKET_LIVE_COUNT)
    }
}
/// iap_packet_construct — original: `FUN_080f745c` @ 0x080f745c
/// (**76 bytes, 0x080f745c..0x080f74a8** — 19 instructions followed by the
/// literal-pool word 0x089ccc24 @ 0x080f74a8). The next real function opens
/// at 0x080f74ac with `push {r4,lr}`. **3 plain `bl` call sites and 0
/// predicated `bl` call sites**, independently counted by decoding every ARM
/// branch word in `osos.dec`.
///
/// Initializes every packet field: clears its pointer, length, and flag
/// fields; leaves its three padding gaps untouched; sets the no-lingo and
/// no-command sentinels at +0x0e/+0x10; increments the live-packet counter
/// at 0x089ccc24; then returns `packet`.
///
/// # Deviations
///
/// Host builds use [`IAP_PACKET_LIVE_COUNT`] for the fixed target counter.
///
/// # Safety
///
/// `packet` must point to a writable, 4-byte-aligned 36-byte iAP packet.
/// Like the original, this has no NULL guard.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn iap_packet_construct(packet: *mut u8) -> *mut u8 {
    packet.cast::<u32>().write(0);
    packet.add(4).cast::<u32>().write(0);
    packet.add(8).cast::<u32>().write(0);
    packet.add(12).cast::<u16>().write(0);
    packet.add(14).write(0xff);
    packet.add(16).cast::<u16>().write(0xffff);
    packet.add(20).cast::<u32>().write(0);
    packet.add(24).cast::<u16>().write(0);
    packet.add(26).write(0);
    packet.add(28).cast::<u32>().write(0);
    packet.add(32).cast::<u32>().write(0);

    let counter = iap_packet_live_count_ptr();
    counter.write_volatile(counter.read_volatile().wrapping_add(1));
    packet
}

/// iap_packet_init — original: `FUN_080f73a0` @ 0x080f73a0 (**128 bytes,
/// 0x080f73a0..0x080f7420** — 32 instructions, no literal pool; the next
/// real function opens at 0x080f7420 with `push {r4-r6,lr}`). **3 plain
/// `bl` calls and 0 predicated `bl` calls**, independently verified from the
/// raw `osos.dec` words: release @ 0x080f7420, `operator_new` @ 0x082aad74,
/// and the 0x08037db0 `__rt_memcpy` ROM veneer.
///
/// Releases existing payloads, stores the owner/context/lingo/command fields,
/// and clears +0x1c/+0x20. A nonzero payload length allocates a buffer,
/// stores its pointer and length, then copies the payload; allocation failure
/// returns zero after storing the NULL pointer. A zero length is success and
/// does not touch +0x08/+0x0c after release.
///
/// # Deliberate deviations
///
/// The unported release helper still uses [`IAP_PACKET_OPS`]'s volatile
/// dispatch seam. The original returns `(success, owner)` in r0/r1; Rust's
/// C ABI exposes only the observed r0 success flag.
///
/// # Safety
///
/// `packet` must point to a writable, aligned 36-byte packet. When
/// `payload_len != 0`, `payload` must be readable for `payload_len` bytes.
/// Like the original, this has no NULL guard.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn iap_packet_init(
    packet: *mut u8,
    owner: *mut u8,
    context: *mut u8,
    lingo: u8,
    command: u16,
    payload: *const u8,
    payload_len: u32,
) -> u32 {
    (iap_packet_ops().release)(packet);
    packet.cast::<u32>().write(owner as usize as u32);
    packet.add(4).cast::<u32>().write(context as usize as u32);
    packet.add(14).write(lingo);
    packet.add(16).cast::<u16>().write(command);
    packet.add(28).cast::<u32>().write(0);
    packet.add(32).cast::<u32>().write(0);

    if payload_len == 0 {
        return 1;
    }

    let allocation = operator_new(payload_len as usize);
    packet.add(8).cast::<u32>().write(allocation as usize as u32);
    if allocation.is_null() {
        return 0;
    }

    packet.add(12).cast::<u16>().write(payload_len as u16);
    crate::libc::rt_memcpy::__rt_memcpy(allocation, payload, payload_len as usize);
    1
}


/// iap_packet_destruct — original: `FUN_080f74ac` @ 0x080f74ac
/// (**36 bytes, 0x080f74ac..0x080f74d0** — 9 instructions, followed by its
/// one literal-pool word 0x089ccc24 @ 0x080f74d0. Ghidra's 36 is exact:
/// the next function opens at 0x080f74d4 with `ldr r0, [r0]; b
/// 0x080f74f8`. **24 `bl` and 0 `b` call sites, none predicated**, counted
/// by decoding every branch word in `osos.dec` — the earlier ledger note
/// on the ops seam claiming a single call site was wrong; 23 of the 24
/// are delete paths in the lingo handlers, each immediately followed by
/// `bl 0x082aad24` (tag-2 `operator_delete`). The address appears in no
/// data word, so it is never dispatched virtually.)
///
/// The packet class destructor:
///
/// ```text
/// 080f74ac  e92d4010  push {r4, lr}
/// 080f74b0  e1a04000  mov  r4, r0            @ r4 = packet
/// 080f74b4  ebffffd9  bl   0x080f7420        @ release payloads
/// 080f74b8  e59f0010  ldr  r0, [pc, #16]     @ &live_count (0x089ccc24)
/// 080f74bc  e5901000  ldr  r1, [r0]
/// 080f74c0  e2411001  sub  r1, r1, #1
/// 080f74c4  e5801000  str  r1, [r0]          @ live_count -= 1
/// 080f74c8  e1a00004  mov  r0, r4            @ return packet
/// 080f74cc  e8bd8010  pop  {r4, pc}
/// ```
///
/// Releases the packet's payload buffers through the release helper @
/// 0x080f7420, decrements the live-packet counter @ 0x089ccc24 (a plain
/// `sub` — it wraps through zero with no guard), and returns `packet`
/// unchanged. The returned pointer is what every delete-path caller feeds
/// to `operator_delete`, which is why this function returns `this` at
/// all.
///
/// There is no NULL guard here and none at any of the 24 call sites —
/// every call is an unconditional `bl`. A NULL packet would fault inside
/// the release helper's first field load; the port keeps that contract.
///
/// # Deviations
///
/// - The release helper @ 0x080f7420 is not ported; the call dispatches
///   through [`IAP_PACKET_OPS`]'s `release` hook.
/// - On target the counter is the real word @ 0x089ccc24 (the stock
///   constructor increments it, so the port must decrement that same
///   word); host builds decrement the stand-in static
///   [`IAP_PACKET_LIVE_COUNT`].
///
/// # Safety
///
/// `packet` must point at a live packet object — the original's
/// precondition, unguarded here and at every call site.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn iap_packet_destruct(packet: *mut u8) -> *mut u8 {
    (iap_packet_ops().release)(packet);
    let counter = iap_packet_live_count_ptr();
    counter.write_volatile(counter.read_volatile().wrapping_sub(1));
    packet
}

/// iap_packet_init_with_compact_payload — original: `FUN_080f6c58` @
/// 0x080f6c58 (**220 bytes, 0x080f6c58..0x080f6d34** — 55 instructions,
/// no literal pool; the next function begins with `push {r2,r3,r4,lr}` at
/// 0x080f6d34). **12 `bl` and 0 `b` call sites, all unconditional**,
/// counted by decoding every branch word in `osos.dec`; no predicated call
/// forms and no matching data word occur in the image.
///
/// Builds the compact payload used by iAP replies, then gives it to the
/// packet initializer:
///
/// ```text
/// payload[0] = header_kind as u8
/// payload[1..] = lingo_word == 4  ? be16(header_value as u16)
///               :                    [header_value as u8]
/// if lingo_word == 12: payload.push(extra_byte)
/// if header_kind == 6: payload.extend(be32(header_data))
/// iap_packet_init(packet, owner, context, lingo_word as u8,
///                 command_word as u16, payload)
/// ```
///
/// The two layout selectors intentionally stay full-width words. The ARM
/// code compares `lingo_word` with 4/12 and `header_kind` with 6 before
/// truncating their stored bytes; for example, `lingo_word = 0x104` passes
/// lingo 4 to the initializer but takes the one-byte layout. The helper
/// neither NULL-checks nor interprets the packet, owner, or context; all 12
/// callers are unconditional reply paths.
///
/// # Deviations
///
/// The initializer is ported directly as [`iap_packet_init`]. The original
/// discards its result; this `void` helper does too.
///
/// # Safety
///
/// Same as the initializer: `packet` must be a live packet object and the
/// owner/context pointers must satisfy its contract. No additional guards
/// exist here.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn iap_packet_init_with_compact_payload(
    packet: *mut u8,
    owner: *mut u8,
    context: *mut u8,
    lingo_word: u32,
    command_word: u32,
    header_kind: u32,
    header_value: u32,
    header_data: u32,
    extra_byte: u8,
) {
    let mut payload = [0u8; 7];
    payload[0] = header_kind as u8;

    let mut payload_len = if lingo_word == LINGO_EXTENDED_INTERFACE as u32 {
        payload[1] = (header_value >> 8) as u8;
        payload[2] = header_value as u8;
        3
    } else {
        payload[1] = header_value as u8;
        if lingo_word == 12 {
            payload[2] = extra_byte;
            3
        } else {
            2
        }
    };

    if header_kind == 6 {
        payload[payload_len] = (header_data >> 24) as u8;
        payload[payload_len + 1] = (header_data >> 16) as u8;
        payload[payload_len + 2] = (header_data >> 8) as u8;
        payload[payload_len + 3] = header_data as u8;
        payload_len += 4;
    }

    iap_packet_init(
        packet,
        owner,
        context,
        lingo_word as u8,
        command_word as u16,
        payload.as_ptr(),
        payload_len as u32,
    );
}

/// iap_packet_create — original: `FUN_080f6da0` @ 0x080f6da0
/// (**104 bytes, 0x080f6da0..0x080f6e08** — 26 instructions, no literal
/// pool. Ghidra's `functions.csv` says 100; it is one word short. The next
/// function opens at 0x080f6e08 with `mov r2, r0; push {lr}`, and the word
/// at 0x080f6e04 is this function's own
/// `pop {r1,r2,r3,r4-r11,pc}`. **59 `bl` and 0 `b` call sites**, counted by
/// decoding every branch word in `osos.dec`.)
///
/// Builds one iAP packet and hands back ownership, or NULL if it could not
/// be completed:
///
/// ```text
/// packet = iap_packet_construct(operator_new(0x24));   @ tag-2 new
/// if (packet == NULL) return NULL;
/// if (iap_packet_init(packet, owner, context, lingo, command,
///                     payload, payload_len)) return packet;
/// operator_delete(iap_packet_destruct(packet));
/// return NULL;
/// ```
///
/// The NULL test is on the **constructor's** result, not the allocator's:
/// the original runs `bl operator_new` and `bl 0x080f745c` back to back and
/// only then does `movs r4, r0`. Since the constructor returns r0 untouched
/// that is an allocation-failure test in effect, but the constructor has
/// already run over the NULL block by the time it is made — the port keeps
/// that order rather than "fixing" it.
///
/// The failure path passes the **destructor's return value** to
/// `operator_delete`, not the saved packet pointer; the original never
/// reloads r4 for the delete. The two are the same pointer only because the
/// destructor ends in `mov r0, r4`, so the port routes it through the hook
/// the same way.
///
/// # Deviations
///
/// - `operator_new` (0x082aadd4) and `operator_delete` (0x082aad24) are
///   ported and called directly.
/// - The destructor (0x080f74ac) is ported — [`iap_packet_destruct`] —
///   and called directly; only its payload-release helper @ 0x080f7420
///   still dispatches, through [`IAP_PACKET_OPS`]'s `release` hook.
/// - The initializer is now ported directly as [`iap_packet_init`].
///
/// # Safety
///
/// `payload` must be readable for `payload_len` bytes when `payload_len` is
/// nonzero; the caller takes ownership of a non-NULL result.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn iap_packet_create(
    owner: *mut u8,
    context: *mut u8,
    lingo: u8,
    command: u16,
    payload: *const u8,
    payload_len: u32,
) -> *mut u8 {
    let packet = iap_packet_construct(operator_new(IAP_PACKET_SIZE));
    if packet.is_null() {
        return core::ptr::null_mut();
    }

    if iap_packet_init(packet, owner, context, lingo, command, payload, payload_len) != 0 {
        return packet;
    }

    operator_delete(iap_packet_destruct(packet));
    core::ptr::null_mut()
}

/// iap_packet_reinit — original: `FUN_080f6efc` @ 0x080f6efc
/// (**48 bytes, 0x080f6efc..0x080f6f2c** — 12 instructions, no literal
/// pool. Ghidra's 48 is exact this time: the next function opens at
/// 0x080f6f2c with `push {r4-r11,lr}; sub sp, sp, #0x14`. **43 `bl` and
/// 0 `b` call sites, none predicated**, counted by decoding every branch
/// word in `osos.dec`; the address appears in no data word, so it is
/// never dispatched virtually.)
///
/// The reinitialize-in-place entry of the iAP packet class — a pure
/// identity forwarder into the file-local initializer @ 0x080f73a0:
///
/// ```text
/// 080f6efc  e92d403e  push {r1,r2,r3,r4,r5,lr}
/// 080f6f00  e1a04003  mov r4, r3
/// 080f6f04  e28d3018  add r3, sp, #0x18
/// 080f6f08  e1a0e002  mov lr, r2
/// 080f6f0c  e1a0c001  mov ip, r1
/// 080f6f10  e893000e  ldmia r3, {r1,r2,r3}
/// 080f6f14  e88d000e  stmia sp, {r1,r2,r3}
/// 080f6f18  e1a03004  mov r3, r4
/// 080f6f1c  e1a0200e  mov r2, lr
/// 080f6f20  e1a0100c  mov r1, ip
/// 080f6f24  eb00011d  bl 0x080f73a0
/// 080f6f28  e8bd803e  pop {r1,r2,r3,r4,r5,pc}
/// ```
///
/// The push makes a 0x18-byte frame; the `ldmia`/`stmia` pair bounces the
/// caller's three stack arguments down into the bottom of it, and r0–r3
/// ride through a three-register shuffle (`r4`/`lr`/`ip`) untouched.
/// Nothing is tested, added, or masked — the wrapper exists because the
/// initializer is file-local and the lingo handlers link against this
/// out-of-line copy.
///
/// The 43 call sites are reply paths: each takes its incoming request
/// packet as r0, reloads the packet's own owner field into r1
/// (`FUN_080f6efc(param_2, *param_2, 0, lingo, command, reply,
/// reply_len)` — the Extended Interface handler @ 0x08139974 even reads
/// the lingo back out of the packet's +0x0e), and hands it here. The
/// initializer's first act is releasing any payload the packet already
/// holds (the release helper @ 0x080f7420), so this call is how a request
/// packet is turned into its reply.
///
/// Neither the wrapper nor any of its 43 call sites guards the packet
/// pointer: every call is unconditional and the wrapper contains no
/// `cmp`.
///
/// # Deviations
///
/// - The initializer is ported directly as [`iap_packet_init`].
/// - `lingo`/`command` are typed `u8`/`u16` — the initializer truncates
///   with `strb`/`strh`, so nothing observable is lost.
/// - The ARM return is the initializer's 64-bit pair (r0 = the success
///   flag, r1 = the owner passing back out); the wrapper leaves both live
///   in r0/r1, but all 43 call sites discard them, so the port returns
///   just r0.
///
/// # Safety
///
/// Same contract as the initializer: `packet` must point at a live packet
/// object, and `payload` must be readable for `payload_len` bytes when
/// nonzero. No NULL guard exists here or at any call site.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn iap_packet_reinit(
    packet: *mut u8,
    owner: *mut u8,
    context: *mut u8,
    lingo: u8,
    command: u16,
    payload: *const u8,
    payload_len: u32,
) -> u32 {
    let result = iap_packet_init(packet, owner, context, lingo, command, payload, payload_len);
    // LLVM's ARM backend breaks the sibling-call this body wants to be:
    // it materializes the volatile ops read with `ldrd r0, [ip]` and the
    // branch target in r1, clobbering the r0/r1 arguments the tail call
    // must forward untouched (verified in the release archive). An empty
    // barrier after the call keeps the `bl`-and-return shape the
    // original has; the original is not a tail call either.
    core::arch::asm!("", options(nomem, nostack, preserves_flags));
    result
}

/// iap_packet_owner_mode — original: `FUN_080f6b3c` @ 0x080f6b3c
/// (**24 bytes, 0x080f6b3c..0x080f6b54** — 6 instructions, no literal
/// pool. Ghidra's 24 is exact: the next function opens at 0x080f6b54 with
/// `mov r1, r0; ldrh r2, [r1, #0x18]`. **43 `bl` and 0 `b` call sites,
/// none predicated**, counted by decoding every branch word in `osos.dec`;
/// the address appears in no data word anywhere in the image, so it is
/// never dispatched virtually.)
///
/// The packet class's owner-mode getter:
///
/// ```text
/// 080f6b3c  e1a01000  mov   r1, r0
/// 080f6b40  e5911000  ldr   r1, [r1]      @ owner = packet->owner (+0x00)
/// 080f6b44  e3a00000  mov   r0, #0
/// 080f6b48  e3510000  cmp   r1, #0
/// 080f6b4c  15910008  ldrne r0, [r1, #8]  @ owner ? owner->mode (+0x08) : 0
/// 080f6b50  e12fff1e  bx    lr
/// ```
///
/// `owner = *(u32 *)packet; return owner != NULL ? *(u32 *)(owner + 8) : 0;`
///
/// What the returned word is, from the call sites: the owner object's
/// framing mode. The packet serializer @ 0x080f6b70 prepends the 0xff
/// sync byte ahead of the fixed 0x55 exactly when this returns 1
/// (`cmp r0, #1; moveq r0, #0xff; strbeq`), and the wire-length helper @
/// 0x080f6e08 budgets that same one extra byte; the mode remap @
/// 0x08192124 translates {1→0, 2→1, 4→3, else 0xff}, so the meaningful
/// range is 0..=4; the reply path @ 0x081fd688 splits on `< 3` vs `>= 3`.
/// The NULL guard is the callee's own — every one of the 43 calls is an
/// unconditional `bl` — so an ownerless packet reports mode 0.
///
/// The owner object's class is not identified; its +0x08 word is the only
/// field observed here, read as a raw u32 and returned verbatim.
///
/// # Deviations
///
/// None. Both loads are aligned word reads, as in the original, and there
/// is no NULL guard on `packet` itself because the original has none.
///
/// # Safety
///
/// `packet` must address a readable word (the owner slot); when that slot
/// is non-NULL it must address at least three readable words
/// (+0x00..+0x0b). These are the original's preconditions, not added ones.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn iap_packet_owner_mode(packet: *const u8) -> u32 {
    let owner = packet.cast::<u32>().read();
    let mut mode = 0;
    if owner != 0 {
        mode = (owner as usize as *const u32).add(2).read();
    }
    mode
}

/// iap_packet_second_buffer_length_or_zero — original: `FUN_080f6e60` @
/// `0x080f6e60` (**28 bytes, `0x080f6e60..0x080f6e7c`** — 7 instructions,
/// no literal pool; the next real function starts at `0x080f6e7c` with
/// `push {r4-r8,lr}`). **3 direct plain `bl` call sites and no predicated
/// `bl` call sites**, verified by decoding every ARM branch word in
/// `osos.dec`: `0x0810559c`, `0x081055d0`, and `0x0814e434`.
///
/// Reads the iAP packet's second-buffer length at +0x18, replacing only the
/// `0xffff` no-buffer sentinel with zero. The three callers forward this
/// length with the packet lingo to their completion dispatches before the
/// packet is destroyed.
///
/// # Deviations
///
/// Ghidra types the result as `short`; the raw `ldrh` and `movne r0,r1`
/// establish a zero-extended word result, so this uses `u16`. This preserves
/// lengths with bit 15 set instead of treating them as negative.
///
/// # Safety
///
/// `packet` must address a readable halfword at +0x18. The original has no
/// NULL guard.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn iap_packet_second_buffer_length_or_zero(packet: *const u8) -> u16 {
    let length = packet.add(0x18).cast::<u16>().read();
    if length == u16::MAX {
        0
    } else {
        length
    }
}

#[cfg(test)]
#[test]
fn second_buffer_length_replaces_only_the_no_buffer_sentinel() {
    let mut packet = [0u32; 7];
    let length = unsafe { packet.as_mut_ptr().cast::<u8>().add(0x18).cast::<u16>() };

    for (stored, expected) in [(u16::MAX, 0), (0, 0), (1, 1), (0x8000, 0x8000), (0xfffe, 0xfffe)] {
        unsafe {
            length.write(stored);
            assert_eq!(iap_packet_second_buffer_length_or_zero(packet.as_ptr().cast()), expected);
        }
    }
}

///
/// iap_packet_owner_mode_index — original: `FUN_08192124` @ `0x08192124`
/// (**40 bytes, 0x08192124..0x0819214c** — 10 instructions, no literal
/// pool; the next distinct function starts at 0x0819214c with `cmp r0,#0`).
/// **7 direct `bl` call sites, all unconditional; no predicated forms**,
/// verified by decoding every ARM branch word in `osos.dec`.
///
/// Maps the iAP packet owner's framing mode into the compact index used by
/// the iAP service tables: mode 1 becomes 0, 2 becomes 1, and 4 becomes 3.
/// Every other full-width input, including the in-range modes 0 and 3,
/// returns the `0xff` invalid-index sentinel. The original has no pointer
/// access, state, or NULL handling.
///
/// # Deviations
///
/// None. The comparisons are over the full 32-bit input exactly as the ARM
/// `cmp` instructions do; the result remains a `u32` rather than being
/// narrowed to its byte-sized sentinel representation.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.iap_packet_owner_mode_index")]
pub extern "C" fn iap_packet_owner_mode_index(owner_mode: u32) -> u32 {
    if owner_mode == 1 {
        0
    } else if owner_mode == 2 {
        1
    } else if owner_mode == 4 {
        3
    } else {
        0xff
    }
}

#[cfg(test)]
#[test]
fn owner_mode_index_maps_only_recognized_modes() {
    assert_eq!(iap_packet_owner_mode_index(1), 0);
    assert_eq!(iap_packet_owner_mode_index(2), 1);
    assert_eq!(iap_packet_owner_mode_index(4), 3);

    for owner_mode in [0, 3, 5, u32::MAX] {
        assert_eq!(iap_packet_owner_mode_index(owner_mode), 0xff);
    }
}

#[cfg(test)]
#[test]
fn owner_mode_index_does_not_narrow_before_matching() {
    assert_eq!(iap_packet_owner_mode_index(0x0000_0101), 0xff);
    assert_eq!(iap_packet_owner_mode_index(0x0000_0102), 0xff);
    assert_eq!(iap_packet_owner_mode_index(0xffff_ff04), 0xff);
}

const IAP_SERVICE_OWNER_MODE_VALID: *const u8 = 0x089c_a8e6 as *const u8;
const IAP_SERVICE_DESCRIPTOR_BASE: *mut u8 = 0x08a2_56b0 as *mut u8;
const IAP_SERVICE_DESCRIPTOR_STRIDE: usize = 0x124;

#[cfg(not(target_os = "none"))]
static mut HOST_IAP_SERVICE_OWNER_MODE_VALID: *const u8 = core::ptr::null();
#[cfg(not(target_os = "none"))]
static mut HOST_IAP_SERVICE_DESCRIPTOR_BASE: *mut u8 = core::ptr::null_mut();

#[inline(always)]
unsafe fn iap_service_owner_mode_valid() -> *const u8 {
    #[cfg(target_os = "none")]
    { IAP_SERVICE_OWNER_MODE_VALID }
    #[cfg(not(target_os = "none"))]
    { core::ptr::read_volatile(core::ptr::addr_of!(HOST_IAP_SERVICE_OWNER_MODE_VALID)) }
}

#[inline(always)]
unsafe fn iap_service_descriptor_base() -> *mut u8 {
    #[cfg(target_os = "none")]
    { IAP_SERVICE_DESCRIPTOR_BASE }
    #[cfg(not(target_os = "none"))]
    { core::ptr::read_volatile(core::ptr::addr_of!(HOST_IAP_SERVICE_DESCRIPTOR_BASE)) }
}

/// iap_service_descriptor_for_owner_mode — original: `FUN_0818dcec` @
/// `0x0818dcec` (**56 bytes, `0x0818dcec..0x0818dd24`** — 14 instructions;
/// the next separately linked function starts at `0x0818dd2c`, after this
/// function's two literal-pool words). **3 direct plain `bl` call sites and
/// no predicated `bl` call sites**, verified by decoding every ARM branch word
/// in `osos.dec`.
///
/// Maps an iAP owner framing mode through [`iap_packet_owner_mode_index`].
/// Only service indices 0 and 1 are eligible; a nonzero corresponding byte
/// in the runtime service-validity table selects its 0x124-byte descriptor.
/// All other modes, indices, and unavailable entries return NULL.
///
/// # Deviations
///
/// The target reads the runtime tables at `0x089ca8e6` and `0x08a256b0`.
/// Host tests install mapped target-width fixture bases in their place; this
/// does not affect target code.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.iap_service_descriptor_for_owner_mode")]
pub extern "C" fn iap_service_descriptor_for_owner_mode(owner_mode: u32) -> *mut u8 {
    let service_index = iap_packet_owner_mode_index(owner_mode);
    if service_index >= 2 {
        return core::ptr::null_mut();
    }

    unsafe {
        if iap_service_owner_mode_valid().add(service_index as usize).read_volatile() == 0 {
            core::ptr::null_mut()
        } else {
            iap_service_descriptor_base().add(service_index as usize * IAP_SERVICE_DESCRIPTOR_STRIDE)
        }
    }
}

#[cfg(test)]
mod service_descriptor_tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::{LazyLock, Mutex};

    const FIXTURE_LEN: usize = 0x1000;
    static LOCK: Mutex<()> = Mutex::new(());
    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::IAP_SERVICE_DESCRIPTOR_FOR_OWNER_MODE, FIXTURE_LEN)
            .map(|pointer| pointer as usize)
    });

    unsafe fn reset() -> *mut u8 {
        let base = FIXTURE.expect("fixture mapping was checked") as *mut u8;
        base.write_bytes(0, FIXTURE_LEN);
        HOST_IAP_SERVICE_OWNER_MODE_VALID = base;
        HOST_IAP_SERVICE_DESCRIPTOR_BASE = base.add(0x400);
        base
    }

    #[test]
    fn service_descriptor_requires_a_recognized_mode_and_available_entry() {
        let _guard = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        if FIXTURE.is_none() {
            assert!(note_missing_u32_fixture("app/iap_packet service descriptor"));
            return;
        }
        unsafe {
            let base = reset();
            assert!(iap_service_descriptor_for_owner_mode(1).is_null());
            assert!(iap_service_descriptor_for_owner_mode(0).is_null());
            assert!(iap_service_descriptor_for_owner_mode(4).is_null());
            assert!(iap_service_descriptor_for_owner_mode(0x0000_0102).is_null());

            base.add(1).write(1);
            assert_eq!(iap_service_descriptor_for_owner_mode(2), base.add(0x400 + IAP_SERVICE_DESCRIPTOR_STRIDE));
        }
    }

    #[test]
    fn service_descriptor_uses_the_target_stride_for_each_eligible_index() {
        let _guard = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        if FIXTURE.is_none() {
            assert!(note_missing_u32_fixture("app/iap_packet service descriptor"));
            return;
        }
        unsafe {
            let base = reset();
            base.write(1);
            assert_eq!(iap_service_descriptor_for_owner_mode(1), base.add(0x400));
        }
    }
}

/// iap_packet_owner_mode_from_index — original: `FUN_0819214c` @
/// `0x0819214c` (**40 bytes, 0x0819214c..0x08192174** — 10 instructions,
/// no literal pool; the next separately linked function starts at
/// 0x08192174 with `push {r4-r9,lr}`). **6 direct `bl` call sites, all
/// unconditional; no predicated forms**, verified by decoding every ARM
/// branch word in `osos.dec`.
///
/// Inverts the valid portion of [`iap_packet_owner_mode_index`] for iAP
/// service-table lookups: index 0 selects framing mode 1, index 1 selects
/// mode 2, and index 3 selects mode 4. Every other full-width input,
/// including the invalid index 2, yields mode 0. The original has no pointer
/// access, state, or NULL handling.
///
/// # Deviations
///
/// None. The comparisons are over the full 32-bit input exactly as the ARM
/// `cmp` instructions do; the result remains a `u32`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.iap_packet_owner_mode_from_index")]
pub extern "C" fn iap_packet_owner_mode_from_index(service_index: u32) -> u32 {
    if service_index == 0 {
        1
    } else if service_index == 1 {
        2
    } else if service_index == 3 {
        4
    } else {
        0
    }
}

#[cfg(test)]
#[test]
fn owner_mode_from_index_maps_only_recognized_indices() {
    assert_eq!(iap_packet_owner_mode_from_index(0), 1);
    assert_eq!(iap_packet_owner_mode_from_index(1), 2);
    assert_eq!(iap_packet_owner_mode_from_index(3), 4);

    for service_index in [2, 4, u32::MAX] {
        assert_eq!(iap_packet_owner_mode_from_index(service_index), 0);
    }
}

#[cfg(test)]
#[test]
fn owner_mode_from_index_does_not_narrow_before_matching() {
    assert_eq!(iap_packet_owner_mode_from_index(0x0000_0100), 0);
    assert_eq!(iap_packet_owner_mode_from_index(0x0000_0101), 0);
    assert_eq!(iap_packet_owner_mode_from_index(0xffff_ff03), 0);
}


#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::veneers::tests::{alloc_log, mock_heap, set_alloc_ret};
    use std::sync::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut RELEASE_CALLS: usize = 0;
    static mut LAST_RELEASE_PACKET: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn recording_release(packet: *mut u8) {
        RELEASE_CALLS += 1;
        LAST_RELEASE_PACKET = packet;
    }

    fn install_mocks() -> (MutexGuard<'static, ()>, MutexGuard<'static, ()>) {
        let ops_guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let heap_guard = mock_heap();
        unsafe {
            IAP_PACKET_OPS = IapPacketOps { release: recording_release };
            RELEASE_CALLS = 0;
            LAST_RELEASE_PACKET = core::ptr::null_mut();
            IAP_PACKET_LIVE_COUNT = 0;
        }
        (ops_guard, heap_guard)
    }

    fn restore_mocks(guards: (MutexGuard<'static, ()>, MutexGuard<'static, ()>)) {
        unsafe { IAP_PACKET_OPS = DEFAULT_IAP_PACKET_OPS };
        drop(guards);
    }

    #[test]
    fn init_releases_stores_target_width_fields_and_copies_payload() {
        let guards = install_mocks();
        let mut packet_words = [0xa5u32; IAP_PACKET_SIZE / 4];
        let packet = packet_words.as_mut_ptr().cast::<u8>();
        let mut allocation = [0u8; 4];
        let payload = [0x11u8, 0x22, 0x33, 0x44];
        let owner = 0x0123_4567usize as *mut u8;
        let context = 0x0765_4321usize as *mut u8;

        unsafe {
            set_alloc_ret(allocation.as_mut_ptr());
            assert_eq!(iap_packet_init(packet, owner, context, 4, 0xbeef, payload.as_ptr(), 4), 1);
            assert_eq!(RELEASE_CALLS, 1);
            assert_eq!(LAST_RELEASE_PACKET, packet);
            assert_eq!(packet.cast::<u32>().read(), owner as usize as u32);
            assert_eq!(packet.add(4).cast::<u32>().read(), context as usize as u32);
            assert_eq!(packet.add(14).read(), 4);
            assert_eq!(packet.add(16).cast::<u16>().read(), 0xbeef);
            assert_eq!(packet.add(8).cast::<u32>().read(), allocation.as_ptr() as usize as u32);
            assert_eq!(packet.add(12).cast::<u16>().read(), 4);
            assert_eq!(&allocation, &payload);
            assert_eq!(packet.add(28).cast::<u32>().read(), 0);
            assert_eq!(packet.add(32).cast::<u32>().read(), 0);
            assert_eq!(alloc_log(), (1, 4, 2));
        }
        restore_mocks(guards);
    }

    #[test]
    fn init_zero_length_is_success_without_allocating_or_overwriting_released_payload_slots() {
        let guards = install_mocks();
        let mut packet = [0xa5u32; IAP_PACKET_SIZE / 4];
        let packet = packet.as_mut_ptr().cast::<u8>();

        unsafe {
            assert_eq!(iap_packet_init(packet, core::ptr::null_mut(), core::ptr::null_mut(), 0xff, 0xffff, core::ptr::null(), 0), 1);
            assert_eq!(RELEASE_CALLS, 1);
            assert_eq!(alloc_log().0, 0);
            assert_eq!(core::slice::from_raw_parts(packet.add(8), 6), &[0xa5, 0, 0, 0, 0xa5, 0]);
            assert_eq!(packet.add(14).read(), 0xff);
            assert_eq!(packet.add(16).cast::<u16>().read(), 0xffff);
        }
        restore_mocks(guards);
    }

    #[test]
    fn init_allocation_failure_stores_null_and_preserves_length() {
        let mut packet = [0xa5u32; IAP_PACKET_SIZE / 4];
        let guards = install_mocks();
        let packet = packet.as_mut_ptr().cast::<u8>();
        unsafe { packet.add(12).cast::<u16>().write(0) };

        unsafe {
            set_alloc_ret(core::ptr::null_mut());
            assert_eq!(iap_packet_init(packet, core::ptr::null_mut(), core::ptr::null_mut(), 1, 2, b"x".as_ptr(), 1), 0);
            assert_eq!(packet.add(8).cast::<u32>().read(), 0);
            assert_eq!(packet.add(12).cast::<u16>().read(), 0);
            assert_eq!(alloc_log(), (1, 1, 2));
        }
        restore_mocks(guards);
    }

    #[test]
    fn destruct_releases_then_decrements_and_returns_packet() {
        let guards = install_mocks();
        let packet = 0x0bee_f000usize as *mut u8;

        unsafe {
            IAP_PACKET_LIVE_COUNT = 0;
            assert_eq!(iap_packet_destruct(packet), packet);
            assert_eq!(RELEASE_CALLS, 1);
            assert_eq!(LAST_RELEASE_PACKET, packet);
            assert_eq!(IAP_PACKET_LIVE_COUNT, u32::MAX);
        }
        restore_mocks(guards);
    }
}
