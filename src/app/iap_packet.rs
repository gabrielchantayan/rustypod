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

/// Indirect dispatch for this cluster's unported callees (the house
/// pattern — see `drivers/display_layer.rs` and `heap/alloc_core.rs`).
#[derive(Clone, Copy)]
pub struct IapPacketOps {
    /// `FUN_080f745c` @ 0x080f745c (3 `bl` call sites — this factory and
    /// the siblings @ 0x080f6f2c and 0x080f6f8c): the default constructor.
    /// Zeroes the object, arms +0x0e = 0xff and +0x10 = 0xffff, and bumps
    /// the live-packet counter @ 0x089ccc24. Its whole body is stores
    /// through r0 followed by `bx lr`, so it returns its argument
    /// unchanged — which is the only thing this factory observes.
    /// Default: identity, no writes.
    pub construct: unsafe extern "C" fn(storage: *mut u8) -> *mut u8,
    /// `FUN_080f73a0` @ 0x080f73a0 (2 `bl` call sites — this factory and
    /// the forwarder @ 0x080f6efc): the initializer. Releases any payload
    /// already held, stores owner/context/lingo/command, zeroes +0x1c and
    /// +0x20, then — only when `payload_len` is nonzero — takes a tag-3
    /// `operator_new(payload_len)` and copies `payload` into it. Returns
    /// **nonzero on success**; zero only when that allocation failed.
    /// A zero `payload_len` is success with no buffer. Default: returns 1.
    pub init: unsafe extern "C" fn(
        packet: *mut u8,
        owner: *mut u8,
        context: *mut u8,
        lingo: u8,
        command: u16,
        payload: *const u8,
        payload_len: u32,
    ) -> u32,
    /// `FUN_080f74ac` @ 0x080f74ac (1 `bl` call site, this factory): the
    /// destructor. Releases both buffers through the payload-release
    /// helper @ 0x080f7420, decrements the live-packet counter, and
    /// returns `packet` — which the factory feeds straight to
    /// `operator_delete`. Default: identity, no writes.
    pub destruct: unsafe extern "C" fn(packet: *mut u8) -> *mut u8,
}

unsafe extern "C" fn construct_stub(storage: *mut u8) -> *mut u8 {
    storage
}

unsafe extern "C" fn init_stub(
    _packet: *mut u8,
    _owner: *mut u8,
    _context: *mut u8,
    _lingo: u8,
    _command: u16,
    _payload: *const u8,
    _payload_len: u32,
) -> u32 {
    1
}

unsafe extern "C" fn destruct_stub(packet: *mut u8) -> *mut u8 {
    packet
}

/// Wired defaults: the documented stubs for the three unported callees.
pub(crate) const DEFAULT_IAP_PACKET_OPS: IapPacketOps = IapPacketOps {
    construct: construct_stub,
    init: init_stub,
    destruct: destruct_stub,
};

/// The active ops. Host tests swap in recording mocks and restore.
pub static mut IAP_PACKET_OPS: IapPacketOps = DEFAULT_IAP_PACKET_OPS;

/// Volatile read so LLVM cannot fold the default stubs in and delete the
/// dispatch (the `alloc_core.rs` rationale).
#[inline(always)]
unsafe fn iap_packet_ops() -> IapPacketOps {
    core::ptr::read_volatile(core::ptr::addr_of!(IAP_PACKET_OPS))
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
/// - The packet constructor, initializer and destructor (0x080f745c,
///   0x080f73a0, 0x080f74ac) are not ported; they dispatch through
///   [`IAP_PACKET_OPS`].
/// - The initializer's ARM return is a 64-bit pair (r0 = the success flag,
///   r1 = the owner argument passing straight back out). The factory reads
///   only r0, so the hook is typed to return just that.
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
    let ops = iap_packet_ops();

    let packet = (ops.construct)(operator_new(IAP_PACKET_SIZE));
    if packet.is_null() {
        return core::ptr::null_mut();
    }

    if (ops.init)(packet, owner, context, lingo, command, payload, payload_len) != 0 {
        return packet;
    }

    operator_delete((ops.destruct)(packet));
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
/// - The initializer @ 0x080f73a0 is not ported; the forward dispatches
///   through [`IAP_PACKET_OPS`]'s `init` hook, same as
///   [`iap_packet_create`].
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
    let result =
        (iap_packet_ops().init)(packet, owner, context, lingo, command, payload, payload_len);
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

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::veneers::tests::{alloc_log, free_log, mock_heap, set_alloc_ret};
    use std::sync::{Mutex, MutexGuard};

    /// Serializes swaps of [`IAP_PACKET_OPS`].
    static OPS_LOCK: Mutex<()> = Mutex::new(());

    static mut CONSTRUCT_CALLS: usize = 0;
    static mut LAST_STORAGE: *mut u8 = core::ptr::null_mut();
    static mut CONSTRUCT_RESULT: *mut u8 = core::ptr::null_mut();

    static mut INIT_CALLS: usize = 0;
    static mut LAST_INIT_PACKET: *mut u8 = core::ptr::null_mut();
    static mut LAST_OWNER: *mut u8 = core::ptr::null_mut();
    static mut LAST_CONTEXT: *mut u8 = core::ptr::null_mut();
    static mut LAST_LINGO: u8 = 0;
    static mut LAST_COMMAND: u16 = 0;
    static mut LAST_PAYLOAD: *const u8 = core::ptr::null();
    static mut LAST_PAYLOAD_LEN: u32 = 0;
    static mut INIT_RESULT: u32 = 1;

    static mut DESTRUCT_CALLS: usize = 0;
    static mut LAST_DESTRUCT_PACKET: *mut u8 = core::ptr::null_mut();
    static mut DESTRUCT_RESULT: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn recording_construct(storage: *mut u8) -> *mut u8 {
        CONSTRUCT_CALLS += 1;
        LAST_STORAGE = storage;
        CONSTRUCT_RESULT
    }

    #[allow(clippy::too_many_arguments)]
    unsafe extern "C" fn recording_init(
        packet: *mut u8,
        owner: *mut u8,
        context: *mut u8,
        lingo: u8,
        command: u16,
        payload: *const u8,
        payload_len: u32,
    ) -> u32 {
        INIT_CALLS += 1;
        LAST_INIT_PACKET = packet;
        LAST_OWNER = owner;
        LAST_CONTEXT = context;
        LAST_LINGO = lingo;
        LAST_COMMAND = command;
        LAST_PAYLOAD = payload;
        LAST_PAYLOAD_LEN = payload_len;
        INIT_RESULT
    }

    unsafe extern "C" fn recording_destruct(packet: *mut u8) -> *mut u8 {
        DESTRUCT_CALLS += 1;
        LAST_DESTRUCT_PACKET = packet;
        DESTRUCT_RESULT
    }

    /// Installs the recording ops and the mock heap. Both guards travel
    /// together so no test ever takes either lock twice.
    fn install_mocks() -> (MutexGuard<'static, ()>, MutexGuard<'static, ()>) {
        let ops_guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let heap_guard = mock_heap();
        unsafe {
            IAP_PACKET_OPS = IapPacketOps {
                construct: recording_construct,
                init: recording_init,
                destruct: recording_destruct,
            };
            CONSTRUCT_CALLS = 0;
            LAST_STORAGE = core::ptr::null_mut();
            CONSTRUCT_RESULT = core::ptr::null_mut();
            INIT_CALLS = 0;
            LAST_INIT_PACKET = core::ptr::null_mut();
            LAST_OWNER = core::ptr::null_mut();
            LAST_CONTEXT = core::ptr::null_mut();
            LAST_LINGO = 0;
            LAST_COMMAND = 0;
            LAST_PAYLOAD = core::ptr::null();
            LAST_PAYLOAD_LEN = 0;
            INIT_RESULT = 1;
            DESTRUCT_CALLS = 0;
            LAST_DESTRUCT_PACKET = core::ptr::null_mut();
            DESTRUCT_RESULT = core::ptr::null_mut();
        }
        (ops_guard, heap_guard)
    }

    fn restore_mocks(guards: (MutexGuard<'static, ()>, MutexGuard<'static, ()>)) {
        unsafe { IAP_PACKET_OPS = DEFAULT_IAP_PACKET_OPS };
        drop(guards);
    }

    #[test]
    fn threads_every_argument_into_the_initializer_in_order() {
        let guards = install_mocks();
        let mut storage = [0u8; IAP_PACKET_SIZE];
        let packet = 0x0BEE_F000usize as *mut u8;
        let owner = 0x0111_1000usize as *mut u8;
        let payload = [0x01u8, 0x02, 0x03, 0x04];

        unsafe {
            set_alloc_ret(storage.as_mut_ptr());
            CONSTRUCT_RESULT = packet;
            INIT_RESULT = 1;

            let result = iap_packet_create(
                owner,
                core::ptr::null_mut(),
                LINGO_EXTENDED_INTERFACE,
                0x0018,
                payload.as_ptr(),
                payload.len() as u32,
            );

            assert_eq!(result, packet, "a successful init hands the packet to the caller");
            assert_eq!(alloc_log(), (1, IAP_PACKET_SIZE, 2), "one tag-2 operator_new(0x24)");
            assert_eq!(LAST_STORAGE, storage.as_mut_ptr(), "the block feeds the constructor");
            assert_eq!(CONSTRUCT_CALLS, 1);
            assert_eq!(INIT_CALLS, 1);
            assert_eq!(LAST_INIT_PACKET, packet, "the constructor's result is what gets inited");
            assert_eq!(LAST_OWNER, owner);
            assert!(LAST_CONTEXT.is_null(), "all 59 call sites pass NULL here");
            assert_eq!(LAST_LINGO, LINGO_EXTENDED_INTERFACE);
            assert_eq!(LAST_COMMAND, 0x0018);
            assert_eq!(LAST_PAYLOAD, payload.as_ptr());
            assert_eq!(LAST_PAYLOAD_LEN, payload.len() as u32);
            assert_eq!(DESTRUCT_CALLS, 0, "no teardown on the success path");
            assert_eq!(free_log().0, 0);
        }
        restore_mocks(guards);
    }

    #[test]
    fn carries_every_observed_lingo_and_a_full_width_command() {
        let guards = install_mocks();
        let mut storage = [0u8; IAP_PACKET_SIZE];

        unsafe {
            // The immediates decoded at the 59 call sites, plus the
            // constructor's 0xff "no lingo" sentinel.
            for lingo in [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0xff] {
                for command in [0u16, 1, 0x00ff, 0x0100, 0xffff] {
                    set_alloc_ret(storage.as_mut_ptr());
                    CONSTRUCT_RESULT = 0x0BEE_F000usize as *mut u8;
                    INIT_RESULT = 1;

                    iap_packet_create(
                        core::ptr::null_mut(),
                        core::ptr::null_mut(),
                        lingo,
                        command,
                        core::ptr::null(),
                        0,
                    );

                    assert_eq!(LAST_LINGO, lingo, "lingo is forwarded, never interpreted");
                    assert_eq!(LAST_COMMAND, command, "16-bit command survives intact");
                }
            }
        }
        restore_mocks(guards);
    }

    #[test]
    fn an_empty_payload_is_forwarded_verbatim() {
        let guards = install_mocks();
        let mut storage = [0u8; IAP_PACKET_SIZE];
        let packet = 0x0BEE_F000usize as *mut u8;

        unsafe {
            set_alloc_ret(storage.as_mut_ptr());
            CONSTRUCT_RESULT = packet;
            INIT_RESULT = 1;

            let result =
                iap_packet_create(core::ptr::null_mut(), core::ptr::null_mut(), 0, 0, core::ptr::null(), 0);

            assert_eq!(result, packet, "a zero-length body is success, not failure");
            assert!(LAST_PAYLOAD.is_null(), "the factory does not substitute a buffer");
            assert_eq!(LAST_PAYLOAD_LEN, 0);
        }
        restore_mocks(guards);
    }

    #[test]
    fn a_failed_init_destroys_and_frees_the_packet_and_returns_null() {
        let guards = install_mocks();
        let mut storage = [0u8; IAP_PACKET_SIZE];
        let packet = 0x0BEE_F000usize as *mut u8;

        unsafe {
            set_alloc_ret(storage.as_mut_ptr());
            CONSTRUCT_RESULT = packet;
            DESTRUCT_RESULT = packet;
            INIT_RESULT = 0;

            let result = iap_packet_create(
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                0,
                0,
                [0xaau8].as_ptr(),
                1,
            );

            assert!(result.is_null(), "a failed init yields NULL, not a half-built packet");
            assert_eq!(DESTRUCT_CALLS, 1);
            assert_eq!(LAST_DESTRUCT_PACKET, packet);
            assert_eq!(free_log(), (1, packet, 2), "tag-2 operator_delete of the packet");
        }
        restore_mocks(guards);
    }

    #[test]
    fn the_delete_takes_the_destructors_result_not_the_saved_pointer() {
        let guards = install_mocks();
        let mut storage = [0u8; IAP_PACKET_SIZE];
        let packet = 0x0BEE_F000usize as *mut u8;
        // The real destructor ends in `mov r0, r4`; the factory never
        // reloads r4, so a destructor returning something else is what the
        // delete would receive.
        let relocated = 0x0BEE_F100usize as *mut u8;

        unsafe {
            set_alloc_ret(storage.as_mut_ptr());
            CONSTRUCT_RESULT = packet;
            DESTRUCT_RESULT = relocated;
            INIT_RESULT = 0;

            assert!(iap_packet_create(
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                4,
                0x0018,
                core::ptr::null(),
                0
            )
            .is_null());
            assert_eq!(free_log(), (1, relocated, 2), "r0 out of the destructor is r0 into delete");
        }
        restore_mocks(guards);
    }

    #[test]
    fn a_null_constructed_packet_short_circuits_before_init() {
        let guards = install_mocks();

        unsafe {
            set_alloc_ret(core::ptr::null_mut());
            CONSTRUCT_RESULT = core::ptr::null_mut();

            let result = iap_packet_create(
                0x0111_1000usize as *mut u8,
                core::ptr::null_mut(),
                4,
                0x0018,
                core::ptr::null(),
                0,
            );

            assert!(result.is_null());
            assert_eq!(CONSTRUCT_CALLS, 1, "the constructor runs before the NULL test");
            assert!(LAST_STORAGE.is_null(), "on the NULL block verbatim");
            assert_eq!(INIT_CALLS, 0, "and the initializer never runs");
            assert_eq!(DESTRUCT_CALLS, 0, "nor the destructor");
            assert_eq!(free_log().0, 0, "nor operator_delete");
        }
        restore_mocks(guards);
    }

    #[test]
    fn reinit_forwards_all_seven_arguments_to_the_initializer_in_order() {
        let guards = install_mocks();
        let packet = 0x0BEE_F000usize as *mut u8;
        let owner = 0x0111_1000usize as *mut u8;
        let context = 0x0222_2000usize as *mut u8;
        let payload = [0xaau8, 0xbb, 0xcc];

        unsafe {
            INIT_RESULT = 1;

            let result = iap_packet_reinit(packet, owner, context, 0xa5, 0xbeef, payload.as_ptr(), 0x0eed);

            assert_eq!(result, 1, "the initializer's success flag comes back in r0");
            assert_eq!(INIT_CALLS, 1);
            assert_eq!(LAST_INIT_PACKET, packet, "r0 rides the r4/lr/ip shuffle untouched");
            assert_eq!(LAST_OWNER, owner);
            assert_eq!(LAST_CONTEXT, context);
            assert_eq!(LAST_LINGO, 0xa5);
            assert_eq!(LAST_COMMAND, 0xbeef);
            assert_eq!(LAST_PAYLOAD, payload.as_ptr(), "stack argument, bounced verbatim");
            assert_eq!(LAST_PAYLOAD_LEN, 0x0eed, "stack argument, bounced verbatim");
            assert_eq!(CONSTRUCT_CALLS, 0, "the reinit path allocates nothing");
            assert_eq!(DESTRUCT_CALLS, 0);
            assert_eq!(alloc_log().0, 0);
            assert_eq!(free_log().0, 0);
        }
        restore_mocks(guards);
    }

    #[test]
    fn reinit_forwards_the_initializers_failure_verbatim() {
        let guards = install_mocks();
        let packet = 0x0BEE_F000usize as *mut u8;

        unsafe {
            INIT_RESULT = 0;

            let result =
                iap_packet_reinit(packet, core::ptr::null_mut(), core::ptr::null_mut(), 4, 0x3d, core::ptr::null(), 0);

            assert_eq!(result, 0, "a failed init propagates unchanged");
            assert_eq!(LAST_INIT_PACKET, packet);
            assert_eq!(DESTRUCT_CALLS, 0, "the wrapper does no teardown of its own");
            assert_eq!(free_log().0, 0);
        }
        restore_mocks(guards);
    }

    #[test]
    fn reinit_passes_null_arguments_through_unguarded() {
        let guards = install_mocks();

        unsafe {
            INIT_RESULT = 1;

            let result = iap_packet_reinit(
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                0,
                0,
                core::ptr::null(),
                0,
            );

            assert_eq!(result, 1);
            assert_eq!(INIT_CALLS, 1);
            assert!(LAST_INIT_PACKET.is_null(), "no NULL guard, matching the 43 unconditional call sites");
            assert!(LAST_OWNER.is_null());
        }
        restore_mocks(guards);
    }

    /// Fixture layout for [`iap_packet_owner_mode`] inside the low slab:
    /// the packet at +0x00 (only its +0x00 owner slot is read) and the
    /// owner object at +0x40 (only its +0x08 mode word is read).
    mod owner_mode {
        extern crate std;

        use super::super::iap_packet_owner_mode;
        use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
        use std::sync::LazyLock;

        const SLAB_LEN: usize = 0x1000;
        const OFF_PACKET: usize = 0x00;
        const OFF_OWNER: usize = 0x40;
        /// Tests run on parallel threads against one shared slab, so each
        /// gets its own 0x80-byte region instead of a lock.
        const REGION: usize = 0x80;

        static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
            try_map_u32_slab(hints::IAP_PACKET_OWNER_MODE, SLAB_LEN).map(|p| p as usize)
        });

        /// Builds the two-word chain in `region`: packet.owner = owner,
        /// owner.mode = mode. `owner == 0` models the ownerless packet.
        fn with_chain(region: usize, owner: bool, mode: u32, body: impl FnOnce(u32)) {
            let Some(slab) = *SLAB else {
                assert!(note_missing_u32_fixture("app::iap_packet::owner_mode"));
                return;
            };
            let base = slab + region;
            unsafe {
                let packet = (base + OFF_PACKET) as *mut u32;
                let owner_slot = (base + OFF_OWNER) as u32;
                packet.write(if owner { owner_slot } else { 0 });
                ((base + OFF_OWNER + 0x08) as *mut u32).write(mode);
                body(iap_packet_owner_mode((base + OFF_PACKET) as *const u8));
            }
        }

        #[test]
        fn an_ownerless_packet_reports_mode_zero() {
            with_chain(0 * REGION, false, 0xdead_beef, |result| {
                assert_eq!(result, 0, "NULL owner short-circuits to 0 without touching the mode word");
            });
        }

        #[test]
        fn the_sync_framing_mode_passes_through() {
            with_chain(1 * REGION, true, 1, |result| {
                assert_eq!(result, 1, "mode 1 is what makes the serializer emit the 0xff sync byte");
            });
        }

        #[test]
        fn a_present_owner_with_zero_mode_reports_zero_through_the_load_path() {
            with_chain(2 * REGION, true, 0, |result| {
                assert_eq!(result, 0, "same answer as the NULL case, but via ldrne, not the guard");
            });
        }

        #[test]
        fn boundary_modes_pass_through() {
            for mode in [2u32, 3, 4] {
                with_chain(3 * REGION, true, mode, |result| {
                    assert_eq!(result, mode, "the remap table's meaningful range is 0..=4");
                });
            }
        }

        #[test]
        fn the_mode_word_is_returned_verbatim_at_full_width() {
            with_chain(4 * REGION, true, 0xffff_ffff, |result| {
                assert_eq!(result, 0xffff_ffff, "a full 32-bit word, no truncation or sign play");
            });
        }
    }
}
