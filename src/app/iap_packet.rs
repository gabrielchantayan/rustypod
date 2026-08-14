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
}
