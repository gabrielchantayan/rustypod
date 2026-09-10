//! The **iAP incoming-client base class constructor** — the shared
//! base of every object that registers itself as a client of the
//! `CIapIncomingProcessThread` incoming-packet worker (see
//! `app/iap_incoming_process_thread.rs`).
//!
//! | address | name | size | `bl` sites |
//! |---|---|---|---|
//! | 0x08139dec | [`iap_incoming_client_base_construct`] | 144 | **14** |
//!
//! ## Extent
//!
//! 144 bytes, 0x08139dec..0x08139e7c: 140 instruction bytes (Ghidra's
//! "140" is exact for the code) plus the vtable literal `0x08984cb8`
//! at 0x08139e78, which the first `ldr` reaches with `[pc, #128]`.
//! The next function opens at 0x08139e7c with `push {r4, lr}` — it is
//! the matching base *destructor* (replants the same vtable, polls and
//! unregisters the slot, destroys the mutex, returns `this`), a
//! separate port. Byte-decoded from `work/firmware/osos.dec`, not from
//! Ghidra's C (which drops the constructor's register-shape arguments
//! and mislabels the pool loop).
//!
//! ## Call sites
//!
//! Binary-scanned by decoding every ARM B/BL word in osos.dec and
//! resolving its target: **14 `bl` sites, all unconditional**
//! (0x0813a2e8, 0x081650b0, 0x08193cbc, 0x08193e3c, 0x08195338,
//! 0x08196e94, 0x081af24c, 0x081d7c30, 0x081e30b8, 0x081f25f0,
//! 0x081f38ec, 0x08200c64, 0x08201224, 0x08209548), zero predicated
//! forms, zero tail `b`, and no DATA word anywhere references the
//! address — only ever direct-called, never dispatched virtually.
//! Every site is a derived-class constructor that immediately
//! overwrites the vtable word with its own (e.g. 0x081650ac plants
//! 0x08987e04 and extends the object at +0x2d0, which is what proves
//! the base object size below).
//!
//! ## The object
//!
//! ```text
//! +0x000  vtable 0x08984cb8 (stale RW data in the image — the
//!         resource_list precedent: the literal ADDRESS is stored,
//!         the runtime table is not in the decrypted blob)
//! +0x004  .. +0x2ab  zeroed by the 0x2a8-byte memzero
//! +0x018  embedded pool free-list head (threaded through node+0x00)
//! +0x02c  node pool: 32 nodes x 20 bytes, spanning +0x02c..+0x2ac
//! +0x2ac  C++ mutex wrapper, 0x1c bytes (ctor 0x08261e28), guarding
//!         the pool
//! +0x2c8  iAP incoming-thread registration slot index, -1 = none
//! +0x2cc  self pointer
//! size    0x2d0
//! ```
//!
//! ## Algorithm (raw ARM)
//!
//! ```text
//! 08139dec  push {r4, r5, r6, lr}
//! 08139df0  ldr  r1, [pc, #128]    @ vtable literal 0x08984cb8
//! 08139df4  str  r1, [r0], #0x2ac  @ plant vtable, r0 = this+0x2ac
//! 08139df8  bl   0x08261e28        @ cxx_mutex_construct(&this->mutex)
//! 08139dfc  sub  r4, r0, #0x2ac    @ r4 = this (ctor returns its arg)
//! 08139e00  mvn  r0, #0
//! 08139e04  str  r0, [r4, #0x2c8]  @ slot = -1
//! 08139e08  add  r0, r4, #4        @ memzero dst = this+4
//! 08139e0c  add  r6, r4, #0x18     @ &pool head
//! 08139e10  add  r5, r4, #0x2c     @ first pool node
//! 08139e14  mov  r1, #0x2a8
//! 08139e18  str  r4, [r4, #0x2cc]  @ self = this
//! 08139e1c  bl   0x08037db8        @ memzero(this+4, 0x2a8)
//! 08139e20  mov  r0, #0            @ count
//! 08139e24  ldr  r1, [r6]          @  loop: head
//! 08139e28  add  r0, r0, #1
//! 08139e2c  str  r1, [r5]          @  node->next = head
//! 08139e30  bic  r0, r0, #0x10000  @  count &= ~0x10000 (dead: 1..32)
//! 08139e34  str  r5, [r6]          @  head = node
//! 08139e38  cmp  r0, #32
//! 08139e3c  add  r5, r5, #20
//! 08139e40  bcc  0x08139e24
//! 08139e44  bl   0x081d71c0        @ iap_incoming_process_thread_instance
//! 08139e48  mov  r3, #1
//! 08139e4c  mov  r2, r4
//! 08139e50  mov  r1, #1
//! 08139e54  bl   0x081d6e38        @ register_client(thread,1,this,1)
//! 08139e58  cmn  r0, #1
//! 08139e5c  str  r0, [r4, #0x2c8]  @ slot = result (stored even on -1)
//! 08139e60  bleq 0x08030f44        @ slot == -1 -> heap_panic
//! 08139e64  bl   0x081d71c0        @ instance RE-READ
//! 08139e68  ldr  r1, [r4, #0x2c8]
//! 08139e6c  bl   0x081d7270        @ slot_poll(thread, slot)
//! 08139e70  mov  r0, r4
//! 08139e74  pop  {r4, r5, r6, pc}
//! ```
//!
//! The pool threads 32 twenty-byte nodes onto the head word newest-
//! first, so afterwards head = node 31 (@ this+0x298) and node 0
//! (@ this+0x2c) terminates the chain with NULL. The registration
//! call 0x081d6e38 wraps the registry body 0x081d6dbc: under the
//! thread context's registry mutex it takes a free slot of the 29-slot
//! table at context+0x154, builds a 0x24-byte wait-registration object
//! (`operator_new(0x24)` + ctor 0x08257cc8) into the slot's +0 word,
//! stores the client (`this`) in the slot's +4 context word, and
//! returns the slot index — or -1 when the table is full or the
//! allocation fails. The constructor then immediately runs one
//! zero-timeout slot poll, draining any signal posted before the
//! client finished constructing.
//!
//! Of the two constant-1 arguments, r1 seeds the scoped object built
//! inside 0x081d6e38 (`bl 0x08261e94` with r1 intact); r3 is carried
//! into 0x081d6dbc but never read there. Both are preserved verbatim.
//!
//! ## Deviations
//!
//! - The registration wrapper 0x081d6e38 is ported as
//!   [`iap_incoming_process_thread_register_client`]. Its unported registry
//!   body @ 0x081d6dbc remains behind that function's
//!   `IAP_THREAD_REGISTER_CLIENT_OPS` seam, whose target default reaches the
//!   stock body and whose host model records the deadline.
//! - The pool-zeroing veneer 0x08037db8 resolves to the IRAM copy of
//!   `memzero_aligned` (names.yaml alias resolution); the port calls
//!   the ported [`memzero_aligned`] through a `read_volatile` callee
//!   load (the libc/iram_veneers pattern) — LLVM recognizes its body
//!   as a memset idiom and would otherwise inline it and re-lower the
//!   loop to `__aeabi_memclr4`, so the port would stop reaching the
//!   ported symbol.
//! - The mutex constructor @ 0x08261e28, the instance accessor @
//!   0x081d71c0, the slot poll @ 0x081d7270 and the fatal @
//!   0x08030f44 are all ported and called directly.
//! - `_incoming_r1`/`scope_word0`/`scope_word1` exist only to keep the
//!   register shape: the original overwrites r1 with the vtable
//!   literal and passes its caller's r2/r3 straight into
//!   `cxx_mutex_construct`'s stack-scope seeds (the ADS
//!   uninitialized-frame idiom that port documents).
//! - The fatal path (`slot == -1` -> [`heap_panic`]) is not exercised
//!   on host: `heap_panic` is `-> !`, the `app/pending_event_take`
//!   precedent. Note the original stores the -1 to +0x2c8 BEFORE the
//!   panic check; the port preserves that store order.

use crate::cxx::mutex::cxx_mutex_construct;
use crate::heap::veneers::heap_panic;
use crate::libc::memzero::memzero_aligned;

use super::iap_incoming_process_thread::{
    iap_incoming_process_thread_instance, iap_incoming_process_thread_register_client,
    iap_incoming_process_thread_slot_poll,
};

/// The base-class vtable address planted at this+0x00 (the literal @
/// 0x08139e78). The runtime table is not readable in the image — the
/// 0x0898xxxx pages hold stale RW data there — so only the address
/// constant survives, the `util/resource_list` precedent.
pub const IAP_INCOMING_CLIENT_BASE_VTABLE: u32 = 0x0898_4cb8;

/// Offset of the embedded pool's free-list head word (original `add
/// r6, r4, #0x18`; threaded through each node's +0x00).
pub const POOL_HEAD_OFFSET: usize = 0x18;

/// Offset of the first pool node (original `add r5, r4, #0x2c`).
pub const POOL_NODES_OFFSET: usize = 0x2c;

/// Number of pool nodes (original `cmp r0, #32`).
pub const POOL_NODE_COUNT: u32 = 32;

/// Bytes per pool node (original `add r5, r5, #20`).
pub const POOL_NODE_STRIDE: usize = 20;

/// Offset of the embedded C++ mutex wrapper (original `str r1, [r0],
/// #0x2ac` post-index).
pub const MUTEX_OFFSET: usize = 0x2ac;

/// Offset of the iAP thread registration slot index (original `str
/// r0, [r4, #0x2c8]`); -1 is the no-slot sentinel.
pub const SLOT_INDEX_OFFSET: usize = 0x2c8;

/// Offset of the self pointer (original `str r4, [r4, #0x2cc]`).
pub const SELF_POINTER_OFFSET: usize = 0x2cc;

/// Start of the zeroed span (original `add r0, r4, #4`).
pub const ZERO_FILL_OFFSET: usize = 4;

/// Length of the zeroed span (original `mov r1, #0x2a8`): this+0x04
/// through this+0x2ab — the head word and the whole pool are zeroed
/// before the threading loop runs.
pub const ZERO_FILL_LEN: usize = 0x2a8;


#[inline(always)]
unsafe fn read_word(base: *mut u8, offset: usize) -> u32 {
    (base.wrapping_add(offset) as *const u32).read()
}

#[inline(always)]
unsafe fn write_word(base: *mut u8, offset: usize, value: u32) {
    (base.wrapping_add(offset) as *mut u32).write(value);
}

/// iap_incoming_client_base_construct — original: `FUN_08139dec` @
/// 0x08139dec (**144 bytes** including the vtable literal; 14
/// unconditional `bl` call sites, binary-verified — see the module
/// header for the full analysis).
///
/// Constructs the iAP incoming-client base object at `this`: plants
/// the base vtable, constructs the pool-guard mutex at +0x2ac, sets
/// the slot index to -1 and the self pointer, zeroes +0x04..+0x2ac,
/// threads the 32-node embedded pool onto the free-list head, then
/// registers `this` with the `CIapIncomingProcessThread` context
/// (fatal on slot exhaustion), and finishes with one zero-timeout
/// poll of the new slot. Returns `this`.
///
/// # Safety
///
/// `this` must point at a writable 0x2d0-byte object. The embedded
/// pool and the self pointer are raw u32 words, so on a 64-bit host
/// `this` must be below 4 GiB (the tests map a slab). A live
/// `CIapIncomingProcessThread` context must be published (the
/// accessor is fatal on NULL) unless the registration seam is
/// mocked.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn iap_incoming_client_base_construct(
    this: *mut u8,
    _incoming_r1: usize,
    scope_word0: usize,
    scope_word1: usize,
) -> *mut u8 {
    (this as *mut u32).write(IAP_INCOMING_CLIENT_BASE_VTABLE);
    cxx_mutex_construct(
        this.wrapping_add(MUTEX_OFFSET),
        IAP_INCOMING_CLIENT_BASE_VTABLE as usize,
        scope_word0,
        scope_word1,
    );
    write_word(this, SLOT_INDEX_OFFSET, 0xffff_ffff);
    write_word(this, SELF_POINTER_OFFSET, this as usize as u32);
    // Load the callee through read_volatile: LLVM recognises
    // memzero_aligned as a memset idiom and would otherwise inline it
    // and re-lower the loop to __aeabi_memclr4, so the port would stop
    // reaching the ported symbol the original's veneer targets (the
    // libc/iram_veneers pattern).
    let zero =
        core::ptr::read_volatile(&(memzero_aligned as unsafe extern "C" fn(*mut u8, usize) -> *mut u8));
    zero(this.wrapping_add(ZERO_FILL_OFFSET), ZERO_FILL_LEN);
    let mut count: u32 = 0;
    let mut node = this.wrapping_add(POOL_NODES_OFFSET);
    loop {
        let head = read_word(this, POOL_HEAD_OFFSET);
        count = count.wrapping_add(1);
        (node as *mut u32).write(head);
        count &= !0x1_0000;
        write_word(this, POOL_HEAD_OFFSET, node as usize as u32);
        if count >= POOL_NODE_COUNT {
            break;
        }
        node = node.wrapping_add(POOL_NODE_STRIDE);
    }
    let thread = iap_incoming_process_thread_instance();
    let slot = iap_incoming_process_thread_register_client(thread, 1, this, 1);
    write_word(this, SLOT_INDEX_OFFSET, slot as u32);
    if slot == -1 {
        heap_panic();
    }
    let thread = iap_incoming_process_thread_instance();
    iap_incoming_process_thread_slot_poll(thread, slot as u32);
    this
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use super::super::iap_incoming_process_thread::{
        IapThreadRegistrationDeadline, IapThreadRegistrationOps, IapThreadSlotPollOps,
        IAP_INCOMING_PROCESS_THREAD_INSTANCE, IAP_THREAD_REGISTER_CLIENT_OPS,
        IAP_THREAD_SLOT_POLL_OPS, SLOT_STRIDE, SLOT_TABLE_OFFSET,
    };
    use crate::cxx::mutex::CXX_MUTEX_STATUS_OFFSET;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes the tests: they share one fixture slab (the mapper
    /// never unmaps), the instance static, and two ops tables.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    /// Client object at +0x000 (0x2d0 bytes, padded), first thread
    /// context at +0x400, second at +0x800 (the instance re-read
    /// test), each 0x240 bytes plus slack for fake slot objects.
    const SLAB_LEN: usize = 0x1000;
    const CLIENT_OFF: usize = 0x000;
    const THREAD_A_OFF: usize = 0x400;
    const THREAD_B_OFF: usize = 0x800;

    /// The registration calls observed by the mock, in order:
    /// (thread, deadline seconds, deadline nanos, client, unread seed).
    static mut REGISTERED: Vec<(usize, i32, i32, usize, u32)> = Vec::new();
    /// The slot-object pointers the poll mock has received, in order.
    static mut POLLED: Vec<usize> = Vec::new();
    /// Slot index the register mock returns.
    static mut MOCK_SLOT: i32 = 0;
    /// When set, the register mock re-publishes the second thread
    /// fixture before returning, so the poll must follow the RE-READ.
    static mut REPUBLISH_B: bool = false;

    struct Bench {
        _lock: MutexGuard<'static, ()>,
        previous_register_ops: IapThreadRegistrationOps,
        previous_poll_ops: IapThreadSlotPollOps,
        previous_instance: *mut u8,
        available: bool,
    }

    unsafe fn slab() -> *mut u8 {
        // Mapped once per process at the unique hint; every later call
        // gets the same block back because the region stays occupied.
        static mut SLAB: *mut u8 = core::ptr::null_mut();
        if SLAB.is_null() {
            match try_map_u32_slab(hints::IAP_INCOMING_CLIENT_BASE, SLAB_LEN) {
                Some(p) => SLAB = p,
                None => {
                    note_missing_u32_fixture("app::iap_incoming_client_base");
                }
            }
        }
        SLAB
    }

    unsafe fn client() -> *mut u8 {
        slab().wrapping_add(CLIENT_OFF)
    }

    unsafe fn thread_a() -> *mut u8 {
        slab().wrapping_add(THREAD_A_OFF)
    }

    unsafe fn thread_b() -> *mut u8 {
        slab().wrapping_add(THREAD_B_OFF)
    }

    unsafe fn word(base: *mut u8, offset: usize) -> u32 {
        (base.wrapping_add(offset) as *const u32).read()
    }

    /// A believable slot-object pointer for a thread fixture: inside
    /// the slab, past the context's own 0x240 bytes, never
    /// dereferenced (the poll callee is mocked).
    unsafe fn fake_slot_object(thread: *mut u8, n: usize) -> u32 {
        thread.wrapping_add(0x240 + n * 4) as usize as u32
    }

    fn bench(slot: i32) -> Bench {
        let lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let available = unsafe { !slab().is_null() };
        let (previous_register_ops, previous_poll_ops, previous_instance) = unsafe {
            (
                ptr::read_volatile(ptr::addr_of!(IAP_THREAD_REGISTER_CLIENT_OPS)),
                ptr::read_volatile(ptr::addr_of!(IAP_THREAD_SLOT_POLL_OPS)),
                ptr::read_volatile(ptr::addr_of!(IAP_INCOMING_PROCESS_THREAD_INSTANCE)),
            )
        };
        if available {
            unsafe {
                ptr::write_bytes(client(), 0xa5, 0x2d0);
                ptr::write_bytes(thread_a(), 0, 0x300);
                ptr::write_bytes(thread_b(), 0, 0x300);
                REGISTERED.clear();
                POLLED.clear();
                MOCK_SLOT = slot;
                REPUBLISH_B = false;
                ptr::write_volatile(
                    ptr::addr_of_mut!(IAP_THREAD_REGISTER_CLIENT_OPS),
                    IapThreadRegistrationOps {
                        register_client: mock_register_client,
                    },
                );
                ptr::write_volatile(
                    ptr::addr_of_mut!(IAP_THREAD_SLOT_POLL_OPS),
                    IapThreadSlotPollOps {
                        poll_slot_object: mock_poll_slot_object,
                    },
                );
                ptr::write_volatile(
                    ptr::addr_of_mut!(IAP_INCOMING_PROCESS_THREAD_INSTANCE),
                    thread_a(),
                );
            }
        }
        Bench {
            _lock: lock,
            previous_register_ops,
            previous_poll_ops,
            previous_instance,
            available,
        }
    }

    impl Drop for Bench {
        fn drop(&mut self) {
            if self.available {
                unsafe {
                    ptr::write_volatile(
                        ptr::addr_of_mut!(IAP_THREAD_REGISTER_CLIENT_OPS),
                        self.previous_register_ops,
                    );
                    ptr::write_volatile(
                        ptr::addr_of_mut!(IAP_THREAD_SLOT_POLL_OPS),
                        self.previous_poll_ops,
                    );
                    ptr::write_volatile(
                        ptr::addr_of_mut!(IAP_INCOMING_PROCESS_THREAD_INSTANCE),
                        self.previous_instance,
                    );
                }
            }
        }
    }

    unsafe extern "C" fn mock_register_client(
        thread: *mut u8,
        deadline: *const IapThreadRegistrationDeadline,
        client: *mut u8,
        unread_seed: u32,
    ) -> i32 {
        REGISTERED.push((
            thread as usize,
            (*deadline).seconds,
            (*deadline).nanos,
            client as usize,
            unread_seed,
        ));
        if REPUBLISH_B {
            ptr::write_volatile(
                ptr::addr_of_mut!(IAP_INCOMING_PROCESS_THREAD_INSTANCE),
                thread_b(),
            );
        }
        MOCK_SLOT
    }

    unsafe extern "C" fn mock_poll_slot_object(slot_object: *mut u8) {
        POLLED.push(slot_object as usize);
    }

    /// Seed the slot table of a thread fixture so the real slot_poll
    /// resolves `slot` to `fake_slot_object(thread, salt)`.
    unsafe fn seed_slot(thread: *mut u8, slot: u32, salt: usize) -> u32 {
        let object = fake_slot_object(thread, salt);
        (thread.wrapping_add(SLOT_TABLE_OFFSET + slot as usize * SLOT_STRIDE) as *mut u32)
            .write(object);
        object
    }

    #[test]
    fn constructs_the_full_layout_and_registers() {
        let bench = bench(3);
        if !bench.available {
            return;
        }
        unsafe {
            let object = seed_slot(thread_a(), 3, 0);
            let this = client();
            let result = iap_incoming_client_base_construct(this, 0xaaaa, 0xbbbb, 0xcccc);
            assert_eq!(result, this, "the constructor returns this");

            assert_eq!(
                word(this, 0),
                IAP_INCOMING_CLIENT_BASE_VTABLE,
                "the base vtable literal is planted at +0x00"
            );
            // The 0x2a8-byte zero fill: everything in +0x04..+0x2ac
            // that the pool threading did not touch is zero.
            for offset in (4..POOL_HEAD_OFFSET).step_by(4) {
                assert_eq!(word(this, offset), 0, "zeroed word at +{offset:#x}");
            }
            for offset in (POOL_HEAD_OFFSET + 4..POOL_NODES_OFFSET).step_by(4) {
                assert_eq!(word(this, offset), 0, "zeroed word at +{offset:#x}");
            }
            // The pool: head is the LAST threaded node (this+0x298),
            // each node's +0x00 chains to the previous node, node 0
            // terminates with NULL; words 1..4 of every node stay zero.
            let mut node = word(this, POOL_HEAD_OFFSET);
            for i in (0..POOL_NODE_COUNT).rev() {
                let expect = this.wrapping_add(POOL_NODES_OFFSET + i as usize * POOL_NODE_STRIDE)
                    as usize as u32;
                assert_eq!(node, expect, "head chain reaches node {i}");
                let node_ptr = node as usize as *mut u8;
                for w in 1..5 {
                    assert_eq!(
                        word(node_ptr, w * 4),
                        0,
                        "node {i} word {w} remains zeroed"
                    );
                }
                node = word(node_ptr, 0);
            }
            assert_eq!(node, 0, "the oldest node terminates the free list");
            assert_eq!(
                word(this, MUTEX_OFFSET + CXX_MUTEX_STATUS_OFFSET),
                0,
                "the embedded mutex wrapper records a successful init"
            );
            assert_eq!(word(this, SLOT_INDEX_OFFSET), 3, "the slot index is stored");
            assert_eq!(
                word(this, SELF_POINTER_OFFSET),
                this as usize as u32,
                "the self pointer is stored"
            );

            assert_eq!(
                REGISTERED.as_slice(),
                &[(thread_a() as usize, 0, 1_000_000, this as usize, 1)],
                "one registration receives the original's one-millisecond deadline"
            );
            assert_eq!(
                POLLED.as_slice(),
                &[object as usize],
                "the fresh slot gets its one zero-timeout poll"
            );
        }
    }

    #[test]
    fn the_thread_instance_is_re_read_for_the_poll() {
        let bench = bench(5);
        if !bench.available {
            return;
        }
        unsafe {
            seed_slot(thread_a(), 5, 1);
            let object_b = seed_slot(thread_b(), 5, 2);
            REPUBLISH_B = true;
            let this = client();
            iap_incoming_client_base_construct(this, 0, 0, 0);
            assert_eq!(
                REGISTERED.as_slice(),
                &[(thread_a() as usize, 0, 1_000_000, this as usize, 1)],
                "the registration went to the instance published at entry"
            );
            assert_eq!(
                POLLED.as_slice(),
                &[object_b as usize],
                "the poll followed the SECOND accessor read, not a cached one"
            );
        }
    }

    #[test]
    fn register_client_preserves_signed_timeout_remainder() {
        let bench = bench(0);
        if !bench.available {
            return;
        }
        unsafe {
            iap_incoming_process_thread_register_client(thread_a(), -1001, client(), 0xfeed_beef);
            assert_eq!(
                REGISTERED.as_slice(),
                &[(thread_a() as usize, -1, -1_000_000, client() as usize, 0xfeed_beef)],
                "the wrapper stores signed division's quotient and remainder as a timespec"
            );
        }
    }

    #[test]
    fn the_last_table_slot_flows_through_verbatim() {
        let bench = bench(28);
        if !bench.available {
            return;
        }
        unsafe {
            let object = seed_slot(thread_a(), 28, 3);
            let this = client();
            iap_incoming_client_base_construct(this, 0, 0, 0);
            assert_eq!(
                word(this, SLOT_INDEX_OFFSET),
                28,
                "slot 28 (the table's last) is stored unmasked"
            );
            assert_eq!(
                POLLED.as_slice(),
                &[object as usize],
                "and resolves to that slot's own registration object"
            );
        }
    }
}
