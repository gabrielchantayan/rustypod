//! Port of the block-manager client's **erase** op — the block hand-back
//! `pool_base_release_blocks` (heap/block_deque.rs) runs on the deque
//! before the commit @ 0x081fc884:
//!
//! - `client_erase` — original: `FUN_081fc080` @ 0x081fc080 (136 bytes;
//!   2 `bl` call sites @ 0x0814bb54 (FUN_0814bb18) and 0x08214198
//!   (`pool_base_release_blocks`), binary-verified). Under the client's
//!   own mutex (client + 0x24 — NOT the pool base's +0x8 one — through
//!   the same C++ owner-tracked mutex pair @ 0x082e8390 / 0x082e83d8 via the
//!   alias thunks @ 0x082621a8 / 0x082621ac), it drains the whole deque
//!   back to the block manager: the hand-back word is preset to 0 (dead
//!   store, kept), the deque count (+0x20) is snapshotted once into the
//!   loop counter, and each iteration
//!     1. copies the 16-byte begin iterator onto the stack through the
//!        0x083d9ec8 copy of `deque_iter_assign` (cxx/templates.rs — one
//!        of the 17 byte-identical copies; real port, called directly,
//!        the handle_deref_or_null-copy precedent),
//!     2. reads the front element's block word: element word 1
//!        (elem + 0x4) is the region object pointer (block_region.rs's
//!        `ELEM_REGION_INDEX`), and the u32 at region + 0xc is the word
//!        handed back (0x081fc124's body dereferences it further as a
//!        handle middle),
//!     3. pops the front element through the real `deque_pop_front`
//!        @ 0x083ddbdc (heap/block_deque.rs — the element's virtual
//!        destructor and any segment/map retirement happen there),
//!     4. hands the block word to the manager: 0x081fc124(client,
//!        &block).
//!   After the loop the drained/completion notification pair runs —
//!   0x081fbf1c(client, 1) then 0x081fc230(client), both verdicts
//!   discarded (the original overwrites r0 with the unlock address just
//!   the same) — and the mutex is released.
//!
//! # Deviations
//!
//! - **Mutex**: client + 0x24 is locked/unlocked through
//!   block_region.rs's `REGION_MUTEX_OPS` (one boundary for the one
//!   original pair — the block_deque.rs precedent; the defaults are
//!   the real ports, kernel/posix_mutex.rs).
//! - **Unported client machinery** dispatches through
//!   [`CLIENT_ERASE_OPS`] (house ops-slot pattern, indirect `blx` in
//!   place of `bl`): the per-block hand-back @ 0x081fc124 and the two
//!   tail notifications @ 0x081fbf1c / 0x081fc230. The defaults are
//!   documented no-ops — the no-manager state, which is the contract
//!   the old `stub_client_erase` default faked wholesale. Both
//!   notifications return a 0/1 verdict the only callers discard, so
//!   the slots return `()`.
//! - **Shipped wiring**: the port is the default of
//!   `POOL_BASE_OPS.client_erase` (heap/block_deque.rs), replacing the
//!   no-op stub — with the no-op defaults above the replacement is
//!   behavior-identical (a drained deque, nothing else), and the real
//!   pop_front now runs where the stub did nothing.
//! - The loop bound is the count **snapshotted before the loop**
//!   (`ldr r4, [r6, #0x20]` precedes the loop; `sub r4, r4, #1` counts
//!   down) — not re-read off the deque, even though `deque_pop_front`
//!   decrements the deque's own count in parallel; the two stay in
//!   lockstep for any well-formed deque, exactly as in the original.
//! - The region's block word is read by literal byte offset 0xc (a
//!   u32, not a pointer field — the util/state_flags.rs precedent);
//!   the element's region pointer is read by pointer word index
//!   (block_region.rs's host-layout lesson).

use crate::cxx::templates::deque_iter_assign;
use crate::heap::block_deque::{deque_pop_front, BlockDeque, DequeIter};
use crate::heap::block_region::REGION_MUTEX_OPS;

/// Byte offset of the client object's own mutex (original:
/// `add r0, r0, #0x24` ahead of both thunk calls). Opaque storage,
/// locked by address — the client object (0x170 bytes, ctor
/// 0x081e6b34) is otherwise unported.
pub const CLIENT_MUTEX_OFFSET: usize = 0x24;

/// u32 index of the block word inside the region object (byte offset
/// 0xc on the 32-bit target — see the module header).
const REGION_BLOCK_INDEX: usize = 3;

/// Indirect dispatch table for the unported callees (see the module
/// header for each default's contract).
#[derive(Clone, Copy)]
pub struct ClientEraseOps {
    /// Per-block hand-back @ 0x081fc124 `(client, &block)`: runs once
    /// per popped element, after the pop.
    pub hand_back_block: unsafe extern "C" fn(client: *mut u8, block: *mut u32),
    /// Drained notification @ 0x081fbf1c `(client, 1)`. The verdict is
    /// discarded by every caller.
    pub notify_drained: unsafe extern "C" fn(client: *mut u8, flag: u32),
    /// Completion notification @ 0x081fc230 `(client)`. Verdict
    /// discarded, as above.
    pub notify_complete: unsafe extern "C" fn(client: *mut u8),
}

/// Default hand-back stub: no block manager — nothing to hand back to
/// (the no-manager contract of the `stub_client_erase` default this
/// table's consumer replaces).
unsafe extern "C" fn stub_hand_back_block(_client: *mut u8, _block: *mut u32) {}

/// Default notification stubs: see [`stub_hand_back_block`].
unsafe extern "C" fn stub_notify_drained(_client: *mut u8, _flag: u32) {}

unsafe extern "C" fn stub_notify_complete(_client: *mut u8) {}

/// Wired defaults (documented no-ops until the block-manager client
/// machinery is ported).
pub(crate) const DEFAULT_CLIENT_ERASE_OPS: ClientEraseOps = ClientEraseOps {
    hand_back_block: stub_hand_back_block,
    notify_drained: stub_notify_drained,
    notify_complete: stub_notify_complete,
};

/// The active implementation table. Written once at init on target;
/// host tests swap in recorders and restore the defaults.
pub static mut CLIENT_ERASE_OPS: ClientEraseOps = DEFAULT_CLIENT_ERASE_OPS;

/// Reads one op (volatile — same rationale as every dispatch table: a
/// build in which nothing swaps it must not constant-fold the default
/// in).
macro_rules! op {
    ($field:ident) => {
        unsafe { core::ptr::read_volatile(core::ptr::addr_of!(CLIENT_ERASE_OPS.$field)) }
    };
}

/// Reads one op of the shared C++ mutex boundary (block_region.rs).
macro_rules! mutex_op {
    ($field:ident) => {
        unsafe { core::ptr::read_volatile(core::ptr::addr_of!(REGION_MUTEX_OPS.$field)) }
    };
}

/// client_erase — original: `FUN_081fc080` @ 0x081fc080 (136 bytes).
///
/// Drains `deque` back to the block manager under the client's mutex:
/// per element, hand the front block's region word (region + 0xc) to
/// the manager after popping, then run the drained/completion
/// notification pair (see the module header for the full protocol).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn client_erase(client: *mut u8, deque: *mut BlockDeque) {
    let mutex = client.add(CLIENT_MUTEX_OFFSET);
    (mutex_op!(lock))(mutex);
    // The original's preset block word ([sp,#0x14] = 0) — dead ahead of
    // the loop store, kept for the frame's shape.
    let mut block: u32 = 0;
    // Snapshot the count once (ldr r4, [r6, #0x20] precedes the loop).
    let mut remaining = (*deque).count;
    while remaining != 0 {
        let mut front = DequeIter::NULL;
        // 0x083d9ec8(dst=sp+4, src=deque): the deque's begin iterator is
        // the deque's first field, so src is the deque pointer itself.
        deque_iter_assign(
            core::ptr::addr_of_mut!(front) as *mut u32,
            deque as *const u32,
        );
        let region = (front.cur as *const *mut u8)
            .add(crate::heap::block_region::ELEM_REGION_INDEX)
            .read_unaligned();
        block = (region as *const u32)
            .add(REGION_BLOCK_INDEX)
            .read_unaligned();
        deque_pop_front(deque);
        (op!(hand_back_block))(client, core::ptr::addr_of_mut!(block));
        remaining = remaining.wrapping_sub(1);
    }
    (op!(notify_drained))(client, 1);
    (op!(notify_complete))(client);
    (mutex_op!(unlock))(mutex);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::heap::block_deque::{
        deque_iter_init, PoolBaseOps, DEQUE_ELEM_SIZE, DEQUE_SEG_BYTES, POOL_BASE_OPS,
    };
    use crate::heap::block_region::{RegionMutexOps, DEFAULT_REGION_MUTEX_OPS};
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes this module's slot swaps (tests run serially —
    /// RUST_TEST_THREADS=1 — so one lock is enough, the block_deque.rs
    /// precedent).
    static OPS_LOCK: Mutex<()> = Mutex::new(());

    /// One shared, ordered event log across every mocked boundary.
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Ev {
        Lock(usize),
        Unlock(usize),
        HandBack { client: usize, block: u32 },
        Drained { client: usize, flag: u32 },
        Complete(usize),
        ElemDtor(usize),
        SegFree { ptr: usize, count: usize },
    }

    static mut EVENTS: Vec<Ev> = Vec::new();

    fn push(ev: Ev) {
        unsafe { (*addr_of_mut!(EVENTS)).push(ev) }
    }

    fn events() -> Vec<Ev> {
        unsafe { (*addr_of!(EVENTS)).clone() }
    }

    unsafe extern "C" fn mock_lock(m: *mut u8) -> u32 {
        push(Ev::Lock(m as usize));
        0
    }

    unsafe extern "C" fn mock_unlock(m: *mut u8) -> u32 {
        push(Ev::Unlock(m as usize));
        0
    }

    unsafe extern "C" fn mock_hand_back(client: *mut u8, block: *mut u32) {
        push(Ev::HandBack {
            client: client as usize,
            block: block.read(),
        });
    }

    unsafe extern "C" fn mock_drained(client: *mut u8, flag: u32) {
        push(Ev::Drained {
            client: client as usize,
            flag,
        });
    }

    unsafe extern "C" fn mock_complete(client: *mut u8) {
        push(Ev::Complete(client as usize));
    }

    unsafe extern "C" fn mock_elem_dtor(elem: *mut u8) {
        push(Ev::ElemDtor(elem as usize));
    }

    unsafe extern "C" fn mock_seg_free(ptr: *mut u8, count: usize, _elem: usize) {
        push(Ev::SegFree {
            ptr: ptr as usize,
            count,
        });
    }

    /// Element vtable: slot 0 = virtual destructor (deque_pop_front's
    /// dispatch shape).
    static ELEM_VTABLE: [unsafe extern "C" fn(*mut u8); 1] = [mock_elem_dtor];

    /// Installs the recorders (this module's ops, the shared mutex
    /// boundary, and the segment deallocator the real pop_front
    /// retires segments through), resets the log, returns the guard.
    fn install() -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            (*addr_of_mut!(EVENTS)).clear();
            addr_of_mut!(CLIENT_ERASE_OPS).write(ClientEraseOps {
                hand_back_block: mock_hand_back,
                notify_drained: mock_drained,
                notify_complete: mock_complete,
            });
            addr_of_mut!(REGION_MUTEX_OPS).write(RegionMutexOps {
                lock: mock_lock,
                unlock: mock_unlock,
            });
            let ops = &mut *addr_of_mut!(POOL_BASE_OPS);
            *ops = PoolBaseOps {
                seg_dealloc: mock_seg_free,
                ..*ops
            };
        }
        guard
    }

    /// Restores every wired default this module dispatches through.
    fn restore(guard: MutexGuard<'static, ()>) {
        unsafe {
            addr_of_mut!(CLIENT_ERASE_OPS).write(DEFAULT_CLIENT_ERASE_OPS);
            addr_of_mut!(REGION_MUTEX_OPS).write(DEFAULT_REGION_MUTEX_OPS);
            addr_of_mut!(POOL_BASE_OPS).write(crate::heap::block_deque::DEFAULT_POOL_BASE_OPS);
        }
        drop(guard);
    }

    /// Fake client object: the mutex lives at +0x24, nothing else is
    /// modeled.
    #[repr(align(4))]
    struct FakeClient([u8; 0x60]);

    /// A region object fixture: only the +0xc block word is read.
    #[repr(align(4))]
    struct FakeRegion([u8; 0x10]);

    impl FakeRegion {
        fn with_block(block: u32) -> Self {
            let mut region = FakeRegion([0; 0x10]);
            unsafe {
                (region.0.as_mut_ptr() as *mut u32)
                    .add(REGION_BLOCK_INDEX)
                    .write_unaligned(block);
            }
            region
        }
        fn ptr(&mut self) -> *mut u8 {
            self.0.as_mut_ptr()
        }
    }

    /// Wires one deque element: vtable at word 0, region pointer at
    /// word index 1 (the block_region.rs ELEM_REGION_INDEX layout).
    unsafe fn init_elem(elem: *mut u8, region: *mut u8) {
        (elem as *mut *const unsafe extern "C" fn(*mut u8))
            .write_unaligned(ELEM_VTABLE.as_ptr());
        ((elem as *mut usize).add(crate::heap::block_region::ELEM_REGION_INDEX))
            .write_unaligned(region as usize);
    }

    /// A one-segment deque fixture over `count` elements.
    struct DequeFixture {
        seg: std::boxed::Box<[u8; DEQUE_SEG_BYTES]>,
        map: std::boxed::Box<[*mut u8; 1]>,
        regions: std::vec::Vec<FakeRegion>,
        dq: std::boxed::Box<BlockDeque>,
    }

    impl DequeFixture {
        fn new(blocks: &[u32]) -> Self {
            let mut fixture = DequeFixture {
                seg: std::boxed::Box::new([0; DEQUE_SEG_BYTES]),
                map: std::boxed::Box::new([core::ptr::null_mut()]),
                regions: blocks.iter().map(|&b| FakeRegion::with_block(b)).collect(),
                dq: std::boxed::Box::new(BlockDeque {
                    begin: DequeIter::NULL,
                    end: DequeIter::NULL,
                    count: blocks.len() as u32,
                    map: core::ptr::null_mut(),
                    map_cap: 1,
                }),
            };
            let seg = fixture.seg.as_mut_ptr();
            fixture.map[0] = seg;
            fixture.dq.map = fixture.map.as_mut_ptr();
            unsafe {
                for (i, region) in fixture.regions.iter_mut().enumerate() {
                    init_elem(seg.add(i * DEQUE_ELEM_SIZE), region.ptr());
                }
                deque_iter_init(
                    addr_of_mut!(fixture.dq.begin),
                    seg,
                    fixture.map.as_mut_ptr(),
                );
            }
            fixture
        }
        fn deque(&mut self) -> *mut BlockDeque {
            &mut *self.dq
        }
    }

    #[test]
    fn an_empty_deque_only_locks_notifies_and_unlocks() {
        let _guard = install();
        unsafe {
            let mut client = FakeClient([0; 0x60]);
            let client = client.0.as_mut_ptr();
            let mut fixture = DequeFixture::new(&[]);
            client_erase(client, fixture.deque());
            let mutex = client.add(CLIENT_MUTEX_OFFSET) as usize;
            assert_eq!(
                events(),
                std::vec![
                    Ev::Lock(mutex),
                    Ev::Drained {
                        client: client as usize,
                        flag: 1
                    },
                    Ev::Complete(client as usize),
                    Ev::Unlock(mutex),
                ],
                "no iterations, both notifications, verdicts discarded"
            );
        }
        restore(_guard);
    }

    #[test]
    fn a_full_drain_hands_every_block_back_in_order() {
        let _guard = install();
        unsafe {
            let mut client = FakeClient([0; 0x60]);
            let client = client.0.as_mut_ptr();
            let blocks = [0xb10c_0001, 0xb10c_0002, 0xb10c_0003];
            let mut fixture = DequeFixture::new(&blocks);
            let elem0 = fixture.seg.as_mut_ptr() as usize;
            let dq = fixture.deque();
            let map = fixture.map.as_mut_ptr() as usize;
            client_erase(client, dq);
            let mutex = client.add(CLIENT_MUTEX_OFFSET) as usize;
            let c = client as usize;
            let mut expected = std::vec![Ev::Lock(mutex)];
            for (i, &b) in blocks.iter().enumerate() {
                // Per element: the real pop_front runs the virtual dtor,
                // THEN the hand-back sees the popped block word.
                expected.push(Ev::ElemDtor(elem0 + i * DEQUE_ELEM_SIZE));
                expected.push(Ev::HandBack { client: c, block: b });
            }
            // The third pop empties the deque: segment and map retire
            // through the deallocator before the hand-back resumes.
            let retire = std::vec![
                Ev::SegFree {
                    ptr: elem0,
                    count: 0x20,
                },
                Ev::SegFree { ptr: map, count: 1 },
            ];
            // Splice the retirement in after the last ElemDtor, before
            // the last HandBack.
            let tail = expected.split_off(expected.len() - 1);
            expected.extend(retire);
            expected.extend(tail);
            expected.push(Ev::Drained { client: c, flag: 1 });
            expected.push(Ev::Complete(c));
            expected.push(Ev::Unlock(mutex));
            assert_eq!(events(), expected);
            assert_eq!((*dq).count, 0, "the real pop_front drained it");
            assert!((*dq).begin.cur.is_null(), "empty deque: NULL iterators");
        }
        restore(_guard);
    }

    #[test]
    fn the_count_is_snapshotted_before_the_loop() {
        // A deque whose stored count is lower than the number of
        // iterations the loop runs cannot exist with the real
        // pop_front (it would underflow), so prove the snapshot the
        // other way: the loop runs the stored count even though each
        // pop decrements the same word — after N pops the deque's own
        // count reached 0 exactly as the snapshot reached 0.
        let _guard = install();
        unsafe {
            let mut client = FakeClient([0; 0x60]);
            let client = client.0.as_mut_ptr();
            let mut fixture = DequeFixture::new(&[1, 2]);
            let dq = fixture.deque();
            client_erase(client, dq);
            let hand_backs = events()
                .iter()
                .filter(|ev| matches!(ev, Ev::HandBack { .. }))
                .count();
            assert_eq!(hand_backs, 2, "exactly the snapshotted count ran");
            assert_eq!((*dq).count, 0);
        }
        restore(_guard);
    }

    #[test]
    fn the_wired_defaults_are_noop_safe_on_an_empty_deque() {
        let guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            (*addr_of_mut!(EVENTS)).clear();
            addr_of_mut!(CLIENT_ERASE_OPS).write(DEFAULT_CLIENT_ERASE_OPS);
            addr_of_mut!(REGION_MUTEX_OPS).write(DEFAULT_REGION_MUTEX_OPS);
            let mut client = FakeClient([0; 0x60]);
            let client = client.0.as_mut_ptr();
            let mut fixture = DequeFixture::new(&[]);
            // No recorders installed: the real mutex pair and the
            // no-op hand-back/notification stubs run, nothing else.
            client_erase(client, fixture.deque());
            assert!(events().is_empty());
        }
        drop(guard);
    }
}
