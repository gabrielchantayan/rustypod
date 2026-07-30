//! retailOS application heap (cluster 0x0819cd5c..0x0819d9d8 + veneers).
pub mod alloc_core;
pub mod block_deque;
pub mod block_mgr;
pub mod block_region;
pub mod dcache;
pub mod free_path;
pub mod init;
pub mod pool;
pub mod pool_client;
pub mod queue_wait;
pub mod stats;
pub mod tracked;
pub mod types;
pub mod veneers;
pub mod wrappers;

/// Cross-module wiring proof: every dispatch table defaults to the real
/// ports (the module headers' "once ported, point here" contract), so the
/// original call graph — region registration linking a real free block
/// into the descriptor's sentinel list, the free path taking the
/// (pre-kernel no-op) heap lock, the lazy default-heap init reaching
/// `heap_create` — runs end-to-end with no mocks installed.
///
/// Not covered on host, by necessity: paths through `heap_alloc_core`'s
/// free-list walk (host test builds represent links as u32 arena offsets,
/// incompatible with the pointer-linked list the other modules build —
/// see alloc_core.rs) and the auto-init region fallback (the descriptor
/// stores region addresses as u32, which truncates 64-bit host pointers —
/// see init.rs's SIGSEGV-probing test).
#[cfg(test)]
mod wiring_tests {
    extern crate std;
    use crate::heap::types::{FreeSentinel, HeapDescriptor, BLOCK_FREE, PREV_FREE};
    use crate::heap::{free_path, init, veneers, wrappers};
    use std::boxed::Box;

    /// Restores every wired default the heap paths dispatch through (other
    /// test modules leave their mocks installed; tests run serially).
    unsafe fn restore_wired_defaults() {
        core::ptr::addr_of_mut!(init::HEAP_INIT_OPS).write(init::DEFAULT_HEAP_INIT_OPS);
        core::ptr::addr_of_mut!(free_path::HEAP_MUTEX_HOOKS)
            .write(free_path::DEFAULT_HEAP_MUTEX_HOOKS);
        core::ptr::addr_of_mut!(free_path::HEAP_PANIC_HOOK)
            .write(free_path::DEFAULT_HEAP_PANIC_HOOK);
        core::ptr::addr_of_mut!(wrappers::HEAP_CORE_HOOKS)
            .write(wrappers::DEFAULT_HEAP_CORE_HOOKS);
        core::ptr::addr_of_mut!(veneers::HEAP_OPS).write(veneers::DEFAULT_HEAP_OPS);
        // Pre-kernel state: the wired heap_lock/heap_unlock must take the
        // original's no-op path (host pointers cannot round-trip through
        // the descriptor's 32-bit mutex slot anyway).
        core::ptr::addr_of_mut!(crate::kernel::sync_mutex::KERNEL_STARTED).write(0);
    }

    fn zeroed_desc() -> *mut HeapDescriptor {
        Box::into_raw(Box::new(unsafe { core::mem::zeroed::<HeapDescriptor>() }))
    }

    /// 8-aligned heap backing memory.
    #[repr(align(8))]
    struct Region([u8; 0x1000]);

    /// The free-list node overlay seen through the public `FreeSentinel`
    /// layout (same first three fields as free_path's node on host and
    /// target).
    unsafe fn node(header: *const u32) -> &'static FreeSentinel {
        &*(header as *const FreeSentinel)
    }

    #[test]
    fn add_region_links_a_real_free_block_through_the_wired_defaults() {
        unsafe {
            restore_wired_defaults();
            let desc = zeroed_desc();
            init::heap_desc_init(desc, 0, 0);
            let mut region = Box::new(Region([0; 0x1000]));
            let start = region.0.as_mut_ptr() as usize; // 8-aligned
            let size = 0x800usize;

            init::heap_add_region(desc, start, size);

            // Same carve as the spied init.rs tests...
            let header = (start + 8) as *mut u32;
            let block_size = (size - 16) as u32;
            assert_eq!((*desc).region_count, 1);
            assert_eq!((*desc).total_bytes, block_size);
            // ...but now the block really went through heap_free_insert:
            // marked free, accounted, footer written, terminator told its
            // predecessor is free, and linked under the sentinel.
            assert_eq!((*desc).free_bytes, block_size, "insert credits free_bytes");
            assert_eq!(header.read(), block_size | BLOCK_FREE);
            let footer = header.add((block_size as usize - 4) / 4).read();
            assert_eq!(footer, block_size, "footer copy at block end - 4");
            let terminator = header.add(block_size as usize / 4).read();
            assert_eq!(terminator, PREV_FREE, "terminator sees the free block");
            let sentinel = core::ptr::addr_of_mut!((*desc).sentinel);
            assert_eq!((*sentinel).next, header as *mut FreeSentinel, "list head");
            assert_eq!(node(header).prev, sentinel, "head points back at the sentinel");
            assert!(node(header).next.is_null(), "single-element list");
            // Pre-kernel: the wired lock pair was a no-op, no mutex made.
            assert_eq!((*desc).mutex_state, 0);
            assert_eq!((*desc).mutex_state2, 0);
            drop(Box::from_raw(desc));
        }
    }

    #[test]
    fn heap_free_reaches_the_free_list_through_the_wired_defaults() {
        unsafe {
            restore_wired_defaults();
            let desc = zeroed_desc();
            init::heap_desc_init(desc, 0, 0);
            let mut arena = Box::new(Region([0; 0x1000]));
            let base = arena.0.as_mut_ptr();
            // A (allocated) | B (allocated, freed below) | C (allocated).
            for (off, flags) in [(0usize, 0x40u32), (0x40, 0x40), (0x80, 0x40)] {
                (base.add(off) as *mut u32).write(flags); // size_flags
                (base.add(off + 4) as *mut u32).write(0); // link_or_tag
            }
            let b = base.add(0x40) as *mut u32;

            free_path::heap_free(desc, (b as *mut u8).add(8), 2);

            assert_eq!(b.read(), 0x40 | BLOCK_FREE);
            assert_eq!((base.add(0x80) as *const u32).read(), 0x40 | PREV_FREE);
            assert_eq!((base.add(0x80 - 4) as *const u32).read(), 0x40, "footer");
            assert_eq!((*desc).free_bytes, 0x40);
            let sentinel = core::ptr::addr_of_mut!((*desc).sentinel);
            assert_eq!((*sentinel).next, b as *mut FreeSentinel);
            assert_eq!(node(b).prev, sentinel);
            assert!(node(b).next.is_null());
            // The wired mutex pair ran its pre-kernel no-op path.
            assert_eq!((*desc).mutex_state, 0);
            drop(Box::from_raw(desc));
        }
    }

    #[test]
    fn lazy_default_heap_init_reaches_heap_create_through_the_wired_defaults() {
        unsafe {
            restore_wired_defaults();
            core::ptr::addr_of_mut!(crate::heap::types::DEFAULT_HEAP)
                .write(core::ptr::null_mut());

            veneers::lazy_init_default_heap();

            // The handle is the storage descriptor, really initialized by
            // heap_desc_init (not a mock): 32 KB initial region recorded,
            // auto-init armed, nothing registered yet.
            let handle = core::ptr::addr_of!(crate::heap::types::DEFAULT_HEAP).read();
            assert!(!handle.is_null());
            let desc = handle as *mut HeapDescriptor;
            assert_eq!((*desc).initial_region_size, 0x8000);
            assert_eq!((*desc).region_count, 0);
            assert!((*desc).sentinel.next.is_null());
            // auto_init byte (low byte of the u32 field, as on target).
            assert_eq!(core::ptr::addr_of!((*desc).auto_init).cast::<u8>().read(), 1);
        }
    }
}

/// End-to-end pool lifecycle proof: `pool_create` runs the whole ported
/// call graph — control-struct allocation, the real base-subobject ctor
/// (block_deque.rs) over the real parent ctor and client attach
/// (pool_client.rs), the real embedded-heap create (init.rs), the real
/// `block_deque_fill`, the real seed walk (deque accessor/iterator
/// copies, `block_to_region_start`, `heap_add_region` carving real host
/// memory), and the full real destroy chain (release, mailbox teardown,
/// deque drain via `deque_pop_front`, embedded `heap_destroy`).
///
/// Host stand-ins, each for a documented reason (precedent: the
/// wiring_tests header above):
/// - the control-struct allocator (`POOL_OPS.new_control`/`delete_control`)
///   and the pool-alloc heap entry: the alloc engine's host test build
///   uses offset links, incompatible with the pointer-linked free lists
///   the rest of the crate builds on host (see alloc_core.rs) — the
///   engine is target-only, so these slots get counting stand-ins;
/// - the mask-ROM kernel-object dispatchers and the mailbox block's
///   os-heap pair (`KOBJ_HOOKS`): the ROM is not part of osos, and the
///   os-heap veneers route into the same target-only engine;
/// - `POOL_CLIENT_OPS.client_alloc` (the real `operator new` for the
///   0x170-byte block-manager client), for the same reason;
/// - the unported 0x081fxxxx block-manager client
///   (`POOL_BASE_OPS.client_attach`/`client_*`) in the success tests,
///   which short-circuit the real attach; its populate
///   stand-in builds a real deque segment the drain then really pops;
/// - `POOL_BASE_OPS.seg_dealloc` in the success tests (the segments are
///   host buffers, not default-heap blocks).
/// Everything else — every POOL_OPS slot, the deque machinery, the
/// region accessors, the embedded heap lifecycle — is the wired default
/// (real port).
#[cfg(test)]
mod pool_integration_tests {
    extern crate std;
    use crate::heap::block_deque::{self, BlockDeque, DequeIter, PoolBase};
    use crate::heap::block_region;
    use crate::heap::pool::{self, PoolControl};
    use crate::heap::pool_client;
    use crate::heap::types::HeapDescriptor;
    use crate::kernel::kobj::{Mailbox, KobjHooks, KOBJ_HOOKS, DEFAULT_KOBJ_HOOKS};
    use std::sync::{Mutex, MutexGuard};

    /// Serializes these tests against everything else that swaps the
    /// shared tables (tests run serially anyway; belt and suspenders).
    static LOCK: Mutex<()> = Mutex::new(());

    // ---- counters -------------------------------------------------------

    static mut NEW_CALLS: usize = 0;
    static mut DELETE_CALLS: usize = 0;
    static mut CLIENT_NEW_CALLS: usize = 0;
    static mut MBOX_ALLOCS: usize = 0;
    static mut MBOX_FREES: usize = 0;
    static mut ROM_CREATES: usize = 0;
    static mut ROM_DELETES: usize = 0;
    static mut ELEM_DTORS: usize = 0;
    static mut SEG_FREES: std::vec::Vec<usize> = std::vec::Vec::new();
    static mut POOL_ALLOC_CALLS: usize = 0;
    static mut LAST_POOL_ALLOC_SIZE: usize = 0;
    static mut LAST_POOL_ALLOC_TAG: usize = 0;

    // ---- fixed storage --------------------------------------------------
    //
    // Every buffer below lives in ONE low mmap rather than in `static mut`,
    // and the reason is not tidiness. The heap descriptor stores region
    // start addresses as u32 (the target is 32-bit), and `pool_alloc` marks
    // uncached pointers by setting bit 31. A `static mut` in a PIE binary on
    // Linux lands wherever ASLR puts the image — routinely above 2^32 — so
    // those round-trips truncate and the test segfaults on roughly 60% of
    // runs while passing every time under gdb (which disables ASLR) and on
    // macOS. Same failure, same fix, same reason as `pool.rs`'s `arena_ptr`.

    /// Base of the shared low slab; every buffer is a fixed offset into it.
    fn slab() -> *mut u8 {
        use std::sync::OnceLock;
        static SLAB: OnceLock<usize> = OnceLock::new();
        *SLAB.get_or_init(|| {
            extern "C" {
                fn mmap(
                    addr: usize,
                    len: usize,
                    prot: i32,
                    flags: i32,
                    fd: i32,
                    offset: i64,
                ) -> usize;
            }
            #[cfg(target_os = "macos")]
            const MAP_PRIVATE_ANON: i32 = 0x1002;
            #[cfg(target_os = "linux")]
            const MAP_PRIVATE_ANON: i32 = 0x22;
            const PROT_READ_WRITE: i32 = 3;
            // Distinct hint from pool.rs's own arena so the two cannot
            // contend for the same span.
            let p = unsafe {
                mmap(0x0900_0000, SLAB_LEN, PROT_READ_WRITE, MAP_PRIVATE_ANON, -1, 0)
            };
            // The requirement is bit 31 CLEAR across the whole slab, not
            // 32-bit addressability: `pool_alloc` marks uncached pointers
            // with bit 31 and `pool_free` strips it again, so a backing
            // address that already has it set comes back corrupted. macOS
            // hands out 0x1_xxxx_xxxx (bit 31 clear) whatever the hint, which
            // is why this only ever failed on Linux, where PIE placement sets
            // it about half the time.
            const UNCACHED_MARK: usize = 0x8000_0000; // pool.rs's, private there
            assert!(
                p != usize::MAX && (p | (p + SLAB_LEN - 1)) & UNCACHED_MARK == 0,
                "integration slab must avoid bit 31 (got {p:#x})"
            );
            p
        }) as *mut u8
    }

    const SLAB_LEN: usize = 0x10000;
    const OFF_CONTROL: usize = 0x0000; // 0x1000 — host PoolControl is wider than 0x418
    const OFF_ARENA: usize = 0x1000; // 0x2000 — block memory the seeded regions cover
    const OFF_SEG: usize = 0x3000; // 0x500  — one real deque segment (4 elements used)
    const OFF_MAP: usize = 0x3800; // segment map, one slot
    const OFF_REGIONS: usize = 0x3840; // 4 x [_, start, mutex], host word index
    const OFF_MBOX: usize = 0x3900; // 2 mailbox cells (parent +0x24, derived +0x78)
    const OFF_CLIENT: usize = 0x3980; // 0x170 — block-manager client object
    const OFF_MGR: usize = 0x3b00; // 0x40   — fake block manager (+0x30 = block size)
    const OFF_BUMP: usize = 0x4000; // 0x4000 — pool-alloc stand-in arena

    unsafe fn control() -> *mut u8 {
        slab().add(OFF_CONTROL)
    }
    unsafe fn arena() -> *mut u8 {
        slab().add(OFF_ARENA)
    }
    unsafe fn seg() -> *mut u8 {
        slab().add(OFF_SEG)
    }
    unsafe fn map_slot() -> *mut *mut u8 {
        slab().add(OFF_MAP) as *mut *mut u8
    }
    unsafe fn region(i: usize) -> *mut usize {
        (slab().add(OFF_REGIONS) as *mut usize).add(i * 3)
    }
    unsafe fn mbox_cell(i: usize) -> *mut Mailbox {
        (slab().add(OFF_MBOX) as *mut Mailbox).add(i)
    }
    unsafe fn client_storage() -> *mut u8 {
        slab().add(OFF_CLIENT)
    }
    unsafe fn mgr_block() -> *mut u8 {
        slab().add(OFF_MGR)
    }
    unsafe fn bump_base() -> *mut u8 {
        slab().add(OFF_BUMP)
    }
    static mut BUMP_AT: usize = 0;

    const BLOCK_SIZE: u32 = 0x800;

    // ---- stand-ins ------------------------------------------------------

    unsafe extern "C" fn std_new(_size: usize) -> *mut u8 {
        NEW_CALLS += 1;
        control()
    }

    unsafe extern "C" fn std_delete(ptr: *mut u8) {
        DELETE_CALLS += 1;
        assert_eq!(ptr, control());
    }

    unsafe extern "C" fn client_new(size: usize) -> *mut u8 {
        CLIENT_NEW_CALLS += 1;
        assert_eq!(size, 0x170, "the block-manager client object size");
        client_storage()
    }

    unsafe extern "C" fn rom_create(_op: u32, slot: *mut u32) {
        ROM_CREATES += 1;
        *slot = 0x77;
    }

    unsafe extern "C" fn rom_delete(_op: u32, slot: *mut u32) {
        ROM_DELETES += 1;
        assert_eq!(*slot, 0x77);
    }

    unsafe extern "C" fn mbox_alloc(size: usize) -> *mut u8 {
        assert_eq!(size, core::mem::size_of::<Mailbox>());
        let cell = mbox_cell(MBOX_ALLOCS);
        MBOX_ALLOCS += 1;
        cell as *mut u8
    }

    unsafe extern "C" fn mbox_free(ptr: *mut u8) {
        MBOX_FREES += 1;
        let cells = mbox_cell(0) as usize;
        let off = ptr as usize - cells;
        assert!(off < 2 * core::mem::size_of::<Mailbox>() && off % core::mem::size_of::<Mailbox>() == 0);
    }

    unsafe extern "C" fn elem_dtor(_elem: *mut u8) {
        ELEM_DTORS += 1;
    }

    /// Element vtable: slot 0 = virtual destructor (deque_pop_front's
    /// dispatch shape).
    static ELEM_VTABLE: [unsafe extern "C" fn(*mut u8); 1] = [elem_dtor];

    unsafe extern "C" fn seg_free_recorder(ptr: *mut u8, _count: usize, _elem: usize) {
        (*core::ptr::addr_of_mut!(SEG_FREES)).push(ptr as usize);
    }

    unsafe extern "C" fn client_ok(_this: *mut PoolBase) -> i32 {
        1
    }

    unsafe extern "C" fn client_reserve_ok(_c: *mut u8, _bytes: usize, _z: usize) -> i32 {
        1
    }

    unsafe extern "C" fn client_avail_ok(_c: *mut u8, _bytes: usize) -> i32 {
        1
    }

    /// Stand-in for the unported client populate @ 0x081fc298: builds a
    /// REAL single-segment deque (4 descriptor elements wired to real
    /// region objects over the arena) that the real seed walk and the
    /// real drain consume.
    unsafe extern "C" fn client_populate(_c: *mut u8, count: usize, dq: *mut BlockDeque) -> i32 {
        assert_eq!(count, 4, "ceil(0x2000 / 0x800)");
        let seg = seg();
        let arena = arena();
        for i in 0..4 {
            let elem = seg.add(i * block_deque::DEQUE_ELEM_SIZE);
            // word 0: vtable pointer; word 1: region object pointer
            // (block_region's ELEM_REGION_INDEX).
            (elem as *mut *const unsafe extern "C" fn(*mut u8)).write(ELEM_VTABLE.as_ptr());
            let region = region(i);
            region.add(block_region::REGION_START_INDEX)
                .write(arena.add(i * BLOCK_SIZE as usize) as usize);
            region.add(block_region::REGION_MUTEX_INDEX).write(0);
            ((elem as *mut usize).add(1)).write(region as usize);
        }
        map_slot().write(seg);
        let map = map_slot();
        (*dq).begin = DequeIter {
            cur: seg,
            seg_base: seg,
            seg_end: seg.add(block_deque::DEQUE_SEG_BYTES),
            seg_slot: map,
        };
        (*dq).end = DequeIter {
            cur: seg.add(4 * block_deque::DEQUE_ELEM_SIZE),
            seg_base: seg,
            seg_end: seg.add(block_deque::DEQUE_SEG_BYTES),
            seg_slot: map,
        };
        (*dq).count = 4;
        (*dq).map = map;
        (*dq).map_cap = 1;
        1
    }

    /// Pool heap-alloc stand-in (the alloc-engine hole): bump allocator.
    unsafe extern "C" fn pool_bump_alloc(
        _heap: *mut HeapDescriptor,
        size: usize,
        tag: usize,
    ) -> *mut u8 {
        POOL_ALLOC_CALLS += 1;
        LAST_POOL_ALLOC_SIZE = size;
        LAST_POOL_ALLOC_TAG = tag;
        let p = bump_base().add(BUMP_AT + 8);
        BUMP_AT += 0x1000;
        p
    }

    // ---- setup ----------------------------------------------------------

    /// Restores every wired default in the pool path, then installs the
    /// documented host stand-ins. Returns the serialization guard.
    fn setup() -> MutexGuard<'static, ()> {
        let guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            NEW_CALLS = 0;
            DELETE_CALLS = 0;
            MBOX_ALLOCS = 0;
            MBOX_FREES = 0;
            ROM_CREATES = 0;
            ROM_DELETES = 0;
            ELEM_DTORS = 0;
            (*core::ptr::addr_of_mut!(SEG_FREES)).clear();
            POOL_ALLOC_CALLS = 0;
            BUMP_AT = 0;
            core::ptr::write_bytes(control(), 0, 0x1000);
            // Wired defaults everywhere...
            core::ptr::addr_of_mut!(pool::POOL_OPS).write(pool::DEFAULT_POOL_OPS);
            core::ptr::addr_of_mut!(block_deque::POOL_BASE_OPS)
                .write(block_deque::DEFAULT_POOL_BASE_OPS);
            core::ptr::addr_of_mut!(block_region::REGION_MUTEX_OPS)
                .write(block_region::DEFAULT_REGION_MUTEX_OPS);
            core::ptr::addr_of_mut!(pool_client::POOL_CLIENT_OPS)
                .write(pool_client::DEFAULT_POOL_CLIENT_OPS);
            core::ptr::addr_of_mut!(pool_client::SHARED_CLIENT)
                .write(pool_client::SharedClientSlot {
                    guard: 0,
                    client: core::ptr::null_mut(),
                });
            core::ptr::addr_of_mut!(crate::heap::init::HEAP_INIT_OPS)
                .write(crate::heap::init::DEFAULT_HEAP_INIT_OPS);
            core::ptr::addr_of_mut!(crate::heap::free_path::HEAP_MUTEX_HOOKS)
                .write(crate::heap::free_path::DEFAULT_HEAP_MUTEX_HOOKS);
            core::ptr::addr_of_mut!(crate::kernel::sync_mutex::KERNEL_STARTED).write(0);
            core::ptr::addr_of_mut!(KOBJ_HOOKS).write(DEFAULT_KOBJ_HOOKS);
            // ...then the documented stand-ins.
            let ops = &mut *core::ptr::addr_of_mut!(pool::POOL_OPS);
            ops.new_control = std_new;
            ops.delete_control = std_delete;
            // Same alloc-engine hole: the real client allocation is
            // `operator new` into the target-only engine.
            (*core::ptr::addr_of_mut!(pool_client::POOL_CLIENT_OPS)).client_alloc = client_new;
            let hooks = &mut *core::ptr::addr_of_mut!(KOBJ_HOOKS);
            *hooks = KobjHooks {
                op_create: rom_create,
                op_delete: rom_delete,
                heap_alloc: mbox_alloc,
                heap_free: mbox_free,
                ..DEFAULT_KOBJ_HOOKS
            };
            // Real install seam: the block-manager global.
            let mgr = mgr_block();
            (mgr.add(crate::heap::block_mgr::BLOCK_SIZE_OFFSET) as *mut u32).write(BLOCK_SIZE);
            crate::heap::block_mgr::BLOCK_MANAGER = mgr;
        }
        guard
    }

    fn teardown() {
        unsafe {
            crate::heap::block_mgr::BLOCK_MANAGER = core::ptr::null_mut();
            core::ptr::addr_of_mut!(pool::POOL_OPS).write(pool::DEFAULT_POOL_OPS);
            core::ptr::addr_of_mut!(block_deque::POOL_BASE_OPS)
                .write(block_deque::DEFAULT_POOL_BASE_OPS);
            core::ptr::addr_of_mut!(KOBJ_HOOKS).write(DEFAULT_KOBJ_HOOKS);
        }
    }

    /// Installs the block-manager-client stand-ins (success-path tests).
    unsafe fn install_client() {
        let ops = &mut *core::ptr::addr_of_mut!(block_deque::POOL_BASE_OPS);
        ops.client_attach = client_ok;
        ops.client_reserve = client_reserve_ok;
        ops.client_avail = client_avail_ok;
        ops.client_populate = client_populate;
        ops.seg_dealloc = seg_free_recorder;
    }

    static NAME: &[u8] = b"integration_pool\0";

    #[test]
    fn create_without_a_client_fails_cleanly_through_the_real_chain() {
        let _guard = setup();
        unsafe {
            // The REAL client attach runs (pool_client.rs) and finds no
            // block manager to construct a client from: the fill gate
            // fails and pool_create must clean up fully.
            let pool = pool::pool_create(0x2000, NAME.as_ptr());
            assert!(pool.is_null());
            assert_eq!(NEW_CALLS, 1);
            assert_eq!(DELETE_CALLS, 1, "failed create frees the control struct");
            assert_eq!(MBOX_ALLOCS, 2, "parent ctor +0x24, base ctor +0x78");
            assert_eq!(MBOX_FREES, 1, "only the base dtor is ported (parent dtor is a stub)");
            assert_eq!(ROM_CREATES, 2);
            assert_eq!(ROM_DELETES, 1);
            assert_eq!(ELEM_DTORS, 0, "deque never got elements");
            // The attach reached the client ctor before refusing.
            assert_eq!(CLIENT_NEW_CALLS, 1, "one 0x170-byte client attempt");
            let base = control() as *mut PoolBase;
            assert!((*base).client_cache.is_null(), "nothing memoized");
            assert_eq!(
                (*base).node.name,
                NAME.as_ptr(),
                "the real parent ctor named the registration node"
            );
            assert_eq!((*base).client_shared, 1, "pool_init constructs with flag 1");
            assert!((*core::ptr::addr_of!(SEG_FREES)).is_empty());
            // The real fill ran far enough to store the computed counts
            // before the attach gate refused (they survive in the buffer
            // because the base dtor's release zeroed them — check zeroed).
            assert_eq!((*base).fill_block_count, 0, "release_blocks zeroed");
            assert_eq!((*base).fill_cap, 0);
        }
        teardown();
    }

    #[test]
    fn create_seeds_the_embedded_heap_from_real_deque_content() {
        let _guard = setup();
        unsafe {
            install_client();
            let pool = pool::pool_create(0x2000, NAME.as_ptr());
            assert!(!pool.is_null(), "populate stand-in makes the fill succeed");
            assert_eq!(pool as *mut u8, control());

            // The REAL seed walk fed the REAL heap_add_region: 4 regions
            // of BLOCK_SIZE carved out of the arena.
            let desc = core::ptr::addr_of_mut!((*pool).heap);
            assert_eq!((*desc).region_count, 4);
            let arena = arena() as usize;
            let carved = BLOCK_SIZE as usize - 16; // aligned start: size - 16
            assert_eq!((*desc).total_bytes as usize, 4 * carved);
            assert_eq!((*desc).free_bytes as usize, 4 * carved, "all blocks free");
            for i in 0..4 {
                let (hdr, size) = (*desc).regions[i];
                // The region table stores u32 words (target width) — on
                // host the recorded header truncates (init.rs precedent).
                assert_eq!(hdr, (arena + i * BLOCK_SIZE as usize + 8) as u32);
                assert_eq!(size as usize, carved);
            }
            // The free list under the sentinel really links arena blocks.
            let mut node = (*desc).sentinel.next;
            let mut n = 0;
            while !node.is_null() {
                let addr = node as usize;
                assert!(
                    (arena..arena + 0x2000).contains(&addr),
                    "free node {addr:#x} must live in the arena"
                );
                node = (*node).next;
                n += 1;
            }
            assert_eq!(n, 4, "four free blocks linked");

            // Real destroy: drains the 4 elements through the real
            // pop_front, frees the segment and its map, tears down the
            // mailbox, and leaves the struct for the owner to delete.
            let ret = pool::pool_destroy(pool);
            assert_eq!(ret, pool);
            assert_eq!(ELEM_DTORS, 4, "every descriptor's virtual dtor ran");
            assert_eq!(
                *core::ptr::addr_of!(SEG_FREES),
                std::vec![
                    seg() as usize,
                    map_slot() as usize
                ],
                "segment then map, like the original drain"
            );
            assert_eq!(MBOX_FREES, 1);
            assert_eq!(DELETE_CALLS, 0, "destroy never frees the struct");
        }
        teardown();
    }

    #[test]
    fn created_pool_serves_aligned_allocations() {
        let _guard = setup();
        unsafe {
            install_client();
            let pool = pool::pool_create(0x2000, NAME.as_ptr());
            assert!(!pool.is_null());
            // The alloc-engine hole (documented above): the embedded
            // heap's entry becomes a bump stand-in; everything in
            // pool_alloc/pool_free itself stays real.
            (*core::ptr::addr_of_mut!(pool::POOL_OPS)).heap_alloc = pool_bump_alloc;
            let ptr = pool::pool_alloc_v1(pool, 0x100, 2, 0);
            assert!(!ptr.is_null());
            assert_eq!(ptr as usize & 31, 0, "class 2 = cache-line aligned");
            assert_eq!(LAST_POOL_ALLOC_SIZE, 0x100 + 32, "size + pad");
            assert_eq!(LAST_POOL_ALLOC_TAG, 0x2b);
            let delta = ((ptr as usize - 4) as *const u32).read() as usize;
            assert!(delta > 0 && delta <= 32, "recoverable delta at ptr - 4");
            // pool_free recovers the raw block through the delta word and
            // reaches the (real) heap_free slot... which is the target-only
            // engine's sibling; assert through a recorder instead.
            static mut FREED: *mut u8 = core::ptr::null_mut();
            unsafe extern "C" fn record_free(
                _h: *mut HeapDescriptor,
                p: *mut u8,
                tag: usize,
            ) {
                FREED = p;
                assert_eq!(tag, 2);
            }
            (*core::ptr::addr_of_mut!(pool::POOL_OPS)).heap_free = record_free;
            pool::pool_free(pool, ptr);
            assert_eq!(
                FREED as usize,
                ptr as usize - delta,
                "free recovered the raw heap block"
            );
            pool::pool_destroy(pool);
        }
        teardown();
    }
}
