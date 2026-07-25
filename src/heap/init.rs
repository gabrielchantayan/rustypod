//! Heap descriptor lifecycle: init, region registration, create/destroy.
//!
//! - `heap_desc_init` — original: `FUN_0819d5a4` @ 0x0819d5a4 (212 bytes).
//!   Stores the initial region (start/size), derives the `auto_init` flag
//!   (both nonzero), zeroes the accounting fields, the 20 region slots, the
//!   telemetry arrays (classes/tags/bins) and copies the 16-byte free-list
//!   sentinel into the descriptor at +0xd0.
//! - `heap_add_region` — original: `FUN_0819cf68` @ 0x0819cf68 (216 bytes,
//!   incl. the tail branch to the unlock helper). Locks the heap, falls back
//!   to the initial region when `auto_init` is set and (start, size) are
//!   both 0, then — while fewer than 20 regions are registered — carves one
//!   free block out of the range: the block header lands at
//!   `align8(start) + 8`, preceded by a zeroed prev-size word at -4 and
//!   followed by a zero-word terminator block; the block is linked into the
//!   free list and the region/table totals updated. Unlocks on the way out.
//! - `heap_create` — original: `FUN_0819d7b4` @ 0x0819d7b4 (20 bytes).
//!   `heap_desc_init(desc, start, size)`, returns `desc`.
//! - `heap_create_empty` — original: `FUN_0819d7c8` @ 0x0819d7c8 (28 bytes).
//!   `heap_desc_init(desc, 0, 0)`, returns `desc`.
//! - `heap_destroy` — original: `FUN_0819d7e4` @ 0x0819d7e4 (32 bytes).
//!   If the mutex state byte (+0xb4) is set, deletes the RTXC semaphore via
//!   `FUN_0807f650(&desc->mutex_handle)`; returns `desc`.
//!
//! Sentinel synthesis (deviation, by necessity): `heap_desc_init` copies the
//! sentinel from a 16-byte constant @ 0x08a77c0c, which lies beyond the
//! osos.dec extent (the image ends at 0x08a1b268), so the original bytes are
//! unrecoverable. The port synthesizes an all-zero head node
//! (`size_flags = 0`, `next = prev = NULL`). A zero size is provably
//! required: both free-list walks start *at* the sentinel (desc+0xd0) and
//! act on `node.size >= request` — the first-fit search @ 0x0819ce28
//! (`ldr r3, [r2]; bic r3, r3, #0xc0000003; cmp r3, r1; bcs found`) would
//! accept a max-size sentinel for every allocation and dereference
//! desc+0x400000cc (outside the 64 MB DRAM), and the sorted-insert walk @
//! 0x0819d314 only advances past the head to real blocks when the head's
//! size is below every block size. So the sentinel is a minimal-size list
//! head, not a max-size terminator; with size 0 the insert walk yields an
//! ascending size-sorted, NULL-terminated list rooted at the sentinel.
//!
//! Unported machinery (deviation, by necessity): the heap lock/unlock
//! helpers (@ 0x0819d6cc / 0x0819cde4), the free-list insert/coalesce
//! helper (@ 0x0819d314), the noreturn heap panic (@ 0x08030f44) and the
//! RTXC semaphore delete (@ 0x0807f650) live in sibling modules that are
//! being ported separately. They dispatch through the `HEAP_INIT_OPS` table:
//! lock/unlock/mutex_delete default to harmless no-ops, insert to a no-op
//! (block stays unlinked; the descriptor bookkeeping is still exact), and
//! panic to a spin. Once those modules land the table can point at the real
//! ports.
//!
//! Simplifications:
//! - The original guards the block-init stores with `(block + 8) & 7 == 0`,
//!   which is always true (`block` is 8-aligned by construction); the stores
//!   are unconditional here.
//! - The original's first sanity check reads back the terminator word it
//!   just wrote (always 0); both checks are kept for parity, so the panic
//!   hook is effectively reachable only via the region-extent check.
//! - `initialized` (+0xc0) and `auto_init` (+0xcc) are written with `strb`
//!   in the original; the port performs byte stores, leaving the upper
//!   bytes of those u32 fields untouched, exactly like the machine code.
//! - `mutex_handle` (+0xb8) and the padding at +0xbc are deliberately *not*
//!   zeroed — the original doesn't touch them.
//! - All four lifecycle functions return `desc`, matching the original's
//!   register behavior (r0 holds the descriptor on every exit path,
//!   including `heap_add_region`'s tail branch through the unlock helper).

use crate::heap::types::{HeapDescriptor, MAX_REGIONS, NUM_BINS, NUM_CLASSES, NUM_TAGS};

/// Synthesized content of the original 16-byte free-list sentinel constant
/// @ 0x08a77c0c (beyond the osos.dec extent — see the module header for the
/// evidence). Zero-size head node of an initially empty free list.
const FREE_SENTINEL_INIT: [u32; 4] = [0, 0, 0, 0];

/// Indirect dispatch for the not-yet-ported cluster helpers (see the module
/// header for the design and default-stub behavior).
#[derive(Clone, Copy)]
pub struct HeapInitOps {
    /// Heap lock @ 0x0819d6cc (creates + takes the RTXC semaphore).
    pub lock: unsafe extern "C" fn(desc: *mut HeapDescriptor),
    /// Heap unlock @ 0x0819cde4 (releases the semaphore if held).
    pub unlock: unsafe extern "C" fn(desc: *mut HeapDescriptor),
    /// Free-list insert with physical coalescing @ 0x0819d314.
    /// `(desc, block_header)`.
    pub insert_free_block: unsafe extern "C" fn(desc: *mut HeapDescriptor, block: *mut u32),
    /// Noreturn heap panic @ 0x08030f44 (corruption/invariant failure).
    pub panic: unsafe extern "C" fn() -> !,
    /// RTXC semaphore delete @ 0x0807f650, called with `&desc->mutex_handle`.
    pub mutex_delete: unsafe extern "C" fn(handle: *mut u32),
}

/// Default stub: without a kernel there is nothing to lock — no-op.
unsafe extern "C" fn missing_lock(_desc: *mut HeapDescriptor) {}

/// Default stub: pairs with `missing_lock` — no-op.
unsafe extern "C" fn missing_unlock(_desc: *mut HeapDescriptor) {}

/// Default stub: the block is not linked into any free list, but the
/// descriptor bookkeeping (regions, totals) stays exact — a harmless no-op
/// until the real insert @ 0x0819d314 is ported and installed.
unsafe extern "C" fn missing_insert_free_block(_desc: *mut HeapDescriptor, _block: *mut u32) {}

/// Default stub: the original panic does not return; the closest stub is a
/// spin (on target the real panic @ 0x08030f44 must be installed).
unsafe extern "C" fn missing_panic() -> ! {
    loop {}
}

/// Default stub: no kernel semaphore exists — deleting it is a no-op.
unsafe extern "C" fn missing_mutex_delete(_handle: *mut u32) {}

/// The active helper implementations. Defaults to the documented stubs;
/// replaced by host tests (spies) and eventually by the ported heap-lock /
/// free-list / panic / RTXC modules.
pub static mut HEAP_INIT_OPS: HeapInitOps = HeapInitOps {
    lock: missing_lock,
    unlock: missing_unlock,
    insert_free_block: missing_insert_free_block,
    panic: missing_panic,
    mutex_delete: missing_mutex_delete,
};

/// Reads the ops table. Volatile so LLVM cannot constant-fold the loads to
/// the default stubs in builds where nothing has written the table yet
/// (same failure mode as `HEAP_OPS` in runtime/malloc_rt.rs).
#[inline(always)]
fn heap_init_ops() -> HeapInitOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(HEAP_INIT_OPS)) }
}

/// Byte read of the `auto_init` flag (the original uses `ldrb` on +0xcc,
/// whose field is a u32 in `HeapDescriptor`; only the low byte is
/// meaningful). Little-endian target, so the low byte is the first byte.
#[inline(always)]
unsafe fn auto_init_flag(desc: *const HeapDescriptor) -> u8 {
    core::ptr::addr_of!((*desc).auto_init).cast::<u8>().read()
}

/// heap_desc_init — original: `FUN_0819d5a4` @ 0x0819d5a4 (212 bytes).
///
/// Initializes the descriptor in place (it is *not* fully zeroed — see the
/// module header for the fields deliberately left alone) and records the
/// initial region for later `heap_add_region(desc, 0, 0)` auto-init.
/// Returns `desc`.
// `#[inline(never)]`: heap_create/heap_create_empty tail-call this in the
// original; when inlined their bodies fold into identical machine code and
// LLVM merges all three symbols, hiding heap_desc_init from the linker.
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn heap_desc_init(
    desc: *mut HeapDescriptor,
    initial_region_start: usize,
    initial_region_size: usize,
) -> *mut HeapDescriptor {
    let d = &mut *desc;
    d.initial_region_start = initial_region_start as u32;
    d.initial_region_size = initial_region_size as u32;
    // Original: strb — only the low bytes of the u32 fields at +0xc0/+0xcc.
    core::ptr::addr_of_mut!((*desc).initialized)
        .cast::<u8>()
        .write(0);
    core::ptr::addr_of_mut!((*desc).auto_init)
        .cast::<u8>()
        .write((initial_region_start != 0 && initial_region_size != 0) as u8);
    d.mutex_state2 = 0;
    d.free_bytes = 0;
    d.total_bytes = 0;
    d.allocated_bytes = 0;
    d.alloc_counter = 0;
    d.mutex_state = 0;
    // The array-clearing loops use volatile word stores: plain stores get
    // recognized and synthesized into a __aeabi_memclr4 call, a helper the
    // freestanding firmware link cannot resolve. Volatile keeps the
    // original's explicit str-per-word loops (and is cheaper than a call).
    let mut p = core::ptr::addr_of_mut!((*desc).regions) as *mut u32;
    for _ in 0..MAX_REGIONS * 2 {
        p.write_volatile(0);
        p = p.add(1);
    }
    d.region_count = 0;
    // Original: ldm/stm copy of the 16-byte constant @ 0x08a77c0c (see the
    // module header for why the content is synthesized as all-zero).
    let sentinel = FREE_SENTINEL_INIT;
    d.sentinel.size_flags = sentinel[0];
    d.sentinel.next = sentinel[1] as *mut _;
    d.sentinel.prev = sentinel[2] as *mut _;
    d.sentinel.unused = sentinel[3];
    let mut p = core::ptr::addr_of_mut!((*desc).bytes_per_class) as *mut u32;
    for _ in 0..NUM_CLASSES {
        p.write_volatile(0);
        p = p.add(1);
    }
    d.class_total = 0;
    let mut p = core::ptr::addr_of_mut!((*desc).bytes_per_tag) as *mut u32;
    for _ in 0..NUM_TAGS {
        p.write_volatile(0);
        p = p.add(1);
    }
    d.tag_total = 0;
    let mut p = core::ptr::addr_of_mut!((*desc).blocks_per_bin) as *mut u32;
    for _ in 0..NUM_BINS {
        p.write_volatile(0);
        p = p.add(1);
    }
    d.bin_total = 0;
    d.peak_bytes = 0;
    desc
}

/// heap_add_region — original: `FUN_0819cf68` @ 0x0819cf68 (216 bytes incl.
/// the tail branch to the unlock helper @ 0x0819cde4).
///
/// Registers `[start, size)` as a heap region and installs one free block
/// spanning it. With `auto_init` set, `(0, 0)` re-uses the initial region
/// recorded by `heap_desc_init`. Beyond `MAX_REGIONS` regions the call
/// still locks/unlocks but changes nothing. Returns `desc`.
#[no_mangle]
pub unsafe extern "C" fn heap_add_region(
    desc: *mut HeapDescriptor,
    mut start: usize,
    mut size: usize,
) -> *mut HeapDescriptor {
    let ops = heap_init_ops();
    (ops.lock)(desc);
    if auto_init_flag(desc) != 0 && start == 0 && size == 0 {
        start = (*desc).initial_region_start as usize;
        size = (*desc).initial_region_size as usize;
    }
    if (*desc).region_count < MAX_REGIONS as u32 {
        // Block header at align8(start) + 8: the 8 skipped bytes hold the
        // zeroed prev-size word at header-4 (and keep the header off the
        // region edge).
        let header = start.wrapping_add(15) & !7;
        let block_size = size
            .wrapping_sub(header.wrapping_add(4).wrapping_sub(start))
            .wrapping_sub(4)
            & !7;
        let block = header as *mut u32;
        block.sub(1).write(0); // prev-block-size word
        block.add(block_size / 4).write(0); // zero-word terminator block
        let count = (*desc).region_count as usize;
        // Guarded by `region_count < MAX_REGIONS` above; raw pointer write
        // avoids a core::panicking::panic_bounds_check call the freestanding
        // link cannot resolve.
        core::ptr::addr_of_mut!((*desc).regions)
            .cast::<(u32, u32)>()
            .add(count)
            .write((header as u32, block_size as u32));
        block.add(0).write(block_size as u32); // size_flags: in-use, prev in-use
        block.add(1).write(0); // link / free-list next
        block.add(2).write(0); // free-list prev
        // Sanity checks (original panics via 0x08030f44, noreturn): the
        // terminator readback is of the word just written, so the effective
        // check is that the carved block fits inside the region.
        if block.add(block_size / 4).read() != 0
            || start.wrapping_add(size).wrapping_sub(4) < header.wrapping_add(block_size)
        {
            (ops.panic)();
        }
        (*desc).total_bytes = (*desc).total_bytes.wrapping_add(block_size as u32);
        (ops.insert_free_block)(desc, block);
        (*desc).region_count += 1;
    }
    (ops.unlock)(desc);
    desc
}

/// heap_create — original: `FUN_0819d7b4` @ 0x0819d7b4 (20 bytes).
///
/// `heap_desc_init` with the given initial region; returns `desc`.
#[no_mangle]
pub unsafe extern "C" fn heap_create(
    desc: *mut HeapDescriptor,
    initial_region_start: usize,
    initial_region_size: usize,
) -> *mut HeapDescriptor {
    heap_desc_init(desc, initial_region_start, initial_region_size);
    desc
}

/// heap_create_empty — original: `FUN_0819d7c8` @ 0x0819d7c8 (28 bytes).
///
/// `heap_desc_init(desc, 0, 0)` — no initial region, no auto-init; returns
/// `desc`.
#[no_mangle]
pub unsafe extern "C" fn heap_create_empty(desc: *mut HeapDescriptor) -> *mut HeapDescriptor {
    heap_desc_init(desc, 0, 0);
    desc
}

/// heap_destroy — original: `FUN_0819d7e4` @ 0x0819d7e4 (32 bytes).
///
/// Deletes the heap's RTXC semaphore when the mutex state byte is set;
/// returns `desc`.
#[no_mangle]
pub unsafe extern "C" fn heap_destroy(desc: *mut HeapDescriptor) -> *mut HeapDescriptor {
    if (*desc).mutex_state != 0 {
        (heap_init_ops().mutex_delete)(core::ptr::addr_of_mut!((*desc).mutex_handle));
    }
    desc
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::boxed::Box;

    // Region backing store, 8-aligned like real heap memory.
    #[repr(align(8))]
    struct Region([u8; 0x2000]);

    /// Spy state for the ops hooks (tests run serially per .cargo/config).
    struct Spy {
        lock_calls: u32,
        unlock_calls: u32,
        insert_calls: u32,
        insert_desc: *mut HeapDescriptor,
        insert_block: *mut u32,
        mutex_delete_calls: u32,
        mutex_delete_handle: *mut u32,
    }

    static mut SPY: Spy = Spy {
        lock_calls: 0,
        unlock_calls: 0,
        insert_calls: 0,
        insert_desc: core::ptr::null_mut(),
        insert_block: core::ptr::null_mut(),
        mutex_delete_calls: 0,
        mutex_delete_handle: core::ptr::null_mut(),
    };

    unsafe extern "C" fn spy_lock(_desc: *mut HeapDescriptor) {
        (*core::ptr::addr_of_mut!(SPY)).lock_calls += 1;
    }

    unsafe extern "C" fn spy_unlock(_desc: *mut HeapDescriptor) {
        (*core::ptr::addr_of_mut!(SPY)).unlock_calls += 1;
    }

    unsafe extern "C" fn spy_insert(desc: *mut HeapDescriptor, block: *mut u32) {
        let spy = &mut *core::ptr::addr_of_mut!(SPY);
        spy.insert_calls += 1;
        spy.insert_desc = desc;
        spy.insert_block = block;
    }

    unsafe extern "C" fn spy_mutex_delete(handle: *mut u32) {
        let spy = &mut *core::ptr::addr_of_mut!(SPY);
        spy.mutex_delete_calls += 1;
        spy.mutex_delete_handle = handle;
    }

    /// Installs the spies and zeroes the spy state.
    unsafe fn install_spies() {
        core::ptr::addr_of_mut!(SPY).write(Spy {
            lock_calls: 0,
            unlock_calls: 0,
            insert_calls: 0,
            insert_desc: core::ptr::null_mut(),
            insert_block: core::ptr::null_mut(),
            mutex_delete_calls: 0,
            mutex_delete_handle: core::ptr::null_mut(),
        });
        core::ptr::addr_of_mut!(HEAP_INIT_OPS).write(HeapInitOps {
            lock: spy_lock,
            unlock: spy_unlock,
            insert_free_block: spy_insert,
            panic: missing_panic,
            mutex_delete: spy_mutex_delete,
        });
    }

    /// Allocates a descriptor filled with 0xAA so zeroing is observable.
    fn garbage_desc() -> *mut HeapDescriptor {
        let desc = Box::into_raw(Box::new(HeapDescriptor {
            free_bytes: 0,
            total_bytes: 0,
            allocated_bytes: 0,
            alloc_counter: 0,
            regions: [(0, 0); MAX_REGIONS],
            region_count: 0,
            mutex_state: 0,
            mutex_state2: 0,
            _pad_b6: [0; 2],
            mutex_handle: 0,
            _pad_bc: 0,
            initialized: 0,
            initial_region_start: 0,
            initial_region_size: 0,
            auto_init: 0,
            sentinel: crate::heap::types::FreeSentinel {
                size_flags: 0,
                next: core::ptr::null_mut(),
                prev: core::ptr::null_mut(),
                unused: 0,
            },
            bytes_per_class: [0; NUM_CLASSES],
            class_total: 0,
            bytes_per_tag: [0; NUM_TAGS],
            tag_total: 0,
            blocks_per_bin: [0; NUM_BINS],
            bin_total: 0,
            peak_bytes: 0,
        }));
        unsafe {
            core::ptr::write_bytes(desc as *mut u8, 0xAA, core::mem::size_of::<HeapDescriptor>());
        }
        desc
    }

    #[test]
    fn desc_init_zeroes_and_sets_sentinel() {
        let desc = garbage_desc();
        unsafe {
            let ret = heap_desc_init(desc, 0x1000, 0x2000);
            assert_eq!(ret, desc);
            let d = &*desc;
            assert_eq!(d.initial_region_start, 0x1000);
            assert_eq!(d.initial_region_size, 0x2000);
            // auto_init is a byte store: low byte 1.
            assert_eq!(auto_init_flag(desc), 1);
            assert_eq!(core::ptr::addr_of!((*desc).initialized).cast::<u8>().read(), 0);
            assert_eq!(d.free_bytes, 0);
            assert_eq!(d.total_bytes, 0);
            assert_eq!(d.allocated_bytes, 0);
            assert_eq!(d.alloc_counter, 0);
            assert_eq!(d.mutex_state, 0);
            assert_eq!(d.mutex_state2, 0);
            assert!(d.regions.iter().all(|&r| r == (0, 0)));
            assert_eq!(d.region_count, 0);
            // Synthesized sentinel: zero-size head node, empty list.
            assert_eq!(d.sentinel.size_flags, 0);
            assert!(d.sentinel.next.is_null());
            assert!(d.sentinel.prev.is_null());
            assert_eq!(d.sentinel.unused, 0);
            assert!(d.bytes_per_class.iter().all(|&v| v == 0));
            assert_eq!(d.class_total, 0);
            assert!(d.bytes_per_tag.iter().all(|&v| v == 0));
            assert_eq!(d.tag_total, 0);
            assert!(d.blocks_per_bin.iter().all(|&v| v == 0));
            assert_eq!(d.bin_total, 0);
            assert_eq!(d.peak_bytes, 0);
            drop(Box::from_raw(desc));
        }
    }

    #[test]
    fn desc_init_auto_init_requires_both_nonzero() {
        let desc = garbage_desc();
        unsafe {
            heap_desc_init(desc, 0, 0x2000);
            assert_eq!(auto_init_flag(desc), 0);
            assert_eq!((*desc).initial_region_start, 0);
            assert_eq!((*desc).initial_region_size, 0x2000); // stored regardless
            heap_desc_init(desc, 0x1000, 0);
            assert_eq!(auto_init_flag(desc), 0);
            assert_eq!((*desc).initial_region_start, 0x1000);
            assert_eq!((*desc).initial_region_size, 0);
            drop(Box::from_raw(desc));
        }
    }

    /// Expected block layout for a region, mirroring the original's
    /// arithmetic.
    fn expected_layout(start: usize, size: usize) -> (usize, usize) {
        let header = start.wrapping_add(15) & !7;
        let block_size = size
            .wrapping_sub(header.wrapping_add(4).wrapping_sub(start))
            .wrapping_sub(4)
            & !7;
        (header, block_size)
    }

    // --- SIGSEGV capture (macOS host) -------------------------------------
    // The auto_init fallback round-trips the region base through the u32
    // descriptor fields (the target is a 32-bit system), so on a 64-bit host
    // the carve deliberately runs against unmapped low memory. Catching the
    // fault address proves which address the carve used.

    extern "C" {
        fn sigaction(sig: i32, act: *const SigAction, old: *mut SigAction) -> i32;
        fn sigsetjmp(env: *mut usize, savemask: i32) -> i32;
        fn siglongjmp(env: *mut usize, val: i32) -> !;
    }

    const SIGSEGV: i32 = 11;
    const SA_SIGINFO: i32 = 0x0040;

    /// macOS `struct sigaction`: handler, then mask (u32) | flags (i32).
    #[repr(C)]
    struct SigAction {
        handler: usize,
        mask_flags: usize,
    }

    static mut JMP_BUF: [usize; 32] = [0; 32];
    static mut FAULT_ADDR: usize = 0;

    unsafe extern "C" fn segv_handler(_sig: i32, info: *const u8, _ctx: *mut u8) {
        // darwin siginfo_t: si_addr at offset 24.
        (*core::ptr::addr_of_mut!(FAULT_ADDR)) = (info.add(24) as *const usize).read();
        siglongjmp(core::ptr::addr_of_mut!(JMP_BUF) as *mut usize, 1);
    }

    /// Runs `body`; returns `Some(fault_address)` if it died on SIGSEGV.
    unsafe fn catch_segv(body: impl FnOnce()) -> Option<usize> {
        let handler = SigAction {
            handler: segv_handler as usize,
            mask_flags: (SA_SIGINFO as usize) << 32,
        };
        let mut old = SigAction {
            handler: 0,
            mask_flags: 0,
        };
        assert_eq!(sigaction(SIGSEGV, &handler, &mut old), 0);
        let result = if sigsetjmp(core::ptr::addr_of_mut!(JMP_BUF) as *mut usize, 1) == 0 {
            body();
            None
        } else {
            Some(*core::ptr::addr_of!(FAULT_ADDR))
        };
        assert_eq!(sigaction(SIGSEGV, &old, core::ptr::null_mut()), 0);
        result
    }

    #[test]
    fn add_region_aligns_and_carves_one_free_block() {
        unsafe {
            install_spies();
            let mut region = Box::new(Region([0xCC; 0x2000]));
            let desc = garbage_desc();
            heap_desc_init(desc, 0, 0);
            // Misaligned start exercises the align-up path.
            let start = region.0.as_mut_ptr() as usize + 3;
            let size = 0x1000usize;
            let ret = heap_add_region(desc, start, size);
            assert_eq!(ret, desc);

            let (header, block_size) = expected_layout(start, size);
            assert_eq!(header % 8, 0);
            assert!(header > start);
            // Region table + totals.
            assert_eq!((*desc).region_count, 1);
            assert_eq!((*desc).regions[0], (header as u32, block_size as u32));
            assert_eq!((*desc).total_bytes, block_size as u32);
            // Block shape: prev-size word, header, links, terminator.
            let block = header as *const u32;
            assert_eq!(block.sub(1).read(), 0, "prev-size word");
            assert_eq!(block.add(0).read(), block_size as u32, "size_flags");
            assert_eq!(block.add(1).read(), 0, "next link");
            assert_eq!(block.add(2).read(), 0, "prev link");
            assert_eq!(
                block.add(block_size / 4).read(),
                0,
                "zero-word terminator block"
            );
            // The block spans the region minus alignment/terminator overhead.
            assert!(header + block_size <= start + size);
            assert!(block_size >= size - 24);
            // One free block was handed to the insert helper.
            let spy = &*core::ptr::addr_of!(SPY);
            assert_eq!(spy.lock_calls, 1);
            assert_eq!(spy.unlock_calls, 1);
            assert_eq!(spy.insert_calls, 1);
            assert_eq!(spy.insert_desc, desc);
            assert_eq!(spy.insert_block, header as *mut u32);
            drop(Box::from_raw(desc));
        }
    }

    #[test]
    fn add_region_aligned_start_skips_eight() {
        unsafe {
            install_spies();
            let mut region = Box::new(Region([0xCC; 0x2000]));
            let desc = garbage_desc();
            heap_desc_init(desc, 0, 0);
            let start = region.0.as_mut_ptr() as usize; // 8-aligned
            let size = 0x800usize;
            heap_add_region(desc, start, size);
            // Header at start + 8, block = size - 16 (8 head + 4+4 tail),
            // rounded down to 8.
            let (header, block_size) = expected_layout(start, size);
            assert_eq!(header, start + 8);
            assert_eq!(block_size, size - 16);
            assert_eq!((*desc).regions[0], (header as u32, block_size as u32));
            drop(Box::from_raw(desc));
        }
    }

    #[test]
    fn add_region_auto_init_uses_initial_region() {
        unsafe {
            install_spies();
            let desc = garbage_desc();
            heap_desc_init(desc, 0x5000, 0x1000);
            assert_eq!(auto_init_flag(desc), 1);

            // Full end-to-end carve via the fallback is impossible on a
            // 64-bit host: the descriptor's region fields are u32 (the
            // target is a 32-bit system), so a real host pointer doesn't
            // survive the round trip and the carve would write into
            // unmapped low memory. Instead, prove the substitution happened
            // by observing *where* the carve faults: with the fallback the
            // first block write lands at align8(0x5000)+8-4 = 0x5004; without
            // it (auto_init clear) a (0,0) call carves at address 8-4 = 4.
            let fault = catch_segv(|| {
                heap_add_region(desc, 0, 0);
            });
            // First block write is at header-4 = 0x5004, the terminator at
            // 0x5ff8; accept either (store order is the compiler's choice).
            let fault = fault.expect("carve must fault in unmapped low memory");
            assert!(
                (0x5000..0x6000).contains(&fault),
                "fallback should carve at the recorded region, faulted at {fault:#x}"
            );

            heap_desc_init(desc, 0, 0); // auto_init = 0
            let fault = catch_segv(|| {
                heap_add_region(desc, 0, 0);
            });
            // No fallback: carves from address 0 (header at 8).
            let fault = fault.expect("carve must fault in unmapped low memory");
            assert!(fault < 0x100, "no fallback: carve near address 0, faulted at {fault:#x}");
            drop(Box::from_raw(desc));
        }
    }

    #[test]
    fn add_region_stops_at_max_regions() {
        unsafe {
            install_spies();
            let mut region = Box::new(Region([0xCC; 0x2000]));
            let base = region.0.as_mut_ptr() as usize;
            let desc = garbage_desc();
            heap_desc_init(desc, 0, 0);
            // Fill all 20 slots with small distinct regions.
            for i in 0..MAX_REGIONS {
                let start = base + i * 0x100;
                heap_add_region(desc, start, 0x100);
                assert_eq!((*desc).region_count, (i + 1) as u32);
            }
            let total_after_20 = (*desc).total_bytes;
            let spy_after_20 = (*core::ptr::addr_of!(SPY)).insert_calls;
            assert_eq!(spy_after_20, MAX_REGIONS as u32);

            // 21st region: ignored, but the lock/unlock pair still runs.
            heap_add_region(desc, base + 0x1f00, 0x100);
            assert_eq!((*desc).region_count, MAX_REGIONS as u32);
            assert_eq!((*desc).total_bytes, total_after_20);
            assert_eq!((*desc).regions[MAX_REGIONS - 1].0, {
                expected_layout(base + (MAX_REGIONS - 1) * 0x100, 0x100).0 as u32
            });
            let spy = &*core::ptr::addr_of!(SPY);
            assert_eq!(spy.insert_calls, MAX_REGIONS as u32);
            assert_eq!(spy.lock_calls, (MAX_REGIONS + 1) as u32);
            assert_eq!(spy.unlock_calls, (MAX_REGIONS + 1) as u32);
            drop(Box::from_raw(desc));
        }
    }

    #[test]
    fn create_and_create_empty_wire_desc_init() {
        unsafe {
            let desc = garbage_desc();
            let ret = heap_create(desc, 0x4000, 0x8000);
            assert_eq!(ret, desc);
            assert_eq!((*desc).initial_region_start, 0x4000);
            assert_eq!((*desc).initial_region_size, 0x8000);
            assert_eq!(auto_init_flag(desc), 1);
            assert_eq!((*desc).region_count, 0);
            assert!(core::ptr::addr_of!((*desc).sentinel.next).read().is_null());
            drop(Box::from_raw(desc));

            let desc = garbage_desc();
            let ret = heap_create_empty(desc);
            assert_eq!(ret, desc);
            assert_eq!((*desc).initial_region_start, 0);
            assert_eq!((*desc).initial_region_size, 0);
            assert_eq!(auto_init_flag(desc), 0);
            drop(Box::from_raw(desc));
        }
    }

    #[test]
    fn destroy_deletes_mutex_only_when_initialized() {
        unsafe {
            install_spies();
            let desc = garbage_desc();
            heap_create_empty(desc);

            // No mutex created: no delete.
            let ret = heap_destroy(desc);
            assert_eq!(ret, desc);
            assert_eq!((*core::ptr::addr_of!(SPY)).mutex_delete_calls, 0);

            // Mutex created (state byte set by the lock helper on target):
            // delete is invoked with &desc->mutex_handle.
            (*desc).mutex_state = 1;
            (*desc).mutex_handle = 0xDEADBEEF;
            let ret = heap_destroy(desc);
            assert_eq!(ret, desc);
            let spy = &*core::ptr::addr_of!(SPY);
            assert_eq!(spy.mutex_delete_calls, 1);
            assert_eq!(
                spy.mutex_delete_handle,
                core::ptr::addr_of_mut!((*desc).mutex_handle)
            );
            drop(Box::from_raw(desc));
        }
    }
}
