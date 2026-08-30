//! `mov_atom_info` — original: `FUN_081c8034` @ 0x081c8034 (**112
//! bytes**, 0x081c8034..0x081c80a4, all code, no literal pool; Ghidra's
//! 112 is exact — the next function opens at 0x081c80a4 with
//! `push {r4, r5, r6, r7, r8, lr}`. Byte-decoded from osos.dec).
//! **33 `bl` call sites, 0 predicated**, verified by decoding every
//! B/BL word in osos.dec; no DATA word anywhere references the
//! address, so it is only ever direct-called, never dispatched
//! virtually.
//!
//! # What it is
//!
//! The MOV/MP4 demuxer's per-atom info query. Every observed call
//! site passes a fourcc atom tag (`elst`, `tkhd`, `mdhd`, `stts`,
//! `stsd`, ... — the literal-pool constants @ 0x081c3088..0x081c30a4
//! in the big caller `FUN_081c2098`) and receives the atom's recorded
//! payload offset, size and a flag byte. The query is keyed into a
//! per-file atom table built while walking the container; callers test
//! the returned u64s against `-1` to learn whether the atom was ever
//! seen (e.g. `(local_64 != -1 || local_68 != -1)` @
//! 081c2098_FUN_081c2098.c).
//!
//! # Algorithm
//!
//! ```text
//! 081c8034  push {r4, r5, r6, r7, r8, lr}
//! 081c8038  mov  r5, r2             @ fourcc
//! 081c803c  mov  r4, r3             @ offset_out
//! 081c8040  mov  r0, r1             @ table (r0 arg dropped unread)
//! 081c8044  ldrd r6, [sp, #24]      @ stack args: r6=size_out, r7=flag_out
//! 081c8048  bl   0x08280114         @ root = *table        (`ldr r0,[r0]`)
//! 081c804c  mov  r2, #1             @ populate = 1
//! 081c8050  mov  r1, r5
//! 081c8054  bl   0x080a3ea0         @ node = find_or_create(root, fourcc, 1)
//! 081c8058  movs r5, r0
//! 081c805c  mvneq r0, #0            @ node == NULL: r0 = 0xffffffff
//! 081c8060  streq r0, [r4]          @   *offset_out = -1 (both halves)
//! 081c8064  streq r0, [r4, #4]
//! 081c8068  streq r0, [r6]          @   *size_out   = -1 (both halves)
//! 081c806c  streq r0, [r6, #4]
//! 081c8070  moveq r0, #0            @   flag byte 0, return NULL
//! 081c8074  beq   0x081c8098
//! 081c8078  mov  r0, r5
//! 081c807c  bl   0x0814d230         @ ldrd [node, #16]  -> payload offset
//! 081c8080  strd r0, [r4]           @ *offset_out = offset
//! 081c8084  mov  r0, r5
//! 081c8088  bl   0x0814d1ac         @ ldrd [node, #24]  -> atom size
//! 081c808c  strd r0, [r6]           @ *size_out = size
//! 081c8090  mov  r0, r5
//! 081c8094  bl   0x0814d270         @ ldrb [node, #32]  -> flag
//! 081c8098  strb r0, [r7]           @ *flag_out (shared tail)
//! 081c809c  mov  r0, r5             @ return node (NULL on miss)
//! 081c80a0  pop  {r4, r5, r6, r7, r8, pc}
//! ```
//!
//! The atom node layout (recovered from the getters above, the setters
//! @ 0x0814d240 / 0x0814d1c4 / 0x0814d278 / 0x0814d1f4 and the node
//! initializer @ 0x0814d2b0):
//!
//! ```text
//! +0x00,+0x04  child links walked by the table search
//! +0x08        duplicate-fourcc chain link
//! +0x10  u64   atom payload offset  (setter rejects < 0;  born -1)
//! +0x18  u64   atom total size      (setter rejects < 8;  born -1)
//! +0x20  u8    flag byte            (born 0)
//! +0x21  u8    kind byte 0..=5
//! +0x24  u32   fourcc key
//! ```
//!
//! The table search `FUN_080a3ea0` (unported) is a recursive
//! child-link walk keyed by the +0x24 fourcc; with `populate == 1` it
//! returns the first matching node (placeholder or filled) and NULL
//! when the fourcc was never registered. The first callee @
//! 0x08280114 is a one-instruction handle dereference
//! (`ldr r0, [r0]; bx lr`): the `table` argument is a pointer whose
//! first word is the table root.
//!
//! Ghidra's C for this one is faithful (including the `-1` stores —
//! `mvneq r0, #0` is move-NOT), except it cannot see that the failure
//! flag byte is written through the *shared* tail store.
//!
//! # Deviations
//!
//! - All five callees are unported (none appears in names.yaml) and
//!   dispatch through [`MOV_ATOM_INFO_OPS`] (the
//!   `app/event_hub.rs` pattern): target builds transmute the ROM
//!   addresses 0x08280114 / 0x080a3ea0 / 0x0814d230 / 0x0814d1ac /
//!   0x0814d270, so this symbol IS hook-ready on device; host defaults
//!   are inert (NULL table root, NULL node, zeroed getters — the miss
//!   path) and every test installs recording models.
//! - The r0 incoming argument is dropped unread by the original
//!   (`mov r0, r1` @ 0x081c8040 before any use); the port keeps it as
//!   `_this` purely to preserve the ABI slot. Observed callers pass
//!   the MOV parser context object.
//! - No NULL guards on the three output pointers — the original's
//!   `streq`/`strd`/`strb` have none, and adding one would be a
//!   behavior change.

/// Indirect dispatch for the five unported callees (see the module
/// header). Host tests install recording models; the real ports
/// replace the defaults when they land.
#[derive(Clone, Copy)]
pub struct MovAtomInfoOps {
    /// Callee 0x08280114 `(table)`: the handle dereference
    /// `ldr r0, [r0]; bx lr` — returns the atom-table root stored in
    /// the handle's first word.
    pub table_root: unsafe extern "C" fn(table: *mut u8) -> *mut u8,
    /// Callee 0x080a3ea0 `(root, fourcc, populate)`: recursive
    /// fourcc-keyed table search. With `populate == 1` (the only value
    /// this function passes) returns the first node whose +0x24 key
    /// matches, or NULL when the fourcc was never registered.
    pub find_or_create:
        unsafe extern "C" fn(root: *mut u8, fourcc: u32, populate: u32) -> *mut u8,
    /// Callee 0x0814d230 `(node)`: `ldrd [node, #16]` — the atom
    /// payload offset, -1 while only a placeholder exists.
    pub offset_get: unsafe extern "C" fn(node: *mut u8) -> u64,
    /// Callee 0x0814d1ac `(node)`: `ldrd [node, #24]` — the atom total
    /// size, -1 while only a placeholder exists.
    pub size_get: unsafe extern "C" fn(node: *mut u8) -> u64,
    /// Callee 0x0814d270 `(node)`: `ldrb [node, #32]` — the flag byte.
    pub flag_get: unsafe extern "C" fn(node: *mut u8) -> u8,
}

/// Target default: the ROM handle dereference @ 0x08280114.
#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_table_root(table: *mut u8) -> *mut u8 {
    let f: unsafe extern "C" fn(*mut u8) -> *mut u8 = core::mem::transmute(0x0828_0114usize);
    f(table)
}

/// Host default: inert — no table. The query then takes the miss path.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_table_root(_table: *mut u8) -> *mut u8 {
    core::ptr::null_mut()
}

/// Target default: the ROM table search @ 0x080a3ea0.
#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_find_or_create(
    root: *mut u8,
    fourcc: u32,
    populate: u32,
) -> *mut u8 {
    let f: unsafe extern "C" fn(*mut u8, u32, u32) -> *mut u8 =
        core::mem::transmute(0x080a_3ea0usize);
    f(root, fourcc, populate)
}

/// Host default: inert — every fourcc misses.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_find_or_create(
    _root: *mut u8,
    _fourcc: u32,
    _populate: u32,
) -> *mut u8 {
    core::ptr::null_mut()
}

/// Target default: the ROM offset getter @ 0x0814d230.
#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_offset_get(node: *mut u8) -> u64 {
    let f: unsafe extern "C" fn(*mut u8) -> u64 = core::mem::transmute(0x0814_d230usize);
    f(node)
}

/// Host default: inert — unreachable (the host find default always
/// misses, so the getters never run); defined so a forgotten install
/// cannot corrupt state.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_offset_get(_node: *mut u8) -> u64 {
    0
}

/// Target default: the ROM size getter @ 0x0814d1ac.
#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_size_get(node: *mut u8) -> u64 {
    let f: unsafe extern "C" fn(*mut u8) -> u64 = core::mem::transmute(0x0814_d1acusize);
    f(node)
}

/// Host default: inert (see `firmware_offset_get`).
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_size_get(_node: *mut u8) -> u64 {
    0
}

/// Target default: the ROM flag getter @ 0x0814d270.
#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_flag_get(node: *mut u8) -> u8 {
    let f: unsafe extern "C" fn(*mut u8) -> u8 = core::mem::transmute(0x0814_d270usize);
    f(node)
}

/// Host default: inert (see `firmware_offset_get`).
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_flag_get(_node: *mut u8) -> u8 {
    0
}

/// Wired default: the ROM addresses on target, documented inert stubs
/// on host.
pub const DEFAULT_MOV_ATOM_INFO_OPS: MovAtomInfoOps = MovAtomInfoOps {
    table_root: firmware_table_root,
    find_or_create: firmware_find_or_create,
    offset_get: firmware_offset_get,
    size_get: firmware_size_get,
    flag_get: firmware_flag_get,
};

/// The active callee set — the dispatch seams for 0x08280114,
/// 0x080a3ea0, 0x0814d230, 0x0814d1ac and 0x0814d270. Host tests
/// install recording models; the real ports replace the defaults when
/// they exist.
pub static mut MOV_ATOM_INFO_OPS: MovAtomInfoOps = DEFAULT_MOV_ATOM_INFO_OPS;

/// Volatile read so LLVM cannot fold the defaults in and delete the
/// dispatch (the `alloc_core.rs` rationale).
#[inline(always)]
unsafe fn ops() -> MovAtomInfoOps {
    core::ptr::read_volatile(core::ptr::addr_of!(MOV_ATOM_INFO_OPS))
}

/// mov_atom_info — original: `FUN_081c8034` @ 0x081c8034 (112 bytes;
/// 33 `bl` call sites, binary-verified).
///
/// Queries the MOV atom table `table` for `fourcc` and unpacks the
/// node: `*offset_out` = payload offset, `*size_out` = total size,
/// `*flag_out` = flag byte. A NULL search result (fourcc never
/// registered) instead writes `-1`/`-1`/`0` and returns NULL. Returns
/// the node on a hit. See the module header for the algorithm, the
/// node layout, and the seam contract.
///
/// Faithful details:
/// - `_this` is dropped unread, exactly like the original's
///   overwritten r0.
/// - `populate` is the constant 1 — with 0 the search would allocate a
///   fresh placeholder behind an already-filled node instead.
/// - The miss path writes both halves of both u64s (`-1` each) and
///   still stores the flag byte (0) through the shared tail store.
/// - Getter results are stored in call order: offset, size, flag —
///   and each getter receives the node, never the table or root.
/// - No NULL guard on any output pointer, exactly like the original.
///
/// # Safety
///
/// `table`, `offset_out`, `size_out` and `flag_out` must be valid,
/// writable as the firmware expects; the node the search returns must
/// stay live for the three getter calls.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn mov_atom_info(
    _this: *mut u8,
    table: *mut u8,
    fourcc: u32,
    offset_out: *mut u64,
    size_out: *mut u64,
    flag_out: *mut u8,
) -> *mut u8 {
    let ops = ops();
    let root = (ops.table_root)(table);
    let node = (ops.find_or_create)(root, fourcc, 1);
    if node.is_null() {
        *offset_out = u64::MAX;
        *size_out = u64::MAX;
        *flag_out = 0;
        return core::ptr::null_mut();
    }
    *offset_out = (ops.offset_get)(node);
    *size_out = (ops.size_get)(node);
    *flag_out = (ops.flag_get)(node);
    node
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::ptr;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes every test below: the ops table is process-wide.
    static MOV_ATOM_INFO_LOCK: Mutex<()> = Mutex::new(());

    /// Calls each recording seam saw, in order.
    static mut TRACE: Vec<&'static str> = Vec::new();
    /// What the recording handle dereference returns.
    static mut ROOT_RESULT: *mut u8 = ptr::null_mut();
    /// What the recording search returns (NULL = miss).
    static mut NODE_RESULT: *mut u8 = ptr::null_mut();
    /// The arguments the recording search saw.
    static mut SEARCH_ARGS: Vec<(*mut u8, u32, u32)> = Vec::new();
    /// The node pointer each recording getter saw.
    static mut GETTER_NODES: Vec<*mut u8> = Vec::new();

    /// A fake atom node, laid out exactly as the firmware reads it:
    /// u64 payload offset at +0x10, u64 total size at +0x18, flag byte
    /// at +0x20. The recording getters below are honest field reads,
    /// not canned values, so the plumbing is tested against the real
    /// offsets.
    #[repr(C, align(8))]
    struct FakeNode {
        bytes: [u8; 40],
    }

    static mut NODE: FakeNode = FakeNode { bytes: [0; 40] };

    fn plant_node(offset: u64, size: u64, flag: u8) -> *mut u8 {
        unsafe {
            let base = ptr::addr_of_mut!(NODE) as *mut u8;
            (base.add(0x10) as *mut u64).write(offset);
            (base.add(0x18) as *mut u64).write(size);
            *base.add(0x20) = flag;
            base
        }
    }

    unsafe extern "C" fn recording_table_root(_table: *mut u8) -> *mut u8 {
        (*ptr::addr_of_mut!(TRACE)).push("root");
        ptr::addr_of!(ROOT_RESULT).read_volatile()
    }

    unsafe extern "C" fn recording_find_or_create(
        root: *mut u8,
        fourcc: u32,
        populate: u32,
    ) -> *mut u8 {
        (*ptr::addr_of_mut!(TRACE)).push("find");
        (*ptr::addr_of_mut!(SEARCH_ARGS)).push((root, fourcc, populate));
        ptr::addr_of!(NODE_RESULT).read_volatile()
    }

    unsafe extern "C" fn recording_offset_get(node: *mut u8) -> u64 {
        (*ptr::addr_of_mut!(TRACE)).push("offset");
        (*ptr::addr_of_mut!(GETTER_NODES)).push(node);
        (node.add(0x10) as *const u64).read()
    }

    unsafe extern "C" fn recording_size_get(node: *mut u8) -> u64 {
        (*ptr::addr_of_mut!(TRACE)).push("size");
        (*ptr::addr_of_mut!(GETTER_NODES)).push(node);
        (node.add(0x18) as *const u64).read()
    }

    unsafe extern "C" fn recording_flag_get(node: *mut u8) -> u8 {
        (*ptr::addr_of_mut!(TRACE)).push("flag");
        (*ptr::addr_of_mut!(GETTER_NODES)).push(node);
        *node.add(0x20)
    }

    /// Installs the recording seams and clears the statics.
    fn mock(root: *mut u8, node: *mut u8) -> MutexGuard<'static, ()> {
        let guard = MOV_ATOM_INFO_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            MOV_ATOM_INFO_OPS = MovAtomInfoOps {
                table_root: recording_table_root,
                find_or_create: recording_find_or_create,
                offset_get: recording_offset_get,
                size_get: recording_size_get,
                flag_get: recording_flag_get,
            };
            ROOT_RESULT = root;
            NODE_RESULT = node;
            (*ptr::addr_of_mut!(TRACE)).clear();
            (*ptr::addr_of_mut!(SEARCH_ARGS)).clear();
            (*ptr::addr_of_mut!(GETTER_NODES)).clear();
        }
        guard
    }

    /// Restores every wired default. Takes the guard by value so it
    /// cannot be re-locked while still held (the seek_core.rs rule).
    fn restore(guard: MutexGuard<'static, ()>) {
        unsafe {
            MOV_ATOM_INFO_OPS = DEFAULT_MOV_ATOM_INFO_OPS;
        }
        drop(guard);
    }

    fn trace() -> Vec<&'static str> {
        unsafe { (*ptr::addr_of!(TRACE)).clone() }
    }

    /// 'stsd', one of the literal-pool fourccs @ 0x081c3098.
    const FOURCC_STSD: u32 = 0x7374_7364;

    #[test]
    fn a_hit_unpacks_offset_size_and_flag_from_the_node() {
        let root = 0x1234_5000usize as *mut u8;
        let node = plant_node(0x1122_3344_5566_7788, 0x0000_0001_0000_0008, 0x5a);
        let guard = mock(root, node);
        let table = 0x0dab_0000usize as *mut u8;
        let ignored = 0x0dad_0000usize as *mut u8;
        let mut offset = 0u64;
        let mut size = 0u64;
        let mut flag = 0xffu8;

        let result = unsafe {
            mov_atom_info(
                ignored,
                table,
                FOURCC_STSD,
                &mut offset,
                &mut size,
                &mut flag,
            )
        };

        assert_eq!(result, node, "the node itself is returned");
        assert_eq!(offset, 0x1122_3344_5566_7788);
        assert_eq!(size, 0x0000_0001_0000_0008);
        assert_eq!(flag, 0x5a);
        assert_eq!(
            trace(),
            std::vec!["root", "find", "offset", "size", "flag"],
            "handle deref, search, then the three getters in order"
        );
        unsafe {
            assert_eq!(
                (*ptr::addr_of!(SEARCH_ARGS)).as_slice(),
                &[(root, FOURCC_STSD, 1)],
                "the search sees the deref result, the fourcc, populate=1"
            );
            assert_eq!(
                (*ptr::addr_of!(GETTER_NODES)).as_slice(),
                &[node, node, node],
                "every getter receives the node, never the table or root"
            );
        }
        restore(guard);
    }

    #[test]
    fn a_miss_writes_minus_one_minus_one_zero_and_returns_null() {
        let root = 0x1234_5000usize as *mut u8;
        let guard = mock(root, ptr::null_mut());
        let table = 0x0dab_0000usize as *mut u8;
        let mut offset = 0xdead_beefu64;
        let mut size = 0xdead_beefu64;
        let mut flag = 0xaau8;

        let result = unsafe {
            mov_atom_info(
                ptr::null_mut(),
                table,
                FOURCC_STSD,
                &mut offset,
                &mut size,
                &mut flag,
            )
        };

        assert!(result.is_null());
        assert_eq!(offset, u64::MAX, "both halves of offset_out are -1");
        assert_eq!(size, u64::MAX, "both halves of size_out are -1");
        assert_eq!(flag, 0, "the shared tail still stores the flag byte");
        assert_eq!(
            trace(),
            std::vec!["root", "find"],
            "the getters never run on a miss"
        );
        unsafe {
            assert_eq!(
                (*ptr::addr_of!(SEARCH_ARGS)).as_slice(),
                &[(root, FOURCC_STSD, 1)]
            );
        }
        restore(guard);
    }

    #[test]
    fn a_null_root_is_fed_to_the_search_verbatim() {
        // The original has no guard between the handle dereference and
        // the search; a NULL root goes straight in (the real search
        // answers NULL for it).
        let node = plant_node(8, 16, 1);
        let guard = mock(ptr::null_mut(), node);
        let mut offset = 0u64;
        let mut size = 0u64;
        let mut flag = 0u8;

        unsafe {
            mov_atom_info(
                ptr::null_mut(),
                0x0dab_0000usize as *mut u8,
                FOURCC_STSD,
                &mut offset,
                &mut size,
                &mut flag,
            )
        };

        unsafe {
            assert_eq!(
                (*ptr::addr_of!(SEARCH_ARGS)).as_slice(),
                &[(ptr::null_mut(), FOURCC_STSD, 1)]
            );
        }
        restore(guard);
    }

    #[test]
    fn default_host_seams_are_inert_but_safe_to_call() {
        // Without installed models the host defaults take the miss
        // path: nothing dereferences the table, nothing reads a node.
        let guard = MOV_ATOM_INFO_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut offset = 1u64;
        let mut size = 2u64;
        let mut flag = 3u8;

        let result = unsafe {
            mov_atom_info(
                ptr::null_mut(),
                0x0dab_0000usize as *mut u8,
                FOURCC_STSD,
                &mut offset,
                &mut size,
                &mut flag,
            )
        };

        assert!(result.is_null());
        assert_eq!((offset, size, flag), (u64::MAX, u64::MAX, 0));
        drop(guard);
    }
}
