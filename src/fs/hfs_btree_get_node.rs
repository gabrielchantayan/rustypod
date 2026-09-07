//! `hfs_btree_get_node` — original: `FUN_08053d6c` @ `0x08053d6c`
//! (168 bytes, `0x08053d6c..0x08053e14`; 21 verified direct `bl` call
//! sites, all unconditional).
//!
//! # What it is
//!
//! The HFS B-tree node fetch. Its shape is Apple's `GetNode` from the
//! classic `hfs` `BTreeIO.c`, in the three-argument form that predates the
//! `flags`/`kGetNodeHint` parameter: the block options word passed to the
//! control block's get-block callback is the constant `0`
//! (`kGetBlock`). The image confirms the family — it carries the
//! `APPLE_HFS` and `HFSPLUS` volume-format strings — and the two callees
//! match the same source file exactly: `0x08044b08` is `CheckNode` (it
//! walks the node descriptor's `fLink`/`bLink`/`kind`/`height`/
//! `numRecords` and the descending record-offset table, returning `36` on
//! any inconsistency) and `0x0806b5b8` is `TrashNode` (it invokes the
//! control block's release-block callback with `kReleaseBlock |
//! kTrashBlock` == `4`, bumps the release counter, and nils the block).
//!
//! # Algorithm
//!
//! 1. Reject a node number at or past `total_nodes` — an *unsigned*
//!    compare (`cmp`/`bls`) — with status [`BTREE_INVALID_NODE_STATUS`].
//! 2. Publish `node_size` into the caller's block descriptor as its
//!    `block_size`, then call the control block's get-block callback as
//!    `(fork, node_number, 0, block)`. A nonzero status aborts.
//! 3. Bump `num_get_nodes`.
//! 4. If the block did **not** come from the disk it came from the block
//!    cache, which only ever holds nodes that were validated on the way
//!    in, so return success without re-validating.
//! 5. Otherwise validate the buffer with `CheckNode`. On success return
//!    `0` and leave the block held by the caller.
//! 6. On failure set the volume's damaged bit through
//!    `control_block.fork -> volume.flags`, trash the block, and return
//!    the validator's status.
//!
//! Every failure exit — and only a failure exit — nils `buffer` and
//! `block_header` in the caller's descriptor. Step 6 does so twice, once
//! inside `TrashNode` and once on the way out; that redundancy is in the
//! original and is preserved.
//!
//! # Deliberate deviations
//!
//! The original reaches its three callees as raw machine addresses: a
//! `blx` through the control block's `+0x3c` word and two direct `bl`s to
//! `0x08044b08` and `0x0806b5b8`. Neither of those two bodies is ported
//! yet, and a 32-bit callback word cannot hold a host function address, so
//! all three go through one volatile [`BTREE_NODE_OPS`] table. Target
//! builds resolve it to the resident firmware addresses and perform the
//! same three transfers; host tests install recorders and observe the
//! complete ABI. Nothing else deviates.

use core::ptr::addr_of;

/// Status returned for a node number outside the tree, and the value
/// `CheckNode` @ `0x08044b08` returns for a malformed node. The firmware's
/// stand-in for Apple's `fsBTInvalidNodeErr`.
pub const BTREE_INVALID_NODE_STATUS: i32 = 36;

/// Block options word the original passes to the get-block callback: the
/// bare `kGetBlock`, with no hint and no dirty marking.
pub const GET_BLOCK_OPTIONS: u32 = 0;

/// Block options word `TrashNode` @ `0x0806b5b8` passes to the
/// release-block callback: `kReleaseBlock | kTrashBlock`.
pub const TRASH_BLOCK_OPTIONS: u32 = 4;

/// Bit this port sets in [`BTreeVolume::flags`] when a node read back from
/// the disk fails validation — the volume is now known inconsistent.
pub const VOLUME_DAMAGED_FLAG: u16 = 1;

/// RetailOS load address of `CheckNode`, the node validator.
pub const CHECK_NODE_ADDRESS: usize = 0x0804_4b08;

/// RetailOS load address of `TrashNode`, the invalidating block release.
pub const TRASH_NODE_ADDRESS: usize = 0x0806_b5b8;

/// One held B-tree node, Apple's `BlockDescriptor`. Pointer fields are
/// 32-bit target words so the host layout is the target layout.
#[repr(C)]
pub struct BTreeNodeBlock {
    /// The node descriptor itself; nil when no block is held.
    pub buffer: u32,
    /// Cache bookkeeping owned by the block callbacks.
    pub block_header: u32,
    /// Device block number the buffer came from.
    pub block_number: u32,
    /// Byte length of `buffer`; this port publishes `node_size` here.
    pub block_size: u32,
    /// Nonzero when the block was read from the disk rather than served
    /// from the cache. Only such a block is validated.
    pub block_read_from_disk: u8,
    /// Set by writers to mark the node dirty.
    pub is_modified: u8,
    /// Tail padding to the target's four-byte descriptor stride.
    pub reserved_12: [u8; 2],
}

/// The fork the tree lives in (Apple's `FCB`), as far as this port reads
/// it: only the volume back-pointer matters here.
#[repr(C)]
pub struct BTreeFork {
    pub reserved_00: u32,
    /// Volume control block this fork belongs to.
    pub volume: u32,
}

/// The volume control block, as far as this port reads it.
#[repr(C)]
pub struct BTreeVolume {
    /// Volume flag word; [`VOLUME_DAMAGED_FLAG`] lives here.
    pub flags: u16,
}

/// The B-tree control block (Apple's `BTreeControlBlock`).
///
/// Only the named fields are read or written by this port; the reserved
/// runs keep the target offsets exact without inventing identities for
/// words no recovered code touches. `tree_depth`, `attributes`,
/// `release_block_proc` and `num_release_nodes` are named because the two
/// callees reached from here read them, and a host fixture must be large
/// enough to contain everything a real callee would touch.
#[repr(C)]
pub struct BTreeControlBlock {
    pub reserved_00: [u8; 2],
    /// Height of the tree; `CheckNode` bounds a node's height by it.
    pub tree_depth: u16,
    /// Fork the tree lives in, and the first argument to both block
    /// callbacks.
    pub fork: u32,
    pub reserved_08: [u8; 0x14],
    /// Byte size of one node.
    pub node_size: u16,
    pub reserved_1e: u16,
    /// Node count; a node number must be strictly below it.
    pub total_nodes: u32,
    pub reserved_24: [u8; 0x0c],
    /// Tree attribute bits; `CheckNode` reads the big-keys bit.
    pub attributes: u32,
    pub reserved_34: [u8; 8],
    /// Callback that hands out a node's block.
    pub get_block_proc: u32,
    /// Callback that gives one back; `TrashNode` uses it.
    pub release_block_proc: u32,
    pub reserved_44: u32,
    /// Count of nodes handed out, bumped by this port.
    pub num_get_nodes: u32,
    pub reserved_4c: u32,
    /// Count of nodes given back, bumped by `TrashNode`.
    pub num_release_nodes: u32,
}

const _: () = assert!(core::mem::offset_of!(BTreeControlBlock, tree_depth) == 0x02);
const _: () = assert!(core::mem::offset_of!(BTreeControlBlock, fork) == 0x04);
const _: () = assert!(core::mem::offset_of!(BTreeControlBlock, node_size) == 0x1c);
const _: () = assert!(core::mem::offset_of!(BTreeControlBlock, total_nodes) == 0x20);
const _: () = assert!(core::mem::offset_of!(BTreeControlBlock, attributes) == 0x30);
const _: () = assert!(core::mem::offset_of!(BTreeControlBlock, get_block_proc) == 0x3c);
const _: () = assert!(core::mem::offset_of!(BTreeControlBlock, release_block_proc) == 0x40);
const _: () = assert!(core::mem::offset_of!(BTreeControlBlock, num_get_nodes) == 0x48);
const _: () = assert!(core::mem::offset_of!(BTreeControlBlock, num_release_nodes) == 0x50);
const _: () = assert!(core::mem::size_of::<BTreeControlBlock>() == 0x54);
const _: () = assert!(core::mem::offset_of!(BTreeNodeBlock, block_size) == 0x0c);
const _: () = assert!(core::mem::offset_of!(BTreeNodeBlock, block_read_from_disk) == 0x10);
const _: () = assert!(core::mem::size_of::<BTreeNodeBlock>() == 0x14);
const _: () = assert!(core::mem::offset_of!(BTreeFork, volume) == 0x04);

/// ABI of the control block's get-block callback, as the `blx` at
/// `0x08053da0` invokes it.
pub type GetBlockProc = unsafe extern "C" fn(
    fork: u32,
    node_number: u32,
    options: u32,
    block: *mut BTreeNodeBlock,
) -> i32;

/// Indirection that performs that `blx` given the raw callback word. It
/// exists because a 32-bit target word cannot hold a host function
/// address; on target it is a transmute and a call.
pub type GetBlockDispatch = unsafe extern "C" fn(
    get_block_proc: u32,
    fork: u32,
    node_number: u32,
    options: u32,
    block: *mut BTreeNodeBlock,
) -> i32;

/// ABI of `CheckNode` @ [`CHECK_NODE_ADDRESS`]. Returns `0` for a
/// well-formed node and [`BTREE_INVALID_NODE_STATUS`] otherwise.
pub type CheckNodeFn =
    unsafe extern "C" fn(btree: *mut BTreeControlBlock, node: u32) -> i32;

/// ABI of `TrashNode` @ [`TRASH_NODE_ADDRESS`].
pub type TrashNodeFn = unsafe extern "C" fn(
    btree: *mut BTreeControlBlock,
    block: *mut BTreeNodeBlock,
) -> i32;

/// The three transfers this port makes out of its own body.
#[derive(Clone, Copy)]
pub struct BTreeNodeOps {
    pub get_block: GetBlockDispatch,
    pub check_node: CheckNodeFn,
    pub trash_node: TrashNodeFn,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn resident_get_block(
    get_block_proc: u32,
    fork: u32,
    node_number: u32,
    options: u32,
    block: *mut BTreeNodeBlock,
) -> i32 {
    let call: GetBlockProc = core::mem::transmute(get_block_proc as usize);
    call(fork, node_number, options, block)
}

#[cfg(target_os = "none")]
unsafe extern "C" fn resident_check_node(btree: *mut BTreeControlBlock, node: u32) -> i32 {
    let call: CheckNodeFn = core::mem::transmute(CHECK_NODE_ADDRESS);
    call(btree, node)
}

#[cfg(target_os = "none")]
unsafe extern "C" fn resident_trash_node(
    btree: *mut BTreeControlBlock,
    block: *mut BTreeNodeBlock,
) -> i32 {
    let call: TrashNodeFn = core::mem::transmute(TRASH_NODE_ADDRESS);
    call(btree, block)
}

/// Host stand-in for the get-block callback: refuse every node, so no
/// unported callee is ever reached by accident.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_get_block(
    _get_block_proc: u32,
    _fork: u32,
    _node_number: u32,
    _options: u32,
    _block: *mut BTreeNodeBlock,
) -> i32 {
    BTREE_INVALID_NODE_STATUS
}

/// Host stand-in for `CheckNode`. Unreachable while [`missing_get_block`]
/// refuses everything; it accepts the node rather than fabricating a
/// corruption verdict this crate has no evidence for.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_check_node(_btree: *mut BTreeControlBlock, _node: u32) -> i32 {
    0
}

/// Host stand-in for `TrashNode`. The caller nils the descriptor itself.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_trash_node(
    _btree: *mut BTreeControlBlock,
    _block: *mut BTreeNodeBlock,
) -> i32 {
    0
}

/// Active boundary for the three transfers. Target builds reach the
/// resident firmware; host builds fail closed until a test installs
/// recorders.
#[cfg(target_os = "none")]
pub static mut BTREE_NODE_OPS: BTreeNodeOps = BTreeNodeOps {
    get_block: resident_get_block,
    check_node: resident_check_node,
    trash_node: resident_trash_node,
};

/// Active host boundary for the three transfers.
#[cfg(not(target_os = "none"))]
pub static mut BTREE_NODE_OPS: BTreeNodeOps = BTreeNodeOps {
    get_block: missing_get_block,
    check_node: missing_check_node,
    trash_node: missing_trash_node,
};

#[inline(always)]
unsafe fn ops() -> BTreeNodeOps {
    addr_of!(BTREE_NODE_OPS).read_volatile()
}

/// Nils the caller's descriptor, the original's shared `ErrorExit`.
#[inline(always)]
unsafe fn release_descriptor(block: *mut BTreeNodeBlock) {
    (*block).buffer = 0;
    (*block).block_header = 0;
}

/// `hfs_btree_get_node` — original: `FUN_08053d6c` @ `0x08053d6c`
/// (168 bytes; 21 verified direct `bl` call sites, all unconditional —
/// there is not one predicated or plain-`b` caller, so every guard this
/// function needs is the one it performs itself).
///
/// Fetches node `node_number` of `btree` into `block`, validating it when
/// it came off the disk. Returns `0` on success with the block held by the
/// caller, or a nonzero status with the descriptor nilled.
///
/// # Safety
///
/// `btree` must point to a live [`BTreeControlBlock`] whose `fork` and
/// callback words are the target's, and `block` to writable descriptor
/// storage. The validation path additionally dereferences
/// `control_block.fork` and that fork's `volume`, exactly as the original
/// does and with no guard of its own.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.hfs_btree_get_node")]
#[inline(never)]
pub unsafe extern "C" fn hfs_btree_get_node(
    btree: *mut BTreeControlBlock,
    node_number: u32,
    block: *mut BTreeNodeBlock,
) -> i32 {
    if node_number >= (*btree).total_nodes {
        release_descriptor(block);
        return BTREE_INVALID_NODE_STATUS;
    }

    (*block).block_size = u32::from((*btree).node_size);

    let ops = ops();
    let status = (ops.get_block)(
        (*btree).get_block_proc,
        (*btree).fork,
        node_number,
        GET_BLOCK_OPTIONS,
        block,
    );
    if status != 0 {
        release_descriptor(block);
        return status;
    }

    (*btree).num_get_nodes = (*btree).num_get_nodes.wrapping_add(1);

    // A cached block was validated when it was first read in.
    if (*block).block_read_from_disk == 0 {
        return 0;
    }

    let status = (ops.check_node)(btree, (*block).buffer);
    if status == 0 {
        return 0;
    }

    let fork = (*btree).fork as usize as *mut BTreeFork;
    let volume = (*fork).volume as usize as *mut BTreeVolume;
    (*volume).flags |= VOLUME_DAMAGED_FLAG;
    (ops.trash_node)(btree, block);
    release_descriptor(block);
    status
}

#[cfg(test)]
pub(crate) unsafe fn reset_btree_node_ops() {
    core::ptr::addr_of_mut!(BTREE_NODE_OPS).write_volatile(BTreeNodeOps {
        get_block: missing_get_block,
        check_node: missing_check_node,
        trash_node: missing_trash_node,
    });
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr;
    use std::sync::{Mutex, MutexGuard};

    /// `BTREE_NODE_OPS` and the recorders below are one shared global set.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    const SLAB_LEN: usize = 0x1000;
    const CONTROL_OFFSET: usize = 0x000;
    const BLOCK_OFFSET: usize = 0x100;
    const FORK_OFFSET: usize = 0x200;
    const VOLUME_OFFSET: usize = 0x300;
    const NODE_BUFFER_OFFSET: usize = 0x400;

    static mut GET_BLOCK_ARGS: [u32; 4] = [0; 4];
    static mut GET_BLOCK_BLOCK: usize = 0;
    static mut GET_BLOCK_CALLS: u32 = 0;
    static mut GET_BLOCK_STATUS: i32 = 0;
    /// Written into the descriptor by the recorder, the way a real
    /// get-block callback fills it in.
    static mut GET_BLOCK_YIELDS: (u32, u32, u8) = (0, 0, 0);

    static mut CHECK_NODE_ARGS: (usize, u32) = (0, 0);
    static mut CHECK_NODE_CALLS: u32 = 0;
    static mut CHECK_NODE_STATUS: i32 = 0;

    static mut TRASH_NODE_ARGS: (usize, usize) = (0, 0);
    static mut TRASH_NODE_CALLS: u32 = 0;

    unsafe extern "C" fn recording_get_block(
        get_block_proc: u32,
        fork: u32,
        node_number: u32,
        options: u32,
        block: *mut BTreeNodeBlock,
    ) -> i32 {
        GET_BLOCK_ARGS = [get_block_proc, fork, node_number, options];
        GET_BLOCK_BLOCK = block as usize;
        GET_BLOCK_CALLS += 1;
        let (buffer, header, from_disk) = GET_BLOCK_YIELDS;
        (*block).buffer = buffer;
        (*block).block_header = header;
        (*block).block_read_from_disk = from_disk;
        GET_BLOCK_STATUS
    }

    unsafe extern "C" fn recording_check_node(btree: *mut BTreeControlBlock, node: u32) -> i32 {
        CHECK_NODE_ARGS = (btree as usize, node);
        CHECK_NODE_CALLS += 1;
        CHECK_NODE_STATUS
    }

    unsafe extern "C" fn recording_trash_node(
        btree: *mut BTreeControlBlock,
        block: *mut BTreeNodeBlock,
    ) -> i32 {
        TRASH_NODE_ARGS = (btree as usize, block as usize);
        TRASH_NODE_CALLS += 1;
        // The real body nils the descriptor too; prove the caller's own
        // nilling is not what the assertions are seeing.
        0
    }

    struct Fixture {
        _guard: MutexGuard<'static, ()>,
    }

    impl Fixture {
        fn install() -> Self {
            let guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            unsafe {
                GET_BLOCK_ARGS = [0; 4];
                GET_BLOCK_BLOCK = 0;
                GET_BLOCK_CALLS = 0;
                GET_BLOCK_STATUS = 0;
                GET_BLOCK_YIELDS = (0, 0, 0);
                CHECK_NODE_ARGS = (0, 0);
                CHECK_NODE_CALLS = 0;
                CHECK_NODE_STATUS = 0;
                TRASH_NODE_ARGS = (0, 0);
                TRASH_NODE_CALLS = 0;
                ptr::addr_of_mut!(BTREE_NODE_OPS).write_volatile(BTreeNodeOps {
                    get_block: recording_get_block,
                    check_node: recording_check_node,
                    trash_node: recording_trash_node,
                });
            }
            Self { _guard: guard }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            unsafe { reset_btree_node_ops() };
        }
    }

    /// A control block and descriptor in ordinary host memory. Enough for
    /// every path that does not walk the fork chain.
    fn control_block() -> BTreeControlBlock {
        BTreeControlBlock {
            reserved_00: [0xa5; 2],
            tree_depth: 3,
            fork: 0xdead_beef,
            reserved_08: [0xa5; 0x14],
            node_size: 4096,
            reserved_1e: 0xa5a5,
            total_nodes: 8,
            reserved_24: [0xa5; 0x0c],
            attributes: 0,
            reserved_34: [0xa5; 8],
            get_block_proc: 0x0805_1234,
            release_block_proc: 0x0805_5678,
            reserved_44: 0xa5a5_a5a5,
            num_get_nodes: 41,
            reserved_4c: 0xa5a5_a5a5,
            num_release_nodes: 7,
        }
    }

    fn held_block() -> BTreeNodeBlock {
        BTreeNodeBlock {
            buffer: 0x1111_1111,
            block_header: 0x2222_2222,
            block_number: 0x3333_3333,
            block_size: 0x4444_4444,
            block_read_from_disk: 0,
            is_modified: 0,
            reserved_12: [0xa5; 2],
        }
    }

    #[test]
    fn rejects_a_node_number_at_the_tree_size_without_calling_out() {
        let _fixture = Fixture::install();
        let mut btree = control_block();
        let mut block = held_block();
        unsafe {
            let status = hfs_btree_get_node(&mut btree, 8, &mut block);
            assert_eq!(status, BTREE_INVALID_NODE_STATUS);
            assert_eq!(GET_BLOCK_CALLS, 0);
            assert_eq!(block.buffer, 0);
            assert_eq!(block.block_header, 0);
            // The early exit never publishes the node size.
            assert_eq!(block.block_size, 0x4444_4444);
            assert_eq!(btree.num_get_nodes, 41);
        }
    }

    /// `cmp`/`bls` is an unsigned compare, so a node number with bit 31
    /// set is far past the tree, not negative and below it.
    #[test]
    fn compares_the_node_number_without_sign() {
        let _fixture = Fixture::install();
        let mut btree = control_block();
        btree.total_nodes = 0x8000_0000;
        let mut block = held_block();
        unsafe {
            assert_eq!(
                hfs_btree_get_node(&mut btree, 0xffff_ffff, &mut block),
                BTREE_INVALID_NODE_STATUS,
            );
            assert_eq!(GET_BLOCK_CALLS, 0);
            assert_eq!(
                hfs_btree_get_node(&mut btree, 0x7fff_ffff, &mut block),
                0,
            );
            assert_eq!(GET_BLOCK_CALLS, 1);
            assert_eq!(GET_BLOCK_ARGS[2], 0x7fff_ffff);
        }
    }

    /// An empty tree rejects every node, node zero included.
    #[test]
    fn an_empty_tree_has_no_node_zero() {
        let _fixture = Fixture::install();
        let mut btree = control_block();
        btree.total_nodes = 0;
        let mut block = held_block();
        unsafe {
            assert_eq!(
                hfs_btree_get_node(&mut btree, 0, &mut block),
                BTREE_INVALID_NODE_STATUS,
            );
            assert_eq!(GET_BLOCK_CALLS, 0);
        }
    }

    #[test]
    fn publishes_the_node_size_and_forwards_the_callback_word_and_fork() {
        let _fixture = Fixture::install();
        let mut btree = control_block();
        btree.node_size = 0xffff;
        let mut block = held_block();
        unsafe {
            GET_BLOCK_YIELDS = (0x5000_0000, 0x6000_0000, 0);
            assert_eq!(hfs_btree_get_node(&mut btree, 7, &mut block), 0);
            assert_eq!(GET_BLOCK_CALLS, 1);
            assert_eq!(
                GET_BLOCK_ARGS,
                [0x0805_1234, 0xdead_beef, 7, GET_BLOCK_OPTIONS],
            );
            assert_eq!(GET_BLOCK_BLOCK, (&mut block as *mut BTreeNodeBlock) as usize);
            // block_size carries the u16 node size zero-extended, and is
            // written before the callback runs.
            assert_eq!(block.block_size, 0xffff);
            assert_eq!(block.buffer, 0x5000_0000);
            assert_eq!(block.block_header, 0x6000_0000);
            assert_eq!(btree.num_get_nodes, 42);
            assert_eq!(CHECK_NODE_CALLS, 0);
        }
    }

    #[test]
    fn a_failing_callback_nils_the_descriptor_and_leaves_the_counter_alone() {
        let _fixture = Fixture::install();
        let mut btree = control_block();
        let mut block = held_block();
        unsafe {
            GET_BLOCK_STATUS = -12345;
            GET_BLOCK_YIELDS = (0x5000_0000, 0x6000_0000, 1);
            assert_eq!(hfs_btree_get_node(&mut btree, 0, &mut block), -12345);
            assert_eq!(block.buffer, 0);
            assert_eq!(block.block_header, 0);
            // The node size was published before the callback failed.
            assert_eq!(block.block_size, 4096);
            assert_eq!(btree.num_get_nodes, 41);
            assert_eq!(CHECK_NODE_CALLS, 0);
            assert_eq!(TRASH_NODE_CALLS, 0);
        }
    }

    /// A cache hit skips validation entirely — that is the whole point of
    /// the `blockReadFromDisk` test.
    #[test]
    fn a_cached_block_is_not_revalidated() {
        let _fixture = Fixture::install();
        let mut btree = control_block();
        let mut block = held_block();
        unsafe {
            GET_BLOCK_YIELDS = (0x5000_0000, 0x6000_0000, 0);
            CHECK_NODE_STATUS = BTREE_INVALID_NODE_STATUS;
            assert_eq!(hfs_btree_get_node(&mut btree, 1, &mut block), 0);
            assert_eq!(CHECK_NODE_CALLS, 0);
            assert_eq!(TRASH_NODE_CALLS, 0);
            assert_eq!(block.buffer, 0x5000_0000);
            assert_eq!(btree.num_get_nodes, 42);
        }
    }

    /// Any nonzero `blockReadFromDisk` byte, not just `1`, triggers it.
    #[test]
    fn a_disk_read_is_validated_and_a_good_node_is_kept() {
        let _fixture = Fixture::install();
        let mut btree = control_block();
        let mut block = held_block();
        unsafe {
            GET_BLOCK_YIELDS = (0x5000_0000, 0x6000_0000, 0x80);
            assert_eq!(hfs_btree_get_node(&mut btree, 2, &mut block), 0);
            assert_eq!(CHECK_NODE_CALLS, 1);
            assert_eq!(
                CHECK_NODE_ARGS,
                ((&mut btree as *mut BTreeControlBlock) as usize, 0x5000_0000),
            );
            assert_eq!(TRASH_NODE_CALLS, 0);
            assert_eq!(block.buffer, 0x5000_0000);
            assert_eq!(block.block_header, 0x6000_0000);
            assert_eq!(btree.num_get_nodes, 42);
        }
    }

    /// The damaged-volume path is the only one that walks
    /// `control_block.fork -> volume`, so it needs a fixture whose
    /// pointers survive a `u32`.
    #[test]
    fn a_corrupt_node_marks_the_volume_damaged_and_trashes_the_block() {
        let _fixture = Fixture::install();
        let Some(slab) = try_map_u32_slab(hints::HFS_BTREE_GET_NODE, SLAB_LEN) else {
            note_missing_u32_fixture("fs::hfs_btree_get_node");
            return;
        };
        unsafe {
            ptr::write_bytes(slab, 0xa5, SLAB_LEN);
            let btree = slab.add(CONTROL_OFFSET) as *mut BTreeControlBlock;
            let block = slab.add(BLOCK_OFFSET) as *mut BTreeNodeBlock;
            let fork = slab.add(FORK_OFFSET) as *mut BTreeFork;
            let volume = slab.add(VOLUME_OFFSET) as *mut BTreeVolume;
            let node = slab.add(NODE_BUFFER_OFFSET);

            btree.write(control_block());
            (*btree).fork = fork as usize as u32;
            block.write(held_block());
            (*fork).reserved_00 = 0xa5a5_a5a5;
            (*fork).volume = volume as usize as u32;
            (*volume).flags = 0x0080;

            GET_BLOCK_YIELDS = (node as usize as u32, 0x6000_0000, 1);
            CHECK_NODE_STATUS = BTREE_INVALID_NODE_STATUS;

            let status = hfs_btree_get_node(btree, 3, block);
            assert_eq!(status, BTREE_INVALID_NODE_STATUS);
            assert_eq!(CHECK_NODE_CALLS, 1);
            assert_eq!(CHECK_NODE_ARGS, (btree as usize, node as usize as u32));
            // The damaged bit is set, the rest of the flag word survives.
            assert_eq!((*volume).flags, 0x0081);
            assert_eq!(TRASH_NODE_CALLS, 1);
            assert_eq!(TRASH_NODE_ARGS, (btree as usize, block as usize));
            assert_eq!((*block).buffer, 0);
            assert_eq!((*block).block_header, 0);
            // The get succeeded, so its counter still advanced.
            assert_eq!((*btree).num_get_nodes, 42);
        }
    }

    /// The validator's own status is what comes back, not a literal 36 —
    /// the original returns the register `CheckNode` left behind.
    #[test]
    fn the_validators_status_is_returned_verbatim() {
        let _fixture = Fixture::install();
        let Some(slab) = try_map_u32_slab(hints::HFS_BTREE_GET_NODE, SLAB_LEN) else {
            note_missing_u32_fixture("fs::hfs_btree_get_node");
            return;
        };
        unsafe {
            let btree = slab.add(CONTROL_OFFSET) as *mut BTreeControlBlock;
            let block = slab.add(BLOCK_OFFSET) as *mut BTreeNodeBlock;
            let fork = slab.add(FORK_OFFSET) as *mut BTreeFork;
            let volume = slab.add(VOLUME_OFFSET) as *mut BTreeVolume;

            btree.write(control_block());
            (*btree).fork = fork as usize as u32;
            block.write(held_block());
            (*fork).volume = volume as usize as u32;
            (*volume).flags = VOLUME_DAMAGED_FLAG;

            GET_BLOCK_YIELDS = (0, 0, 1);
            CHECK_NODE_STATUS = -99;

            assert_eq!(hfs_btree_get_node(btree, 4, block), -99);
            // Already-damaged volumes stay damaged; the OR is idempotent.
            assert_eq!((*volume).flags, VOLUME_DAMAGED_FLAG);
            assert_eq!(TRASH_NODE_CALLS, 1);
        }
    }
}
