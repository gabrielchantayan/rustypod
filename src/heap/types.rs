//! Shared heap data-structure layouts for the retailOS app-level heap
//! (cluster 0x0819cd5c..0x0819d9d8), recovered from the machine code.
//! Every heap module uses these — do not redefine them locally.

/// Block header word (`size_flags`) semantics:
/// bits 2..29 = block size (8-aligned units masked by `!0xC0000003`),
/// bit 0 = this block is free/on the free list,
/// bit 1 = the previous physical block is free.
pub const BLOCK_FREE: u32 = 0x1;
pub const PREV_FREE: u32 = 0x2;
pub const SIZE_MASK: u32 = !0xC0000003;

/// Block header (8 bytes at user_ptr - 8).
#[repr(C)]
pub struct BlockHeader {
    pub size_flags: u32,
    /// Free block: next in size-sorted doubly-linked free list.
    /// Allocated block: caller tag (0..57) in the low halfword,
    /// size class (0..79) in the high halfword (telemetry).
    pub link_or_tag: u32,
}

/// Free block link extension (at header+8, overlapping user area).
pub const FREE_PREV_OFFSET: usize = 4;

/// 16-byte free-list sentinel node, embedded in the descriptor at +0xd0.
#[repr(C)]
pub struct FreeSentinel {
    pub size_flags: u32,
    pub next: *mut FreeSentinel,
    pub prev: *mut FreeSentinel,
    pub unused: u32,
}

pub const MAX_REGIONS: usize = 20;
pub const NUM_TAGS: usize = 58;
pub const NUM_CLASSES: usize = 80;
pub const NUM_BINS: usize = 32;

/// Heap descriptor (0x398 bytes).
#[repr(C)]
pub struct HeapDescriptor {
    pub free_bytes: u32,          // 0x000
    pub total_bytes: u32,         // 0x004
    pub allocated_bytes: u32,     // 0x008
    pub alloc_counter: u32,       // 0x00c
    pub regions: [(u32, u32); MAX_REGIONS], // 0x010..0x0af {start, size}
    pub region_count: u32,        // 0x0b0
    pub mutex_state: u8,          // 0x0b4
    pub mutex_state2: u8,         // 0x0b5
    pub _pad_b6: [u8; 2],         // 0x0b6
    pub mutex_handle: u32,        // 0x0b8 RTXC semaphore handle
    pub _pad_bc: u32,             // 0x0bc
    pub initialized: u32,         // 0x0c0
    pub initial_region_start: u32,// 0x0c4
    pub initial_region_size: u32, // 0x0c8
    pub auto_init: u32,           // 0x0cc
    pub sentinel: FreeSentinel,   // 0x0d0
    pub bytes_per_class: [u32; NUM_CLASSES], // 0x0e0..0x21f
    pub class_total: u32,         // 0x220
    pub bytes_per_tag: [u32; NUM_TAGS],      // 0x224..0x30b
    pub tag_total: u32,           // 0x30c
    pub blocks_per_bin: [u32; NUM_BINS],     // 0x310..0x38f
    pub bin_total: u32,           // 0x390
    pub peak_bytes: u32,          // 0x394
}

// Exact 0x398 layout holds on 32-bit targets (pointers are 4 bytes);
// on 64-bit hosts the two sentinel pointers widen the struct — fine for
// field access, but the size check only applies to the ARM target.
#[cfg(target_pointer_width = "32")]
const _DESCRIPTOR_SIZE_CHECK: [u8; 0x398] = [0; core::mem::size_of::<HeapDescriptor>()];

/// Default-heap pointer: original global @ 0x089ca638.
pub static mut DEFAULT_HEAP: *mut HeapDescriptorDescriptor = core::ptr::null_mut();

/// Second indirection used by malloc_wrapper (desc = *0x089ca638).
#[repr(C)]
pub struct HeapDescriptorDescriptor {
    pub desc: *mut HeapDescriptor,
}
