//! Buffer-pool owner constructor, `FUN_082972e4` @ 0x082972e4.
//! True extent: 216 bytes through 0x082973bc: 208 executable bytes and
//! literals {0x089a7378, 0x428}. The next function starts at 0x082973bc.
//! Raw decoding finds two inbound plain BLs (0x0814a260, 0x081efc50), ten
//! outbound plain BLs, and zero predicated BLs in either direction.
//! Initialize owner fields, query capacity and its 512-byte sector count,
//! construct the embedded pool, condvar and aligned buffer, then allocate
//! and construct a mode-selected child. Rebase both member-constructor
//! returns before subsequent stores. Only the stored mode/flag truncate.
//!
//! Deliberate deviations: fixed-width target words also on hosts; host
//! operations replace resident constructors and the native-pointer condvar.
//! Unported constructor identities are structural, not concrete class names.
//! Raw 0x081bc95c preserves r0 despite Ghidra's void return. The mode-one
//! constructor passes r3 onward, but 0x0816217c never reads entry r3;
//! its effective ABI has three arguments, not Ghidra's four.
//! Codegen: match.py exits 1 with a structural diff. LLVM keeps the full
//! mode comparisons, capacity shift, member offsets and child store; resident
//! seams use BLX. It eliminates the aligned-buffer rebase because the port
//! always returns its input. Initial independent stores are reordered.

use crate::cxx::transition_addon::owner_capacity_query;
use crate::heap::aligned_buffer::aligned_buffer_init;
use crate::heap::veneers::operator_new;

pub type PoolConstruct = unsafe extern "C" fn(*mut u8, *mut u8) -> *mut u8;
pub type ChildConstruct = unsafe extern "C" fn(*mut u8, *mut u8, u32) -> *mut u8;
pub type BasicChildConstruct = unsafe extern "C" fn(*mut u8, *mut u8) -> *mut u8;

#[derive(Clone, Copy)]
pub struct BufferPoolOwnerConstructOps {
    pub pool: PoolConstruct,
    pub mode_one: ChildConstruct,
    pub mode_two: ChildConstruct,
    pub basic: BasicChildConstruct,
    pub capacity: unsafe extern "C" fn(*mut u8) -> u32,
    pub condvar: unsafe extern "C" fn(*mut u8),
    pub buffer: unsafe extern "C" fn(*mut u8, usize) -> *mut u8,
    pub allocate: unsafe extern "C" fn(usize) -> *mut u8,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn initialize_condvar(lock: *mut u8) {
    crate::kernel::condvar::condvar_init(lock.cast());
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_pool(_: *mut u8, _: *mut u8) -> *mut u8 { panic!("install owner pool constructor") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_child(_: *mut u8, _: *mut u8, _: u32) -> *mut u8 { panic!("install owner child constructor") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_basic(_: *mut u8, _: *mut u8) -> *mut u8 { panic!("install owner basic constructor") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_condvar(_: *mut u8) { panic!("install owner target-word condvar initializer") }

#[cfg(not(target_os = "none"))]
pub static mut BUFFER_POOL_OWNER_CONSTRUCT_OPS: BufferPoolOwnerConstructOps = BufferPoolOwnerConstructOps {
    pool: missing_pool, mode_one: missing_child, mode_two: missing_child, basic: missing_basic,
    capacity: owner_capacity_query, condvar: missing_condvar,
    buffer: aligned_buffer_init, allocate: operator_new,
};

/// Construct an owner in 88 bytes of word-aligned writable storage.
///
/// # Safety
/// The interface and child context must satisfy the resident constructors.
/// Host operations must be installed, and all stored pointers fit u32.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn buffer_pool_owner_construct(
    owner: *mut u8, interface: u32, mode: u32, parameter: u32,
    limit: u32, child_context: u32, flag: u32,
) -> *mut u8 {
    #[cfg(target_os = "none")]
    let ops = BufferPoolOwnerConstructOps {
        pool: core::mem::transmute(0x081e_2078usize),
        mode_one: core::mem::transmute(0x081b_fbecusize),
        mode_two: core::mem::transmute(0x081b_e1f8usize),
        basic: core::mem::transmute(0x081b_c95cusize),
        capacity: owner_capacity_query, condvar: initialize_condvar,
        buffer: aligned_buffer_init, allocate: operator_new,
    };
    #[cfg(not(target_os = "none"))]
    let ops = core::ptr::addr_of!(BUFFER_POOL_OWNER_CONSTRUCT_OPS).read();
    construct(owner, interface, mode, parameter, limit, child_context, flag, ops)
}

unsafe fn construct(owner: *mut u8, interface: u32, mode: u32, parameter: u32,
    limit: u32, child_context: u32, flag: u32, ops: BufferPoolOwnerConstructOps) -> *mut u8 {
    owner.cast::<u32>().write(0x089a_7378);
    owner.add(4).cast::<u32>().write(interface);
    owner.add(8).cast::<u32>().write(0);
    owner.add(12).write(mode as u8);
    owner.add(20).cast::<u32>().write(limit);
    owner.add(16).cast::<u32>().write(parameter);
    owner.add(24).write(flag as u8);
    owner.add(25).write(0);
    let capacity = (ops.capacity)(owner);
    owner.add(28).cast::<u32>().write(capacity);
    owner.add(32).cast::<u32>().write(capacity >> 9);
    let owner = (ops.pool)(owner.add(36), owner.add(68)).sub(36);
    (ops.condvar)(owner.add(68));
    let capacity = owner.add(28).cast::<u32>().read();
    let owner = (ops.buffer)(owner.add(80), capacity as usize).sub(80);
    let child = match mode {
        1 => (ops.mode_one)((ops.allocate)(0x428), owner, child_context),
        2 => (ops.mode_two)((ops.allocate)(100), owner, child_context),
        _ => (ops.basic)((ops.allocate)(12), owner),
    };
    owner.add(8).cast::<u32>().write(child as usize as u32);
    owner
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn capacity(owner: *mut u8) -> u32 {
        assert_eq!(owner.add(8).cast::<u32>().read(), 0);
        owner.add(4).cast::<u32>().read()
    }
    unsafe extern "C" fn pool(pool: *mut u8, lock: *mut u8) -> *mut u8 {
        assert_eq!(lock, pool.add(32));
        pool.cast::<u32>().write(0x1234);
        pool
    }
    unsafe extern "C" fn lock(lock: *mut u8) { lock.cast::<u32>().write(0x5678); }
    unsafe extern "C" fn buffer(buffer: *mut u8, size: usize) -> *mut u8 {
        assert_eq!(buffer.sub(12).cast::<u32>().read(), 0x5678);
        buffer.cast::<u32>().write(size as u32);
        buffer.add(4).cast::<u32>().write(0);
        buffer
    }
    unsafe extern "C" fn allocate(size: usize) -> *mut u8 { size as *mut u8 }
    unsafe extern "C" fn one(block: *mut u8, _: *mut u8, context: u32) -> *mut u8 {
        assert_eq!(block as usize, 0x428); assert_eq!(context, 0x9876); 0x1110 as *mut u8
    }
    unsafe extern "C" fn two(block: *mut u8, _: *mut u8, context: u32) -> *mut u8 {
        assert_eq!(block as usize, 100); assert_eq!(context, 0x9876); 0x2220 as *mut u8
    }
    unsafe extern "C" fn basic(block: *mut u8, _: *mut u8) -> *mut u8 {
        assert_eq!(block as usize, 12); core::ptr::null_mut()
    }
    fn ops() -> BufferPoolOwnerConstructOps {
        BufferPoolOwnerConstructOps { pool, mode_one: one, mode_two: two, basic,
            capacity, condvar: lock, buffer, allocate }
    }

    #[test]
    fn full_mode_selection_capacity_boundaries_and_untouched_padding() {
        for mode in [0, 1, 2, 3, 257, 258, u32::MAX] {
            for capacity in [0, 511, 512, 513, u32::MAX] {
                let mut words = [0xa5a5_a5a5u32; 24];
                let owner = words.as_mut_ptr().cast::<u8>();
                assert_eq!(unsafe { construct(owner, capacity, mode, 0x12345678,
                    0xabcdef01, 0x9876, 0x123, ops()) }, owner);
                assert_eq!(words[0], 0x089a7378);
                assert_eq!(words[2], match mode { 1 => 0x1110, 2 => 0x2220, _ => 0 });
                assert_eq!(words[3], 0xa5a5_a500 | (mode & 255));
                assert_eq!(words[4], 0x12345678);
                assert_eq!(words[5], 0xabcdef01);
                assert_eq!(words[6], 0xa5a5_0023);
                assert_eq!(words[7], capacity);
                assert_eq!(words[8], capacity >> 9);
                assert_eq!(words[20], capacity);
                assert_eq!(words[21], 0);
                assert_eq!(&words[22..], &[0xa5a5_a5a5; 2]);
            }
        }
    }

    unsafe extern "C" fn relocated_pool(pool: *mut u8, _: *mut u8) -> *mut u8 { pool.add(88) }
    unsafe extern "C" fn relocated_buffer(buffer: *mut u8, size: usize) -> *mut u8 {
        assert_eq!(size, 123);
        buffer.add(88)
    }
    #[test]
    fn constructor_returns_rebase_subsequent_members_and_final_child_store() {
        let mut words = [0xa5a5_a5a5u32; 66];
        words[22 + 7] = 123;
        let owner = words.as_mut_ptr().cast::<u8>();
        let mut operations = ops();
        operations.pool = relocated_pool;
        operations.buffer = relocated_buffer;
        assert_eq!(unsafe { construct(owner, 512, 2, 0, 0, 0x9876, 0, operations) }, unsafe { owner.add(176) });
        assert_eq!(words[22 + 17], 0x5678);
        assert_eq!(words[44 + 2], 0x2220);
        assert_eq!(words[2], 0, "original child remains cleared");
        assert_eq!(words[22 + 2], 0xa5a5_a5a5, "intermediate owner child is untouched");
    }
}
