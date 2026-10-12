//! `two_buffer_owner_release` — destroy an owner of two releasable buffer pointers.
//!
//! Original: `FUN_0803dba8` @ 0x0803dba8 (48 bytes exactly,
//! 0x0803dba8..0x0803dbd8; `FUN_0803dbd8` starts at the next word, with no
//! trailing literal pool). Ghidra reports 48 bytes, which matches the raw
//! extent. Decoding every ARM B/BL immediate in `osos.dec` finds exactly 5
//! direct call sites, matching Ghidra's count: two unconditional `bl`
//! (0x0803dcf4, 0x08062248) and three `blne` (0x0806242c, 0x080cbae0,
//! 0x080cbe24). The predicated callers gate the call on their own owner word
//! being non-NULL; the body retains its own NULL guard.
//!
//! ```text
//! 0803dba8:  stmdb sp!,{r4,lr}
//! 0803dbac:  movs r4,r0
//! 0803dbb0:  ldmiaeq sp!,{r4,pc}        ; if (this == NULL) return
//! 0803dbb4:  ldr r0,[r4,#0x4]
//! 0803dbb8:  cmp r0,#0x0
//! 0803dbbc:  blne releasable_buffer_release   ; 0x0803eee4
//! 0803dbc0:  ldr r0,[r4,#0x8]
//! 0803dbc4:  cmp r0,#0x0
//! 0803dbc8:  blne releasable_buffer_release   ; 0x0803eee4
//! 0803dbcc:  mov r0,r4
//! 0803dbd0:  ldmia sp!,{r4,lr}
//! 0803dbd4:  b traced_free                    ; 0x08043994
//! ```
//!
//! Algorithm: return for NULL; release the buffer pointer at +0x04 when
//! non-NULL, then the buffer pointer at +0x08 when non-NULL; finally release
//! the owner itself through `traced_free` unconditionally. Unlike
//! [`crate::heap::three_buffer_owner`], the buffers are heap pointers rather
//! than embedded and there is no outer flags gate on the final free.
//!
//! Deliberate deviation: the retail final `b traced_free` tail branch is an
//! ordinary returning Rust call. `traced_free` returns normally, so observable
//! behavior is unchanged.

use crate::drivers::ata_cmd::traced_free;
use crate::heap::releasable_buffer::{releasable_buffer_release, ReleasableBuffer};
use crate::drivers::ata_cmd::traced_alloc;
use crate::heap::tagged_word_buffer::tagged_word_buffer_create;
use crate::heap::word_buffer::{marked_word_buffer_assign, MarkedWordBuffer};
use crate::kernel::diag_ring_record::diag_ring_record;

/// Target-layout owner of two independently releasable buffer pointers, as
/// allocated by the paired create function `FUN_0803dc50` (0x14 bytes).
#[repr(C)]
pub struct TwoBufferOwner {
    /// +0x00: field not inspected by this destructor.
    pub reserved: u32,
    /// +0x04: first buffer pointer, NULL when absent.
    pub first: u32,
    /// +0x08: second buffer pointer, NULL when absent.
    pub second: u32,
    /// +0x0c..+0x10: fields not inspected by this destructor.
    pub trailing: [u32; 2],
}

const _: [u8; 0x04] = [0; core::mem::offset_of!(TwoBufferOwner, first)];
const _: [u8; 0x08] = [0; core::mem::offset_of!(TwoBufferOwner, second)];
const _: [u8; 0x14] = [0; core::mem::size_of::<TwoBufferOwner>()];

/// (48 bytes; 2 `bl` and 3 `blne` direct call sites.)
///
/// Releases the two non-NULL buffer pointers in target offset order, then
/// releases `this` through `traced_free`. The caller must provide NULL or a
/// readable, aligned [`TwoBufferOwner`]; each non-NULL buffer pointer has the
/// ownership contract of [`releasable_buffer_release`].
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn two_buffer_owner_release(this: *mut TwoBufferOwner) {
    if this.is_null() {
        return;
    }

    let first = unsafe { core::ptr::addr_of!((*this).first).read_volatile() };
    if first != 0 {
        unsafe { releasable_buffer_release(first as *mut ReleasableBuffer) };
    }

    let second = unsafe { core::ptr::addr_of!((*this).second).read_volatile() };
    if second != 0 {
        unsafe { releasable_buffer_release(second as *mut ReleasableBuffer) };
    }

    unsafe { traced_free(this.cast::<u8>()) };
}

/// Create an owner holding independent copies of two marked word buffers.
///
/// Original: FUN_0803dc50 @ 0x0803dc50, 176 bytes, ending at the next
/// independent entry 0x0803dd00. Raw-word decoding verifies two incoming
/// plain BLs (0x08062318, 0x0808b398), eight outgoing plain BLs, and no
/// predicated BLs in either set.
///
/// Allocate and zero a 20-byte owner, create both buffers, then assign first
/// and second in order. Publish the context word at +12 only after both
/// assignments succeed. Any buffer allocation or assignment failure releases
/// the partially initialized owner; owner allocation failure records
/// diagnostic (3, 0x66, 0x41, 0, 0) and returns NULL.
///
/// Deliberate deviation: call the ported zero-fill helper through a volatile
/// function pointer to prevent LLVM builtin substitution. Ghidra's fourth
/// argument is not consumed by the raw code; the interface has three arguments.
///
/// # Safety
/// Sources must satisfy `marked_word_buffer_assign`'s readable header/data
/// contract. The allocator must return aligned writable target-addressable
/// objects, and allocation/free services must be initialized.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn two_buffer_owner_create(
    first_source: *const MarkedWordBuffer,
    second_source: *const MarkedWordBuffer,
    context: u32,
) -> *mut TwoBufferOwner {
    let owner = traced_alloc(20, 0, 0).cast::<TwoBufferOwner>();
    if owner.is_null() {
        diag_ring_record(3, 0x66, 0x41, 0, 0);
        return core::ptr::null_mut();
    }
    let zero: unsafe extern "C" fn(*mut u8, usize) -> *mut u8 =
        crate::libc::memzero::memzero_aligned;
    core::ptr::read_volatile(&zero)(owner.cast(), 20);
    let first = tagged_word_buffer_create();
    core::ptr::addr_of_mut!((*owner).first).write_volatile(first as usize as u32);
    if !first.is_null() {
        let second = tagged_word_buffer_create();
        core::ptr::addr_of_mut!((*owner).second).write_volatile(second as usize as u32);
        if !second.is_null()
            && !marked_word_buffer_assign(
                (*owner).first as usize as *mut MarkedWordBuffer, first_source,
            ).is_null()
            && !marked_word_buffer_assign(
                (*owner).second as usize as *mut MarkedWordBuffer, second_source,
            ).is_null()
        {
            core::ptr::addr_of_mut!((*owner).trailing[0]).write_volatile(context);
            return owner;
        }
    }
    two_buffer_owner_release(owner);
    core::ptr::null_mut()
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::drivers::ata_cmd::{TracedFreeHooks, TRACED_FREE_HOOKS};
    use crate::heap::releasable_buffer::{FLAG_BUFFER_BORROWED, FLAG_RELEASED};
    use crate::testing::TRACED_ALLOC_TEST_LOCK;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut FREED: Vec<usize> = Vec::new();

    unsafe extern "C" fn mock_free(block: *mut u8) {
        unsafe { (*core::ptr::addr_of_mut!(FREED)).push(block as usize) };
    }

    fn install() -> (MutexGuard<'static, ()>, MutexGuard<'static, ()>, TracedFreeHooks) {
        let alloc_guard = TRACED_ALLOC_TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let guard = TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        unsafe {
            let old = core::ptr::read_volatile(core::ptr::addr_of!(TRACED_FREE_HOOKS));
            TRACED_FREE_HOOKS = TracedFreeHooks { free: mock_free, trace: None };
            (*core::ptr::addr_of_mut!(FREED)).clear();
            (guard, alloc_guard, old)
        }
    }

    unsafe fn restore(
        guard: MutexGuard<'static, ()>,
        alloc_guard: MutexGuard<'static, ()>,
        old: TracedFreeHooks,
    ) {
        unsafe { TRACED_FREE_HOOKS = old };
        drop(guard);
        drop(alloc_guard);
    }

    fn freed() -> Vec<usize> {
        unsafe { (*core::ptr::addr_of!(FREED)).clone() }
    }

    /// Unique low-address mapping because each buffer pointer and each
    /// embedded `data` field is a target-width pointer word. The mapper
    /// deliberately never unmaps. Layout: two `ReleasableBuffer`s at +0x00
    /// and +0x14, then two spare data words at +0x28 and +0x2c.
    fn try_slab() -> Option<*mut u8> {
        static SLAB: std::sync::LazyLock<Option<usize>> = std::sync::LazyLock::new(|| {
            crate::testing::try_map_u32_slab(crate::testing::hints::TWO_BUFFER_OWNER_RELEASE, 0x1000)
                .map(|pointer| pointer as usize)
        });
        (*SLAB).map(|pointer| pointer as *mut u8)
    }

    fn fixture_unavailable() -> bool {
        try_slab().is_none() && crate::testing::note_missing_u32_fixture("heap::two_buffer_owner")
    }

    #[test]
    fn null_owner_does_not_call_allocator() {
        let (guard, alloc_guard, old) = install();
        unsafe { two_buffer_owner_release(core::ptr::null_mut()) };
        assert!(freed().is_empty());
        unsafe { restore(guard, alloc_guard, old) };
    }

    #[test]
    fn null_buffers_free_only_the_owner() {
        let (guard, alloc_guard, old) = install();
        let mut owner = TwoBufferOwner { reserved: 0x1111_1111, first: 0, second: 0, trailing: [0x2222_2222; 2] };
        let this = &mut owner as *mut TwoBufferOwner;

        unsafe { two_buffer_owner_release(this) };

        assert_eq!(freed(), std::vec![this as usize]);
        assert_eq!(owner.reserved, 0x1111_1111, "unread fields are untouched");
        assert_eq!(owner.trailing, [0x2222_2222; 2]);
        unsafe { restore(guard, alloc_guard, old) };
    }

    #[test]
    fn releases_pointed_buffers_in_order_then_owner() {
        if fixture_unavailable() {
            return;
        }
        let (guard, alloc_guard, old) = install();
        let slab = try_slab().unwrap();
        let first = slab as *mut ReleasableBuffer;
        let second = unsafe { slab.add(0x14) } as *mut ReleasableBuffer;
        let data_a = unsafe { slab.add(0x28) } as usize as u32;
        let data_b = unsafe { slab.add(0x2c) } as usize as u32;
        unsafe {
            first.write(ReleasableBuffer { data: data_a, reserved: [0; 3], flags: 0 });
            second.write(ReleasableBuffer { data: data_b, reserved: [0; 3], flags: FLAG_BUFFER_BORROWED });
        }
        let mut owner = TwoBufferOwner {
            reserved: 0,
            first: first as usize as u32,
            second: second as usize as u32,
            trailing: [0; 2],
        };
        let this = &mut owner as *mut TwoBufferOwner;

        unsafe { two_buffer_owner_release(this) };

        assert_eq!(freed(), std::vec![data_a as usize, this as usize]);
        assert_eq!(unsafe { (*first).flags }, FLAG_RELEASED);
        assert_eq!(unsafe { (*second).flags }, FLAG_BUFFER_BORROWED | FLAG_RELEASED);
        assert_eq!(unsafe { (*first).data }, data_a, "retail code leaves freed data dangling");
        assert_eq!(unsafe { (*second).data }, data_b, "borrowed data never reaches traced_free");
        unsafe { restore(guard, alloc_guard, old) };
    }

    #[test]
    fn second_null_still_releases_first_then_owner() {
        if fixture_unavailable() {
            return;
        }
        let (guard, alloc_guard, old) = install();
        let slab = try_slab().unwrap();
        let first = slab as *mut ReleasableBuffer;
        unsafe { first.write(ReleasableBuffer { data: 0, reserved: [0; 3], flags: 0 }) };
        let mut owner = TwoBufferOwner { reserved: 0, first: first as usize as u32, second: 0, trailing: [0; 2] };
        let this = &mut owner as *mut TwoBufferOwner;

        unsafe { two_buffer_owner_release(this) };

        assert_eq!(freed(), std::vec![this as usize], "NULL data frees nothing; owner always freed");
        assert_eq!(unsafe { (*first).flags }, FLAG_RELEASED);
        unsafe { restore(guard, alloc_guard, old) };
    }
}

#[cfg(test)]
mod create_tests {
    extern crate std;
    use super::*;
    use crate::drivers::ata_cmd::{
        TracedAllocHooks, TracedFreeHooks, TRACED_ALLOC_HOOKS, TRACED_FREE_HOOKS,
    };
    use crate::heap::word_buffer::{WordBuffer, WordBufferGrow, WORD_BUFFER_GROW};
    use std::vec::Vec;

    static mut SLAB: *mut u8 = core::ptr::null_mut();
    static mut ALLOCATIONS: usize = 0;
    static mut FAIL_ALLOCATION: usize = usize::MAX;
    static mut GROWS: usize = 0;
    static mut FAIL_GROW: usize = usize::MAX;
    static mut FREED: Vec<usize> = Vec::new();

    unsafe extern "C" fn allocate(size: i32, _: u32, _: u32) -> *mut u8 {
        assert_eq!(size, 20);
        let index = ALLOCATIONS;
        ALLOCATIONS += 1;
        if index == FAIL_ALLOCATION { return core::ptr::null_mut(); }
        let block = SLAB.add(index * 0x40);
        core::ptr::write_bytes(block, 0xa5, 20);
        block
    }

    unsafe extern "C" fn grow(_: *mut WordBuffer, count: u32) -> *mut u32 {
        GROWS += 1;
        assert!(count <= 5);
        if GROWS == FAIL_GROW { return core::ptr::null_mut(); }
        SLAB.add(0x200 + GROWS * 0x40).cast()
    }

    unsafe extern "C" fn free(block: *mut u8) {
        (*core::ptr::addr_of_mut!(FREED)).push(block as usize);
    }

    struct Restore(TracedAllocHooks, TracedFreeHooks, WordBufferGrow);
    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe {
                TRACED_ALLOC_HOOKS = self.0;
                TRACED_FREE_HOOKS = self.1;
                WORD_BUFFER_GROW = self.2;
            }
        }
    }

    #[test]
    fn factory_copies_sources_and_unwinds_each_failure_stage() {
        let _guard = crate::testing::TRACED_ALLOC_TEST_LOCK.lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::TWO_BUFFER_OWNER_CREATE, 0x1000,
        ) else {
            assert!(crate::testing::note_missing_u32_fixture("two_buffer_owner_create"));
            return;
        };
        unsafe {
            let _restore = Restore(TRACED_ALLOC_HOOKS, TRACED_FREE_HOOKS, WORD_BUFFER_GROW);
            TRACED_ALLOC_HOOKS = TracedAllocHooks { alloc: allocate, trace: None };
            TRACED_FREE_HOOKS = TracedFreeHooks { free, trace: None };
            WORD_BUFFER_GROW = grow;
            SLAB = slab;
            let data = slab.add(0x400).cast::<u32>();
            for index in 0..5 { data.add(index).write(0x100 + index as u32); }
            // Owner allocation, first allocation, second allocation, first
            // assignment and second assignment fail independently.
            for stage in 0..5 {
                ALLOCATIONS = 0;
                GROWS = 0;
                FAIL_ALLOCATION = if stage < 3 { stage } else { usize::MAX };
                FAIL_GROW = if stage >= 3 { stage - 2 } else { usize::MAX };
                (*core::ptr::addr_of_mut!(FREED)).clear();
                let source = MarkedWordBuffer {
                    data: data as usize as u32, len: 5, capacity: 5, marker: 7,
                };
                assert!(two_buffer_owner_create(&source, &source, 99).is_null());
                let expected = match stage {
                    0 => std::vec![],
                    1 => std::vec![slab as usize],
                    2 => std::vec![slab.add(0x40) as usize, slab as usize],
                    3 => std::vec![slab.add(0x40) as usize, slab.add(0x80) as usize, slab as usize],
                    _ => std::vec![slab.add(0x240) as usize, slab.add(0x40) as usize,
                        slab.add(0x80) as usize, slab as usize],
                };
                assert_eq!(&*core::ptr::addr_of!(FREED), &expected);
                if stage != 0 {
                    assert_eq!((*slab.cast::<TwoBufferOwner>()).trailing, [0, 0]);
                }
            }
            FAIL_ALLOCATION = usize::MAX;
            FAIL_GROW = usize::MAX;
            for len in [0, 1, 5] {
                ALLOCATIONS = 0;
                GROWS = 0;
                (*core::ptr::addr_of_mut!(FREED)).clear();
                let first = MarkedWordBuffer {
                    data: data as usize as u32, len, capacity: 5, marker: 7,
                };
                let second = MarkedWordBuffer { marker: 9, ..first };
                let owner = two_buffer_owner_create(&first, &second, 0xfedc_ba98);
                assert_eq!(owner, slab.cast());
                assert_eq!((*owner).reserved, 0);
                assert_eq!((*owner).trailing, [0xfedc_ba98, 0]);
                for (pointer, marker) in [((*owner).first, 7), ((*owner).second, 9)] {
                    let copy = &*(pointer as usize as *const MarkedWordBuffer);
                    assert_eq!((copy.len, copy.marker), (len, marker));
                    if len != 0 {
                        assert_ne!(copy.data, first.data);
                        assert_eq!(
                            core::slice::from_raw_parts(copy.data as usize as *const u32, len as usize),
                            core::slice::from_raw_parts(data, len as usize),
                        );
                    } else { assert_eq!(copy.data, 0); }
                }
                two_buffer_owner_release(owner);
                let expected = if len == 0 {
                    std::vec![slab.add(0x40) as usize, slab.add(0x80) as usize, slab as usize]
                } else {
                    std::vec![slab.add(0x240) as usize, slab.add(0x40) as usize,
                        slab.add(0x280) as usize, slab.add(0x80) as usize, slab as usize]
                };
                assert_eq!(&*core::ptr::addr_of!(FREED), &expected);
                assert_eq!(core::slice::from_raw_parts(data, 5), &[0x100, 0x101, 0x102, 0x103, 0x104]);
            }
        }
    }
}
