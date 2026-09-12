//! Strided-array element addressing — retailOS's generic accessor pair:
//! `FUN_082a4b94` @ 0x082a4b94 (**40 bytes**, 0x082a4b94..0x082a4bb8; the
//! next separately linked leaf begins at 0x082a4bbc) and
//! `FUN_082a4cf8` @ 0x082a4cf8 (24 bytes).
//!
//! Raw ARM for the newly ported helper:
//!
//! ```text
//! 082a4b94  push {r4,r5,r6,lr}
//! 082a4b98  mov  r4,r0
//! 082a4b9c  ldr  r0,[r0]       @ vtable
//! 082a4ba0  mov  r5,r1         @ index
//! 082a4ba4  ldr  r1,[r0,#0x18] @ virtual element_stride(this)
//! 082a4ba8  mov  r0,r4
//! 082a4bac  blx  r1
//! 082a4bb0  ldr  r1,[r4,#8]    @ storage
//! 082a4bb4  mla  r0,r5,r0,r1
//! 082a4bb8  pop  {r4,r5,r6,pc}
//! ```
//!
//! Its **8 direct `bl` call sites, 0 predicated**, were verified by decoding
//! every ARM B/BL word in `work/firmware/osos.dec`: 0x08135250, 0x08135284,
//! 0x08271798, 0x082a4884, 0x082a4944, 0x082a4a38, 0x082a4b44, and
//! 0x082a4c4c. There are also two tail branches: predicated `bne` from
//! 0x082a47ac and the unconditional `b` from `array_element_at` at
//! 0x082a4d0c. The absence of predicated calls means callers do not gate this
//! helper; it has no NULL or bounds guard of its own.
//!
//! Algorithm: call vtable slot +0x18 to get the element stride, then return
//! `storage + index * stride` in wrapping 32-bit arithmetic. `array_element_at`
//! handles `LAST_ELEMENT_INDEX` before tail-calling this helper.
//!
//! Deliberate host deviation: the target's vtable and its function slots are
//! 32-bit words, while host function pointers are wider. The host vtable is
//! structurally widened with named fields; target-only assertions retain the
//! physical offsets. The sampled observable-array vtable at 0x089a5d0c has
//! slot +0x18 = 0x08102f80, which is not a function entry in Ghidra's listing
//! (it falls inside `FUN_08102f44` with r4 live-in). This port dispatches the
//! slot but does not invent a concrete callee identity.

/// The index value that names the final element (`cmn r1, #-0x7fffffff`
/// sets Z exactly when r1 == 0x7fffffff).
pub const LAST_ELEMENT_INDEX: i32 = 0x7fff_ffff;

/// The polymorphic strided array shared by both accessors.
#[repr(C)]
pub struct StridedArray {
    /// +0x00: vtable pointer; slot +0x18 returns the element stride.
    pub vtable: *const StridedArrayVtable,
    /// +0x04: signed element count, read only by [`array_element_at`].
    pub count: i32,
    /// +0x08: base address of the element storage.
    pub storage: u32,
}

/// Vtable portion reached by [`strided_array_element_address`].
///
/// The unresolved slots occupy +0x00..+0x14 on the target. `usize` keeps the
/// host fixture's function pointer naturally wide without overlapping slots.
#[repr(C)]
pub struct StridedArrayVtable {
    pub unresolved_00_14: [usize; 6],
    /// +0x18: returns the byte stride for an element of `this`.
    pub element_stride: unsafe extern "C" fn(*const StridedArray) -> u32,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x00] = [0; core::mem::offset_of!(StridedArray, vtable)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x04] = [0; core::mem::offset_of!(StridedArray, count)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x08] = [0; core::mem::offset_of!(StridedArray, storage)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x0c] = [0; core::mem::size_of::<StridedArray>()];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x18] = [0; core::mem::offset_of!(StridedArrayVtable, element_stride)];

/// strided_array_element_address — original: `FUN_082a4b94` @ `0x082a4b94`
/// (40 bytes; 8 plain `bl` call sites, no predicated calls). See the module
/// header for the raw listing and algorithm.
///
/// Returns `this.storage + index * this.vtable.element_stride(this)` using
/// ARM's wrapping 32-bit multiply-accumulate semantics.
///
/// # Safety
///
/// `this` must point to a readable strided-array object with a readable
/// vtable and a valid +0x18 stride callback. Neither `this`, the vtable, nor
/// the virtual slot is NULL-checked by retailOS.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn strided_array_element_address(
    this: *const StridedArray,
    index: i32,
) -> u32 {
    let vtable = core::ptr::read_volatile(core::ptr::addr_of!((*this).vtable));
    let element_stride =
        core::ptr::read_volatile(core::ptr::addr_of!((*vtable).element_stride));
    let stride = element_stride(this);
    let storage = core::ptr::read_volatile(core::ptr::addr_of!((*this).storage));
    storage.wrapping_add((index as u32).wrapping_mul(stride))
}

/// array_element_at — original: `FUN_082a4cf8` @ 0x082a4cf8 (24 bytes;
/// 23 `bl` call sites, binary-scanned).
///
/// Returns the address of element `index`, where `index ==
/// `[`LAST_ELEMENT_INDEX`] names the final element of a non-empty array.
/// All arithmetic is the original's mod $2^{32}$ word arithmetic.
///
/// # Safety
///
/// `this` must point to a readable strided-array and satisfy
/// [`strided_array_element_address`]'s virtual-dispatch contract. As in
/// retailOS, it is not NULL-checked.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn array_element_at(this: *const StridedArray, index: i32) -> u32 {
    let mut index = index;
    if index == LAST_ELEMENT_INDEX {
        let count = core::ptr::addr_of!((*this).count).read_volatile();
        if count > 0 {
            index = count - 1;
        }
    }
    strided_array_element_address(this, index)
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use parking_lot::Mutex;
    use std::ptr;

    static VTABLE_LOCK: Mutex<()> = Mutex::new(());
    static mut STRIDE: u32 = 0;
    static mut STRIDE_CALLS: u32 = 0;
    static mut SEEN_THIS: *const StridedArray = ptr::null();

    unsafe extern "C" fn recorded_stride(this: *const StridedArray) -> u32 {
        ptr::addr_of_mut!(STRIDE_CALLS).write(
            ptr::addr_of!(STRIDE_CALLS).read_volatile().wrapping_add(1),
        );
        ptr::addr_of_mut!(SEEN_THIS).write(this);
        ptr::addr_of!(STRIDE).read_volatile()
    }

    static VTABLE: StridedArrayVtable = StridedArrayVtable {
        unresolved_00_14: [0; 6],
        element_stride: recorded_stride,
    };

    fn reset(stride: u32) {
        unsafe {
            ptr::addr_of_mut!(STRIDE).write_volatile(stride);
            ptr::addr_of_mut!(STRIDE_CALLS).write_volatile(0);
            ptr::addr_of_mut!(SEEN_THIS).write_volatile(ptr::null());
        }
    }

    fn array(count: i32, storage: u32) -> StridedArray {
        StridedArray { vtable: &VTABLE, count, storage }
    }

    #[test]
    fn helper_calls_the_stride_slot_and_accumulates_a_positive_index() {
        let _lock = VTABLE_LOCK.lock();
        let object = array(-1, 0x0840_0000);
        reset(12);

        let address = unsafe { strided_array_element_address(&object, 3) };

        assert_eq!(address, 0x0840_0024);
        unsafe {
            assert_eq!(ptr::addr_of!(STRIDE_CALLS).read_volatile(), 1);
            assert_eq!(ptr::addr_of!(SEEN_THIS).read_volatile(), &object as *const StridedArray);
        }
    }

    #[test]
    fn helper_retains_signed_index_as_a_wrapping_word_multiply() {
        let _lock = VTABLE_LOCK.lock();
        let object = array(0x1234, 0x0000_0040);
        reset(6);

        assert_eq!(
            unsafe { strided_array_element_address(&object, -2) },
            0x0000_0034,
            "mla treats -2 as 0xfffffffe"
        );
    }

    #[test]
    fn helper_wraps_the_multiply_accumulate_result() {
        let _lock = VTABLE_LOCK.lock();
        let object = array(0, 0xffff_fffc);
        reset(4);

        assert_eq!(unsafe { strided_array_element_address(&object, 2) }, 4);
    }

    #[test]
    fn a_plain_index_reaches_the_helper_unchanged() {
        let _lock = VTABLE_LOCK.lock();
        let object = array(-1, 0x0840_0000);
        reset(8);

        assert_eq!(unsafe { array_element_at(&object, 3) }, 0x0840_0018);
        unsafe {
            assert_eq!(ptr::addr_of!(STRIDE_CALLS).read_volatile(), 1);
            assert_eq!(ptr::addr_of!(SEEN_THIS).read_volatile(), &object as *const StridedArray);
        }
    }

    #[test]
    fn the_sentinel_names_the_last_element_of_a_non_empty_array() {
        let _lock = VTABLE_LOCK.lock();
        let object = array(7, 0x0840_0000);
        reset(4);

        assert_eq!(unsafe { array_element_at(&object, LAST_ELEMENT_INDEX) }, 0x0840_0018);
    }

    #[test]
    fn the_sentinel_on_a_one_element_array_yields_index_zero() {
        let _lock = VTABLE_LOCK.lock();
        let object = array(1, 0x0840_0000);
        reset(4);

        assert_eq!(unsafe { array_element_at(&object, LAST_ELEMENT_INDEX) }, 0x0840_0000);
    }

    #[test]
    fn the_sentinel_passes_through_on_an_empty_or_negative_count() {
        let _lock = VTABLE_LOCK.lock();
        let empty = array(0, 0);
        let negative = array(-3, 0);
        reset(4);

        let sentinel_address = (LAST_ELEMENT_INDEX as u32).wrapping_mul(4);
        assert_eq!(unsafe { array_element_at(&empty, LAST_ELEMENT_INDEX) }, sentinel_address);
        assert_eq!(unsafe { array_element_at(&negative, LAST_ELEMENT_INDEX) }, sentinel_address);
        unsafe {
            assert_eq!(ptr::addr_of!(STRIDE_CALLS).read_volatile(), 2);
        }
    }

    #[test]
    fn one_below_the_sentinel_is_an_ordinary_index() {
        let _lock = VTABLE_LOCK.lock();
        let object = array(2, 0);
        reset(4);

        assert_eq!(
            unsafe { array_element_at(&object, LAST_ELEMENT_INDEX - 1) },
            ((LAST_ELEMENT_INDEX - 1) as u32).wrapping_mul(4)
        );
    }
}
