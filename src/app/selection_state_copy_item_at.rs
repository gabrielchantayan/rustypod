//! Selection-state indexed item copy.
//!
//! `selection_state_copy_item_at` — original: `FUN_08203458` @ `0x08203458`
//! (24 bytes, `0x08203458..0x08203470`). Raw ARM establishes the next real
//! function boundary at `0x08203470` (`push {r4,r5,r6,lr}`):
//!
//! ```text
//! 08203458  push {r3,lr}
//! 0820345c  mov  r2,sp
//! 08203460  add  r0,r0,#0xe8
//! 08203464  bl   0x082a4d10
//! 08203468  ldr  r0,[sp]
//! 0820346c  pop  {r3,pc}
//! ```
//!
//! Raw decoding finds one outbound plain, unconditional `bl` and no predicated
//! outbound `bl`. It also finds three inbound direct plain `bl` sites
//! (`0x082034e0`, `0x082036d0`, and `0x08203738`) and no predicated inbound
//! `bl` sites.
//!
//! # Algorithm
//!
//! The state embeds an array-like object at target offset `+0xe8`. This wrapper
//! passes that object, `item_index`, and a pointer to its stack-resident
//! `fallback_item` to the stock `0x082a4d10` array dispatch, then returns the
//! resulting output word. The callee's boolean result is deliberately ignored.
//!
//! # Deliberate deviation
//!
//! `FUN_082a4d10` has no recovered concrete identity or Rust port. The target
//! calls it at its fixed retail address; host tests replace that one explicit
//! boundary with a typed callback. The target uses a four-byte stack word,
//! whereas the host callback receives a native pointer to the same `u32` value.

#[cfg(not(target_os = "none"))]
use core::ptr;

const EMBEDDED_ARRAY_OFFSET: usize = 0xe8;

type ArrayCopyDispatch = unsafe extern "C" fn(*mut u8, i32, *mut u32) -> u32;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_array_copy_dispatch(
    _array: *mut u8,
    _item_index: i32,
    _output: *mut u32,
) -> u32 {
    panic!("selection_state_copy_item_at requires dispatch 0x082a4d10")
}

#[cfg(not(target_os = "none"))]
static mut ARRAY_COPY_DISPATCH: ArrayCopyDispatch = missing_array_copy_dispatch;

#[cfg(target_os = "none")]
core::arch::global_asm!(
    r#"
    .section .text.selection_state_copy_item_at,"ax",%progbits
    .global selection_state_copy_item_at
    .type selection_state_copy_item_at,%function
selection_state_copy_item_at:
    push    {{r3,lr}}
    mov     r2,sp
    add     r0,r0,#0xe8
    bl      .Lretail_array_copy_dispatch
    ldr     r0,[sp]
    pop     {{r12,pc}}
    .size selection_state_copy_item_at, .-selection_state_copy_item_at
.Lretail_array_copy_dispatch:
    ldr     pc,[pc,#-4]
    .word   0x082a4d10
"#
);

/// Copies indexed item state from the embedded selection array — original:
/// `FUN_08203458` @ `0x08203458` (24 bytes; three inbound direct plain `bl`
/// sites, no predicated inbound `bl` sites; one outbound plain `bl`, no
/// predicated outbound `bl`). See the module header for the raw listing and
/// algorithm.
///
/// # Safety
///
/// `selection_state` must have a valid array-like object at target byte offset
/// `+0xe8`, acceptable to the dispatch at `0x082a4d10`. As in retailOS, this
/// wrapper performs no NULL or bounds checks.
#[cfg(not(target_os = "none"))]
#[cfg_attr(target_os = "none", link_section = ".text.selection_state_copy_item_at")]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn selection_state_copy_item_at(
    selection_state: *mut u8,
    item_index: i32,
    fallback_item: u32,
) -> u32 {
    let mut item = fallback_item;
    let dispatch = ptr::read_volatile(ptr::addr_of!(ARRAY_COPY_DISPATCH));
    dispatch(selection_state.add(EMBEDDED_ARRAY_OFFSET), item_index, ptr::addr_of_mut!(item));
    item
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::SELECTION_STATE_COPY_ITEM_AT_TEST_LOCK;

    static mut EXPECTED_ARRAY: *mut u8 = ptr::null_mut();
    static mut RECORDED_INDEX: i32 = 0;
    static mut RESULT: u32 = 0;
    static mut WRITE_RESULT: bool = false;

    unsafe extern "C" fn recording_dispatch(array: *mut u8, item_index: i32, output: *mut u32) -> u32 {
        assert_eq!(array, ptr::addr_of!(EXPECTED_ARRAY).read());
        ptr::addr_of_mut!(RECORDED_INDEX).write(item_index);
        if ptr::addr_of!(WRITE_RESULT).read() {
            output.write(ptr::addr_of!(RESULT).read());
        }
        0
    }

    struct DispatchGuard(ArrayCopyDispatch);
    impl Drop for DispatchGuard {
        fn drop(&mut self) {
            unsafe { ptr::addr_of_mut!(ARRAY_COPY_DISPATCH).write_volatile(self.0) }
        }
    }

    unsafe fn install(expected_array: *mut u8, result: u32, write_result: bool) -> DispatchGuard {
        ptr::addr_of_mut!(EXPECTED_ARRAY).write(expected_array);
        ptr::addr_of_mut!(RECORDED_INDEX).write(0);
        ptr::addr_of_mut!(RESULT).write(result);
        ptr::addr_of_mut!(WRITE_RESULT).write(write_result);
        let seam = ptr::addr_of_mut!(ARRAY_COPY_DISPATCH);
        let previous = seam.read_volatile();
        seam.write_volatile(recording_dispatch);
        DispatchGuard(previous)
    }

    #[test]
    fn returns_the_dispatch_written_item_and_passes_embedded_array() {
        let _lock = SELECTION_STATE_COPY_ITEM_AT_TEST_LOCK.lock();
        let mut selection_state = [0u8; EMBEDDED_ARRAY_OFFSET + 4];
        unsafe {
            let _guard = install(selection_state.as_mut_ptr().add(EMBEDDED_ARRAY_OFFSET), 0xa5a5_5a5a, true);
            assert_eq!(selection_state_copy_item_at(selection_state.as_mut_ptr(), -7, 0), 0xa5a5_5a5a);
            assert_eq!(ptr::addr_of!(RECORDED_INDEX).read(), -7);
        }
    }

    #[test]
    fn preserves_fallback_when_dispatch_leaves_output_unchanged() {
        let _lock = SELECTION_STATE_COPY_ITEM_AT_TEST_LOCK.lock();
        let mut selection_state = [0u8; EMBEDDED_ARRAY_OFFSET + 4];
        unsafe {
            let _guard = install(selection_state.as_mut_ptr().add(EMBEDDED_ARRAY_OFFSET), 0, false);
            assert_eq!(selection_state_copy_item_at(selection_state.as_mut_ptr(), 0x7fff_ffff, 0xdec0_de01), 0xdec0_de01);
            assert_eq!(ptr::addr_of!(RECORDED_INDEX).read(), 0x7fff_ffff);
        }
    }
}
