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
//! `fallback_item` to ported `observable_array_read_at`, then returns the
//! resulting output word. The callee's boolean result is deliberately ignored.
//!
//! # Deliberate deviation
//!
//! Target assembly preserves the original caller's r3 fallback word. Host
//! code uses a native stack pointer and the read wrapper's widened vtable.

#[cfg(not(target_os = "none"))]
use core::ptr;

const EMBEDDED_ARRAY_OFFSET: usize = 0xe8;


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
    bl      observable_array_read_at
    ldr     r0,[sp]
    pop     {{r12,pc}}
    .size selection_state_copy_item_at, .-selection_state_copy_item_at
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
    crate::cxx::observable_array::observable_array_read_at(
        selection_state.add(EMBEDDED_ARRAY_OFFSET).cast(), item_index,
        ptr::addr_of_mut!(item).cast(),
    );
    item
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::observable_array::{
        ObservableArray, ObservableArrayReadHost, ObservableArrayReadVtable,
    };

    #[test]
    fn indexed_copy_keeps_fallback_only_when_index_is_invalid() {
        unsafe extern "C" fn copy(
            _: *mut ObservableArray, index: i32, output: *mut u8,
        ) -> u32 {
            output.cast::<u32>().write(0x1234_0000 + index as u32);
            0
        }
        #[repr(C)]
        struct Selection {
            prefix: [u8; EMBEDDED_ARRAY_OFFSET],
            array: ObservableArrayReadHost,
        }
        let vtable = ObservableArrayReadVtable {
            unresolved_00_a0: [0; 41], read_element: copy,
        };
        let mut selection = Selection {
            prefix: [0; EMBEDDED_ARRAY_OFFSET],
            array: ObservableArrayReadHost { vtable: &vtable, len: 3 },
        };
        let state = (&mut selection as *mut Selection).cast();
        unsafe {
            assert_eq!(selection_state_copy_item_at(state, i32::MAX, 0xdead_beef), 0x1234_0002);
            assert_eq!(selection_state_copy_item_at(state, 3, 0xdead_beef), 0xdead_beef);
            selection.array.len = 0;
            assert_eq!(selection_state_copy_item_at(state, i32::MAX, 0xdead_beef), 0xdead_beef);
        }
    }
}
