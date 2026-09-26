//! `list_member_destroy` — original: `FUN_083db7a8` @ **0x083db7a8**.
//!
//! Raw `osos.dec` words establish the exact 64-byte extent
//! `0x083db7a8..0x083db7e4`; `push {r4,r5,lr}` at `0x083db7e8` begins the
//! next independently entered function. The body has one unconditional direct
//! `bl`, to the unported `FUN_083c69ec` @ 0x083c69ec, and no predicated `bl`.
//! Full-image decoding finds two inbound unconditional plain `bl` sites
//! (0x081b6130 and 0x081b6780), and no inbound predicated `bl` sites.
//!
//! # Algorithm
//!
//! The member owns an opaque list header at `this + 0x10`. Stock code copies
//! that header's first-node word (`+0x08`) and the header word itself to stack
//! homes, then passes their addresses with `this` to `FUN_083c69ec`. It returns
//! those two original words in r0/r1.
//!
//! # Deliberate deviation
//!
//! `FUN_083c69ec` is unported and its identity is not inferred. Device builds
//! call its verified fixed address; host tests inject its observed ABI. Rust
//! omits dead stack setup while retaining the ordered target-width reads, call,
//! and packed r0/r1 result.

const LIST_HEADER_OFFSET: usize = 0x10;
const FIRST_NODE_OFFSET: usize = 0x08;
const LIST_MEMBER_DESTROY_ADDRESS: usize = 0x083c_69ec;

type ListMemberDestroyHelper = unsafe extern "C" fn(*mut u32, *mut u8, *mut u32, *mut u32);

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_list_member_destroy_helper(
    out: *mut u32,
    object: *mut u8,
    first: *mut u32,
    header: *mut u32,
) {
    unsafe {
        core::mem::transmute::<usize, ListMemberDestroyHelper>(LIST_MEMBER_DESTROY_ADDRESS)(
            out, object, first, header,
        )
    }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_list_member_destroy_helper(
    _: *mut u32,
    _: *mut u8,
    _: *mut u32,
    _: *mut u32,
) {
    panic!("list_member_destroy requires FUN_083c69ec")
}

/// Destroys the opaque list member at `object + 0x10`.
///
/// # Safety
///
/// `object` and its target-width list-header word must be readable; that header
/// must name storage readable through `+0x08`. The helper receives stack-local
/// copies of the header and first-node words and follows retailOS's ownership
/// contract for the member.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn list_member_destroy(object: *mut u8) -> u64 {
    unsafe { list_member_destroy_with(object, firmware_list_member_destroy_helper) }
}

#[inline(always)]
unsafe fn list_member_destroy_with(object: *mut u8, helper: ListMemberDestroyHelper) -> u64 {
    unsafe {
        let mut header = object.add(LIST_HEADER_OFFSET).cast::<u32>().read();
        let mut first = (header as usize as *const u8)
            .add(FIRST_NODE_OFFSET)
            .cast::<u32>()
            .read();
        let mut out = [0u32; 2];
        helper(out.as_mut_ptr(), object, &mut first, &mut header);
        u64::from(header) | (u64::from(first) << 32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, try_map_u32_slab};

    unsafe extern "C" fn verify_helper(
        out: *mut u32,
        object: *mut u8,
        first: *mut u32,
        header: *mut u32,
    ) {
        unsafe {
            assert_eq!(header.read(), object.add(0x200) as usize as u32);
            assert_eq!(first.read(), object.add(0x300) as usize as u32);
            out.write(0xdead_beef);
            out.add(1).write(0xcafe_babe);
        }
    }

    #[test]
    fn passes_target_width_list_words_and_returns_their_original_pair() {
        let Some(slab) = try_map_u32_slab(hints::CXX_LIST_MEMBER_DESTROY, 0x1000) else {
            return;
        };
        unsafe {
            let object = slab;
            let header = slab.add(0x200);
            let first = slab.add(0x300);
            object.add(LIST_HEADER_OFFSET).cast::<u32>().write(header as usize as u32);
            header.add(FIRST_NODE_OFFSET).cast::<u32>().write(first as usize as u32);

            let result = list_member_destroy_with(object, verify_helper);

            assert_eq!(result as u32, header as usize as u32);
            assert_eq!((result >> 32) as u32, first as usize as u32);
            assert_eq!(object.add(LIST_HEADER_OFFSET).cast::<u32>().read(), header as usize as u32);
            assert_eq!(header.add(FIRST_NODE_OFFSET).cast::<u32>().read(), first as usize as u32);
        }
    }
}
