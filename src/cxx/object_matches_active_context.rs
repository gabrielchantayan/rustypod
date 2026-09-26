//! Active-context object identity predicate.

/// `object_matches_active_context` — original: `FUN_083d6e9c` @
/// `0x083d6e9c` (36 bytes; source:
/// `ipod-decomp/decomp/c/037/083d6e9c_FUN_083d6e9c.c`).
///
/// Raw `osos.dec` words establish the complete extent `0x083d6e9c..0x083d6ec0`:
/// the literal at `0x083d6ec0` is data and `push {r4,lr}` at `0x083d6ec4`
/// begins the next real function. The body has no outgoing plain or predicated
/// `bl` instructions. Raw ARM decoding finds two inbound plain `bl` calls
/// (`0x083d6ecc`, `0x083d849c`) and no predicated inbound calls.
///
/// Recovers the owning object by adding the signed adjustment stored three words
/// before the object's first word, then compares it with word 1 of the active
/// context at `0x08b316e8`.
///
/// Deliberate deviations: the active-context address is replaced with writable
/// host storage outside the firmware target so tests can exercise the exact
/// 32-bit pointer-word layout.

const ACTIVE_CONTEXT_ADDRESS: usize = 0x08b3_16e8;

#[cfg(not(target_os = "none"))]
static mut HOST_ACTIVE_CONTEXT: [u32; 2] = [0; 2];

#[inline(always)]
unsafe fn active_object_word() -> u32 {
    #[cfg(target_os = "none")]
    {
        unsafe { core::ptr::read_volatile((ACTIVE_CONTEXT_ADDRESS as *const u32).add(1)) }
    }

    #[cfg(not(target_os = "none"))]
    {
        unsafe { core::ptr::addr_of!(HOST_ACTIVE_CONTEXT).cast::<u32>().add(1).read() }
    }
}

/// # Safety
///
/// `object` must point to an aligned retailOS object word, and the three-word
/// prefix addressed by its first word must contain a readable signed adjustment.
/// As in retailOS, neither pointer is NULL-checked.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn object_matches_active_context(object: *const u32) -> bool {
    let adjustment = unsafe { (object.read() as *const i32).sub(3).read() };
    let owner = (object as *const u8).wrapping_offset(adjustment as isize) as usize as u32;
    owner == unsafe { active_object_word() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, try_map_u32_slab};

    const SLAB_SIZE: usize = 0x100;
    const OBJECT_OFFSET: usize = 0x40;
    const TABLE_OFFSET: usize = 0x60;

    #[test]
    fn recognizes_only_the_adjusted_active_owner() {
        let Some(base) = try_map_u32_slab(hints::CXX_OBJECT_MATCHES_ACTIVE_CONTEXT, SLAB_SIZE) else {
            return;
        };
        unsafe {
            base.write_bytes(0, SLAB_SIZE);
            let object = base.add(OBJECT_OFFSET).cast::<u32>();
            let table = base.add(TABLE_OFFSET).cast::<u32>();
            table.sub(3).write((TABLE_OFFSET - OBJECT_OFFSET) as u32);
            object.write(table as usize as u32);
            HOST_ACTIVE_CONTEXT[1] = base.add(TABLE_OFFSET) as usize as u32;
            assert!(object_matches_active_context(object));

            HOST_ACTIVE_CONTEXT[1] = base.add(TABLE_OFFSET + 4) as usize as u32;
            assert!(!object_matches_active_context(object));
        }
    }
}
