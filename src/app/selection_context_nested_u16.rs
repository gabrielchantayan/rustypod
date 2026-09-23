//! `selection_context_nested_u16` — original: `FUN_081a3178` @
//! **0x081a3178** (**8 bytes**, `0x081a3178..0x081a317f`). The next real
//! function begins at `0x081a3180` with `push {r4, r5, r6, lr}`. A complete
//! raw A32 branch decode finds **3 unconditional plain `bl` call sites**
//! (`0x0815fd24`, `0x081b4b18`, and `0x0820aad0`), with **0 predicated
//! `bl`** forms and no direct `b` callers.
//!
//! # Algorithm
//!
//! This is a veneer: it loads the nested selection-context pointer from
//! `context + 0x44` then tail-branches to the independently entered,
//! unported `FUN_08054214`. That target returns zero when its `+0xf50` word
//! is null; otherwise it follows `+0xf50`, then `+0x40`, and reads the u16 at
//! `+0x2e`. The concrete meaning of that u16 is unrecovered.
//!
//! # Deliberate deviations
//!
//! The target's verified reads are inlined on every build because
//! `FUN_08054214` has no recovered Rust identity; target-layout pointer fields
//! remain u32 words.

/// selection_context_nested_u16 — retailOS `FUN_081a3178` at `0x081a3178`.
///
/// # Safety
///
/// `context` must be non-NULL and four-byte aligned with a readable u32 at
/// `+0x44`. When the nested target's `+0xf50` word is nonzero, that pointer
/// and its `+0x40` word must name readable target-layout objects through u16
/// offset `+0x2e`. The retail veneer and its tail target make no checks other
/// than the `+0xf50` null test.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.selection_context_nested_u16")]
#[inline(never)]
pub unsafe extern "C" fn selection_context_nested_u16(context: *const u8) -> u16 {
    let target = context.add(0x44).cast::<u32>().read() as usize as *const u8;
    let nested = target.add(0xf50).cast::<u32>().read();
    if nested == 0 {
        0
    } else {
        let header = (nested as usize as *const u8).add(0x40).cast::<u32>().read() as usize as *const u8;
        header.add(0x2e).cast::<u16>().read()
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use std::sync::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    const SLAB_BYTES: usize = 0x2000;
    const TARGET: usize = 0x100;
    const NESTED: usize = 0x1200;
    const HEADER: usize = 0x1600;

    #[test]
    fn returns_zero_for_a_missing_nested_record_and_reads_the_unaligned_u16() {
        let _guard = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some(slab) = try_map_u32_slab(hints::SELECTION_CONTEXT_NESTED_U16, SLAB_BYTES) else {
            return;
        };
        unsafe {
            slab.write_bytes(0, SLAB_BYTES);
            slab.add(0x44).cast::<u32>().write((slab.add(TARGET)) as usize as u32);
            slab.add(TARGET + 0xf50).cast::<u32>().write(0);
            assert_eq!(selection_context_nested_u16(slab), 0);

            slab.add(TARGET + 0xf50).cast::<u32>().write((slab.add(NESTED)) as usize as u32);
            slab.add(NESTED + 0x40).cast::<u32>().write((slab.add(HEADER)) as usize as u32);
            slab.add(HEADER + 0x2e).cast::<u16>().write(0xbeef);
            assert_eq!(selection_context_nested_u16(slab), 0xbeef);
        }
    }
}
