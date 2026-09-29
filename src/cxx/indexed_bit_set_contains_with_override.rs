//! Indexed bit-set membership with an override record.

/// Resident indexed-bit-set predicate at `0x08370738`, not yet ported.
const INDEXED_BIT_SET_CONTAINS_ADDRESS: usize = 0x0837_0738;
type IndexedBitSetContains = unsafe extern "C" fn(*const u8, u32) -> u32;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn indexed_bit_set_contains_resident(bit_set: *const u8, index: u32) -> u32 {
    let predicate: IndexedBitSetContains = core::mem::transmute(INDEXED_BIT_SET_CONTAINS_ADDRESS);
    predicate(bit_set, index)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_indexed_bit_set_contains(_: *const u8, _: u32) -> u32 { 0 }

#[cfg(not(target_os = "none"))]
static mut INDEXED_BIT_SET_CONTAINS: IndexedBitSetContains = missing_indexed_bit_set_contains;

#[inline(always)]
unsafe fn indexed_bit_set_contains(bit_set: *const u8, index: u32) -> u32 {
    #[cfg(target_os = "none")]
    { indexed_bit_set_contains_resident(bit_set, index) }
    #[cfg(not(target_os = "none"))]
    { INDEXED_BIT_SET_CONTAINS(bit_set, index) }
}

/// `indexed_bit_set_contains_with_override` — original: `FUN_082dd00c` @
/// `0x082dd00c` (40 bytes; no outgoing `bl` instructions). Two verified
/// inbound direct plain `bl` calls are at `0x082de9b4` and `0x082debb4`; none
/// are predicated.
///
/// Reads the target-width object pointer at `context + 0`. When its byte at
/// `+0x14` is clear, tail-calls the resident indexed-bit-set predicate with the
/// bit set at `+0x58` and the index at `context + 4`. Otherwise it returns the
/// byte at `context + object[+0x3c] + 0x48`.
///
/// Deliberate deviation: the unported resident predicate remains a verified
/// address call on target; host builds substitute a test seam. Pointer fields
/// are read as 32-bit target words, independent of host pointer width.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn indexed_bit_set_contains_with_override(context: *const u8) -> u32 {
    let object = (context.cast::<u32>().read() as usize) as *const u8;
    if object.add(0x14).read() == 0 {
        let index = context.add(4).cast::<u32>().read();
        let bit_set = (object.add(0x58).cast::<u32>().read() as usize) as *const u8;
        indexed_bit_set_contains(bit_set, index)
    } else {
        let offset = object.add(0x3c).cast::<u32>().read() as usize;
        context.add(offset + 0x48).read() as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut EXPECTED_BIT_SET: usize = 0;
    static mut EXPECTED_INDEX: u32 = 0;

    unsafe extern "C" fn recording_predicate(bit_set: *const u8, index: u32) -> u32 {
        assert_eq!(bit_set as usize, EXPECTED_BIT_SET);
        assert_eq!(index, EXPECTED_INDEX);
        1
    }

    #[test]
    fn calls_bit_set_predicate_or_reads_override_byte() {
        let _lock = LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::INDEXED_BIT_SET_CONTAINS_WITH_OVERRIDE, 0x1000) else { return; };
        unsafe {
            slab.write_bytes(0, 0x1000);
            let context = slab;
            let object = slab.add(0x100);
            let bit_set = slab.add(0x300);
            context.cast::<u32>().write(object as usize as u32);
            context.add(4).cast::<u32>().write(0x1234);
            object.add(0x58).cast::<u32>().write(bit_set as usize as u32);
            EXPECTED_BIT_SET = bit_set as usize;
            EXPECTED_INDEX = 0x1234;
            INDEXED_BIT_SET_CONTAINS = recording_predicate;
            assert_eq!(indexed_bit_set_contains_with_override(context), 1);

            object.add(0x14).write(1);
            object.add(0x3c).cast::<u32>().write(0x200);
            context.add(0x248).write(0xa5);
            assert_eq!(indexed_bit_set_contains_with_override(context), 0xa5);
            INDEXED_BIT_SET_CONTAINS = missing_indexed_bit_set_contains;
        }
    }
}
