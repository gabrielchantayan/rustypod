//! Close a banked object slot.
//!
//! Original: FUN_081962f8 @ 0x081962f8. True extent 124 bytes:
//! 120 instruction bytes plus literal 0x08aca424 at 0x08196370;
//! next function begins at 0x08196374. Verified calls: one plain BL,
//! zero predicated BL, one register BLX (vtable +4).
//! Return 13 for an out-of-range slot or absent object. For kinds 1 and 2,
//! call the resident finalizer at 0x081969b0 and preserve its status. Reload
//! the object after finalization; release any remaining object through its
//! second virtual word and clear the slot. Other kinds skip finalization
//! and return zero after release. Banks are intentionally not validated.
//!
//! Deliberate deviations: volatile target-word accesses preserve callback
//! mutations. The unported finalizer remains a resident-address seam;
//! host tests inject finalization/release callbacks into the same algorithm
//! rather than dereferencing firmware addresses. No class identity assumed.

#[cfg(test)]
extern crate std;

const SLOT_TABLE: usize = 0x08ac_a424;
const BANK_BYTES: u32 = 0x2100;
const SLOT_BYTES: u32 = 0x210;

type Finalize = unsafe extern "C" fn(u32, u32, u32) -> u32;
type Release = unsafe fn(u32);

unsafe fn close_in_table(
    table: *mut u8, context: u32, bank: u32, index: u32,
    finalize: Finalize, release: Release,
) -> u32 {
    if index >= 16 { return 13; }
    let offset = bank.wrapping_mul(BANK_BYTES).wrapping_add(index * SLOT_BYTES);
    let slot = table.wrapping_add(offset as usize).cast::<u32>();
    if slot.read_volatile() == 0 { return 13; }
    let kind = slot.cast::<u8>().add(8).read_volatile();
    let status = if kind == 1 || kind == 2 {
        let status = finalize(context, bank, index);
        if slot.read_volatile() == 0 { return status; }
        status
    } else { 0 };
    release(slot.read_volatile());
    slot.write_volatile(0);
    status
}

unsafe fn release_object(object: u32) {
    let object = object as usize as *mut u32;
    let vtable = object.read_volatile() as usize as *const u32;
    let release: unsafe extern "C" fn(*mut u32) =
        core::mem::transmute(vtable.add(1).read_volatile() as usize);
    release(object);
}

/// Close one slot in the resident table. Caller supplies a valid bank and
/// live objects with a target-width vtable containing a release method at +4.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn banked_slot_close(context: u32, bank: u32, index: u32) -> u32 {
    let finalize: Finalize = core::mem::transmute(0x0819_69b0usize);
    close_in_table(SLOT_TABLE as *mut u8, context, bank, index, finalize, release_object)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    std::thread_local! {
        static SLOT: Cell<*mut u32> = const { Cell::new(core::ptr::null_mut()) };
        static ACTION: Cell<u32> = const { Cell::new(0) };
        static FINALIZED: Cell<u32> = const { Cell::new(0) };
        static RELEASED: Cell<u32> = const { Cell::new(0) };
    }
    unsafe extern "C" fn finalize(context: u32, bank: u32, index: u32) -> u32 {
        assert_eq!((context, bank, index), (0x1234, 1, 15));
        FINALIZED.with(|n| n.set(n.get() + 1));
        SLOT.with(|s| ACTION.with(|a| match a.get() {
            1 => s.get().write(0),
            2 => s.get().write(0x5678),
            _ => (),
        }));
        37
    }
    unsafe fn release(object: u32) {
        SLOT.with(|s| assert_eq!(s.get().read(), object));
        RELEASED.with(|r| r.set(object));
    }

    #[test]
    fn kinds_and_finalizer_mutations() {
        let mut table = [0xa5a5a5a5u32; (2 * BANK_BYTES / 4) as usize];
        let offset = ((BANK_BYTES + 15 * SLOT_BYTES) / 4) as usize;
        for kind in 0..=255u32 {
            for action in 0..=2 {
                table[offset] = 0x123;
                table[offset + 2] = 0xa5a5a500 | kind;
                let slot = unsafe { table.as_mut_ptr().add(offset) };
                SLOT.with(|s| s.set(slot));
                ACTION.with(|a| a.set(action));
                FINALIZED.with(|n| n.set(0));
                RELEASED.with(|r| r.set(0));
                let active = kind == 1 || kind == 2;
                let status = unsafe { close_in_table(table.as_mut_ptr().cast(), 0x1234, 1, 15, finalize, release) };
                assert_eq!(status, if active { 37 } else { 0 });
                FINALIZED.with(|n| assert_eq!(n.get(), u32::from(active)));
                RELEASED.with(|r| assert_eq!(r.get(), if active && action == 1 { 0 } else if active && action == 2 { 0x5678 } else { 0x123 }));
                assert_eq!(table[offset], 0);
                assert_eq!(table[offset - 1], 0xa5a5a5a5);
                assert_eq!(table[offset + 1], 0xa5a5a5a5);
                assert_eq!(table[offset + 2], 0xa5a5a500 | kind);
                assert_eq!(table[offset + 3], 0xa5a5a5a5);
            }
        }
    }

    #[test]
    fn invalid_index_and_empty_slot_do_not_dispatch() {
        unsafe extern "C" fn forbidden(_: u32, _: u32, _: u32) -> u32 { panic!("unexpected finalizer") }
        unsafe fn forbidden_release(_: u32) { panic!("unexpected release") }
        for index in [16, 17, u32::MAX] {
            assert_eq!(unsafe { close_in_table(core::ptr::null_mut(), 0, u32::MAX, index, forbidden, forbidden_release) }, 13);
        }
        let mut table = [0u32; (SLOT_BYTES / 4) as usize];
        table[2] = 1;
        assert_eq!(unsafe { close_in_table(table.as_mut_ptr().cast(), 0, 0, 0, forbidden, forbidden_release) }, 13);
        assert_eq!(table[2], 1);
    }
}
