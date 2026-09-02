//! array_element_at — original: `FUN_082a4cf8` @ 0x082a4cf8 (**24 bytes**,
//! 0x082a4cf8..0x082a4d10 — the next function's `push {r4..r8, lr}` starts
//! exactly at 0x082a4d10, so Ghidra's extent is right for once; **23 `bl`
//! call sites, 0 predicated**, binary-scanned by decoding every B/BL word
//! in `work/firmware/osos.dec`).
//!
//! Element-address accessor of retailOS's polymorphic strided-array class
//! (layout below), with a "last element" sentinel:
//!
//! ```text
//! 082a4cf8  cmn r1, #-0x7fffffff   @ index == 0x7fffffff (LAST_ELEMENT)?
//! 082a4cfc  bne 0x082a4d0c
//! 082a4d00  ldr r2, [r0, #4]       @ count
//! 082a4d04  cmp r2, #0
//! 082a4d08  subgt r1, r2, #1       @ count > 0: index = count - 1
//! 082a4d0c  b   0x082a4b94         @ tail: element address helper
//! ```
//!
//! Algorithm: if `index` is the `LAST_ELEMENT_INDEX` sentinel and the
//! signed `count` at +0x04 is positive, replace `index` with `count - 1`
//! (so the sentinel names the final element; an empty or negative-count
//! array passes the sentinel through untouched — `subgt` is a signed
//! test). Then tail-branch into the element-address helper
//! `FUN_082a4b94` @ 0x082a4b94 (40 bytes, binary-verified:
//! `push {r4,r5,r6,lr}; size = vtable[+0x18](this); r0 = storage +
//! index*size; pop {r4,r5,r6,pc}` — one `mla`).
//!
//! Callers confirm the sentinel semantics: `FUN_081b92e4` calls it as
//! `(array, 0x7fffffff)` to fetch the last element, and the sibling
//! `FUN_082a4c20` proves vtable slot +0x18 is the element size (`if
//! (size != 4) <generic copy> else *out = *element`).
//!
//! Deliberate deviation: the tail target 0x082a4b94 is a distinct,
//! separately-called function (a dozen direct `bl` sites of its own) and
//! is not yet ported, so it rides the [`STRIDED_ARRAY_ELEMENT_ADDRESS`]
//! dispatch seam (the `command_dispatch` house pattern): target builds
//! transmute the ROM address, host tests install recording mocks, and a
//! later port of 0x082a4b94 replaces the default without touching this
//! wrapper.
//!
//! Anomaly, recorded not resolved: the one concrete vtable sampled — the
//! observable array's 0x089a5d0c — has slot +0x18 = 0x08102f80, which is
//! not a function entry in Ghidra's listing (it falls inside
//! `FUN_08102f44` and decodes with r4 live-in). That class is therefore
//! probably not among this wrapper's receivers; the wrapper is generic
//! over any object with the layout below and no concrete class identity
//! is claimed.

/// The index value that names the final element (`cmn r1, #-0x7fffffff`
/// sets Z exactly when r1 == 0x7fffffff).
pub const LAST_ELEMENT_INDEX: i32 = 0x7fff_ffff;

/// The polymorphic strided array the accessor runs on: a vtable whose
/// slot +0x18 is the virtual `element_size(this)` getter, a signed
/// element count, and the storage base. All fields are target words so
/// the layout stays exact in 64-bit host tests.
#[repr(C)]
pub struct StridedArray {
    /// +0x00: vtable pointer; slot +0x18 returns the element stride.
    pub vtable: u32,
    /// +0x04: signed element count; read only for the last-element
    /// sentinel, and only a positive count clamps.
    pub count: i32,
    /// +0x08: base address of the element storage.
    pub storage: u32,
}

const _: [u8; 0x00] = [0; core::mem::offset_of!(StridedArray, vtable)];
const _: [u8; 0x04] = [0; core::mem::offset_of!(StridedArray, count)];
const _: [u8; 0x08] = [0; core::mem::offset_of!(StridedArray, storage)];
const _: [u8; 0x0c] = [0; core::mem::size_of::<StridedArray>()];

/// Firmware load address of the unported element-address helper
/// `FUN_082a4b94` the original tail-branches into.
pub const ELEMENT_ADDRESS_HELPER_ADDRESS: usize = 0x082a_4b94;

/// Target default for [`STRIDED_ARRAY_ELEMENT_ADDRESS`]: the stock
/// helper at [`ELEMENT_ADDRESS_HELPER_ADDRESS`].
#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_element_address(this: *const StridedArray, index: i32) -> u32 {
    let helper: unsafe extern "C" fn(*const StridedArray, i32) -> u32 =
        core::mem::transmute(ELEMENT_ADDRESS_HELPER_ADDRESS);
    helper(this, index)
}

/// Host default for [`STRIDED_ARRAY_ELEMENT_ADDRESS`]: the helper is
/// unported, so an unswapped call is a test-setup error.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_element_address(_this: *const StridedArray, _index: i32) -> u32 {
    panic!("array_element_at requires the element-address helper 0x082a4b94")
}

/// Dispatch seam for the unported tail target `FUN_082a4b94` @
/// 0x082a4b94 (`storage + index * element_size(this)`). Target builds
/// wire the ROM address; host tests install recording mocks; a later
/// port of the helper replaces the default.
#[cfg(target_os = "none")]
pub static mut STRIDED_ARRAY_ELEMENT_ADDRESS: unsafe extern "C" fn(
    this: *const StridedArray,
    index: i32,
) -> u32 = firmware_element_address;

/// Host wired default (panics; see [`missing_element_address`]).
#[cfg(not(target_os = "none"))]
pub static mut STRIDED_ARRAY_ELEMENT_ADDRESS: unsafe extern "C" fn(
    this: *const StridedArray,
    index: i32,
) -> u32 = missing_element_address;

/// array_element_at — original: `FUN_082a4cf8` @ 0x082a4cf8 (24 bytes;
/// 23 `bl` call sites, binary-scanned). See the module header for the
/// algorithm and the listing.
///
/// Returns the address of element `index`, where `index ==
/// `[`LAST_ELEMENT_INDEX`] names the final element of a non-empty array.
/// All arithmetic is the original's mod $2^{32}$ word arithmetic.
///
/// # Safety
///
/// `this` must point to at least eight readable, word-aligned bytes (the
/// count at +0x04 is read when, and only when, `index` is the sentinel);
/// the storage word and vtable are touched only by the dispatched helper.
/// As in the original, `this` is not NULL-checked.
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
    let element_address =
        core::ptr::read_volatile(core::ptr::addr_of!(STRIDED_ARRAY_ELEMENT_ADDRESS));
    element_address(this, index)
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use parking_lot::Mutex;
    use std::ptr;
    use std::vec::Vec;

    /// Serializes the tests: they all swap the one crate-global seam.
    static SEAM_LOCK: Mutex<()> = Mutex::new(());

    static mut CALLS: Vec<(usize, i32)> = Vec::new();
    static mut RESULT: u32 = 0;

    unsafe extern "C" fn recording_element_address(
        this: *const StridedArray,
        index: i32,
    ) -> u32 {
        (*ptr::addr_of_mut!(CALLS)).push((this as usize, index));
        ptr::addr_of!(RESULT).read_volatile()
    }

    struct SeamGuard;

    impl SeamGuard {
        fn install() -> Self {
            unsafe {
                ptr::addr_of_mut!(STRIDED_ARRAY_ELEMENT_ADDRESS)
                    .write_volatile(recording_element_address);
                (*ptr::addr_of_mut!(CALLS)).clear();
            }
            SeamGuard
        }
    }

    impl Drop for SeamGuard {
        fn drop(&mut self) {
            unsafe {
                ptr::addr_of_mut!(STRIDED_ARRAY_ELEMENT_ADDRESS)
                    .write_volatile(missing_element_address);
            }
        }
    }

    fn recorded_calls() -> Vec<(usize, i32)> {
        unsafe { (*ptr::addr_of!(CALLS)).clone() }
    }

    fn array(count: i32) -> StridedArray {
        StridedArray { vtable: 0x089a_0000, count, storage: 0x0840_0000 }
    }

    #[test]
    fn a_plain_index_passes_through_without_reading_the_count() {
        let _lock = SEAM_LOCK.lock();
        let _seam = SeamGuard::install();
        // Poison the count at an unmapped-looking value; if the wrapper
        // read it for a non-sentinel index the recorded index would move.
        let object = array(-1);

        unsafe {
            ptr::addr_of_mut!(RESULT).write_volatile(0x0840_0060);
            let returned = array_element_at(&object, 3);
            assert_eq!(returned, 0x0840_0060, "the helper's r0 is handed back untouched");
        }

        assert_eq!(
            recorded_calls(),
            std::vec![(&object as *const _ as usize, 3)],
            "index 3 reaches the helper verbatim"
        );
    }

    #[test]
    fn the_sentinel_names_the_last_element_of_a_non_empty_array() {
        let _lock = SEAM_LOCK.lock();
        let _seam = SeamGuard::install();
        let object = array(7);

        unsafe {
            array_element_at(&object, LAST_ELEMENT_INDEX);
            assert_eq!(
                recorded_calls(),
                std::vec![(&object as *const _ as usize, 6)],
                "0x7fffffff with count 7 becomes index 6"
            );
        }
    }

    #[test]
    fn the_sentinel_on_a_one_element_array_yields_index_zero() {
        let _lock = SEAM_LOCK.lock();
        let _seam = SeamGuard::install();
        let object = array(1);

        unsafe {
            array_element_at(&object, LAST_ELEMENT_INDEX);
            assert_eq!(recorded_calls()[0].1, 0);
        }
    }

    #[test]
    fn the_sentinel_passes_through_on_an_empty_array() {
        let _lock = SEAM_LOCK.lock();
        let _seam = SeamGuard::install();
        let object = array(0);

        unsafe {
            array_element_at(&object, LAST_ELEMENT_INDEX);
            assert_eq!(
                recorded_calls()[0].1,
                LAST_ELEMENT_INDEX,
                "count == 0 fails the signed subgt, so the sentinel survives"
            );
        }
    }

    #[test]
    fn the_sentinel_passes_through_on_a_negative_count() {
        let _lock = SEAM_LOCK.lock();
        let _seam = SeamGuard::install();
        let object = array(-3);

        unsafe {
            array_element_at(&object, LAST_ELEMENT_INDEX);
            assert_eq!(
                recorded_calls()[0].1,
                LAST_ELEMENT_INDEX,
                "the clamp is signed: a negative count never clamps"
            );
        }
    }

    #[test]
    fn one_below_the_sentinel_is_an_ordinary_index() {
        let _lock = SEAM_LOCK.lock();
        let _seam = SeamGuard::install();
        let object = array(2);

        unsafe {
            array_element_at(&object, LAST_ELEMENT_INDEX - 1);
            assert_eq!(recorded_calls()[0].1, LAST_ELEMENT_INDEX - 1);
        }
    }
}
