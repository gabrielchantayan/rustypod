//! Default constructor for the otherwise unidentified 80-byte result object.
//!
//! This is the constructor paired with [`super::opaque_result_destroy`]. It
//! builds five embedded `StringObject` values, clears the intervening opaque
//! word, then clears the three target-width vector headers.

use crate::cxx::opaque_result_destroy::OpaqueResult;
use crate::cxx::string_object::string_default_construct;

/// `opaque_result_construct` — original: `FUN_082679c4` @ `0x082679c4`
/// (52 bytes; three direct `bl` call sites, all unconditional, zero predicated).
///
/// Raw `osos.dec` establishes the exact extent: `push {r4,lr}` at
/// `0x082679c4` through `pop {r4,pc}` at `0x082679f4`; the next real function
/// starts at `0x082679f8`. The body calls the separately linked base
/// constructor at `0x08267958`, then clears nine words at target offsets
/// `+0x2c..+0x4c`: the three owned vector headers.
///
/// The base constructor initializes five embedded StringObjects at target
/// offsets `+0`, `+8`, `+0x14`, `+0x1c`, and `+0x24`, and clears the opaque
/// word at `+0x10`. Returns `this`.
///
/// Deliberate deviation: named `repr(C)` fields preserve target member
/// semantics when host pointers widen; on ARM the field layout is the exact
/// 80-byte retailOS object.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn opaque_result_construct(this: *mut OpaqueResult) -> *mut OpaqueResult {
    string_default_construct(core::ptr::addr_of_mut!((*this).primary));
    string_default_construct(core::ptr::addr_of_mut!((*this).secondary));
    (*this).opaque_word = 0;
    string_default_construct(core::ptr::addr_of_mut!((*this).third));
    string_default_construct(core::ptr::addr_of_mut!((*this).fourth));
    string_default_construct(core::ptr::addr_of_mut!((*this).fifth));
    (*this).vector32.begin = 0;
    (*this).vector32.end = 0;
    (*this).vector32.capacity = 0;
    (*this).vector16.begin = 0;
    (*this).vector16.end = 0;
    (*this).vector16.capacity = 0;
    (*this).vector28.begin = 0;
    (*this).vector28.end = 0;
    (*this).vector28.capacity = 0;
    this
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initializes_every_owned_member_and_returns_this() {
        let mut result: OpaqueResult = unsafe { core::mem::zeroed() };
        result.opaque_word = 0xdead_beef;
        result.vector32.begin = 1;
        result.vector32.end = 2;
        result.vector32.capacity = 3;
        result.vector16.begin = 4;
        result.vector16.end = 5;
        result.vector16.capacity = 6;
        result.vector28.begin = 7;
        result.vector28.end = 8;
        result.vector28.capacity = 9;

        let returned = unsafe { opaque_result_construct(&mut result) };

        assert!(core::ptr::eq(returned, &mut result));
        assert!(result.primary.payload.is_null());
        assert!(result.secondary.payload.is_null());
        assert!(result.third.payload.is_null());
        assert!(result.fourth.payload.is_null());
        assert!(result.fifth.payload.is_null());
        assert_eq!(result.opaque_word, 0);
        assert_eq!(result.vector32.begin, 0);
        assert_eq!(result.vector32.end, 0);
        assert_eq!(result.vector32.capacity, 0);
        assert_eq!(result.vector16.begin, 0);
        assert_eq!(result.vector16.end, 0);
        assert_eq!(result.vector16.capacity, 0);
        assert_eq!(result.vector28.begin, 0);
        assert_eq!(result.vector28.end, 0);
        assert_eq!(result.vector28.capacity, 0);
    }
}
