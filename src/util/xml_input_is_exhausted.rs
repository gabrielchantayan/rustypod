//! `xml_input_is_exhausted` — original: `FUN_0825d5ac` @ `0x0825d5ac`
//! (**48 bytes**, `0x0825d5ac..0x0825d5db`; extent verified against the UTF-8
//! decoder prologue at `0x0825d5dc`).
//!
//! Returns one when the XML input's status word is nonzero, or when its vtable
//! `+8` predicate returns nonzero; otherwise returns zero. The status check
//! avoids the virtual call. Raw ARM has five verified static `bl` call sites,
//! all unconditional; the indirect `blx r1` at `0x0825d5c4` is not a static
//! `bl` call site. The vtable predicate has no independently verified identity,
//! so host tests use a volatile dispatch seam; target builds dispatch through
//! the verified vtable word. This is the sole deliberate deviation.

/// The two target-sized words consumed by [`xml_input_is_exhausted`].
///
/// The first word points to a vtable whose `+8` entry accepts this object;
/// `status` is tested before that entry is loaded.
#[repr(C)]
pub struct XmlInput {
    pub vtable: u32,
    pub status: u32,
}

/// Host-test dispatch for the XML input vtable's opaque `+8` predicate.
#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct XmlInputOps {
    pub is_exhausted: unsafe extern "C" fn(*mut XmlInput) -> u32,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_is_exhausted(input: *mut XmlInput) -> u32 {
    let vtable = unsafe { (*input).vtable as *const u32 };
    let predicate: unsafe extern "C" fn(*mut XmlInput) -> u32 =
        unsafe { core::mem::transmute(vtable.add(2).read()) };
    unsafe { predicate(input) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_is_exhausted(_input: *mut XmlInput) -> u32 {
    panic!("xml_input_is_exhausted requires an input predicate seam on host")
}

#[cfg(not(target_os = "none"))]
pub const DEFAULT_XML_INPUT_OPS: XmlInputOps = XmlInputOps {
    is_exhausted: missing_is_exhausted,
};

/// Volatile host-test seam for the XML input's unclassified vtable `+8`
/// predicate. Target builds dispatch directly through that vtable entry.
#[cfg(not(target_os = "none"))]
pub static mut XML_INPUT_OPS: XmlInputOps = DEFAULT_XML_INPUT_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn ops() -> XmlInputOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(XML_INPUT_OPS)) }
}

/// `xml_input_is_exhausted` — original: `FUN_0825d5ac` @ `0x0825d5ac`
/// (48 bytes; five binary-verified unconditional `bl` call sites).
///
/// A nonzero `status` returns one without touching the vtable. Otherwise the
/// vtable `+8` result is normalized to zero or one, exactly as `cmp r0,#0` /
/// `movne r0,#1` does in retailOS.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn xml_input_is_exhausted(input: *mut XmlInput) -> u32 {
    if unsafe { (*input).status } != 0 {
        return 1;
    }
    #[cfg(target_os = "none")]
    let exhausted = unsafe { firmware_is_exhausted(input) };
    #[cfg(not(target_os = "none"))]
    let exhausted = unsafe { (ops().is_exhausted)(input) };
    if exhausted != 0 {
        1
    } else {
        0
    }
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;
    use parking_lot::Mutex;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: u32 = 0;
    static mut RESULT: u32 = 0;
    static mut SEEN_INPUT: *mut XmlInput = ptr::null_mut();

    unsafe extern "C" fn controlled_is_exhausted(input: *mut XmlInput) -> u32 {
        unsafe {
            CALLS = CALLS.wrapping_add(1);
            SEEN_INPUT = input;
            RESULT
        }
    }

    fn install(result: u32) {
        unsafe {
            CALLS = 0;
            RESULT = result;
            SEEN_INPUT = ptr::null_mut();
            XML_INPUT_OPS = XmlInputOps { is_exhausted: controlled_is_exhausted };
        }
    }

    fn restore() {
        unsafe { XML_INPUT_OPS = DEFAULT_XML_INPUT_OPS; }
    }

    #[test]
    fn status_short_circuits_the_virtual_predicate() {
        let _lock = OPS_LOCK.lock();
        install(0);
        let mut input = XmlInput { vtable: 0, status: 7 };

        assert_eq!(unsafe { xml_input_is_exhausted(&mut input) }, 1);
        assert_eq!(unsafe { CALLS }, 0);
        restore();
    }

    #[test]
    fn predicate_result_is_normalized_and_receives_input() {
        let _lock = OPS_LOCK.lock();
        let mut input = XmlInput { vtable: 0, status: 0 };

        install(0);
        assert_eq!(unsafe { xml_input_is_exhausted(&mut input) }, 0);
        assert_eq!(unsafe { CALLS }, 1);
        assert_eq!(unsafe { SEEN_INPUT as usize }, (&mut input as *mut XmlInput) as usize);

        install(u32::MAX);
        assert_eq!(unsafe { xml_input_is_exhausted(&mut input) }, 1);
        assert_eq!(unsafe { CALLS }, 1);
        assert_eq!(unsafe { SEEN_INPUT as usize }, (&mut input as *mut XmlInput) as usize);
        restore();
    }
}
