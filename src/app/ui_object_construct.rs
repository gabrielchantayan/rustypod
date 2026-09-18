//! `ui_object_construct` — original: `FUN_081b8e74` @ **0x081b8e74**
//! (188 bytes: 47 instruction words through the `pop` at 0x081b8f2c,
//! followed by three literal-pool words; the next independent function starts
//! at 0x081b8f3c). Raw decoding finds four inbound unconditional `bl` call
//! sites, zero predicated inbound `bl` sites, and nine unconditional outbound
//! `bl` instructions.
//!
//! Constructs the unidentified 0x580-byte UI object by first delegating its
//! five-word base construction to 0x0815c9ac, then installing this derived
//! vtable and initializing two PairHeaderBase, two draw-state, and two
//! FixedValue members. The return is derived from the second FixedValue
//! constructor result (`result - 0x2e8`), not the entry pointer.
//!
//! Deliberate deviation: 0x0815c9ac remains unidentified and unported. Its
//! recovered five-word ABI is isolated behind [`UI_OBJECT_BASE_CONSTRUCT_OPS`]
//! for host tests; target builds call its retail entry directly. All identified
//! callees use their existing Rust ports.

use crate::app::fixed_value::{fixed_value_default_init, FixedValue};
use crate::cxx::draw_state::draw_state_construct;
use crate::cxx::pair_header::pair_header_base_construct;

const UI_OBJECT_VTABLE: u32 = 0x0898_c350;
const UI_OBJECT_FIRST_MEMBER_VTABLE: u32 = 0x0898_7f00;
const UI_OBJECT_SECOND_MEMBER_VTABLE: u32 = 0x0898_7d60;

#[derive(Clone, Copy)]
pub struct UiObjectBaseConstructOps {
    pub construct: unsafe extern "C" fn(*mut u8, u32, u32, u32, u32) -> *mut u8,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_ui_object_base_construct(
    this: *mut u8,
    first: u32,
    second: u32,
    third: u32,
    spec: u32,
) -> *mut u8 {
    let construct: unsafe extern "C" fn(*mut u8, u32, u32, u32, u32) -> *mut u8 =
        unsafe { core::mem::transmute(0x0815_c9acusize) };
    unsafe { construct(this, first, second, third, spec) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_ui_object_base_construct(
    _this: *mut u8,
    _first: u32,
    _second: u32,
    _third: u32,
    _spec: u32,
) -> *mut u8 {
    panic!("ui_object_construct requires base constructor 0x0815c9ac")
}

#[cfg(target_os = "none")]
pub static mut UI_OBJECT_BASE_CONSTRUCT_OPS: UiObjectBaseConstructOps = UiObjectBaseConstructOps {
    construct: firmware_ui_object_base_construct,
};

#[cfg(not(target_os = "none"))]
pub static mut UI_OBJECT_BASE_CONSTRUCT_OPS: UiObjectBaseConstructOps = UiObjectBaseConstructOps {
    construct: missing_ui_object_base_construct,
};

#[inline(always)]
unsafe fn ui_object_base_construct_op() -> unsafe extern "C" fn(*mut u8, u32, u32, u32, u32) -> *mut u8 {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(UI_OBJECT_BASE_CONSTRUCT_OPS.construct)) }
}

/// Constructs the derived UI object and returns the retail-derived member
/// address. The original has no NULL or bounds checks.
///
/// # Safety
///
/// `this` and the pointer returned by the base constructor must identify the
/// 0x580-byte writable object storage and satisfy each member constructor's
/// alignment requirements.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ui_object_construct(
    this: *mut u8,
    first: u32,
    second: u32,
    third: u32,
    spec: u32,
) -> *mut u8 {
    let base = unsafe { ui_object_base_construct_op()(this, first, second, third, spec) };
    unsafe {
        (base as *mut u32).write(UI_OBJECT_VTABLE);
        (base.add(0x2dc) as *mut u32).write(UI_OBJECT_VTABLE.wrapping_add(0x16c));
        (base.add(0x2e0) as *mut u32).write(spec.wrapping_add(0x6c));

        pair_header_base_construct(base.add(0x2f8).cast());
        let first_draw_state = draw_state_construct(base.add(0x3b0));
        (first_draw_state.add(0x44) as *mut u32).write(0);

        pair_header_base_construct(base.add(0x3f8).cast());
        let second_draw_state = draw_state_construct(base.add(0x4b0));
        (second_draw_state.add(0x44) as *mut u32).write(0);

        let first_value = fixed_value_default_init(base.add(0x4f8).cast::<FixedValue>());
        let first_value = first_value.cast::<u8>();
        (first_value as *mut u32).write(UI_OBJECT_FIRST_MEMBER_VTABLE);
        (first_value.add(0x18) as *mut u32).write(0);
        (first_value.add(0x1c) as *mut u32).write(0);
        (first_value.add(0x20) as *mut u32).write(0);

        let second_value = fixed_value_default_init(base.add(0x510).cast::<FixedValue>());
        let second_value = second_value.cast::<u8>();
        (second_value as *mut u32).write(UI_OBJECT_SECOND_MEMBER_VTABLE);
        (second_value.add(0x24) as *mut u32).write(0);
        (second_value.add(0x08) as *mut u32).write(1);
        (second_value.sub(0x264) as *mut u32).write(0);
        (second_value.sub(0x260) as *mut u32).write(0);
        (second_value.sub(0x25c) as *mut u32).write(0);
        (second_value.sub(0x258) as *mut u32).write(0);

        second_value.sub(0x2e8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::UI_OBJECT_BASE_CONSTRUCT_TEST_LOCK;

    static mut OBSERVED: [u32; 5] = [0; 5];

    unsafe extern "C" fn construct_base(
        this: *mut u8, first: u32, second: u32, third: u32, spec: u32,
    ) -> *mut u8 {
        unsafe { OBSERVED = [this as usize as u32, first, second, third, spec] };
        unsafe { this.add(0x20) }
    }

    #[test]
    fn constructs_members_from_the_base_constructor_result() {
        let _guard = UI_OBJECT_BASE_CONSTRUCT_TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let original = unsafe { UI_OBJECT_BASE_CONSTRUCT_OPS };
        unsafe { UI_OBJECT_BASE_CONSTRUCT_OPS.construct = construct_base };

        let mut storage = [0xa5u8; 0x600];
        let result = unsafe { ui_object_construct(storage.as_mut_ptr(), 1, 2, 3, 0x1000) };
        let base = unsafe { storage.as_mut_ptr().add(0x20) };

        assert_eq!(unsafe { OBSERVED }, [storage.as_ptr() as usize as u32, 1, 2, 3, 0x1000]);
        assert_eq!(result, unsafe { base.add(0x228) });
        assert_eq!(unsafe { (base.add(0x2dc) as *const u32).read() }, 0x0898_c4bc);
        assert_eq!(unsafe { (base.add(0x2e0) as *const u32).read() }, 0x106c);
        assert_eq!(unsafe { (base.add(0x3f4) as *const u32).read() }, 0);
        assert_eq!(unsafe { (base.add(0x4f4) as *const u32).read() }, 0);
        assert_eq!(unsafe { (base.add(0x4f8) as *const u32).read() }, UI_OBJECT_FIRST_MEMBER_VTABLE);
        assert_eq!(unsafe { (base.add(0x510) as *const u32).read() }, UI_OBJECT_SECOND_MEMBER_VTABLE);
        assert_eq!(unsafe { (base.add(0x518) as *const u32).read() }, 1);
        assert_eq!(unsafe { (base.add(0x2ac) as *const u32).read() }, 0);
        unsafe { UI_OBJECT_BASE_CONSTRUCT_OPS = original };
    }
}
