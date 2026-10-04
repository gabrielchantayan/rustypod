//! Refresh before navigating to the language screen.
//!
//! Original: `FUN_081ebf1c` at load address `0x081ebf1c`. True extent:
//! `0x081ebf1c..0x081ebf58` (60 bytes: 56 instruction bytes and the
//! `0x089ca674` global-slot literal). The next function starts with a push.
//! Whole-image aligned A32 decoding verifies two inbound plain BLs at
//! `0x080fead0` and `0x0821c2f8`, zero predicated inbound BLs, four outbound
//! plain BLs, zero predicated outbound BLs, and one `bx r1` virtual tail call.
//!
//! Refresh the context loaded from the global slot, update the screen's two
//! item groups in order, obtain TMediaNowPlayingCntlr, then dispatch its
//! vtable slot +0xd4. Both item-group helper results are ignored, including
//! zero (their no-matching-view result). The language-navigation caller is
//! `FUN_0821c2d4`; `FUN_080fea98` also calls this during screen setup.
//!
//! Deliberate deviations: the three unported helpers retain verified-address
//! seams, not guessed class identities. Host builds inject these dependencies
//! and use native-width vtable pointers. Rust expresses the virtual tail call
//! as a returned call and preserves its r0 result, which Ghidra labels void.

const CONTROLLER_REFRESH_SLOT: usize = 0xd4 / 4;
type ContextRefresh = unsafe extern "C" fn(*mut u8);
type GroupRefresh = unsafe extern "C" fn(*mut u8) -> u32;
type ControllerLookup = unsafe extern "C" fn() -> *mut u8;
type ControllerRefresh = unsafe extern "C" fn(*mut u8) -> u32;

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct LanguageScreenRefreshOps {
    pub context: *mut u8,
    pub refresh_context: ContextRefresh,
    pub refresh_first_group: GroupRefresh,
    pub refresh_second_group: GroupRefresh,
    pub controller: ControllerLookup,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_context(_: *mut u8) { panic!("install language refresh context dependency") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_group(_: *mut u8) -> u32 { panic!("install language refresh group dependency") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_controller() -> *mut u8 { panic!("install language refresh controller dependency") }
#[cfg(not(target_os = "none"))]
pub static mut LANGUAGE_SCREEN_REFRESH_OPS: LanguageScreenRefreshOps = LanguageScreenRefreshOps {
    context: core::ptr::null_mut(),
    refresh_context: missing_context,
    refresh_first_group: missing_group,
    refresh_second_group: missing_group,
    controller: missing_controller,
};

/// Refreshes the language-screen dependencies and returns the controller's
/// virtual refresh result unchanged.
///
/// # Safety
/// `screen` and the global context must satisfy the retail helpers' layouts.
/// The singleton must be nonnull with a callable +0xd4 vtable slot. Host
/// dependency installation must be serialized against every caller.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn language_screen_refresh(screen: *mut u8) -> u32 {
    #[cfg(target_os = "none")]
    let controller = {
        let refresh_context: ContextRefresh = core::mem::transmute(0x0811_2f18usize);
        let first_group: GroupRefresh = core::mem::transmute(0x081e_b0f4usize);
        let second_group: GroupRefresh = core::mem::transmute(0x081e_b204usize);
        refresh_context((0x089c_a674 as *const *mut u8).read_volatile());
        first_group(screen);
        second_group(screen);
        crate::app::registry::instance_of_class_3280()
    };
    #[cfg(not(target_os = "none"))]
    let controller = {
        let ops = LANGUAGE_SCREEN_REFRESH_OPS;
        (ops.refresh_context)(ops.context);
        (ops.refresh_first_group)(screen);
        (ops.refresh_second_group)(screen);
        (ops.controller)()
    };
    let vtable = controller.cast::<*const usize>().read();
    let refresh: ControllerRefresh = core::mem::transmute(vtable.add(CONTROLLER_REFRESH_SLOT).read());
    refresh(controller)
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut ACTIVE: *mut Fixture = core::ptr::null_mut();

    #[repr(C)]
    struct Fixture {
        vtable: *const usize,
        context_generation: u32,
        first_generation: u32,
        second_generation: u32,
        controller_generation: u32,
        group_result: u32,
        result: u32,
    }

    unsafe extern "C" fn context(p: *mut u8) {
        let f = &mut *p.cast::<Fixture>();
        f.context_generation = f.context_generation.wrapping_add(1);
    }
    unsafe extern "C" fn first(p: *mut u8) -> u32 {
        let f = &mut *p.cast::<Fixture>();
        f.first_generation = f.context_generation;
        f.group_result
    }
    unsafe extern "C" fn second(p: *mut u8) -> u32 {
        let f = &mut *p.cast::<Fixture>();
        f.second_generation = f.first_generation;
        !f.group_result
    }
    unsafe extern "C" fn lookup() -> *mut u8 { ACTIVE.cast() }
    unsafe extern "C" fn finish(p: *mut u8) -> u32 {
        let f = &mut *p.cast::<Fixture>();
        f.controller_generation = f.second_generation;
        f.result
    }
    unsafe extern "C" fn wrong_slot(_: *mut u8) -> u32 { panic!("wrong controller vtable slot") }

    #[test]
    fn refreshes_all_generations_even_when_group_has_no_view() {
        let _lock = LOCK.lock();
        let mut vtable = [wrong_slot as usize; CONTROLLER_REFRESH_SLOT + 2];
        vtable[CONTROLLER_REFRESH_SLOT] = finish as usize;
        unsafe {
            let saved = LANGUAGE_SCREEN_REFRESH_OPS;
            for group_result in [0, 1, u32::MAX] {
                for result in [0, 0x8000_0000, u32::MAX] {
                    let mut f = Fixture {
                        vtable: vtable.as_ptr(), context_generation: u32::MAX,
                        first_generation: 3, second_generation: 4,
                        controller_generation: 5, group_result, result,
                    };
                    ACTIVE = &mut f;
                    LANGUAGE_SCREEN_REFRESH_OPS = LanguageScreenRefreshOps {
                        context: ACTIVE.cast(), refresh_context: context,
                        refresh_first_group: first, refresh_second_group: second,
                        controller: lookup,
                    };
                    assert_eq!(language_screen_refresh(ACTIVE.cast()), result);
                    assert_eq!((f.context_generation, f.first_generation, f.second_generation, f.controller_generation), (0, 0, 0, 0));
                    assert_eq!(language_screen_refresh(ACTIVE.cast()), result);
                    assert_eq!((f.context_generation, f.first_generation, f.second_generation, f.controller_generation), (1, 1, 1, 1));
                }
            }
            LANGUAGE_SCREEN_REFRESH_OPS = saved;
            ACTIVE = core::ptr::null_mut();
        }
    }
}
