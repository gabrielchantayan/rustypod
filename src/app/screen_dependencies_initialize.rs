//! Initialize a screen's player and class-0x8900 dependencies.
//!
//! Original FUN_080fea98, load address 0x080fea98, true extent
//! 0x080fea98..0x080feaf8 (96 bytes); next entry is mov r0,#0; bx lr.
//! Raw aligned A32 decoding: zero plain and two predicated inbound BLs
//! (0x080feda0, 0x080feebc), seven plain outbound BLs, zero predicated
//! outbound BLs, and one BLX through player vtable +0xec.
//! Cache player, dispatch +0xec, reload player for 0x0817a2cc, cache
//! class 0x8900, save its prID table index, refresh it, reload and apply
//! the saved index, set controller mode halfword +0x80 to 6, then mark
//! screen initialized. No initialized guard here: callers supply it.
//! Deviations: native-pointer repr(C) fields/vtables on hosts; unported
//! player helper uses its verified retail address on ARM and injection
//! on hosts. Existing singleton ports retain their documented constructor
//! limitations. The incidental final r0=1 is not a semantic return value.

use super::class_8900::Class8900;
use super::class_8900_prid_table_index::class_8900_prid_table_index;
use super::class_8900_apply_directory_transition::class_8900_apply_directory_transition;
use super::language_screen_refresh::language_screen_refresh;
use super::singletons::{media_player_get, singleton_class_8900, app_controller_get};

#[repr(C)]
pub struct ScreenDependencies {
    pub prefix: [u32; 0xb0 / 4],
    pub directory: *mut Class8900,
    pub player: *mut u8,
    pub initialized: u8,
}

type Lookup = unsafe extern "C" fn() -> *mut u8;
type PlayerPrepare = unsafe extern "C" fn(*mut u8);
type Index = unsafe extern "C" fn(*const Class8900) -> u32;
type Refresh = unsafe extern "C" fn(*mut u8) -> u32;
type Apply = unsafe extern "C" fn(*mut Class8900, u32);

unsafe extern "C" fn directory_get() -> *mut u8 { singleton_class_8900().cast() }
unsafe extern "C" fn player_get() -> *mut u8 { media_player_get().cast() }
unsafe extern "C" fn controller_get() -> *mut u8 { app_controller_get().cast() }
unsafe extern "C" fn prepare_player(player: *mut u8) {
    #[cfg(target_os = "none")]
    { let call: PlayerPrepare = core::mem::transmute(0x0817_a2ccusize); call(player); }
    #[cfg(not(target_os = "none"))]
    { let _ = player; panic!("install retail player preparation dependency"); }
}

#[derive(Clone, Copy)]
pub struct ScreenDependenciesOps {
    pub player_get: Lookup,
    pub prepare_player: PlayerPrepare,
    pub directory_get: Lookup,
    pub index: Index,
    pub refresh: Refresh,
    pub apply: Apply,
    pub controller_get: Lookup,
}
const DEFAULT_OPS: ScreenDependenciesOps = ScreenDependenciesOps {
    player_get, prepare_player, directory_get, index: class_8900_prid_table_index,
    refresh: language_screen_refresh, apply: class_8900_apply_directory_transition,
    controller_get,
};
#[cfg(not(target_os = "none"))]
pub static mut SCREEN_DEPENDENCIES_OPS: ScreenDependenciesOps = DEFAULT_OPS;

/// # Safety
/// Receiver and singleton objects must be valid for all dependency calls;
/// player vtable +0xec must be callable, controller must cover +0x82.
/// Host operation installation and calls must be externally serialized.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn screen_dependencies_initialize(screen: *mut ScreenDependencies) {
    #[cfg(target_os = "none")]
    let ops = DEFAULT_OPS;
    #[cfg(not(target_os = "none"))]
    let ops = SCREEN_DEPENDENCIES_OPS;
    let player = (ops.player_get)();
    core::ptr::addr_of_mut!((*screen).player).write_volatile(player);
    let vtable = player.cast::<*const usize>().read();
    let dispatch: PlayerPrepare = core::mem::transmute(vtable.add(0xec / 4).read());
    dispatch(player);
    (ops.prepare_player)(core::ptr::addr_of!((*screen).player).read_volatile());
    let directory = (ops.directory_get)().cast::<Class8900>();
    core::ptr::addr_of_mut!((*screen).directory).write_volatile(directory);
    let index = (ops.index)(directory);
    (ops.refresh)(core::ptr::addr_of!((*screen).directory).read_volatile().cast());
    (ops.apply)(core::ptr::addr_of!((*screen).directory).read_volatile(), index);
    (ops.controller_get)().add(0x80).cast::<u16>().write(6);
    (*screen).initialized = 1;
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());
    static mut ACTIVE: *mut Fixture = core::ptr::null_mut();
    struct Fixture {
        screen: ScreenDependencies,
        player: [usize; 2],
        replacement_player: [usize; 2],
        directories: [[u32; 0x380 / 4]; 3],
        controller: [u16; 0xe8 / 2],
        index: u32,
        stage: u32,
    }
    unsafe extern "C" fn get_player() -> *mut u8 {
        let f = &mut *ACTIVE; assert_eq!(f.stage, 0); f.stage = 1;
        f.player.as_mut_ptr().cast()
    }
    unsafe extern "C" fn dispatch(p: *mut u8) {
        let f = &mut *ACTIVE; assert_eq!(f.stage, 1);
        assert_eq!(p, f.player.as_mut_ptr().cast()); assert_eq!(f.screen.player, p);
        f.screen.player = f.replacement_player.as_mut_ptr().cast(); f.stage = 2;
    }
    unsafe extern "C" fn prepare(p: *mut u8) {
        let f = &mut *ACTIVE; assert_eq!(f.stage, 2);
        assert_eq!(p, f.replacement_player.as_mut_ptr().cast()); f.stage = 3;
    }
    unsafe extern "C" fn get_directory() -> *mut u8 {
        let f = &mut *ACTIVE; assert_eq!(f.stage, 3); f.stage = 4;
        f.directories[0].as_mut_ptr().cast()
    }
    unsafe extern "C" fn index(p: *const Class8900) -> u32 {
        let f = &mut *ACTIVE; assert_eq!(f.stage, 4);
        assert_eq!(p, f.directories[0].as_ptr().cast());
        assert_eq!(f.screen.directory.cast::<u32>(), f.directories[0].as_mut_ptr());
        f.screen.directory = f.directories[1].as_mut_ptr().cast(); f.stage = 5; f.index
    }
    unsafe extern "C" fn refresh(p: *mut u8) -> u32 {
        let f = &mut *ACTIVE; assert_eq!(f.stage, 5);
        assert_eq!(p, f.directories[1].as_mut_ptr().cast());
        f.screen.directory = f.directories[2].as_mut_ptr().cast(); f.stage = 6; 0
    }
    unsafe extern "C" fn apply(p: *mut Class8900, i: u32) {
        let f = &mut *ACTIVE; assert_eq!(f.stage, 6);
        assert_eq!(p, f.directories[2].as_mut_ptr().cast()); assert_eq!(i, f.index);
        assert_eq!(f.screen.initialized, 0xa5); f.stage = 7;
    }
    unsafe extern "C" fn get_controller() -> *mut u8 {
        let f = &mut *ACTIVE; assert_eq!(f.stage, 7); f.stage = 8;
        f.controller.as_mut_ptr().cast()
    }
    #[test]
    fn callbacks_reload_fields_preserve_index_and_finish_in_order() {
        let _guard = LOCK.lock();
        unsafe {
            let saved = SCREEN_DEPENDENCIES_OPS;
            SCREEN_DEPENDENCIES_OPS = ScreenDependenciesOps {
                player_get: get_player, prepare_player: prepare, directory_get: get_directory,
                index, refresh, apply, controller_get: get_controller,
            };
            let mut vtable = [0usize; 0xec / 4 + 1];
            vtable[0xec / 4] = dispatch as *const () as usize;
            for value in [0, 20, u32::MAX] {
                let mut f = Fixture {
                    screen: ScreenDependencies { prefix: [0xdeadbeef; 44],
                        directory: core::ptr::null_mut(), player: core::ptr::null_mut(), initialized: 0xa5 },
                    player: [vtable.as_ptr() as usize, 0], replacement_player: [0; 2],
                    directories: [[0; 0x380 / 4]; 3], controller: [0xa5a5; 0xe8 / 2],
                    index: value, stage: 0,
                };
                ACTIVE = &mut f;
                screen_dependencies_initialize(&mut f.screen);
                assert_eq!(f.stage, 8); assert_eq!(f.screen.initialized, 1);
                assert_eq!(f.screen.prefix, [0xdeadbeef; 44]);
                let mut expected = [0xa5a5; 0xe8 / 2]; expected[0x80 / 2] = 6;
                assert_eq!(f.controller, expected);
            }
            SCREEN_DEPENDENCIES_OPS = saved; ACTIVE = core::ptr::null_mut();
        }
    }
}
