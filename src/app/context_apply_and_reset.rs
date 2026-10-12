//! Apply the subject scope, conditionally invoke the player, and reset cached results.
//!
//! Original FUN_08044e38 @ 0x08044e38; true extent [0x08044e38,0x08044eb8),
//! 128 bytes, followed by an independent PUSH. Whole-image aligned A32 decoding
//! finds two incoming plain BLs (0x08065cf0, 0x08115214), zero predicated BLs.
//! The body has six plain BLs, zero predicated BLs, one BLX and one BLXNE.
//! Fetch the player before constructing a 20-byte scope for owner+0xf40 with
//! flag zero. Apply the scope; query player slot +0x1b8 and, for any nonzero
//! result, reload its vtable and invoke slot +0xec. Clear cached results,
//! dispatch the selected resource, reload owner+0xf00, set context+0xb92 to
//! one, destroy the scope, and return zero. Ignore all helper return values.
//!
//! Deviations: native pointer fields on hosts retain target offsets on ARM;
//! vtable offsets are target word indices. Host-only operation replacement
//! isolates firmware boundaries. The empty scope destructor may be elided by
//! LLVM. No identity is guessed for either virtual method.

use core::{mem::MaybeUninit, ptr};

#[repr(C)]
pub struct ContextResetOwner {
    pub prefix: [u32; 0xf00 / 4],
    pub context: *mut u8,
    pub intervening_words: [u32; (0xf40 - 0xf04) / 4],
    pub subject: *mut u8,
}

type Get = unsafe extern "C" fn() -> *mut u8;
type Init = unsafe extern "C" fn(*mut u8, *mut u8, u8) -> *mut u8;
type ScopeOperation = unsafe extern "C" fn(*mut u8) -> i32;
type Clear = unsafe extern "C" fn(*mut u8);
type Dispatch = unsafe extern "C" fn(*mut u8) -> i32;
type DropScope = unsafe extern "C" fn(*mut u8) -> *mut u8;
type Query = unsafe extern "C" fn(*mut u8) -> u32;
type PlayerOperation = unsafe extern "C" fn(*mut u8);

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct HostOps {
    pub get: Get,
    pub init: Init,
    pub apply: ScopeOperation,
    pub clear: Clear,
    pub dispatch: Dispatch,
    pub drop_scope: DropScope,
}
#[cfg(not(target_os = "none"))]
static mut HOST_OPS: HostOps = HostOps {
    get: crate::app::singletons::media_player_get,
    init: super::context_scope::context_scope_init,
    apply: super::context_scope_apply_subject::context_scope_apply_subject,
    clear: crate::util::inner_state::inner_clear_cached_results,
    dispatch: crate::util::inner_state::inner_dispatch_selected_resource,
    drop_scope: super::context_scope::context_scope_drop,
};

/// # Safety
/// Serialize installation with every call; operations must obey the retail ABI
/// and accept the owner and the aligned 20-byte scope supplied to them.
#[cfg(not(target_os = "none"))]
pub unsafe fn set_host_ops(ops: HostOps) {
    ptr::addr_of_mut!(HOST_OPS).write(ops);
}

/// # Safety
/// Owner fields, context through +0xb92, and player vtable slots 110 and 59
/// must be valid. All called operations must accept their supplied objects.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn context_apply_and_reset(owner: *mut ContextResetOwner) -> u32 {
    #[cfg(not(target_os = "none"))]
    let HostOps { get, init, apply, clear, dispatch, drop_scope } = ptr::addr_of!(HOST_OPS).read();
    #[cfg(target_os = "none")]
    let (get, init, apply, clear, dispatch, drop_scope): (Get, Init, ScopeOperation, Clear, Dispatch, DropScope) = (
        crate::app::singletons::media_player_get,
        super::context_scope::context_scope_init,
        super::context_scope_apply_subject::context_scope_apply_subject,
        crate::util::inner_state::inner_clear_cached_results,
        crate::util::inner_state::inner_dispatch_selected_resource,
        super::context_scope::context_scope_drop,
    );
    let player = get();
    let mut scope = MaybeUninit::<[u32; 5]>::uninit();
    let scope = scope.as_mut_ptr().cast::<u8>();
    init(scope, ptr::addr_of!((*owner).subject).read(), 0);
    apply(scope);
    let table = player.cast::<*const usize>().read();
    let query: Query = core::mem::transmute(table.add(0x1b8 / 4).read());
    if query(player) != 0 {
        let table = player.cast::<*const usize>().read();
        let operation: PlayerOperation = core::mem::transmute(table.add(0xec / 4).read());
        operation(player);
    }
    clear(owner.cast());
    dispatch(owner.cast());
    let context = ptr::addr_of!((*owner).context).read();
    context.add(0xb92).write(1);
    drop_scope(scope);
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());
    #[repr(C)]
    struct Player { table: *const usize, replacement: *const usize, query: u32, calls: u32 }
    static mut PLAYER: *mut Player = ptr::null_mut();
    static mut NEXT_CONTEXT: *mut u8 = ptr::null_mut();
    unsafe extern "C" fn get() -> *mut u8 { PLAYER.cast() }
    unsafe extern "C" fn init(scope: *mut u8, subject: *mut u8, flag: u8) -> *mut u8 {
        assert_eq!(flag, 0);
        scope.cast::<u32>().write(subject.cast::<u32>().read());
        scope
    }
    unsafe extern "C" fn apply(scope: *mut u8) -> i32 {
        (*PLAYER).query = scope.cast::<u32>().read();
        -7
    }
    unsafe extern "C" fn query(player: *mut u8) -> u32 {
        let player = &mut *player.cast::<Player>();
        player.table = player.replacement;
        player.query
    }
    unsafe extern "C" fn invoke(player: *mut u8) { (*player.cast::<Player>()).calls += 1; }
    unsafe extern "C" fn clear(owner: *mut u8) { (*owner.cast::<ContextResetOwner>()).prefix[0] = 0; }
    unsafe extern "C" fn dispatch(owner: *mut u8) -> i32 {
        let owner = &mut *owner.cast::<ContextResetOwner>();
        assert_eq!(owner.prefix[0], 0);
        owner.context = NEXT_CONTEXT;
        -50
    }
    unsafe extern "C" fn drop_scope(scope: *mut u8) -> *mut u8 {
        assert_eq!(NEXT_CONTEXT.add(0xb92).read(), 1);
        scope
    }

    #[test]
    fn nonzero_query_uses_reloaded_vtable_and_late_context_despite_helper_errors() {
        let _guard = LOCK.lock();
        unsafe {
            let saved = ptr::addr_of!(HOST_OPS).read();
            set_host_ops(HostOps { get, init, apply, clear, dispatch, drop_scope });
            let mut initial = [0usize; 111];
            let mut replacement = [0usize; 111];
            initial[110] = query as Query as usize;
            // Slot 59 in the old table is invalid: the query replaces it.
            replacement[59] = invoke as PlayerOperation as usize;
            let mut player = Player { table: initial.as_ptr(), replacement: replacement.as_ptr(), query: 0, calls: 0 };
            PLAYER = &mut player;
            for mut result in [0u32, 1, 0x8000_0000, u32::MAX] {
                let mut old_context = [0xa5u8; 0xb94];
                let mut new_context = [0x5au8; 0xb94];
                NEXT_CONTEXT = new_context.as_mut_ptr();
                let mut owner = ContextResetOwner {
                    prefix: [0xffff_ffff; 0xf00 / 4], context: old_context.as_mut_ptr(),
                    intervening_words: [0; (0xf40 - 0xf04) / 4], subject: ptr::addr_of_mut!(result).cast(),
                };
                player.table = initial.as_ptr();
                let previous = player.calls;
                assert_eq!(context_apply_and_reset(&mut owner), 0);
                assert_eq!(player.calls - previous, u32::from(result != 0));
                assert_eq!(owner.prefix[0], 0);
                assert!(owner.prefix[1..].iter().all(|&word| word == u32::MAX));
                assert!(old_context.iter().all(|&byte| byte == 0xa5));
                assert_eq!(&new_context[0xb91..0xb94], &[0x5a, 1, 0x5a]);
            }
            set_host_ops(saved);
            PLAYER = ptr::null_mut();
            NEXT_CONTEXT = ptr::null_mut();
        }
    }
}
