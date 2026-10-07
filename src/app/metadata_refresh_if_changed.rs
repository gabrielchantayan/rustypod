//! `metadata_refresh_if_changed` — retailOS `FUN_08162058` at `0x08162058`.
//! True extent: 84 bytes, [0x08162058, 0x081620ac); next entry pushes r4-r6/lr.
//! Raw aligned decoding verifies two plain outbound BLs, zero predicated BLs,
//! and two virtual BLX sites. Whole-image decoding finds two plain inbound
//! BLs (0x080441d4, 0x081620c4), zero predicated inbound BLs.
//!
//! Call virtual slot 0; preserve any nonzero result. On success, compare the
//! current header with the cached metadata via 0x08161d10. If changed, rebuild
//! the header via 0x08161b28, reload the vtable, call slot 1, and return its
//! result unchanged. Equal metadata returns zero without rebuilding.
//!
//! Deliberate deviations: no target behavior changes. Verified, unported
//! comparison/rebuild helpers remain retail calls, named only for their role.
//! Host pointers widen via repr(C); host helper seams must be installed before
//! use and otherwise panic rather than silently omitting retail side effects.
//! Codegen review: LLVM uses BLX for the two fixed retail addresses and
//! tail-enters the reloaded commit method with BX; this preserves its result.

pub type MetadataMethod = unsafe extern "C" fn(*mut MetadataObject) -> u32;

#[repr(C)]
pub struct MetadataVtable {
    pub prepare: MetadataMethod,
    pub commit: MetadataMethod,
}

#[repr(C)]
pub struct MetadataObject {
    pub vtable: *const MetadataVtable,
}

#[derive(Clone, Copy)]
pub struct MetadataRefreshOps {
    pub differs: MetadataMethod,
    pub rebuild: unsafe extern "C" fn(*mut MetadataObject),
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_comparison(_: *mut MetadataObject) -> u32 {
    panic!("install metadata comparison seam before host use")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_rebuild(_: *mut MetadataObject) {
    panic!("install metadata rebuild seam before host use")
}

/// Host replacement for the verified retail metadata helper boundaries.
#[cfg(not(target_os = "none"))]
pub static mut METADATA_REFRESH_OPS: MetadataRefreshOps = MetadataRefreshOps {
    differs: missing_comparison,
    rebuild: missing_rebuild,
};

#[inline(always)]
unsafe fn operations() -> MetadataRefreshOps {
    #[cfg(target_os = "none")]
    { MetadataRefreshOps {
        differs: core::mem::transmute(0x0816_1d10usize),
        rebuild: core::mem::transmute(0x0816_1b28usize),
    } }
    #[cfg(not(target_os = "none"))]
    { core::ptr::read(core::ptr::addr_of!(METADATA_REFRESH_OPS)) }
}

/// Refreshes changed metadata after a successful virtual preparation.
///
/// # Safety
/// `object` must be a complete live retail object accepted by both helpers
/// and both virtual methods. All vtables must be valid; no NULL checks are
/// added. Host callers must serialize installation/use of the helper seams.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn metadata_refresh_if_changed(object: *mut MetadataObject) -> u32 {
    let result = ((*(*object).vtable).prepare)(object);
    if result != 0 {
        return result;
    }
    let ops = operations();
    if (ops.differs)(object) == 0 {
        return 0;
    }
    (ops.rebuild)(object);
    ((*(*object).vtable).commit)(object)
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());

    #[repr(C)]
    struct Fixture {
        object: MetadataObject,
        prepare_result: u32,
        current: u32,
        cached: u32,
        committed: u32,
        comparisons: u32,
        rebuilds: u32,
        commits: u32,
        commit_result: u32,
    }
    unsafe extern "C" fn prepare(object: *mut MetadataObject) -> u32 {
        (*(object.cast::<Fixture>())).prepare_result
    }
    unsafe extern "C" fn differs(object: *mut MetadataObject) -> u32 {
        let state = &mut *object.cast::<Fixture>();
        state.comparisons += 1;
        (state.current != state.cached) as u32
    }
    unsafe extern "C" fn rebuild(object: *mut MetadataObject) {
        let state = &mut *object.cast::<Fixture>();
        state.rebuilds += 1;
        state.current = state.cached;
        state.object.vtable = &REBUILT;
    }
    unsafe extern "C" fn stale_commit(_: *mut MetadataObject) -> u32 {
        panic!("must reload vtable after rebuilding")
    }
    unsafe extern "C" fn commit(object: *mut MetadataObject) -> u32 {
        let state = &mut *object.cast::<Fixture>();
        state.commits += 1;
        state.committed = state.current;
        state.commit_result
    }
    static INITIAL: MetadataVtable = MetadataVtable { prepare, commit: stale_commit };
    static REBUILT: MetadataVtable = MetadataVtable { prepare, commit };

    #[test]
    fn errors_and_equal_metadata_do_not_commit_and_changed_metadata_reloads_vtable() {
        let _guard = LOCK.lock();
        unsafe {
            let saved = METADATA_REFRESH_OPS;
            METADATA_REFRESH_OPS = MetadataRefreshOps { differs, rebuild };
            for error in [0, 1, 0x8000_0000, u32::MAX] {
                for changed in [false, true] {
                    let mut state = Fixture {
                        object: MetadataObject { vtable: &INITIAL },
                        prepare_result: error, current: 17,
                        cached: if changed { 29 } else { 17 }, committed: 99,
                        comparisons: 0, rebuilds: 0, commits: 0,
                        commit_result: 0x8000_0007,
                    };
                    let refresh = error == 0 && changed;
                    assert_eq!(metadata_refresh_if_changed(&mut state.object),
                        if refresh { 0x8000_0007 } else { error });
                    assert_eq!(state.comparisons, (error == 0) as u32);
                    assert_eq!(state.rebuilds, refresh as u32);
                    assert_eq!(state.commits, refresh as u32);
                    assert_eq!(state.current, if refresh { 29 } else { 17 });
                    assert_eq!(state.committed, if refresh { 29 } else { 99 });
                }
            }
            METADATA_REFRESH_OPS = saved;
        }
    }
}
