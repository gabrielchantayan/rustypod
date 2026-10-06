//! Reset controller declaration resources — retail `FUN_0818361c` at
//! 0x0818361c, 232 bytes (0x0818361c..0x08183704), including three literals.
//! Binary scan: two plain inbound BL calls (0x081dded4, 0x081ddf68), zero
//! predicated calls; the body contains eight unconditional BL instructions.
//! Constructs a 92-byte temporary event source using controller word +0x28,
//! traverses the vector selected by byte +0xcd with a signed count comparison,
//! resolves each declaration's +4 key, and stops on the first NULL result.
//! Applies tags 0x564c7974, 0x56536c74, 0x56437673 in order, reloading controller
//! word +0x20 before each application, then always destroys the temporary.
//! Deliberate deviations: LLVM chooses the stack/register layout; the unported
//! resource application at 0x081827d8 uses a typed retail-address call. The
//! caller's unused r1 is not an argument. No guards or initialization added.

use super::event_source::{event_source_construct, event_source_destruct};
use super::fallback_keyed_object::{primary_or_demo_mode_keyed_object, FallbackKeyedObjectContext};
use super::opaque_keyed_collection_item_at::opaque_keyed_collection_item_at;
use super::opaque_keyed_collection_item_count::opaque_keyed_collection_item_count;

const RESOURCE_TAGS: [u32; 3] = [0x564c_7974, 0x5653_6c74, 0x5643_7673];
type ApplyResource = unsafe extern "C" fn(*mut u8, u32, *mut u8, *const u32, u32, u32) -> u32;

#[cfg(target_os = "none")]
unsafe extern "C" fn apply_resource(
    controller: *mut u8, resource: u32, object: *mut u8,
    declaration: *const u32, tag: u32, mode: u32,
) -> u32 {
    let apply: ApplyResource = core::mem::transmute(0x0818_27d8usize);
    apply(controller, resource, object, declaration, tag, mode)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn apply_resource(
    _: *mut u8, _: u32, _: *mut u8, _: *const u32, _: u32, _: u32,
) -> u32 {
    panic!("controller_declaration_resources_reset requires retail 0x081827d8")
}

#[derive(Clone, Copy)]
struct ResetOps {
    construct: unsafe extern "C" fn(*mut u8, i32, u8, u32) -> *mut u8,
    count: unsafe extern "C" fn(*const u8, u32) -> u32,
    item: unsafe extern "C" fn(*const u8, u32, u32) -> u32,
    resolve: unsafe extern "C" fn(*mut FallbackKeyedObjectContext, u32, *mut u8) -> *mut u8,
    apply: ApplyResource,
    destruct: unsafe extern "C" fn(*mut u8) -> *mut u8,
}

/// # Safety
/// `controller` must be a live retail controller, including its +0x38 resolver,
/// +0xcd selector byte, and +0x20/+0x28 resource words. Selected declarations
/// and the framework services must satisfy the original callees' contracts.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn controller_declaration_resources_reset(controller: *mut u8) {
    reset_with_ops(controller, ResetOps {
        construct: event_source_construct,
        count: opaque_keyed_collection_item_count,
        item: opaque_keyed_collection_item_at,
        resolve: primary_or_demo_mode_keyed_object,
        apply: apply_resource,
        destruct: event_source_destruct,
    });
}

#[inline(always)]
unsafe fn reset_with_ops(controller: *mut u8, ops: ResetOps) {
    let mut storage = core::mem::MaybeUninit::<[u32; 23]>::uninit();
    let source = storage.as_mut_ptr().cast::<u8>();
    (ops.construct)(source, controller.add(0x28).cast::<i32>().read(), 0, 0);
    let mut index = 0u32;
    while ((ops.count)(source, controller.add(0xcd).read() as u32) as i32) > index as i32 {
        let declaration = (ops.item)(source, controller.add(0xcd).read() as u32, index)
            as usize as *const u32;
        let object = (ops.resolve)(controller.cast(), declaration.add(1).read(), core::ptr::null_mut());
        if object.is_null() {
            break;
        }
        for tag in RESOURCE_TAGS {
            (ops.apply)(controller, controller.add(0x20).cast::<u32>().read(), object, declaration, tag, 0);
        }
        index = index.wrapping_add(1);
    }
    (ops.destruct)(source);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use parking_lot::Mutex;

    struct State {
        count: i32,
        missing: u32,
        declaration: u32,
        keys: std::vec::Vec<u32>,
        applied: std::vec::Vec<(u32, u32)>,
        destroyed: bool,
    }
    static STATE: Mutex<State> = Mutex::new(State {
        count: 0, missing: u32::MAX, declaration: 0,
        keys: std::vec::Vec::new(), applied: std::vec::Vec::new(), destroyed: false,
    });
    unsafe extern "C" fn construct(source: *mut u8, _: i32, _: u8, _: u32) -> *mut u8 {
        source.cast::<u32>().write(0x1234);
        source
    }
    unsafe extern "C" fn count(_: *const u8, _: u32) -> u32 { STATE.lock().count as u32 }
    unsafe extern "C" fn item(_: *const u8, _: u32, index: u32) -> u32 {
        let state = STATE.lock();
        let declaration = state.declaration as usize as *mut u32;
        declaration.add(1).write(index);
        state.declaration
    }
    unsafe extern "C" fn resolve(_: *mut FallbackKeyedObjectContext, key: u32, _: *mut u8) -> *mut u8 {
        let mut state = STATE.lock();
        state.keys.push(key);
        if key == state.missing { core::ptr::null_mut() } else { core::ptr::NonNull::<u8>::dangling().as_ptr() }
    }
    unsafe extern "C" fn apply(controller: *mut u8, resource: u32, _: *mut u8, _: *const u32, tag: u32, _: u32) -> u32 {
        STATE.lock().applied.push((resource, tag));
        controller.add(0x20).cast::<u32>().write(resource + 1);
        0 // A zero resource-application result must not stop traversal.
    }
    unsafe extern "C" fn destruct(source: *mut u8) -> *mut u8 {
        assert_eq!(source.cast::<u32>().read(), 0x1234);
        STATE.lock().destroyed = true;
        source
    }

    #[test]
    fn signed_counts_first_miss_and_resource_reload() {
        let Some(slab) = crate::testing::try_map_u32_slab(crate::testing::hints::CONTROLLER_DECLARATION_RESET, 4096) else { return; };
        let declaration = slab as usize as u32;
        for (count_value, missing, expected_keys, expected_tags) in [
            (0, u32::MAX, 0, 0), (-1, u32::MAX, 0, 0),
            (3, 0, 1, 0), (3, 1, 2, 3), (2, u32::MAX, 2, 6),
        ] {
            *STATE.lock() = State {
                count: count_value, missing, declaration, keys: std::vec::Vec::new(),
                applied: std::vec::Vec::new(), destroyed: false,
            };
            let mut controller = [0u32; 52];
            controller[8] = 10;
            unsafe { reset_with_ops(controller.as_mut_ptr().cast(), ResetOps { construct, count, item, resolve, apply, destruct }); }
            let state = STATE.lock();
            assert_eq!(state.keys, (0..expected_keys).collect::<std::vec::Vec<_>>());
            assert_eq!(state.applied, (0..expected_tags).map(|i| (10 + i, RESOURCE_TAGS[i as usize % 3])).collect::<std::vec::Vec<_>>());
            assert!(state.destroyed);
        }

        // Callees can change both the selector and the selected vector's size.
        // A cached selector or loop bound would visit a second declaration.
        unsafe extern "C" fn changing_count(_: *const u8, selector: u32) -> u32 {
            if STATE.lock().keys.is_empty() {
                assert_eq!(selector, 0);
                3
            } else {
                assert_eq!(selector, 0x80);
                1
            }
        }
        unsafe extern "C" fn changing_apply(
            controller: *mut u8, resource: u32, object: *mut u8,
            declaration: *const u32, tag: u32, mode: u32,
        ) -> u32 {
            controller.add(0xcd).write(0x80);
            apply(controller, resource, object, declaration, tag, mode)
        }
        *STATE.lock() = State {
            count: 3, missing: u32::MAX, declaration, keys: std::vec::Vec::new(),
            applied: std::vec::Vec::new(), destroyed: false,
        };
        let mut controller = [0u32; 52];
        controller[8] = 10;
        unsafe {
            reset_with_ops(controller.as_mut_ptr().cast(), ResetOps {
                construct, count: changing_count, item, resolve,
                apply: changing_apply, destruct,
            });
        }
        let state = STATE.lock();
        assert_eq!(state.keys, [0]);
        assert_eq!(state.applied, [(10, RESOURCE_TAGS[0]), (11, RESOURCE_TAGS[1]), (12, RESOURCE_TAGS[2])]);
        assert!(state.destroyed);
    }
}
