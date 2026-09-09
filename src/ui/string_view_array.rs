//! Constructor for the unidentified derived string-view class with a five-
//! element trailing array and a second timer.

use crate::app::resource_chain::ResourceProvider;
#[cfg(target_os = "none")]
use crate::cxx::string_object::string_default_construct;
use crate::cxx::string_object::string_object_assign_cstr;
#[cfg(not(target_os = "none"))]
use crate::cxx::string_object::STRING_OBJECT_VTABLE_ADDRESS;
use crate::drivers::timer::timer_schedule_shim;
use crate::runtime::cpp_array_construct::cpp_array_construct;
use crate::ui::string_view::{string_view_construct, StringView, StringViewSpec};

/// ROM vtable literal loaded from 0x081b3788.
pub const STRING_VIEW_ARRAY_VTABLE_ADDRESS: u32 = 0x0898_b884;
/// Raw element-constructor word passed to the C++ array helper. Ghidra has no
/// function entry at this address, so its identity is deliberately unknown.
const ARRAY_ELEMENT_CONSTRUCTOR_ADDRESS: u32 = 0x081a_87b0;
const ARRAY_ELEMENT_SIZE: u32 = 0x6c;
const ARRAY_ELEMENT_COUNT: u32 = 5;

/// The derived class's 124-byte specification. Its first 104 bytes are the
/// StringView specification forwarded unchanged to the base constructor.
#[repr(C)]
pub struct StringViewArraySpec {
    /// +0x00..+0x68 -- common StringView fields.
    pub view: StringViewSpec,
    /// +0x68 -- copied to the derived object at +0x230.
    pub word_68: u32,
    /// +0x6c -- copied to the derived object at +0x22c.
    pub word_6c: u32,
    /// +0x70 -- reduced by `word_78`, saturating at zero, into +0x234.
    pub word_70: u32,
    /// +0x74 -- copied to the derived object at +0x238.
    pub word_74: u32,
    /// +0x78 -- copied to the derived object at +0x23c and subtracted from
    /// `word_70`.
    pub word_78: u32,
}

/// Layout assembled by the constructor. The words after the StringView base
/// have no recovered semantic names, but their target offsets are fixed by
/// the raw ARM stores.
#[repr(C)]
pub struct StringViewArray {
    /// +0x000..+0x220 -- the StringView base subobject.
    pub view: StringView,
    /// +0x220 -- a two-word StringObject, constructed then assigned "".
    pub empty_string: [u8; 8],
    /// +0x228 -- cleared after assigning the empty string.
    pub word_228: u32,
    /// +0x22c..+0x23c -- copies and clamped difference from the derived spec.
    pub word_22c: u32,
    pub word_230: u32,
    pub word_234: u32,
    pub word_238: u32,
    pub word_23c: u32,
    /// +0x240..+0x244 -- untouched by this constructor.
    pub untouched_240: [u8; 4],
    /// +0x244 -- cleared before constructing the element array.
    pub word_244: u32,
    /// +0x248..+0x464 -- five 0x6c-byte elements, initialized by the
    /// unported array helper through `cpp_array_construct`.
    pub elements: [u8; ARRAY_ELEMENT_SIZE as usize * ARRAY_ELEMENT_COUNT as usize],
    /// +0x464..+0x468 -- untouched by this constructor.
    pub untouched_464: [u8; 4],
    /// +0x468..+0x494 -- the derived embedded timer.
    pub timer: [u8; 0x2c],
    /// +0x494..+0x49c -- allocation tail, untouched by this constructor.
    pub untouched_tail: [u8; 8],
}

const _: [u8; 0x7c] = [0; core::mem::size_of::<StringViewArraySpec>()];
const _: [u8; 0x49c] = [0; core::mem::size_of::<StringViewArray>()];
const _: [u8; 0x220] = [0; core::mem::offset_of!(StringViewArray, empty_string)];
const _: [u8; 0x228] = [0; core::mem::offset_of!(StringViewArray, word_228)];
const _: [u8; 0x22c] = [0; core::mem::offset_of!(StringViewArray, word_22c)];
const _: [u8; 0x248] = [0; core::mem::offset_of!(StringViewArray, elements)];
const _: [u8; 0x468] = [0; core::mem::offset_of!(StringViewArray, timer)];

/// string_view_array_construct — original: `FUN_081b36e0` @ 0x081b36e0
/// (176 bytes: 168 bytes of code through the return at 0x081b3784, plus the
/// two 4-byte literal-pool words at 0x081b3788/0x081b378c; the next function
/// starts at 0x081b3790).
///
/// 17 `bl` call sites, all unconditional; zero predicated forms or tail
/// branches, verified by decoding every B/BL word in osos.dec. It first
/// constructs the embedded StringView from all five caller arguments, replaces
/// its vtable, default-constructs and clears a trailing StringObject, then
/// constructs five 0x6c-byte elements. It copies the five derived-spec words,
/// stores `max(spec.word_70 - spec.word_78, 0)`, clears +0x228/+0x244, builds
/// the timer at +0x468 with this object as its config word, and returns this.
///
/// Deliberate deviations: Ghidra reports `int FUN_081b36e0(void)`, dropping
/// all four register arguments and the stacked specification; raw ARM proves
/// the same five-argument constructor ABI as `string_view_construct`, so this
/// port exposes that ABI and its pointer return. `0x081a87b0` is passed only as
/// a raw C++ element-constructor word to the array helper; it is not a decoded
/// function entry and is intentionally not named as one. On 64-bit hosts, the
/// base StringView's StringObjects and this one require incompatible 8-byte
/// alignments, so this constructor plants the derived StringObject's two
/// target-width words directly; the ARM target calls its ported constructor.
///
/// # Safety
/// `this` must point to writable, 4-byte-aligned [`StringViewArray`] storage;
/// `spec` must point to a readable [`StringViewArraySpec`]. The installed
/// StringView, StringObject, array-helper, and timer operation seams must
/// accept their respective subobject pointers.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn string_view_array_construct(
    this: *mut StringViewArray,
    resources: *mut ResourceProvider,
    controller: *mut u8,
    parent: *mut u8,
    spec: *const StringViewArraySpec,
) -> *mut StringViewArray {
    string_view_construct(
        core::ptr::addr_of_mut!((*this).view),
        resources,
        controller,
        parent,
        spec.cast(),
    );
    core::ptr::addr_of_mut!((*this).view.vtable).write_volatile(STRING_VIEW_ARRAY_VTABLE_ADDRESS);

    let empty_string: *mut u8 = core::ptr::addr_of_mut!((*this).empty_string).cast();
    #[cfg(target_os = "none")]
    string_default_construct(empty_string.cast());
    #[cfg(not(target_os = "none"))]
    {
        empty_string.cast::<u32>().write_volatile(STRING_OBJECT_VTABLE_ADDRESS as u32);
        empty_string.cast::<u32>().add(1).write_volatile(0);
    }
    cpp_array_construct(
        core::ptr::addr_of_mut!((*this).elements).cast(),
        ARRAY_ELEMENT_CONSTRUCTOR_ADDRESS,
        ARRAY_ELEMENT_SIZE,
        ARRAY_ELEMENT_COUNT,
    );

    core::ptr::addr_of_mut!((*this).word_22c).write_volatile((*spec).word_6c);
    core::ptr::addr_of_mut!((*this).word_230).write_volatile((*spec).word_68);
    core::ptr::addr_of_mut!((*this).word_234)
        .write_volatile((*spec).word_70.saturating_sub((*spec).word_78));
    core::ptr::addr_of_mut!((*this).word_238).write_volatile((*spec).word_74);
    core::ptr::addr_of_mut!((*this).word_23c).write_volatile((*spec).word_78);
    string_object_assign_cstr(empty_string.cast(), c"".as_ptr().cast());
    core::ptr::addr_of_mut!((*this).word_228).write_volatile(0);
    core::ptr::addr_of_mut!((*this).word_244).write_volatile(0);
    timer_schedule_shim(
        this as usize as u32,
        core::ptr::addr_of_mut!((*this).timer).cast(),
        0,
        0,
    );
    this
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::cxx::pair_header::{PairHeaderElementArrayOps, PAIR_HEADER_ELEMENT_ARRAY_OPS};
    use crate::cxx::string_object::{
        StringObject, StringObjectAssignCstrOps, STRING_OBJECT_ASSIGN_CSTR_OPS,
    };
    use crate::drivers::timer::{TimerOps, TIMER_OPS};
    use crate::testing::{
        hints, note_missing_u32_fixture, try_map_u32_slab, CPP_ARRAY_OPS_TEST_LOCK,
        STRING_OBJECT_ASSIGN_CSTR_TEST_LOCK, STRING_VIEW_OPS_TEST_LOCK, TIMER_OPS_TEST_LOCK,
    };
    use crate::ui::string_view::{StringViewOps, STRING_VIEW_OPS};
    use core::ptr;
    use std::sync::Mutex;
    use std::vec::Vec;

    const SLAB_LEN: usize = 0x2000;
    const OBJECT_OFFSET: usize = 4;
    const SPEC_OFFSET: usize = 0x800;
    const RESOURCES_OFFSET: usize = 0x1000;
    const CONTROLLER_OFFSET: usize = 0x1100;
    const PARENT_OFFSET: usize = 0x1200;

    struct Fixture {
        object: *mut StringViewArray,
        spec: *const StringViewArraySpec,
        resources: *mut ResourceProvider,
        controller: *mut u8,
        parent: *mut u8,
    }
    fn fixture() -> Option<Fixture> {
        let base = try_map_u32_slab(hints::STRING_VIEW_ARRAY, SLAB_LEN)?;
        unsafe { base.write_bytes(0xa5, SLAB_LEN) };
        Some(Fixture {
            object: unsafe { base.add(OBJECT_OFFSET) }.cast(),
            spec: unsafe { base.add(SPEC_OFFSET) }.cast(),
            resources: unsafe { base.add(RESOURCES_OFFSET) }.cast(),
            controller: unsafe { base.add(CONTROLLER_OFFSET) },
            parent: unsafe { base.add(PARENT_OFFSET) },
        })
    }

    #[derive(Debug, PartialEq, Eq)]
    enum Event {
        ConstructBase(usize, usize, usize, usize, usize),
        ResolveResources(usize, usize, u32),
        ArrayReset(usize, u32, u32, u32, u32),
        ClearString(usize),
        ConstructTimer(usize, u32, u32, usize),
    }

    static EVENTS: Mutex<Vec<Event>> = Mutex::new(Vec::new());

    fn record(event: Event) {
        EVENTS
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .push(event);
    }

    unsafe extern "C" fn record_construct_base(
        view: *mut StringView,
        resources: *mut ResourceProvider,
        controller: *mut u8,
        parent: *mut u8,
        spec: *const StringViewSpec,
    ) -> *mut StringView {
        record(Event::ConstructBase(
            view as usize,
            resources as usize,
            controller as usize,
            parent as usize,
            spec as usize,
        ));
        view
    }

    unsafe extern "C" fn record_resolve_resources(
        view: *mut StringView,
        spec: *const StringViewSpec,
        flags: u32,
    ) {
        record(Event::ResolveResources(view as usize, spec as usize, flags));
    }

    unsafe extern "C" fn record_array_reset(
        array: *mut u32,
        field_count: u32,
        field_size: u32,
        _allocation_header_bytes: u32,
        _initializer_argument: u32,
        element_initializer: u32,
        initializer_context: u32,
        _allocator_callback: u32,
        _allocator_context: u32,
        _allocation_flags: u32,
        _zero_initialize: u32,
    ) -> *mut u32 {
        record(Event::ArrayReset(
            array as usize,
            field_count,
            field_size,
            element_initializer,
            initializer_context,
        ));
        array
    }

    unsafe extern "C" fn record_clear_string(this: *mut StringObject) {
        record(Event::ClearString(this as usize));
    }

    unsafe extern "C" fn record_construct_timer(
        timer: *mut u8,
        init_arg: u32,
        config_word: u32,
        callback_handle: usize,
    ) {
        record(Event::ConstructTimer(
            timer as usize,
            init_arg,
            config_word,
            callback_handle,
        ));
    }

    struct OpsRestore {
        string_view: StringViewOps,
        array: PairHeaderElementArrayOps,
        string: StringObjectAssignCstrOps,
        timer: TimerOps,
    }

    impl Drop for OpsRestore {
        fn drop(&mut self) {
            unsafe {
                ptr::addr_of_mut!(STRING_VIEW_OPS).write_volatile(self.string_view);
                ptr::addr_of_mut!(PAIR_HEADER_ELEMENT_ARRAY_OPS).write_volatile(self.array);
                ptr::addr_of_mut!(STRING_OBJECT_ASSIGN_CSTR_OPS).write_volatile(self.string);
                ptr::addr_of_mut!(TIMER_OPS).write_volatile(self.timer);
            }
        }
    }

    unsafe fn install_recorders() -> OpsRestore {
        let string_view = ptr::addr_of!(STRING_VIEW_OPS).read_volatile();
        let array = ptr::addr_of!(PAIR_HEADER_ELEMENT_ARRAY_OPS).read_volatile();
        let string = ptr::addr_of!(STRING_OBJECT_ASSIGN_CSTR_OPS).read_volatile();
        let timer = ptr::addr_of!(TIMER_OPS).read_volatile();
        let mut recorded_timer = timer;
        recorded_timer.construct_timer = record_construct_timer;
        ptr::addr_of_mut!(STRING_VIEW_OPS).write_volatile(StringViewOps {
            construct_base: record_construct_base,
            clear_resource_ref: string_view.clear_resource_ref,
            resolve_resources: record_resolve_resources,
        });
        ptr::addr_of_mut!(PAIR_HEADER_ELEMENT_ARRAY_OPS).write_volatile(PairHeaderElementArrayOps {
            reset: record_array_reset,
        });
        ptr::addr_of_mut!(STRING_OBJECT_ASSIGN_CSTR_OPS).write_volatile(StringObjectAssignCstrOps {
            allocate_payload: string.allocate_payload,
            clear_payload: record_clear_string,
        });
        ptr::addr_of_mut!(TIMER_OPS).write_volatile(recorded_timer);
        OpsRestore {
            string_view,
            array,
            string,
            timer,
        }
    }

    fn word(object: *mut StringViewArray, offset: usize) -> u32 {
        unsafe { (object.cast::<u8>().add(offset) as *const u32).read() }
    }

    #[test]
    fn constructs_derived_members_and_saturates_the_spec_difference() {
        let _string_view_lock = STRING_VIEW_OPS_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let _array_lock = CPP_ARRAY_OPS_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let _string_lock = STRING_OBJECT_ASSIGN_CSTR_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let _timer_lock = TIMER_OPS_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let Some(fixture) = fixture() else {
            assert!(note_missing_u32_fixture("ui::string_view_array"));
            return;
        };
        unsafe {
            let spec = fixture.spec.cast_mut();
            (*spec).word_68 = 0x1111_2222;
            (*spec).word_6c = 0x3333_4444;
            (*spec).word_70 = 7;
            (*spec).word_74 = 0x5555_6666;
            (*spec).word_78 = 9;
        }
        let _restore = unsafe { install_recorders() };
        EVENTS
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .clear();

        let result = unsafe {
            string_view_array_construct(
                fixture.object,
                fixture.resources,
                fixture.controller,
                fixture.parent,
                fixture.spec,
            )
        };

        let object = fixture.object as usize;
        assert_eq!(result, fixture.object);
        assert_eq!(word(fixture.object, 0), STRING_VIEW_ARRAY_VTABLE_ADDRESS);
        assert_eq!(word(fixture.object, 0x228), 0);
        assert_eq!(word(fixture.object, 0x22c), 0x3333_4444);
        assert_eq!(word(fixture.object, 0x230), 0x1111_2222);
        assert_eq!(word(fixture.object, 0x234), 0, "underflow saturates");
        assert_eq!(word(fixture.object, 0x238), 0x5555_6666);
        assert_eq!(word(fixture.object, 0x23c), 9);
        assert_eq!(word(fixture.object, 0x244), 0);
        assert_eq!(word(fixture.object, 0x240), 0xa5a5_a5a5, "untouched gap");
        assert_eq!(word(fixture.object, 0x464), 0xa5a5_a5a5, "untouched timer gap");
        assert_eq!(word(fixture.object, 0x494), 0xa5a5_a5a5, "untouched allocation tail");
        assert_eq!(
            *EVENTS.lock().unwrap_or_else(|poison| poison.into_inner()),
            std::vec![
                Event::ConstructBase(
                    object,
                    fixture.resources as usize,
                    fixture.controller as usize,
                    fixture.parent as usize,
                    fixture.spec as usize,
                ),
                Event::ArrayReset(object + 0x154, 4, 0x14, 0x0828_3a74, 0),
                Event::ResolveResources(object, fixture.spec as usize, 0),
                Event::ConstructTimer(object + 0x1f4, 0, object as u32, 0),
                Event::ArrayReset(object + 0x248, 5, 0x6c, 0x081a_87b0, 0),
                Event::ClearString(object + 0x220),
                Event::ConstructTimer(object + 0x468, 0, object as u32, 0),
            ],
            "base construction precedes the derived string, array, and timer",
        );
    }
}
