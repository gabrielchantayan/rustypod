//! `silver_controller_transition_addon_destroy` — original:
//! `FUN_08278f60` @ 0x08278f60 (52 bytes: 48 code bytes plus the
//! 4-byte derived-class literal-pool word at 0x08278f94; 55 `bl` call
//! sites, binary-scanned).
//!
//! Source: `ipod-decomp/decomp/c/026/08278f60_FUN_08278f60.c`.
//!
//! The plain destructor of retailOS's as-yet-unidentified Silver-controller
//! transition-addon class. Its evidence-based name comes from the base-class
//! descriptor planted at +0 by the base constructor/destructor: the literal
//! 0x0898994c begins `TSilverCntlrTransitionAddon...`; the derived vtable
//! literal is 0x089a60bc. The paired constructor @ 0x08278e8c and all sampled
//! call sites establish the object as a scoped C++ object, not a deleting
//! destructor: callers construct it in caller-owned storage and later invoke
//! this function without an operator-delete call.
//!
//! Decoded from the raw ARM, rather than Ghidra's folded tail call:
//!
//! ```text
//! 08278f60: push {r4,lr}
//! 08278f64: mov  r4,r0
//! 08278f68: ldr  r0,[0x8278f94]       ; 0x089a60bc, derived vtable
//! 08278f6c: str  r0,[r4]
//! 08278f70: mov  r0,r4
//! 08278f74: bl   0x08278894           ; derived cleanup
//! 08278f78: add  r0,r4,#0x40
//! 08278f7c: bl   0x08278190           ; embedded vector destructor
//! 08278f80: sub  r0,r0,#0x34          ; its result -> StringObject +0x0c
//! 08278f84: bl   0x082792fc           ; string_object_destroy veneer
//! 08278f88: pop  {r4,lr}
//! 08278f8c: sub  r0,r0,#0x0c          ; StringObject result -> this
//! 08278f90: b    0x0818a0fc           ; base destructor tail call
//! ```
//!
//! The tail target @ 0x0818a0fc installs the base descriptor/vtable
//! 0x0898994c, then calls `FUN_081e1fe8(this[1] + 0x24, this)` and returns
//! `this`. Ghidra inlines that target into `FUN_08278f60`, which is why its
//! decompile appears to contain both stores and the final call. This port
//! makes that tail body explicit: it preserves the true dataflow through the
//! embedded vector destructor's return (`-0x34`) and the StringObject
//! destructor's return (`-0x0c`) before running the base teardown.
//!
//! Layout evidence from the paired constructor @ 0x08278e8c: a base
//! transition-addon subobject begins at +0x00; its owner pointer is +0x04;
//! the embedded [`StringObject`] begins at +0x0c; and the vector-like member
//! begins at +0x40 (its begin/end/capacity words are +0x48/+0x4c/+0x50).
//! `FUN_08278190` walks and releases that member's elements, returning its
//! argument. `FUN_08278894` performs derived cleanup before either member is
//! destroyed.
//!
//! Deviation: derived cleanup, vector destruction, and base deregistration
//! remain unported, so they cross [`TRANSITION_ADDON_DESTROY_OPS`] dispatch
//! slots. The vector default faithfully returns its argument but performs no
//! element destruction; the other defaults are no-ops. Consequently this
//! function is **not hook-ready** until those three callees are ported and
//! wired in. The raw target uses 32-bit words; raw object slots here use
//! pointer-sized unaligned reads/writes so the 32-bit offsets remain distinct
//! and testable on a 64-bit host (the crate's face-word model).

use super::string_object::{string_object_destroy_veneer, StringObject};
use crate::app::facade_for_selector::facade_for_selector;
use crate::app::path_probe::InterfaceGuard;
use crate::heap::block_deque::deque_seg_capacity;

/// Literal-pool word at 0x08278f94, installed before derived cleanup.
pub const TRANSITION_ADDON_VTABLE_ADDRESS: usize = 0x089a_60bc;
/// Literal-pool word at 0x0818a124, installed by the base destructor.
pub const TRANSITION_ADDON_BASE_VTABLE_ADDRESS: usize = 0x0898_994c;

/// Byte offset of the owner pointer in the base transition-addon subobject.
pub const TRANSITION_ADDON_OWNER_OFFSET: usize = 0x04;
/// Byte offset of the embedded [`StringObject`] member.
pub const TRANSITION_ADDON_STRING_OFFSET: usize = 0x0c;
/// Byte offset of the vector-like member destroyed first.
pub const TRANSITION_ADDON_VECTOR_OFFSET: usize = 0x40;
/// The vector destructor result is this many bytes after the StringObject.
pub const VECTOR_RESULT_TO_STRING_OFFSET: usize = 0x34;
/// The StringObject destructor result is this many bytes after the outer object.
pub const STRING_RESULT_TO_OBJECT_OFFSET: usize = 0x0c;
/// The base destructor passes its owner's +0x24 member to deregistration.
pub const TRANSITION_ADDON_OWNER_MEMBER_OFFSET: usize = 0x24;

/// Literal-pool word at 0x082792c8 (= 0x089a60d8), planted at the embedded
/// string member's +0x00 by the member-construction veneer @ 0x082792b4 on
/// top of the StringObject copy constructor's own vtable — the derived
/// string member's class vtable, 0x1c bytes above the derived object vtable
/// in the image.
pub const TRANSITION_ADDON_STRING_MEMBER_VTABLE_ADDRESS: u32 = 0x089a_60d8;

/// +0x14 — byte receiving the constructor's raw `flag` argument (the base
/// subobject's +0x09 byte receives the same flag inverted).
pub const TRANSITION_ADDON_MODE_FLAG_OFFSET: usize = 0x14;
/// +0x18 — word initialized to the `0xffff_ffff` invalid sentinel.
pub const TRANSITION_ADDON_INVALID_WORD_OFFSET: usize = 0x18;
/// +0x20 — word zeroed at construction.
pub const TRANSITION_ADDON_ZEROED_WORD_OFFSET: usize = 0x20;
/// +0x24 — owner capacity word, the result of the 0x08296efc query on the
/// owner/interface word at +0x04.
pub const TRANSITION_ADDON_CAPACITY_OFFSET: usize = 0x24;
/// +0x28 — context word (the constructor's third stack argument), stored
/// before and consulted by the quantum and scale helpers.
pub const TRANSITION_ADDON_CONTEXT_OFFSET: usize = 0x28;
/// +0x2c — transfer-quantum word, the result of the 0x08277b64 helper.
pub const TRANSITION_ADDON_QUANTUM_OFFSET: usize = 0x2c;
/// +0x30 — scale-class word, the result of the 0x08277bd0 helper.
pub const TRANSITION_ADDON_SCALE_CLASS_OFFSET: usize = 0x30;
/// +0x34 — second word zeroed at construction.
pub const TRANSITION_ADDON_SECOND_ZEROED_WORD_OFFSET: usize = 0x34;
/// +0x38 — byte copied from the selected facade's +0x09 byte.
pub const TRANSITION_ADDON_FACADE_BYTE_OFFSET: usize = 0x38;
/// +0x3c — word receiving the 0x081a81bc alignment constant (0x20).
pub const TRANSITION_ADDON_ALIGNMENT_OFFSET: usize = 0x3c;

#[inline(always)]
unsafe fn read_u32_unaligned(address: *const u8) -> u32 {
    (address as *const u32).read_unaligned()
}

#[inline(always)]
unsafe fn write_u32_unaligned(address: *mut u8, value: u32) {
    (address as *mut u32).write_unaligned(value);
}

#[inline(always)]
unsafe fn read_word_unaligned(address: *const u8) -> usize {
    (address as *const usize).read_unaligned()
}

#[inline(always)]
unsafe fn write_word_unaligned(address: *mut u8, value: usize) {
    (address as *mut usize).write_unaligned(value);
}

/// Dispatch boundaries for the three unported calls in
/// [`silver_controller_transition_addon_destroy`].
#[derive(Clone, Copy)]
pub struct TransitionAddonDestroyOps {
    /// `FUN_08278894`: releases the derived class's own state before member
    /// destructors run; its return value is ignored by the caller.
    pub derived_cleanup: unsafe extern "C" fn(this: *mut u8),
    /// `FUN_08278190`: destroys the vector-like member at `this+0x40` and
    /// returns that member pointer. The caller derives the StringObject
    /// address from this *returned* pointer, not from its entry `this`.
    pub vector_destroy: unsafe extern "C" fn(member: *mut u8) -> *mut u8,
    /// `FUN_081e1fe8`, reached by the base destructor @ 0x0818a0fc with the
    /// owner's +0x24 member and the outer transition-addon object.
    pub base_deregister: unsafe extern "C" fn(owner_member: *mut u8, this: *mut u8),
}

unsafe extern "C" fn derived_cleanup_unported(_this: *mut u8) {}

/// The fully decoded vector destructor returns its entry pointer; its element
/// destruction is not yet available, so the default preserves just that
/// caller-visible return convention.
unsafe extern "C" fn vector_destroy_unported(member: *mut u8) -> *mut u8 {
    member
}

unsafe extern "C" fn base_deregister_unported(_owner_member: *mut u8, _this: *mut u8) {}

/// Wired defaults for the unresolved teardown boundaries.
pub const DEFAULT_TRANSITION_ADDON_DESTROY_OPS: TransitionAddonDestroyOps =
    TransitionAddonDestroyOps {
        derived_cleanup: derived_cleanup_unported,
        vector_destroy: vector_destroy_unported,
        base_deregister: base_deregister_unported,
    };

/// Active teardown boundaries. Host tests replace these slots with recording
/// mocks; future callee ports replace the defaults without changing this
/// destructor's offset/dataflow contract.
pub static mut TRANSITION_ADDON_DESTROY_OPS: TransitionAddonDestroyOps =
    DEFAULT_TRANSITION_ADDON_DESTROY_OPS;

#[inline(always)]
unsafe fn derived_cleanup_op() -> unsafe extern "C" fn(*mut u8) {
    core::ptr::read_volatile(core::ptr::addr_of!(
        TRANSITION_ADDON_DESTROY_OPS.derived_cleanup
    ))
}

#[inline(always)]
unsafe fn vector_destroy_op() -> unsafe extern "C" fn(*mut u8) -> *mut u8 {
    core::ptr::read_volatile(core::ptr::addr_of!(
        TRANSITION_ADDON_DESTROY_OPS.vector_destroy
    ))
}

#[inline(always)]
unsafe fn base_deregister_op() -> unsafe extern "C" fn(*mut u8, *mut u8) {
    core::ptr::read_volatile(core::ptr::addr_of!(
        TRANSITION_ADDON_DESTROY_OPS.base_deregister
    ))
}

/// silver_controller_transition_addon_destroy — original: `FUN_08278f60` @
/// 0x08278f60 (52 bytes; 55 `bl` call sites).
///
/// Plain destructor for a caller-owned Silver-controller transition addon.
/// Installs the derived vtable, performs derived cleanup, destroys the
/// vector-like member at +0x40, then derives and destroys the `StringObject`
/// member from that destructor chain's returns. It finally runs the base
/// destructor body: installs the base vtable and deregisters `this` through
/// the owner's +0x24 member. Returns the recovered `this` pointer. There is
/// no NULL guard, matching every unconditional object access in the ARM.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn silver_controller_transition_addon_destroy(
    this: *mut u8,
) -> *mut u8 {
    write_u32_unaligned(this, TRANSITION_ADDON_VTABLE_ADDRESS as u32);
    derived_cleanup_op()(this);

    let vector = vector_destroy_op()(this.add(TRANSITION_ADDON_VECTOR_OFFSET));
    let string = vector
        .sub(VECTOR_RESULT_TO_STRING_OFFSET)
        .cast::<StringObject>();
    let string = string_object_destroy_veneer(string).cast::<u8>();
    let this = string.sub(STRING_RESULT_TO_OBJECT_OFFSET);

    write_u32_unaligned(this, TRANSITION_ADDON_BASE_VTABLE_ADDRESS as u32);
    let owner = read_word_unaligned(this.add(TRANSITION_ADDON_OWNER_OFFSET)) as *mut u8;
    base_deregister_op()(owner.add(TRANSITION_ADDON_OWNER_MEMBER_OFFSET), this);
    this
}

/// Dispatch boundaries for the seven unresolved calls in
/// [`silver_controller_transition_addon_construct`]. Two more callees are
/// already ported and called directly: the facade accessor 0x0818a0bc
/// ([`facade_for_selector`]) and the alignment query 0x081a81bc (a
/// byte-identical copy of [`deque_seg_capacity`], which the 0x083d9fc0
/// ledger entry sanctions hooking any copy to).
#[derive(Clone, Copy)]
pub struct TransitionAddonConstructOps {
    /// `FUN_0818a0c4`: the base transition-addon constructor. Plants the
    /// base vtable 0x0898994c at +0x00, resolves the interface word at
    /// +0x04 through the guard accessor 0x0818a06c (which forwards `hint`
    /// to the resolver 0x0814a130), zeroes the +0x08 byte and stores the
    /// inverted flag at +0x09. Returns `this`.
    pub base_construct: unsafe extern "C" fn(this: *mut u8, hint: u32, flag: u32) -> *mut u8,
    /// `FUN_082792b4`: the embedded string member's construction veneer —
    /// chains to the StringObject copy constructor @ 0x082773e0 on
    /// `member` with `source`, then plants the derived string vtable
    /// 0x089a60d8 at the returned member's +0x00. Returns the member.
    pub string_member_construct: unsafe extern "C" fn(
        member: *mut u8,
        source: *const u8,
    ) -> *mut u8,
    /// `FUN_08296efc`: reads the owner's +0x04 interface word; NULL yields
    /// 0x200, otherwise the interface vtable slot +0x2c is called. The
    /// caller-visible boundary takes the owner word stored at this+0x04.
    pub owner_capacity_query: unsafe extern "C" fn(owner: *mut u8) -> u32,
    /// `FUN_08277b64`: the transfer-quantum helper. Reads the context word
    /// at this+0x28 (already stored) and the capacity word at this+0x24,
    /// optionally re-queries the context through 0x081a8198, clamps against
    /// 0x40000, and returns a capacity-rounded quantum through 0x08036f14.
    pub transfer_quantum: unsafe extern "C" fn(this: *mut u8, arg: u32) -> u32,
    /// `FUN_08277bd0`: the scale-class helper. Fully decoded and
    /// self-contained: with a NULL context word at this+0x28 and
    /// `arg - 1 < 16` (unsigned) it returns `arg`, otherwise 1.
    pub scale_class: unsafe extern "C" fn(this: *mut u8, arg: u32) -> u32,
    /// `FUN_08278104`: the vector-like member constructor at this+0x40.
    /// Stores the owner pointer at member+0x00, zeroes the words at
    /// +0x04/+0x08/+0x0c/+0x10 (the begin/end/capacity triple is
    /// +0x08/+0x0c/+0x10), then runs an operator_new(24) node-fill loop
    /// through the node constructor 0x08277e2c. Returns the member.
    pub vector_member_construct: unsafe extern "C" fn(
        member: *mut u8,
        owner: *mut u8,
    ) -> *mut u8,
    /// `FUN_08278250`: the registration/open step. Guarded by 0x0818a144,
    /// it probes the owner through 0x0829d0b4, records a failure status at
    /// this+0x1c, and consults the +0x14 mode flag and the owner's +0x18
    /// byte; its result is discarded by the constructor.
    pub register_with_owner: unsafe extern "C" fn(this: *mut u8),
}

/// Default for the unresolved base constructor @ 0x0818a0c4: reproduces
/// every store of the decoded body in the original's order — base vtable
/// at +0x00, interface word at +0x04, zero byte at +0x08, flag byte at
/// +0x09 — with the unresolved interface-resolution chain (0x0818a06c →
/// 0x0814a130 → 0x081e1f64) modeled as a zero word. Returns `this`, the
/// ADS constructor convention.
unsafe extern "C" fn base_construct_unported(this: *mut u8, _hint: u32, flag: u32) -> *mut u8 {
    write_u32_unaligned(this, TRANSITION_ADDON_BASE_VTABLE_ADDRESS as u32);
    write_u32_unaligned(this.add(TRANSITION_ADDON_OWNER_OFFSET), 0);
    *this.add(0x08) = 0;
    *this.add(0x09) = flag as u8;
    this
}

/// Default for the unresolved string-member veneer @ 0x082792b4: the
/// empty-construction prefix (the string_object.rs
/// `STRING_OBJECT_COPY_CONSTRUCT` stub precedent) — derived string vtable
/// at +0x00, NULL payload word at +0x04, `source` ignored — returning the
/// member so the caller's return-minus-offset dataflow holds.
unsafe extern "C" fn string_member_construct_unported(
    member: *mut u8,
    _source: *const u8,
) -> *mut u8 {
    write_u32_unaligned(member, TRANSITION_ADDON_STRING_MEMBER_VTABLE_ADDRESS);
    write_u32_unaligned(member.add(4), 0);
    member
}

/// Default for the unresolved owner capacity query @ 0x08296efc: the
/// decoded body's own `moveq r0, #0x200` fallback for a NULL interface
/// word, reproduced without dereferencing the owner (the default base
/// boundary models an unresolved interface, so there is nothing valid to
/// dispatch on). The live-interface vtable slot +0x2c call is not
/// reproduced.
unsafe extern "C" fn owner_capacity_query_unported(_owner: *mut u8) -> u32 {
    0x200
}

/// Default for the unresolved transfer-quantum helper @ 0x08277b64: inert
/// zero. The decoded body entangles two more unported callees (the
/// align-up query 0x081a8198 and the divider 0x08036f14), so no faithful
/// partial behavior is available.
unsafe extern "C" fn transfer_quantum_unported(_this: *mut u8, _arg: u32) -> u32 {
    0
}

/// The scale-class helper @ 0x08277bd0 is fully decoded and self-contained
/// (six instructions, no calls): `ldr r0,[r0,#0x28]; cmp r0,#0; bne +0x1c`;
/// on the NULL-context path `sub r0,r1,#1; cmp r0,#16; movcc r0,r1;
/// bxcc lr`; the common tail is `mov r0,#1`. The default is the faithful
/// body, not a stub.
unsafe extern "C" fn scale_class_body(this: *mut u8, arg: u32) -> u32 {
    if read_u32_unaligned(this.add(TRANSITION_ADDON_CONTEXT_OFFSET)) == 0
        && arg.wrapping_sub(1) < 16
    {
        arg
    } else {
        1
    }
}

/// Default for the unresolved vector-member constructor @ 0x08278104:
/// reproduces the decoded prologue — owner word at +0x00, zeroed words at
/// +0x04/+0x08/+0x0c/+0x10 — and omits the operator_new(24) node-fill
/// loop, whose node constructor 0x08277e2c is unported. Returns `member`.
/// All stores are 32-bit like the original's; on a 64-bit host the owner
/// word keeps the pointer's low half only.
unsafe extern "C" fn vector_member_construct_unported(
    member: *mut u8,
    owner: *mut u8,
) -> *mut u8 {
    write_u32_unaligned(member, owner as u32);
    write_u32_unaligned(member.add(4), 0);
    write_u32_unaligned(member.add(8), 0);
    write_u32_unaligned(member.add(12), 0);
    write_u32_unaligned(member.add(16), 0);
    member
}

/// Default for the unresolved registration step @ 0x08278250: inert. Its
/// observable side effects (status word at this+0x1c, trace calls) are not
/// reproduced.
unsafe extern "C" fn register_with_owner_unported(_this: *mut u8) {}

/// Wired defaults for the unresolved construction boundaries.
pub const DEFAULT_TRANSITION_ADDON_CONSTRUCT_OPS: TransitionAddonConstructOps =
    TransitionAddonConstructOps {
        base_construct: base_construct_unported,
        string_member_construct: string_member_construct_unported,
        owner_capacity_query: owner_capacity_query_unported,
        transfer_quantum: transfer_quantum_unported,
        scale_class: scale_class_body,
        vector_member_construct: vector_member_construct_unported,
        register_with_owner: register_with_owner_unported,
    };

/// Active construction boundaries. Host tests replace these slots with
/// recording mocks; future callee ports replace the defaults without
/// changing this constructor's offset/dataflow contract.
pub static mut TRANSITION_ADDON_CONSTRUCT_OPS: TransitionAddonConstructOps =
    DEFAULT_TRANSITION_ADDON_CONSTRUCT_OPS;

#[inline(always)]
unsafe fn base_construct_op() -> unsafe extern "C" fn(*mut u8, u32, u32) -> *mut u8 {
    core::ptr::read_volatile(core::ptr::addr_of!(
        TRANSITION_ADDON_CONSTRUCT_OPS.base_construct
    ))
}

#[inline(always)]
unsafe fn string_member_construct_op() -> unsafe extern "C" fn(*mut u8, *const u8) -> *mut u8 {
    core::ptr::read_volatile(core::ptr::addr_of!(
        TRANSITION_ADDON_CONSTRUCT_OPS.string_member_construct
    ))
}

#[inline(always)]
unsafe fn owner_capacity_query_op() -> unsafe extern "C" fn(*mut u8) -> u32 {
    core::ptr::read_volatile(core::ptr::addr_of!(
        TRANSITION_ADDON_CONSTRUCT_OPS.owner_capacity_query
    ))
}

#[inline(always)]
unsafe fn transfer_quantum_op() -> unsafe extern "C" fn(*mut u8, u32) -> u32 {
    core::ptr::read_volatile(core::ptr::addr_of!(
        TRANSITION_ADDON_CONSTRUCT_OPS.transfer_quantum
    ))
}

#[inline(always)]
unsafe fn scale_class_op() -> unsafe extern "C" fn(*mut u8, u32) -> u32 {
    core::ptr::read_volatile(core::ptr::addr_of!(
        TRANSITION_ADDON_CONSTRUCT_OPS.scale_class
    ))
}

#[inline(always)]
unsafe fn vector_member_construct_op() -> unsafe extern "C" fn(*mut u8, *mut u8) -> *mut u8 {
    core::ptr::read_volatile(core::ptr::addr_of!(
        TRANSITION_ADDON_CONSTRUCT_OPS.vector_member_construct
    ))
}

#[inline(always)]
unsafe fn register_with_owner_op() -> unsafe extern "C" fn(*mut u8) {
    core::ptr::read_volatile(core::ptr::addr_of!(
        TRANSITION_ADDON_CONSTRUCT_OPS.register_with_owner
    ))
}

/// silver_controller_transition_addon_construct — original: `FUN_08278e8c`
/// @ 0x08278e8c (184 code bytes plus the 4-byte literal-pool word at
/// 0x08278f44 = 0x089a60bc, binary-verified against osos.dec; the next
/// function starts at 0x08278f48. **31 `bl` call sites**, binary-scanned
/// by decoding every B/BL word in osos.dec — all plain `bl`, no predicated
/// forms and no tail `b`: 0x08047508, 0x0804fec0, 0x08058928, 0x080fe2e4,
/// 0x080ff974, 0x08104380, 0x08104660, 0x08104754, 0x08119dec, 0x0813a578,
/// 0x0813a5c0, 0x0813aca4, 0x0813ad00, 0x08149504, 0x08149d34, 0x0814c470,
/// 0x0815abfc, 0x081b1d4c, 0x081e1ec4, 0x08210348, 0x08264b64, 0x08264d54,
/// 0x08265860, 0x0826c630, 0x0826c73c, 0x0827eff4, 0x0827f04c, 0x0827f824,
/// 0x0827fbc0, 0x0828fb00 and 0x082c7180).
///
/// The seven-argument derived constructor of this module's
/// Silver-controller transition-addon class ([`silver_controller_transition_addon_destroy`]
/// is the paired teardown): four register arguments plus three stack
/// arguments lifted by `ldm r8,{r6,r7,r8}` after `add r8,sp,#24`. The
/// caller owns the storage (the ft/system.rs vtable_set call site allocates
/// 0x54 bytes — matching the +0x50 capacity word of the vector member —
/// and stashes the constructed object at its record+0x30).
///
/// Sequence, decoded from the raw ARM:
///
/// ```text
/// base     = base_construct(this, base_hint, flag ^ 1)   // 0x0818a0c4
/// base[0]  = 0x089a60bc                                  // derived vtable
/// string   = string_member_construct(base + 0x0c, source)// 0x082792b4
/// string[8]  as byte = flag                              // +0x14 mode flag
/// this'    = string - 0x0c
/// this'[0x18] = 0xffffffff;  this'[0x20] = 0
/// this'[0x24] = owner_capacity_query(this'[0x04])        // 0x08296efc
/// this'[0x28] = context                       // stored BEFORE the helpers
/// this'[0x2c] = transfer_quantum(this', quantum_arg)     // 0x08277b64
/// this'[0x30] = scale_class(this', scale_arg)            // 0x08277bd0
/// this'[0x34] = 0
/// this'[0x38] as byte = facade_for_selector(this', 1)[9] // 0x0818a0bc
/// this'[0x3c] = alignment query 0x081a81bc               // = 0x20
/// vector   = vector_member_construct(this' + 0x40, this')// 0x08278104
/// this''   = vector - 0x40
/// register_with_owner(this'')                            // 0x08278250
/// return this''
/// ```
///
/// Every intermediate object address derives from the previous callee's
/// RETURN, never from the entry `this` — the base constructor's, string
/// veneer's and vector constructor's returns are all threaded (`sub r4,
/// r0, #12` and `sub r4, r0, #64` in the original). The base hint reaches
/// the interface resolver 0x0814a130 through the base constructor's guard
/// accessor 0x0818a06c (r1 is live there); its semantics are unresolved.
///
/// Deviations: the seven unresolved callees cross
/// [`TRANSITION_ADDON_CONSTRUCT_OPS`] dispatch slots — see each default's
/// documentation; the scale-class default is the faithful decoded body,
/// the base/string/vector defaults reproduce their decoded stores, the
/// capacity default reproduces the NULL-interface 0x200 fallback, and the
/// quantum/registration defaults are inert. The two already-ported callees
/// are called directly: [`facade_for_selector`] (its `ldr r0,[r0,#4]`
/// reads the owner/interface word this constructor just stored) and
/// [`deque_seg_capacity`], the byte-identical ported body of the 0x081a81bc
/// alignment query. Consequently this constructor is **not hook-ready**
/// until the five non-faithful boundaries are ported and wired in. All
/// object stores are 32-bit like the original's `str`s; on a 64-bit host
/// pointer-valued words keep their low half (no host fixture needs the
/// full width — the recording mocks receive `this` directly).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn silver_controller_transition_addon_construct(
    this: *mut u8,
    source: *const u8,
    flag: u32,
    base_hint: u32,
    quantum_arg: u32,
    scale_arg: u32,
    context: u32,
) -> *mut u8 {
    let base = base_construct_op()(this, base_hint, flag ^ 1);
    write_u32_unaligned(base, TRANSITION_ADDON_VTABLE_ADDRESS as u32);

    let string = string_member_construct_op()(
        base.add(TRANSITION_ADDON_STRING_OFFSET),
        source,
    );
    *string.add(8) = flag as u8;
    let this = string.sub(TRANSITION_ADDON_STRING_OFFSET);

    write_u32_unaligned(this.add(TRANSITION_ADDON_INVALID_WORD_OFFSET), 0xffff_ffff);
    write_u32_unaligned(this.add(TRANSITION_ADDON_ZEROED_WORD_OFFSET), 0);

    let owner = read_u32_unaligned(this.add(TRANSITION_ADDON_OWNER_OFFSET)) as *mut u8;
    let capacity = owner_capacity_query_op()(owner);
    write_u32_unaligned(this.add(TRANSITION_ADDON_CAPACITY_OFFSET), capacity);

    write_u32_unaligned(this.add(TRANSITION_ADDON_CONTEXT_OFFSET), context);
    let quantum = transfer_quantum_op()(this, quantum_arg);
    write_u32_unaligned(this.add(TRANSITION_ADDON_QUANTUM_OFFSET), quantum);

    let scale = scale_class_op()(this, scale_arg);
    write_u32_unaligned(this.add(TRANSITION_ADDON_SCALE_CLASS_OFFSET), scale);
    write_u32_unaligned(this.add(TRANSITION_ADDON_SECOND_ZEROED_WORD_OFFSET), 0);

    let facade = facade_for_selector(this as *mut InterfaceGuard, 1);
    *this.add(TRANSITION_ADDON_FACADE_BYTE_OFFSET) = *(facade as *const u8).add(9);

    let alignment = deque_seg_capacity() as u32;
    write_u32_unaligned(this.add(TRANSITION_ADDON_ALIGNMENT_OFFSET), alignment);

    let vector = vector_member_construct_op()(
        this.add(TRANSITION_ADDON_VECTOR_OFFSET),
        this,
    );
    let this = vector.sub(TRANSITION_ADDON_VECTOR_OFFSET);
    register_with_owner_op()(this);
    this
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::{sync::{Mutex, MutexGuard}, vec, vec::Vec};

    static DESTROY_OPS_LOCK: Mutex<()> = Mutex::new(());

    #[derive(Clone, Debug, Eq, PartialEq)]
    enum Call {
        Derived { this: usize, vtable: usize },
        Vector { member: usize },
        Deregister { owner_member: usize, this: usize },
    }

    static mut CALLS: Vec<Call> = Vec::new();
    static mut VECTOR_RETURN: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn recording_derived_cleanup(this: *mut u8) {
        (*core::ptr::addr_of_mut!(CALLS)).push(Call::Derived {
            this: this as usize,
            vtable: read_u32_unaligned(this) as usize,
        });
    }

    unsafe extern "C" fn recording_vector_destroy(member: *mut u8) -> *mut u8 {
        (*core::ptr::addr_of_mut!(CALLS)).push(Call::Vector {
            member: member as usize,
        });
        core::ptr::read_volatile(core::ptr::addr_of!(VECTOR_RETURN))
    }

    unsafe extern "C" fn recording_base_deregister(owner_member: *mut u8, this: *mut u8) {
        (*core::ptr::addr_of_mut!(CALLS)).push(Call::Deregister {
            owner_member: owner_member as usize,
            this: this as usize,
        });
    }

    struct DestroyOpsGuard {
        _lock: MutexGuard<'static, ()>,
    }

    impl Drop for DestroyOpsGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(TRANSITION_ADDON_DESTROY_OPS)
                    .write_volatile(DEFAULT_TRANSITION_ADDON_DESTROY_OPS);
            }
        }
    }

    fn install_recorders(vector_return: *mut u8) -> DestroyOpsGuard {
        let lock = DESTROY_OPS_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        unsafe {
            (*core::ptr::addr_of_mut!(CALLS)).clear();
            core::ptr::addr_of_mut!(VECTOR_RETURN).write(vector_return);
            core::ptr::addr_of_mut!(TRANSITION_ADDON_DESTROY_OPS).write_volatile(
                TransitionAddonDestroyOps {
                    derived_cleanup: recording_derived_cleanup,
                    vector_destroy: recording_vector_destroy,
                    base_deregister: recording_base_deregister,
                },
            );
        }
        DestroyOpsGuard { _lock: lock }
    }

    fn calls() -> Vec<Call> {
        unsafe { (*core::ptr::addr_of!(CALLS)).clone() }
    }

    #[repr(align(8))]
    struct Object([u8; 0x100]);

    #[test]
    fn destroy_routes_all_offsets_and_vtable_transitions_through_callee_returns() {
        let mut object = Object([0; 0x100]);
        let this = object.0.as_mut_ptr();

        // The vector mock returns a deliberately shifted member pointer. The
        // final result therefore proves both original container-of steps:
        // vector result - 0x34 -> StringObject, then string result - 0x0c
        // -> outer object. Keeping that StringObject 8-aligned also gives the
        // real, already-ported StringObject destructor a valid host object.
        let vector_return = unsafe { this.add(0x74) };
        let expected_string = unsafe { vector_return.sub(VECTOR_RESULT_TO_STRING_OFFSET) };
        let expected_this = unsafe { expected_string.sub(STRING_RESULT_TO_OBJECT_OFFSET) };
        let owner = 0x1234_5000usize as *mut u8;
        unsafe {
            write_word_unaligned(expected_this.add(TRANSITION_ADDON_OWNER_OFFSET), owner as usize);
        }
        let _guard = install_recorders(vector_return);

        let returned = unsafe { silver_controller_transition_addon_destroy(this) };

        assert_eq!(returned, expected_this);
        assert_eq!(
            calls(),
            vec![
                Call::Derived {
                    this: this as usize,
                    vtable: TRANSITION_ADDON_VTABLE_ADDRESS,
                },
                Call::Vector {
                    member: unsafe { this.add(TRANSITION_ADDON_VECTOR_OFFSET) } as usize,
                },
                Call::Deregister {
                    owner_member: unsafe { owner.add(TRANSITION_ADDON_OWNER_MEMBER_OFFSET) } as usize,
                    this: expected_this as usize,
                },
            ]
        );
        assert_eq!(
            unsafe { read_u32_unaligned(expected_this) as usize },
            TRANSITION_ADDON_BASE_VTABLE_ADDRESS,
            "the tail base destructor replaces the derived vtable"
        );
        assert_eq!(
            unsafe { read_word_unaligned(expected_string) },
            &super::super::string_object::STRING_OBJECT_VTABLE as *const _ as usize,
            "the direct StringObject veneer received vector_return - 0x34"
        );
    }

    #[test]
    fn default_unported_boundaries_preserve_the_destructor_dataflow() {
        let mut object = Object([0xa5; 0x100]);
        // With the default vector-return stub, string = this+0x0c. Offset the
        // host fixture by four bytes so that the embedded pointer-sized object
        // is naturally aligned on the 64-bit test host while retaining every
        // target byte offset.
        let this = unsafe { object.0.as_mut_ptr().add(4) };
        let owner = 0x7654_3000usize as *mut u8;
        unsafe {
            write_word_unaligned(this.add(TRANSITION_ADDON_OWNER_OFFSET), owner as usize);
            // The already-ported StringObject destructor reaches this host
            // payload field at string+8; make it NULL so no heap boundary is
            // intentionally exercised by this default-seam test.
            write_word_unaligned(this.add(TRANSITION_ADDON_STRING_OFFSET + 8), 0);
        }

        let returned = unsafe { silver_controller_transition_addon_destroy(this) };

        assert_eq!(returned, this);
        assert_eq!(
            unsafe { read_u32_unaligned(this) as usize },
            TRANSITION_ADDON_BASE_VTABLE_ADDRESS
        );
        assert_eq!(
            unsafe { read_word_unaligned(this.add(TRANSITION_ADDON_STRING_OFFSET)) },
            &super::super::string_object::STRING_OBJECT_VTABLE as *const _ as usize
        );
    }

    use crate::app::facade_for_selector::{tests::FACADE_TEST_LOCK, FACADE_REGISTRY_WALK};
    use crate::app::facade_registry_walk::{facade_registry_walk, RegistryFacade, RegistryNode};

    static CONSTRUCT_OPS_LOCK: Mutex<()> = Mutex::new(());

    #[derive(Clone, Debug, Eq, PartialEq)]
    enum ConstructCall {
        Base { this: usize, hint: u32, flag: u32, prior_vtable: u32 },
        StringMember { member: usize, source: usize },
        Capacity { owner: u32 },
        Quantum { this: usize, arg: u32, context_at_call: u32 },
        Scale { this: usize, arg: u32 },
        Walk { selector: u32 },
        Vector { member: usize, owner: usize },
        Register { this: usize },
    }

    static mut CONSTRUCT_CALLS: Vec<ConstructCall> = Vec::new();
    static mut STRING_RETURN_SHIFT: usize = 0;
    static mut VECTOR_RETURN_SHIFT: usize = 0;
    static mut FAKE_FACADE: [u8; 16] = [0; 16];

    unsafe extern "C" fn recording_base_construct(
        this: *mut u8,
        hint: u32,
        flag: u32,
    ) -> *mut u8 {
        (*core::ptr::addr_of_mut!(CONSTRUCT_CALLS)).push(ConstructCall::Base {
            this: this as usize,
            hint,
            flag,
            // The constructor plants the derived vtable only after this
            // boundary returns, so the recorder still sees the pre-fill.
            prior_vtable: read_u32_unaligned(this),
        });
        this
    }

    unsafe extern "C" fn recording_string_member_construct(
        member: *mut u8,
        source: *const u8,
    ) -> *mut u8 {
        (*core::ptr::addr_of_mut!(CONSTRUCT_CALLS)).push(ConstructCall::StringMember {
            member: member as usize,
            source: source as usize,
        });
        member.add(core::ptr::read_volatile(core::ptr::addr_of!(STRING_RETURN_SHIFT)))
    }

    unsafe extern "C" fn recording_owner_capacity_query(owner: *mut u8) -> u32 {
        (*core::ptr::addr_of_mut!(CONSTRUCT_CALLS)).push(ConstructCall::Capacity {
            owner: owner as usize as u32,
        });
        0x1111
    }

    unsafe extern "C" fn recording_transfer_quantum(this: *mut u8, arg: u32) -> u32 {
        (*core::ptr::addr_of_mut!(CONSTRUCT_CALLS)).push(ConstructCall::Quantum {
            this: this as usize,
            arg,
            // The original stores the context word BEFORE this helper runs.
            context_at_call: read_u32_unaligned(this.add(TRANSITION_ADDON_CONTEXT_OFFSET)),
        });
        0x2222
    }

    unsafe extern "C" fn recording_scale_class(this: *mut u8, arg: u32) -> u32 {
        (*core::ptr::addr_of_mut!(CONSTRUCT_CALLS)).push(ConstructCall::Scale {
            this: this as usize,
            arg,
        });
        0x3333
    }

    unsafe extern "C" fn recording_vector_member_construct(
        member: *mut u8,
        owner: *mut u8,
    ) -> *mut u8 {
        (*core::ptr::addr_of_mut!(CONSTRUCT_CALLS)).push(ConstructCall::Vector {
            member: member as usize,
            owner: owner as usize,
        });
        member.add(core::ptr::read_volatile(core::ptr::addr_of!(VECTOR_RETURN_SHIFT)))
    }

    unsafe extern "C" fn recording_register_with_owner(this: *mut u8) {
        (*core::ptr::addr_of_mut!(CONSTRUCT_CALLS)).push(ConstructCall::Register {
            this: this as usize,
        });
    }

    unsafe extern "C" fn recording_walk(
        _interface: *mut RegistryNode,
        selector: u32,
    ) -> *mut RegistryFacade {
        (*core::ptr::addr_of_mut!(CONSTRUCT_CALLS)).push(ConstructCall::Walk { selector });
        (*core::ptr::addr_of_mut!(FAKE_FACADE)).as_mut_ptr() as *mut RegistryFacade
    }

    struct ConstructOpsGuard {
        _lock: MutexGuard<'static, ()>,
        _facade_lock: MutexGuard<'static, ()>,
    }

    impl Drop for ConstructOpsGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(TRANSITION_ADDON_CONSTRUCT_OPS)
                    .write_volatile(DEFAULT_TRANSITION_ADDON_CONSTRUCT_OPS);
                core::ptr::addr_of_mut!(FACADE_REGISTRY_WALK)
                    .write_volatile(facade_registry_walk);
            }
        }
    }

    fn construct_guard(ops: TransitionAddonConstructOps) -> ConstructOpsGuard {
        // Lock order is construct-then-facade everywhere; the facade tests
        // never take the construct lock, so no cycle is possible.
        let lock = CONSTRUCT_OPS_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let facade_lock = FACADE_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        unsafe {
            (*core::ptr::addr_of_mut!(CONSTRUCT_CALLS)).clear();
            core::ptr::addr_of_mut!(TRANSITION_ADDON_CONSTRUCT_OPS).write_volatile(ops);
            core::ptr::addr_of_mut!(FACADE_REGISTRY_WALK).write_volatile(recording_walk);
        }
        ConstructOpsGuard { _lock: lock, _facade_lock: facade_lock }
    }

    fn install_construct_recorders(string_shift: usize, vector_shift: usize) -> ConstructOpsGuard {
        unsafe {
            core::ptr::addr_of_mut!(STRING_RETURN_SHIFT).write(string_shift);
            core::ptr::addr_of_mut!(VECTOR_RETURN_SHIFT).write(vector_shift);
        }
        construct_guard(TransitionAddonConstructOps {
            base_construct: recording_base_construct,
            string_member_construct: recording_string_member_construct,
            owner_capacity_query: recording_owner_capacity_query,
            transfer_quantum: recording_transfer_quantum,
            scale_class: recording_scale_class,
            vector_member_construct: recording_vector_member_construct,
            register_with_owner: recording_register_with_owner,
        })
    }

    fn install_construct_defaults() -> ConstructOpsGuard {
        construct_guard(DEFAULT_TRANSITION_ADDON_CONSTRUCT_OPS)
    }

    fn construct_calls() -> Vec<ConstructCall> {
        unsafe { (*core::ptr::addr_of!(CONSTRUCT_CALLS)).clone() }
    }

    #[test]
    fn construct_threads_every_object_address_through_callee_returns() {
        let mut object = Object([0xa5; 0x100]);
        let this = object.0.as_mut_ptr();
        let source = 0x5eedusize as *const u8;
        unsafe {
            (*core::ptr::addr_of_mut!(FAKE_FACADE))[9] = 0x5a;
        }
        // The string and vector mocks return deliberately shifted member
        // pointers; every later field and the final result must derive from
        // those returns (`sub r4,r0,#12` / `sub r4,r0,#64`), never from the
        // entry `this`.
        let _guard = install_construct_recorders(0x20, 0x10);

        let returned = unsafe {
            silver_controller_transition_addon_construct(
                this,
                source,
                1,
                0xbabe,
                0xaaaa,
                7,
                0xdead_beef,
            )
        };

        let derived = unsafe { this.add(0x20) };
        let final_this = unsafe { this.add(0x30) };
        assert_eq!(returned, final_this);
        assert_eq!(
            construct_calls(),
            vec![
                ConstructCall::Base {
                    this: this as usize,
                    hint: 0xbabe,
                    flag: 0, // the constructor inverts the flag for the base
                    prior_vtable: 0xa5a5_a5a5,
                },
                ConstructCall::StringMember {
                    member: unsafe { this.add(TRANSITION_ADDON_STRING_OFFSET) } as usize,
                    source: source as usize,
                },
                ConstructCall::Capacity { owner: 0xa5a5_a5a5 },
                ConstructCall::Quantum {
                    this: derived as usize,
                    arg: 0xaaaa,
                    context_at_call: 0xdead_beef,
                },
                ConstructCall::Scale {
                    this: derived as usize,
                    arg: 7,
                },
                ConstructCall::Walk { selector: 1 },
                ConstructCall::Vector {
                    member: unsafe { derived.add(TRANSITION_ADDON_VECTOR_OFFSET) } as usize,
                    owner: derived as usize,
                },
                ConstructCall::Register {
                    this: final_this as usize,
                },
            ]
        );
        unsafe {
            // The derived vtable overwrites whatever the base boundary left.
            assert_eq!(read_u32_unaligned(this), TRANSITION_ADDON_VTABLE_ADDRESS as u32);
            // The raw flag byte lands at the string member's +8 (this'+0x14).
            assert_eq!(*this.add(0x2c + 8), 1);
            assert_eq!(read_u32_unaligned(derived.add(TRANSITION_ADDON_INVALID_WORD_OFFSET)), 0xffff_ffff);
            assert_eq!(read_u32_unaligned(derived.add(TRANSITION_ADDON_ZEROED_WORD_OFFSET)), 0);
            assert_eq!(read_u32_unaligned(derived.add(TRANSITION_ADDON_CAPACITY_OFFSET)), 0x1111);
            assert_eq!(read_u32_unaligned(derived.add(TRANSITION_ADDON_CONTEXT_OFFSET)), 0xdead_beef);
            assert_eq!(read_u32_unaligned(derived.add(TRANSITION_ADDON_QUANTUM_OFFSET)), 0x2222);
            assert_eq!(read_u32_unaligned(derived.add(TRANSITION_ADDON_SCALE_CLASS_OFFSET)), 0x3333);
            assert_eq!(read_u32_unaligned(derived.add(TRANSITION_ADDON_SECOND_ZEROED_WORD_OFFSET)), 0);
            assert_eq!(*derived.add(TRANSITION_ADDON_FACADE_BYTE_OFFSET), 0x5a);
            assert_eq!(read_u32_unaligned(derived.add(TRANSITION_ADDON_ALIGNMENT_OFFSET)), 0x20);
        }
    }

    #[test]
    fn construct_defaults_reproduce_every_decoded_store() {
        let mut object = Object([0xa5; 0x100]);
        let this = object.0.as_mut_ptr();
        let source = 0x5eedusize as *const u8;
        unsafe {
            (*core::ptr::addr_of_mut!(FAKE_FACADE))[9] = 0x5a;
        }
        // Only the facade walk is mocked: with the default base boundary
        // the +0x04 interface word is zero, which the real host walk would
        // dereference. Every construction slot stays at its default.
        let _guard = install_construct_defaults();

        let returned = unsafe {
            silver_controller_transition_addon_construct(this, source, 1, 0, 0, 7, 0)
        };

        assert_eq!(returned, this);
        assert_eq!(construct_calls(), vec![ConstructCall::Walk { selector: 1 }]);
        unsafe {
            // Base boundary stores, then the derived vtable overwrites +0x00.
            assert_eq!(read_u32_unaligned(this), TRANSITION_ADDON_VTABLE_ADDRESS as u32);
            assert_eq!(read_u32_unaligned(this.add(TRANSITION_ADDON_OWNER_OFFSET)), 0);
            assert_eq!(*this.add(8), 0);
            assert_eq!(*this.add(9), 0, "flag ^ 1 with flag = 1");
            // String member: derived vtable + NULL payload at target offsets.
            assert_eq!(
                read_u32_unaligned(this.add(TRANSITION_ADDON_STRING_OFFSET)),
                TRANSITION_ADDON_STRING_MEMBER_VTABLE_ADDRESS
            );
            assert_eq!(read_u32_unaligned(this.add(TRANSITION_ADDON_STRING_OFFSET + 4)), 0);
            assert_eq!(*this.add(TRANSITION_ADDON_MODE_FLAG_OFFSET), 1, "the raw flag");
            assert_eq!(read_u32_unaligned(this.add(TRANSITION_ADDON_INVALID_WORD_OFFSET)), 0xffff_ffff);
            assert_eq!(read_u32_unaligned(this.add(TRANSITION_ADDON_ZEROED_WORD_OFFSET)), 0);
            assert_eq!(read_u32_unaligned(this.add(TRANSITION_ADDON_CAPACITY_OFFSET)), 0x200);
            assert_eq!(read_u32_unaligned(this.add(TRANSITION_ADDON_CONTEXT_OFFSET)), 0);
            assert_eq!(read_u32_unaligned(this.add(TRANSITION_ADDON_QUANTUM_OFFSET)), 0);
            // Faithful scale default: NULL context and 7 - 1 < 16 -> 7.
            assert_eq!(read_u32_unaligned(this.add(TRANSITION_ADDON_SCALE_CLASS_OFFSET)), 7);
            assert_eq!(read_u32_unaligned(this.add(TRANSITION_ADDON_SECOND_ZEROED_WORD_OFFSET)), 0);
            assert_eq!(*this.add(TRANSITION_ADDON_FACADE_BYTE_OFFSET), 0x5a);
            assert_eq!(read_u32_unaligned(this.add(TRANSITION_ADDON_ALIGNMENT_OFFSET)), 0x20);
            // Vector member prologue: owner word, then four zeroed words.
            assert_eq!(
                read_u32_unaligned(this.add(TRANSITION_ADDON_VECTOR_OFFSET)),
                this as usize as u32
            );
            for offset in [4usize, 8, 12, 16] {
                assert_eq!(read_u32_unaligned(this.add(TRANSITION_ADDON_VECTOR_OFFSET + offset)), 0);
            }
        }
    }

    #[test]
    fn scale_class_default_matches_the_decoded_truth_table() {
        let mut object = Object([0; 0x100]);
        let this = object.0.as_mut_ptr();
        unsafe {
            write_u32_unaligned(this.add(TRANSITION_ADDON_CONTEXT_OFFSET), 0);
            // NULL context: arg in 1..=16 passes through, everything else
            // collapses to 1 (arg = 0 wraps the subtraction to 0xffff_ffff).
            assert_eq!(scale_class_body(this, 1), 1);
            assert_eq!(scale_class_body(this, 16), 16);
            assert_eq!(scale_class_body(this, 17), 1);
            assert_eq!(scale_class_body(this, 0), 1);
            assert_eq!(scale_class_body(this, u32::MAX), 1);
            // Live context: always 1.
            write_u32_unaligned(this.add(TRANSITION_ADDON_CONTEXT_OFFSET), 0x1111);
            assert_eq!(scale_class_body(this, 7), 1);
        }
    }
}
