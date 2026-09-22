//! The Vincent 3D software JIT's intermediate representation
//! (`codegen.*` of the Vincent 3D Rendering Library, the OpenGL ES 1.1
//! implementation Apple embedded in retailOS and identified in the image
//! by the `glGetString` table @ 0x082559fc — `"Hans-Martin Will"` /
//! `"Software"` / `"OpenGL ES-CM 1.1"` — and by
//! `"1.1.0.APPLE Software JIT"` @ 0x082cb0f4).
//!
//! The renderer builds a fragment/rasterizer pipeline as SSA-ish IR and
//! compiles it to ARM at runtime. Every IR object lives in a bump arena
//! ([`heap`]); the builders ([`ir`]) are among the most-called functions
//! in the whole firmware because the IR is emitted one node at a time
//! from the pipeline generators in 0x0823a000-0x0826f5ff:
//! `cg_virtual_reg_create` alone has **835 `bl` call sites**, more than
//! any other unported function in osos.
pub mod block;
/// `cg_pack_color` @ 0x0823a5d8 — packs RGBA component bytes into the
/// pipeline's RGBA8888, RGB565, RGBA4444, or RGBA5551 representations.
pub mod cg_color_pack;
pub mod block_ref;
/// `cg_arm_immediate_rotation` @ 0x082be96c — recognizes literals the
/// Vincent ARM code generator can encode as an immediate or its complement.
pub mod arm_immediate_rotation;
/// `cg_wait_and_dispatch` @ 0x082bcd2c — waits for either availability
/// predicate, then performs the target callback dispatch.
pub mod availability_dispatch;
/// `cg_first_availability` @ 0x082bcf38 — checks the first code-generator
/// availability condition and feeds the dispatch wait loop.
pub mod first_availability;
/// `cg_exp_golomb_ue_read` @ 0x082c5df0 — the H.264 decoder's `ue(v)`
/// Exp-Golomb reader. Not IR either, but it sits inside the JIT's
/// address block (0x082c5dxx), one function away from `se(v)` @
/// 0x082c5dcc, and is ported under the same `cg_*` roof.
pub mod exp_golomb;
/// `cg_expression_collection_dependency_mask` @ 0x082cd8c4 — ORs the
/// dependency masks of a counted collection's 12-byte expression entries.
pub mod expression_collection_dependency_mask;
/// `cg_expression_dependency_mask` @ 0x082cda48 — recursively combines
/// an opaque expression node's two child and two collection dependency masks.
pub mod expression_dependency_mask;
/// `cg_dependency_mask_lookup` @ `0x082d07f8` — maps a dependency-table
/// identifier to its 64-bit position mask.
pub mod dependency_mask_lookup;
/// `cg_dependency_tail_has_uncovered_mask` @ 0x083672e4 — checks whether
/// a suffix of expression entries introduces a dependency absent from a mask.
pub mod dependency_tail_has_uncovered_mask;
/// `file_has_directory_entry` @ 0x082a548c — platform-file directory-entry
/// sentinel predicate in the JIT address block.
pub mod file_directory_entry;
/// `field_10_low_u16` @ 0x082a4f58 — opaque record state-word low-halfword
/// accessor in the codegen address block.
pub mod field_10_low_u16;
pub mod heap;
/// `cg_interference_edge_link` @ 0x082b2e98 — prepends a missing
/// target-width edge identity to a code-generator interference list.
pub mod interference;
/// `cg_register_bitset_create` @ 0x082c0c54 — allocates the code generator's
/// register-count header and its zeroed 32-bit bitset words.
pub mod register_bitset;
pub mod module_owner;
pub mod ir;
/// `cg_emit_load_word_at_offset` @ 0x082605f0 — emission sugar the
/// pipeline generators share; it lives in their address block, not the
/// IR library's, but it is IR construction all the same.
pub mod pipeline_emit;
/// `cg_rbsp_read_bits` @ 0x082d0630 — the H.264 decoder's `u(n)`
/// fixed-width RBSP bit reader. Not IR either, but it sits inside the
/// JIT's address block (0x082dxxxx) and is ported under the same
/// `cg_*` roof.
pub mod rbsp_read_bits;
/// `cg_timer_wait` @ 0x082bc4fc — the timer-armed event wait used by
/// the display path; not IR, but it lives inside the JIT's address
/// block and is ported under the same `cg_*` roof.
pub mod timer_wait;
/// `cg_two_bit_code_or_zero` @ 0x082b4964 — preserves the code
/// generator's nonzero two-bit codes and rejects all other representations.
pub mod two_bit_code;
