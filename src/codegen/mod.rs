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
pub mod block_ref;
/// `cg_exp_golomb_ue_read` @ 0x082c5df0 — the H.264 decoder's `ue(v)`
/// Exp-Golomb reader. Not IR either, but it sits inside the JIT's
/// address block (0x082c5dxx), one function away from `se(v)` @
/// 0x082c5dcc, and is ported under the same `cg_*` roof.
pub mod exp_golomb;
/// `file_has_directory_entry` @ 0x082a548c — platform-file directory-entry
/// sentinel predicate in the JIT address block.
pub mod file_directory_entry;
pub mod heap;
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
