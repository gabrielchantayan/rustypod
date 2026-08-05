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
pub mod heap;
pub mod ir;
/// `cg_timer_wait` @ 0x082bc4fc — the timer-armed event wait used by
/// the display path; not IR, but it lives inside the JIT's address
/// block and is ported under the same `cg_*` roof.
pub mod timer_wait;
