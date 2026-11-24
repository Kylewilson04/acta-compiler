pub mod budget;
pub mod formatter;
pub mod pipeline;
pub mod resolver;

pub use budget::{apply_budget_and_omissions, apply_budget_and_omissions_with_mode, count_tokens, encode_token_spans, BudgetedSelection};
pub use formatter::{
    format_dispute_entry, format_intent_entry, format_memory_entry, format_resolution_compact,
    format_resolution_entry, is_line_or_control_char, render_context_text, sanitize_header_atom,
};
pub use pipeline::{
    compute_resolution_changed, CompilePipeline, CompileSimulation, PipelineConfig,
    SimulationCompat,
};
pub use resolver::{
    resolve_claims, resolve_claims_with_overrides, resolve_claims_with_overrides_compat, resolve_claims_with_overrides_v171_compat,
    ResolverConfig, ResolverOutput,
};
