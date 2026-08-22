//! OpenAI 兼容类型与模型目录

pub mod catalog;
pub mod openai;
pub mod upstream;

pub use catalog::{available_model_count, deprecated_models, get_model_info, is_deprecated, model_count, DEPRECATED_MODELS, ModelInfo, NIMMODEL_CATALOG};
