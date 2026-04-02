from __future__ import annotations

from pathlib import Path
from typing import List, Optional, Literal, Dict, Any

# --- Pydantic (v1/v2 compatibility) ------------------------------------------
try:
    from pydantic import BaseSettings, Field  # type: ignore
    try:
        # v2
        from pydantic import field_validator as _validator  # type: ignore
        _IS_PYDANTIC_V2 = True
    except Exception:
        # v1
        from pydantic import validator as _validator  # type: ignore
        _IS_PYDANTIC_V2 = False
except Exception as e:  # pragma: no cover
    raise ImportError("pydantic is required for configuration management.") from e

# YAML is optional
try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None  # YAML support becomes a no-op

# Paths (assumes file is at <repo>/src/xic/config.py)
_THIS_FILE = Path(__file__).resolve()
_REPO_ROOT = _THIS_FILE.parents[2]
_DEFAULT_YAML = _REPO_ROOT / "config" / "settings.yaml"

__all__ = [
    "XICConfig", "get_config", "schema_version", "debug_summary",
    "RopeSettings", "AttentionSettings", "KVCacheSettings", "FFNSettings",
    "NormInitSettings", "PrecisionSettings", "QuantizationSettings",
    "RegularizationSettings", "OptimSettings", "SchedSettings",
    "DataSettings", "CheckpointSettings", "TrainLoopSettings",
    "GenSettings", "ExportSettings", "DistributedSettings",
    "ParallelismSettings", "MoESettings", "ProfilingSettings",
    "TelemetrySettings", "SecuritySettings", "ExperimentSettings",
    "ensure_dirs_exist"
]

# ---------------------------------------------------------------------------

class RopeSettings(BaseSettings):
    """Settings for RoPE scaling and application."""
    scaling: Literal["none", "linear", "dynamic"] = Field("linear")
    base_theta: float = Field(1e6)
    factor: float = Field(8.0, gt=0.0)
    rope_kv: bool = Field(True)

    class Config:
        env_prefix = "ROPE_"


class AttentionSettings(BaseSettings):
    """Settings for attention mechanisms including FlashAttention and sliding-window attention."""
    gqa_groups: int = Field(4, ge=1)
    heads_kv_override: Optional[int] = Field(None, ge=1)
    use_flash: bool = Field(True)
    sliding_window: Optional[int] = Field(None, ge=256)
    causal: bool = Field(True)

    class Config:
        env_prefix = "ATTN_"


class KVCacheSettings(BaseSettings):
    """Settings for key-value cache management."""
    enable: bool = Field(True)
    dtype: Literal["auto", "float16", "bfloat16"] = Field("auto")
    shard_policy: Literal["none", "tensor", "sequence"] = Field("tensor")
    cpu_offload: bool = Field(False)
    prefill_chunk: int = Field(0, ge=0)

    class Config:
        env_prefix = "KVCACHE_"


class FFNSettings(BaseSettings):
    """Settings for feed-forward network implementations."""
    impl: Literal["swiglu", "gelu", "relu"] = Field("swiglu")
    mult: float = Field(2.0, gt=1.0)
    dropout: float = Field(0.0, ge=0.0, le=0.5)

    class Config:
        env_prefix = "FFN_"


class NormInitSettings(BaseSettings):
    """Settings for normalization and initialization."""
    norm: Literal["prerms", "postrms"] = Field("prerms")
    eps: float = Field(1e-5)
    init: Literal["xavier_uniform", "xavier_normal", "kaiming_uniform"] = Field("xavier_uniform")

    class Config:
        env_prefix = "NORMINIT_"


class PrecisionSettings(BaseSettings):
    """
    Settings for precision and device management.
    device: "auto" -> cuda if available else cpu
    """
    device: Literal["auto", "cpu", "cuda"] = Field("auto")
    dtype: Literal["auto", "float32", "float16", "bfloat16"] = Field("auto")
    amp: bool = Field(True)
    compile: bool = Field(False)
    grad_checkpoint: bool = Field(False)
    max_batch_tokens: int = Field(16384, ge=1024)

    if _IS_PYDANTIC_V2:
        @_validator("device", mode="before")  # type: ignore[misc]
        def _resolve_device_v2(cls, v: str) -> str:
            if v == "auto":
                try:
                    import torch  # lazy import
                    return "cuda" if torch.cuda.is_available() else "cpu"
                except Exception:
                    return "cpu"
            return v
    else:
        @_validator("device", pre=True, always=True)  # type: ignore[misc]
        def _resolve_device_v1(cls, v: str) -> str:
            if v == "auto":
                try:
                    import torch  # lazy import
                    return "cuda" if torch.cuda.is_available() else "cpu"
                except Exception:
                    return "cpu"
            return v

    class Config:
        env_prefix = "PRECISION_"


class QuantizationSettings(BaseSettings):
    """Settings for model quantization."""
    enable: bool = Field(False)
    scheme: Literal["awq", "gptq", "int8", "nf4"] = Field("awq")
    per_channel: bool = Field(True)
    sym: bool = Field(True)
    bits: int = Field(8)
    activation_dtype: Literal["float16", "bfloat16"] = Field("bfloat16")

    class Config:
        env_prefix = "QUANT_"


class RegularizationSettings(BaseSettings):
    """Settings for regularization techniques."""
    dropout: float = Field(0.0, ge=0.0, le=0.5)
    weight_decay: float = Field(0.1, ge=0.0)
    attention_dropout: float = Field(0.0, ge=0.0, le=0.5)

    class Config:
        env_prefix = "REGULARIZE_"


class OptimSettings(BaseSettings):
    """Settings for optimization algorithms."""
    opt: Literal["adamw", "adamw_8bit", "adamw_32bit"] = Field("adamw")
    lr: float = Field(3e-4, gt=0)
    betas_0: float = Field(0.9, ge=0.0, le=1.0)
    betas_1: float = Field(0.95, ge=0.0, le=1.0)
    eps: float = Field(1e-8, gt=0.0)
    wd_exempt_patterns: List[str] = Field(default_factory=lambda: ["bias", "LayerNorm.weight"])

    class Config:
        env_prefix = "OPTIM_"


class SchedSettings(BaseSettings):
    """Settings for learning rate scheduling."""
    sched: Literal["cosine", "linear", "constant"] = Field("cosine")
    warmup_steps: int = Field(100, ge=0)
    total_steps: int = Field(10000, ge=1)
    min_lr_ratio: float = Field(0.1, ge=0.0, le=1.0)

    class Config:
        env_prefix = "SCHED_"


class DataSettings(BaseSettings):
    """Settings for data paths and tokenization."""
    tokenizer_path: str = Field("data/tokenizer/xlayer_tokenizer.model")
    processed_dir: str = Field("data/processed")
    train_path: str = Field("data/processed/train_ids.pt")
    val_path: str = Field("data/processed/val_ids.pt")
    seq_len: int = Field(4096, ge=512)
    vocab_size: int = Field(32000, ge=2048)
    pack_sequences: bool = Field(True)
    shuffle_buffer: int = Field(100000, ge=0)
    num_workers: int = Field(4, ge=0)

    class Config:
        env_prefix = "DATA_"


class CheckpointSettings(BaseSettings):
    """Settings for model checkpointing."""
    model_path: str = Field("checkpoints/best.pt")
    save_dir: str = Field("checkpoints")
    save_every: int = Field(1000, ge=1)
    keep_last: int = Field(3, ge=1)
    resume: bool = Field(True)
    best_metric: Literal["val_loss", "ppl"] = Field("val_loss")
    atomic_writes: bool = Field(True)

    class Config:
        env_prefix = "CKPT_"


class TrainLoopSettings(BaseSettings):
    """Settings for the training loop."""
    batch_size: int = Field(8, ge=1)
    micro_batch: int = Field(1, ge=1)
    grad_accum_steps: int = Field(1, ge=1)
    deterministic: bool = Field(False)
    seed: int = Field(1337)
    log_every: int = Field(50, ge=1)
    eval_every: int = Field(1000, ge=1)
    save_on_exit: bool = Field(True)

    class Config:
        env_prefix = "TRAIN_"


class GenSettings(BaseSettings):
    """Settings for generation parameters."""
    max_new_tokens: int = Field(256, ge=1)
    temperature: float = Field(0.7, ge=0.0)
    top_p: float = Field(0.9, ge=0.0, le=1.0)
    top_k: int = Field(50, ge=0)
    repetition_penalty: float = Field(1.0, ge=0.0)
    eos_id: Optional[int] = None
    stop: List[str] = Field(default_factory=list)

    class Config:
        env_prefix = "GEN_"


class ExportSettings(BaseSettings):
    """Settings for model export."""
    enable: bool = Field(False)
    formats: List[Literal["torchscript", "onnx", "gguf"]] = Field(default_factory=list)
    opset: int = Field(17, ge=11)
    quantize_on_export: bool = Field(False)
    out_dir: str = Field("exports")

    class Config:
        env_prefix = "EXPORT_"


class DistributedSettings(BaseSettings):
    """Settings for distributed training."""
    backend: Literal["none", "ddp", "fsdp", "deepspeed"] = Field("none")
    world_size: int = Field(1, ge=1)
    rank: int = Field(0, ge=0)
    local_rank: int = Field(0, ge=0)
    master_addr: str = Field("127.0.0.1")
    master_port: int = Field(29500)

    class Config:
        env_prefix = "DIST_"


class ParallelismSettings(BaseSettings):
    """Settings for model parallelism."""
    gradient_parallel: bool = Field(False)
    tensor_parallel: int = Field(1, ge=1)
    pipeline_parallel: int = Field(1, ge=1)
    zero_stage: Literal[0, 1, 2, 3] = Field(0)
    fsdp_wrap_policy: Literal["auto", "transformer_block"] = Field("auto")

    class Config:
        env_prefix = "PARALLEL_"


class MoESettings(BaseSettings):
    """Settings for mixture of experts (MoE)."""
    enable: bool = Field(False)
    experts: int = Field(4, ge=1)
    top_k: int = Field(2, ge=1)
    capacity_factor: float = Field(1.2, gt=0.0)
    router_z_loss: float = Field(0.001, ge=0.0)
    aux_loss: float = Field(0.01, ge=0.0)

    class Config:
        env_prefix = "MOE_"


class ProfilingSettings(BaseSettings):
    """Settings for profiling and performance tracing."""
    enable: bool = Field(False)
    trace_memory: bool = Field(False)
    schedule: str = Field("warmup,active")
    out_dir: str = Field("profiles")

    class Config:
        env_prefix = "PROFILING_"


class TelemetrySettings(BaseSettings):
    """Settings for telemetry and logging."""
    enable: bool = Field(False)
    json_logs: bool = Field(False)
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = Field("INFO")
    otlp_endpoint: Optional[str] = None
    tags: Dict[str, str] = Field(default_factory=dict)

    class Config:
        env_prefix = "TELEMETRY_"


class SecuritySettings(BaseSettings):
    """Settings for security and filtering."""
    enable_filters: bool = Field(True)
    deny_keywords: List[str] = Field(default_factory=lambda: ["ransomware", "botnet", "ddos-for-hire"])
    allow_defensive_only: bool = Field(True)

    class Config:
        env_prefix = "SECURITY_"


class ExperimentSettings(BaseSettings):
    """Settings for experiment tracking."""
    name: str = Field("default")
    id: Optional[str] = None
    notes: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    resume_policy: Literal["latest", "best", "none"] = Field("latest")

    class Config:
        env_prefix = "EXPERIMENT_"


class XICConfig(BaseSettings):
    """Root configuration for XLayer AI's LLM core."""
    env: Literal["dev", "prod", "test"] = Field("dev")
    d_model: int = Field(2048, ge=256)
    n_layers: int = Field(24, ge=1)
    n_heads: int = Field(16, ge=1)
    tie_embeddings: bool = Field(True)

    rope: RopeSettings = RopeSettings()
    attn: AttentionSettings = AttentionSettings()
    kv_cache: KVCacheSettings = KVCacheSettings()
    ffn: FFNSettings = FFNSettings()
    norminit: NormInitSettings = NormInitSettings()
    precision: PrecisionSettings = PrecisionSettings()
    quant: QuantizationSettings = QuantizationSettings()
    regularize: RegularizationSettings = RegularizationSettings()
    optim: OptimSettings = OptimSettings()
    sched: SchedSettings = SchedSettings()
    data: DataSettings = DataSettings()
    ckpt: CheckpointSettings = CheckpointSettings()
    train: TrainLoopSettings = TrainLoopSettings()
    gen: GenSettings = GenSettings()
    export: ExportSettings = ExportSettings()
    distributed: DistributedSettings = DistributedSettings()
    parallelism: ParallelismSettings = ParallelismSettings()
    moe: MoESettings = MoESettings()
    profiling: ProfilingSettings = ProfilingSettings()
    telemetry: TelemetrySettings = TelemetrySettings()
    security: SecuritySettings = SecuritySettings()
    experiment: ExperimentSettings = ExperimentSettings()

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


# ----------------------------- YAML helpers ----------------------------------

def _load_yaml(path: Path) -> Dict[str, Any]:
    if yaml is None or not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _deep_merge(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
    """
    Merge dict b into a (one-level deep is enough for our nested settings).
    """
    out = dict(a)
    for k, v in b.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = {**out[k], **v}
        else:
            out[k] = v
    return out


def ensure_dirs_exist(*paths: str) -> None:
    """Ensure that directories exist for the given paths."""
    for path in paths:
        Path(path).mkdir(parents=True, exist_ok=True)


# ----------------------------- Singleton accessor ----------------------------

_CFG: Optional[XICConfig] = None


def get_config() -> XICConfig:
    """
    Load precedence: defaults -> YAML (config/settings.yaml) -> ENV (.env/system).
    ENV precedence is handled by BaseSettings when constructing the final model.
    """
    global _CFG
    if _CFG is not None:
        return _CFG

    # 1) defaults (BaseSettings will also read ENV here, but we want to overlay YAML then re-read ENV)
    base = XICConfig()

    # 2) YAML overlay (optional)
    yaml_cfg = _load_yaml(_DEFAULT_YAML)

    # Convert model to dict compatibly across pydantic versions
    base_dict = base.dict() if hasattr(base, "dict") else base.model_dump()  # v1 or v2

    merged = _deep_merge(base_dict, yaml_cfg)

    # 3) Re-instantiate so ENV wins (BaseSettings re-applies environment)
    _CFG = XICConfig(**merged)

    # Ensure necessary directories exist
    ensure_dirs_exist(
        _CFG.ckpt.save_dir,
        _CFG.data.processed_dir,
        _CFG.export.out_dir,
        _CFG.profiling.out_dir
    )

    return _CFG


def debug_summary() -> Dict[str, Any]:
    """Minimal snapshot for logs/tests."""
    cfg = get_config()
    return {
        "env": cfg.env,
        "device": cfg.precision.device,
        "dtype": cfg.precision.dtype,
        "amp": cfg.precision.amp,
        "compile": cfg.precision.compile,
        "rope.scaling": cfg.rope.scaling,
        "attn.use_flash": cfg.attn.use_flash,
        "attn.sliding_window": cfg.attn.sliding_window,
        "kv_cache.enable": cfg.kv_cache.enable,
        "quant.enable": cfg.quant.enable,
        "moe.enable": cfg.moe.enable,
        "tie_embeddings": cfg.tie_embeddings,
        "d_model": cfg.d_model,
        "n_layers": cfg.n_layers,
        "n_heads": cfg.n_heads,
        "seq_len": cfg.data.seq_len,
        "max_batch_tokens": cfg.precision.max_batch_tokens,
    }


def schema_version() -> str:
    """Return the schema version."""
    return "1.0.0"
