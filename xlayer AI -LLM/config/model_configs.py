# Model hyperparameters for ~500M params
MODEL_CONFIG = {
    'vocab_size': 32000,      # From tokenizer
    'embed_dim': 768,
    'num_layers': 12,
    'num_heads': 12,
    'ff_hidden_dim': 3072,    # 4x embed_dim
    'max_seq_len': 1024,
}