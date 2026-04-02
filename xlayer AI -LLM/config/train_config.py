# Training config
TRAIN_CONFIG = {
    'epochs': 5,              # Start small, increase later
    'batch_size': 8,          # Adjust based on GPU memory
    'accum_steps': 4,         # Gradient accumulation for larger effective batch
    'lr': 1e-4,               # Learning rate
    'device': 'cuda' if torch.cuda.is_available() else 'cpu',
}