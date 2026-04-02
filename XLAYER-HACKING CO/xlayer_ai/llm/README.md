# XLayer AI - LLM Module

A unified interface for managing and using multiple LLM models in the XLayer AI project. Uses a unified chat model loader to support multiple providers seamlessly.

## Supported Providers & Models

### OpenAI
| Model | Description | Context | Best For |
|---|---|---|---|
| `gpt-5.2` | Latest flagship model (Feb 2026 default) | 256K | General purpose, highest quality |
| `gpt-5` | Unified standard + thinking model | 256K | Complex reasoning, coding |
| `o3` | Most powerful reasoning model | 200K | Math, coding, visual perception |
| `o4-mini` | Fast cost-efficient reasoning | 200K | Fast reasoning, math |
| `o3-pro` | Extended thinking (Pro tier) | 200K | Deep analysis, complex queries |
| `gpt-4.5` | Large general-purpose model | 128K | Writing, fewer hallucinations |
| `gpt-4o-mini` | Lightweight, fast | 128K | Quick tasks, low cost |

### Anthropic
| Model | Description | Context | Best For |
|---|---|---|---|
| `claude-sonnet-4-6` | Latest balanced model (Feb 2026) | 1M | Agentic tasks, reduced token usage |
| `claude-opus-4` | World's best coding model | 200K | Complex long-running tasks, agent workflows |
| `claude-sonnet-4` | High performance, efficient | 200K | Coding (72.7% SWE-bench), general |
| `claude-haiku-4-5` | Fast, lightweight | 200K | Quick tasks, low latency |

### Google
| Model | Description | Context | Best For |
|---|---|---|---|
| `gemini-3.1-pro-preview` | Latest preview (Feb 2026) | 1M | Cutting-edge performance |
| `gemini-3-pro` | Newest stable model | 1M | General purpose, multimodal |
| `gemini-3-flash-preview` | Fast next-gen model | 1M | Speed-optimized tasks |
| `gemini-2.5-pro` | Thinking model with deep reasoning | 1M | Advanced reasoning, coding, math |
| `gemini-2.5-flash` | Fast with thinking capability | 1M | Balanced speed and reasoning |
| `gemini-2.0-flash` | Previous gen fast model | 1M | Quick inference |

### Groq (Ultra-Fast Inference)
| Model | Description | Speed | Best For |
|---|---|---|---|
| `llama-4-scout-17b-16e` | Llama 4 Scout (17B, 16 experts) | ~750 tok/s | Fast multimodal, 12 languages |
| `llama-4-maverick` | Llama 4 Maverick (17B, 128 experts) | Fast | Superior image + text |
| `llama-3.3-70b` | Llama 3.3 70B | ~280 tok/s | General purpose, reliable |
| `llama-3.1-8b` | Llama 3.1 8B | ~560 tok/s | Ultra-fast lightweight |
| `gpt-oss-120b` | OpenAI open-source 120B | ~500 tok/s | Agent tasks |
| `gpt-oss-20b` | OpenAI open-source 20B | ~1000 tok/s | Fastest agent tasks |

### Mistral AI
| Model | Description | Context | Best For |
|---|---|---|---|
| `mistral-large-3` | Flagship MoE (41B active / 675B total) | 256K | Multimodal, multilingual |
| `mistral-medium-3.1` | Frontier multimodal model | 128K | Balanced quality and cost |
| `magistral-medium-1.2` | Reasoning model with vision | 128K | Complex reasoning |
| `codestral-2508` | Specialized coding model | 256K | Code generation |
| `ministral-14b` | Dense small model | 128K | Efficient local tasks |
| `ministral-8b` | Dense lightweight model | 128K | Fast lightweight tasks |
| `ministral-3b` | Dense tiny model | 128K | Edge / embedded |

### xAI (Grok)
| Model | Description | Context | Best For |
|---|---|---|---|
| `grok-4.1` | Latest fast-reasoning model | 2M | Complex reasoning, coding |
| `grok-3` | Flagship model (200K GPU trained) | 131K | Advanced reasoning, math (93% AIME) |
| `grok-3-mini` | Lightweight reasoning model | 131K | Fast reasoning tasks |
| `grok-code-fast-1` | Specialized coding model | 131K | Code generation |
| `grok-2-vision` | Vision-capable model | 131K | Image analysis |

### Perplexity (Search-Augmented)
| Model | Description | Best For |
|---|---|---|
| `sonar` | Lightweight search model (Llama 3.3 70B) | Fast answers with web search |
| `sonar-pro` | Higher quality with more context | Production search tasks |
| `sonar-reasoning` | Multi-step reasoning with search | Complex questions |
| `sonar-reasoning-pro` | Advanced reasoning with search | Deep analysis |
| `sonar-deep-research` | In-depth research agent | Research reports with citations |

### DeepSeek
| Model | Description | Context | Best For |
|---|---|---|---|
| `deepseek-v3.2` | Latest production model (Feb 2026) | 128K | GPT-5 level, tool calling |
| `deepseek-v3.2-speciale` | High-compute reasoning variant | 128K | Math olympiad, deep reasoning |
| `deepseek-v3` | 671B MoE (37B active) | 128K | General purpose, efficient |
| `deepseek-reasoner` | R1 reasoning model | 128K | Chain-of-thought reasoning |
| `deepseek-chat` | General chat model | 128K | Conversation, quick tasks |

### Azure OpenAI
| Model | Description | Best For |
|---|---|---|
| `gpt-5.2` (Azure-hosted) | Enterprise GPT-5.2 | Compliance, enterprise |
| `gpt-4o` (Azure-hosted) | Enterprise GPT-4o | Enterprise deployments |
| Custom deployments | Your fine-tuned models | Domain-specific tasks |

### Ollama (Local Models -- Free, Private, No API Key)
| Model | VRAM Required | Best For |
|---|---|---|
| `llama4-scout` | ~12 GB | Multimodal, fast local inference |
| `llama4-maverick` | ~24 GB | Best local multimodal |
| `qwen3:72b` | ~44 GB | Strongest local dense model |
| `qwen3:32b` | ~20 GB | Best balance of quality/VRAM |
| `qwen3:8b` | ~6 GB | Light machines |
| `qwen3-coder` | ~20 GB | Best local coding + tool calling |
| `deepseek-r1:70b` | ~44 GB | Best local reasoning |
| `deepseek-r1:7b` | ~6 GB | Lightweight reasoning |
| `gemma3:27b` | ~18 GB | Efficient Google model |
| `mistral-large-3` | ~48 GB | Best local multilingual |
| `gpt-oss:120b` | ~72 GB | OpenAI open-weight agent model |
| `gpt-oss:20b` | ~14 GB | Lightweight OpenAI open-weight |
| `codestral:22b` | ~14 GB | Fast local coding |
| `phi4:14b` | ~10 GB | Microsoft efficient model |
| `glm-4.7` | ~20 GB | Precise tool calling |

## Installation & Setup

### 1. Install Required Packages

```bash
# Core packages
pip install langchain langchain-core

# Provider-specific packages (install only what you need)
pip install langchain-openai        # OpenAI
pip install langchain-anthropic     # Anthropic
pip install langchain-google-genai  # Google Gemini
pip install langchain-groq          # Groq
pip install langchain-mistralai     # Mistral AI
pip install langchain-xai           # xAI (Grok)
pip install langchain-perplexity    # Perplexity
pip install langchain-deepseek      # DeepSeek
pip install langchain-ollama        # Ollama
```

### 2. API Key Configuration

Set the required API keys in your `.env` file:

```env
# OpenAI
OPENAI_API_KEY=sk-...

# Anthropic
ANTHROPIC_API_KEY=sk-ant-...

# Google
GOOGLE_API_KEY=AIza...

# Groq
GROQ_API_KEY=gsk_...

# Mistral AI
MISTRAL_API_KEY=...

# xAI (Grok)
XAI_API_KEY=xai-...

# Perplexity
PPLX_API_KEY=pplx-...

# DeepSeek
DEEPSEEK_API_KEY=sk-...

# Azure OpenAI
AZURE_OPENAI_API_KEY=...
AZURE_OPENAI_ENDPOINT=https://your-resource.openai.azure.com/
AZURE_OPENAI_DEPLOYMENT_NAME=your-deployment
OPENAI_API_VERSION=2024-02-15-preview
```

### 3. Ollama Setup (Local Models)

Ollama runs models locally with no API key required. The Ollama service must be running.

#### Install Ollama

```bash
# Download from https://ollama.ai/
# Or install via curl (Linux/Mac)
curl -fsSL https://ollama.ai/install.sh | sh
```

#### Start Ollama

```bash
ollama serve
```

#### Download Models

```bash
# Latest recommended models
ollama pull llama4-scout          # Meta Llama 4 Scout (multimodal)
ollama pull qwen3:32b             # Alibaba Qwen 3 (best balance)
ollama pull qwen3-coder           # Best coding + tool calling
ollama pull deepseek-r1:7b        # DeepSeek reasoning (lightweight)
ollama pull gemma3:27b            # Google Gemma 3
ollama pull gpt-oss:20b           # OpenAI open-weight
ollama pull phi4:14b              # Microsoft Phi-4
ollama pull codestral:22b         # Mistral coding model
ollama pull glm-4.7               # GLM tool calling

# For powerful machines (24GB+ VRAM)
ollama pull deepseek-r1:70b       # Full reasoning model
ollama pull qwen3:72b             # Strongest dense local model
ollama pull llama4-maverick       # Best local multimodal

# List installed models
ollama list
```

#### Optional Environment Variables

```env
OLLAMA_HOST=localhost
OLLAMA_BASE_URL=http://localhost:11434
```

## Basic Usage

### 1. Load a Specific Model

```python
from src.utils.llm import load_llm

# Load latest models
llm = load_llm("claude-sonnet-4-6", "anthropic")
llm = load_llm("gpt-5.2", "openai")
llm = load_llm("gemini-3-pro", "google")
llm = load_llm("grok-4.1", "xai")
llm = load_llm("deepseek-v3.2", "deepseek")
llm = load_llm("mistral-large-3", "mistral")

# Load with parameters
llm = load_llm("gpt-5.2", "openai", temperature=0.7, max_tokens=4096)

# Load a local Ollama model
llm = load_llm("qwen3:32b", "ollama")

# Use the model
response = llm.invoke("Explain security testing best practices.")
print(response.content)
```

### 2. Runtime Model Switching

```python
from src.utils.llm import load_llm

# Load without specifying a model to enable runtime switching
llm = load_llm()

# Use Claude Sonnet 4.6
response = llm.invoke(
    "Explain vulnerability scanning.",
    config={
        "configurable": {
            "model": "claude-sonnet-4-6",
            "model_provider": "anthropic"
        }
    }
)

# Switch to GPT-5.2
response = llm.invoke(
    "Describe penetration testing methodology.",
    config={
        "configurable": {
            "model": "gpt-5.2",
            "model_provider": "openai"
        }
    }
)

# Switch to Grok 4.1
response = llm.invoke(
    "Analyze this code for vulnerabilities.",
    config={
        "configurable": {
            "model": "grok-4.1",
            "model_provider": "xai"
        }
    }
)
```

### 3. Using with Agents

```python
from langgraph.prebuilt import create_react_agent
from src.utils.llm import load_llm

agent = create_react_agent(
    load_llm("claude-opus-4", "anthropic"),
    tools=your_tools,
    name="SecurityAgent"
)
```

## Advanced Usage

### 1. List Available Models

```python
from src.utils.llm import list_available_models, list_available_providers

# List all models
models = list_available_models()
for model in models:
    status = "✅" if model["api_key_available"] else "❌"
    print(f"{status} {model['display_name']} - {model['description']}")

# List models by provider
openai_models = list_available_models(provider="openai")

# List providers
providers = list_available_providers()
for provider in providers:
    print(f"{provider['display_name']}: {provider['model_count']} models")
```

### 2. Model Selection UI

```python
from src.utils.llm.selection import (
    create_model_selection_menu,
    get_model_from_selection,
    load_model_from_config
)

# Generate model menu for UI
menu = create_model_selection_menu()
for item in menu:
    print(f"{item['display']}: {item['description']}")

# Handle user selection
selection = "anthropic:claude-sonnet-4-6"
model_info = get_model_from_selection(selection)
llm = load_llm(model_info["model_name"], model_info["provider"])
```

### 3. Ollama-Specific Features

```python
from src.utils.llm import get_ollama_info, get_installed_ollama_models, check_ollama_connection

# Check Ollama status
status = get_ollama_info()
print(f"Connected: {status['connected']}")
print(f"URL: {status['url']}")
print(f"Installed models: {status['installed_models']}")

# Check connection only
connection = check_ollama_connection()
if connection["connected"]:
    print("✅ Ollama is running")
else:
    print(f"❌ Ollama error: {connection['error']}")

# List installed models
models = get_installed_ollama_models()
for model in models:
    print(f"  • {model}")

# Use an Ollama model
if "qwen3:32b" in models:
    llm = load_llm("qwen3:32b", "ollama")
    response = llm.invoke("Explain cybersecurity fundamentals.")
    print(response.content)
```

### 4. Configuration Validation

```python
from src.utils.llm.selection import validate_model_config

config = {
    "model": "claude-sonnet-4-6",
    "provider": "anthropic",
    "temperature": 0.0
}

result = validate_model_config(config)
if result["valid"]:
    print("✅ Configuration is valid")
else:
    print(f"❌ Error: {result['error']}")
    if "missing_env_var" in result:
        print(f"Required environment variable: {result['missing_env_var']}")
```

## Recommended Models by Use Case

| Use Case | Recommended Model | Provider | Why |
|---|---|---|---|
| **Security code analysis** | `claude-opus-4` | Anthropic | Best coding model, long-running agent tasks |
| **General pentesting** | `claude-sonnet-4-6` | Anthropic | Best balance of quality, speed, cost |
| **Fast reasoning** | `o3` or `o4-mini` | OpenAI | Strong math/logic reasoning |
| **Budget-friendly** | `deepseek-v3.2` | DeepSeek | GPT-5 level at fraction of cost |
| **Ultra-fast inference** | `llama-4-scout-17b-16e` | Groq | 750 tok/s, good quality |
| **Search-augmented** | `sonar-reasoning-pro` | Perplexity | Built-in web search |
| **Local/private** | `qwen3:32b` | Ollama | Best local balance, no API key |
| **Local coding** | `qwen3-coder` | Ollama | Best local tool calling |
| **Local reasoning** | `deepseek-r1:70b` | Ollama | Best local chain-of-thought |
| **Multimodal** | `gemini-3-pro` | Google | Native vision, audio, video |
| **Multilingual** | `mistral-large-3` | Mistral | Best-in-class multilingual |

## CLI Tools

### Model Testing

```bash
# Interactive model selection
python src/utils/llm/test_llm.py

# Test specific models
python src/utils/llm/test_llm.py -m "claude-sonnet-4-6" -p "anthropic"
python src/utils/llm/test_llm.py -m "gpt-5.2" -p "openai"
python src/utils/llm/test_llm.py -m "grok-4.1" -p "xai"
python src/utils/llm/test_llm.py -m "deepseek-v3.2" -p "deepseek"
python src/utils/llm/test_llm.py -m "qwen3:32b" -p "ollama"

# Chat mode
python src/utils/llm/test_llm.py -m "gpt-5.2" -p "openai" --chat

# List available models
python src/utils/llm/test_llm.py --list

# Show model info (including Ollama status)
python src/utils/llm/test_llm.py --info

# Check Ollama status only
python src/utils/llm/test_llm.py --ollama
```

### Print Help

```python
from src.utils.llm import print_model_selection_help

print_model_selection_help()
```

## Migration from Legacy Code

### Before (legacy)

```python
from src.utils.llm1 import CLAUDE_AGENT_LLM

agent = create_react_agent(
    CLAUDE_AGENT_LLM,
    tools=tools
)
```

### After (new)

```python
from src.utils.llm import load_llm

agent = create_react_agent(
    load_llm("claude-sonnet-4-6", "anthropic"),
    tools=tools
)
```

### Runtime Model Switching with Agents

```python
from src.utils.llm import load_llm

# Create a configurable agent (no model specified = runtime configurable)
agent = create_react_agent(
    load_llm(),
    tools=tools
)

# Specify the model at invocation time
response = agent.invoke(
    {"messages": [("user", "Create a penetration testing plan")]},
    config={
        "configurable": {
            "model": "gpt-5.2",
            "model_provider": "openai"
        }
    }
)
```

## Configuration File

Model configurations are stored in `src/utils/llm/llm_models_config.json`. To add custom models:

```python
from src.utils.llm import LLMModelManager, LLMModelConfig, ModelProvider

manager = LLMModelManager()
custom_model = LLMModelConfig(
    display_name="Custom GPT-5",
    model_name="gpt-5-custom",
    provider=ModelProvider.OPENAI,
    description="Custom fine-tuned GPT-5 model",
    context_length=256000,
    supports_tools=True,
    supports_streaming=True
)

manager.add_custom_model(custom_model)
```

## Troubleshooting

### 1. API Key Error

```
ValueError: API key not found for anthropic. Please set ANTHROPIC_API_KEY in your environment.
```

**Solution**: Add the corresponding API key to your `.env` file or set it as an environment variable.

### 2. Missing Package Error

```
ImportError: langchain-anthropic package not installed
```

**Solution**: Install the required package:
```bash
pip install langchain-anthropic
```

### 3. Model Inference Failure

Usually caused by an incorrect API key or wrong model name. Use `validate_model_config()` to verify your configuration.

### 4. Ollama Issues

```
ValueError: Ollama is not running or not accessible
```

**Solution**:
1. Start the Ollama service: `ollama serve`
2. Verify Ollama is installed: https://ollama.ai/
3. Install a model: `ollama pull qwen3:32b`
4. Check connection: `python src/utils/llm/test_llm.py --ollama`

```
Model 'qwen3:72b' not found
```

**Solution**: Install the model:
```bash
ollama pull qwen3:72b
ollama list  # Verify installed models
```

## Roadmap

- [ ] Expanded local model support (Ollama optimization)
- [ ] Model performance comparison tool
- [ ] Automatic model selection by task type
- [ ] Cost tracking features
- [ ] Batch processing optimization
- [ ] Gemini 3.1 Pro integration on stable release
- [ ] DeepSeek V4 integration when available

## Contributing

To add a new provider or feature:

1. Add the new provider to the `ModelProvider` enum
2. Add API key validation logic to `validate_api_key()`
3. Add default model configurations for the new provider
4. Write tests

## License

This module follows the XLayer AI project license.