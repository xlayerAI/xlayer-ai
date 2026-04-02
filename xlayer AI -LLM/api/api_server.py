from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import torch
from sentencepiece import SentencePieceProcessor
from Xic.Model_llm import XICModel  # From Xic/
from Xic.Inference import generate_response  # Reuse inference logic

app = FastAPI(title="XLayer AI API")

class QueryRequest(BaseModel):
    prompt: str
    max_len: int = 100

@app.post("/predict")
async def predict(query: QueryRequest):
    try:
        # Load model and tokenizer (in production, load once)
        model_config = {'vocab_size': 32000, 'embed_dim': 768, 'num_layers': 12, 'num_heads': 12, 'ff_hidden_dim': 3072, 'max_seq_len': 1024}
        tokenizer = SentencePieceProcessor('Checkpoints/Tokenizer.model')
        model = XICModel(**model_config)
        model.load_state_dict(torch.load('Checkpoints/Model.pt', map_location='cpu'))  # Adjust path
        model.eval()
        
        response = generate_response(query.prompt, model=model, tokenizer=tokenizer, max_len=query.max_len)
        return {"response": response}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)