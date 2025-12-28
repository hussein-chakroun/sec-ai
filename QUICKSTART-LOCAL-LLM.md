# Quick Start: Local LLM Setup (5 Minutes)

## LM Studio (Windows/Mac - GUI)

```bash
# 1. Download & Install
https://lmstudio.ai/

# 2. In LM Studio:
- Search for: "mistral-7b-instruct"
- Download: TheBloke/Mistral-7B-Instruct-v0.2-GGUF (Q4_K_M)
- Go to "Local Server" tab
- Select the model
- Click "Start Server" ✅

# 3. Configure
echo "LLM_PROVIDER=lmstudio" > .env

# 4. Test & Run
python test_llm_connection.py
python main.py --target example.com
```

## Ollama (Linux/Mac - CLI)

```bash
# 1. Install
curl https://ollama.ai/install.sh | sh

# 2. Pull Model & Start
ollama pull mistral
ollama serve &

# 3. Configure
echo "LLM_PROVIDER=ollama" >> .env
echo "OLLAMA_MODEL=mistral" >> .env

# 4. Test & Run
python test_llm_connection.py
python main.py --target example.com
```

## Done! 🎉

Now running with:
- ✅ 100% Privacy (local)
- ✅ $0 API costs
- ✅ Offline capable
- ✅ All 4 phases working

See `LOCAL-LLM-GUIDE.md` for full documentation.
