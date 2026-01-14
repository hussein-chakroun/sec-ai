# Low Context Mode Guide

## Overview

Low Context Mode is a feature designed to help users with limited hardware resources (RAM/VRAM) run SEC-AI effectively. Instead of processing large amounts of data at once, it splits the data into smaller chunks and processes them sequentially.

## When to Use Low Context Mode

Enable Low Context Mode if you experience:
- **Out of memory errors** when running LLMs
- **System freezing** during analysis
- **Model crashes** with large data sets
- **Limited RAM/VRAM** (8GB or less)
- **Small context window** models (local LLMs)

## How It Works

### Normal Mode
```
[Large Data] → LLM → Results
```

### Low Context Mode
```
[Large Data] → Split into chunks
  ↓
[Chunk 1] → LLM → Result 1
  ↓
[Chunk 2] → LLM → Result 2
  ↓
[Chunk 3] → LLM → Result 3
  ↓
[Combine Results] → Final Report
```

## Configuration

### Option 1: GUI Configuration (Recommended)

1. Launch the GUI: `python main.py --gui`
2. Go to **🔧 Configuration** tab
3. Find **⚙️ Performance Settings** section
4. Check **"Enable Low Context Mode (for limited RAM/VRAM)"**
5. Adjust **Chunk Size** based on your system:
   - **4GB RAM**: 1000 tokens
   - **8GB RAM**: 2000 tokens (default)
   - **16GB+ RAM**: 4000-8000 tokens or disable low context mode
6. Click **💾 Apply Configuration**

### Option 2: Configuration File

Edit `config/config.yaml`:

```yaml
llm:
  temperature: 0.7
  max_tokens: 4096
  timeout: 120
  low_context_mode: true     # Set to true to enable
  low_context_chunk_size: 2000  # Adjust based on your system
```

### Option 3: Environment Variables

```bash
# Windows PowerShell
$env:LOW_CONTEXT_MODE = "true"
$env:LOW_CONTEXT_CHUNK_SIZE = "2000"

# Linux/Mac
export LOW_CONTEXT_MODE=true
export LOW_CONTEXT_CHUNK_SIZE=2000
```

## Trade-offs

### Advantages ✅
- **Lower memory usage** - Works on systems with limited RAM/VRAM
- **More stable** - Reduces crashes and out-of-memory errors
- **Compatible** with smaller models
- **Reliable** - Processes data in manageable pieces

### Disadvantages ⚠️
- **Slower processing** - Takes longer to complete each phase
- **Sequential execution** - Steps are processed one at a time
- **More LLM calls** - May use more API tokens (if using API)

## Performance Comparison

| System Specs | Recommended Setting | Expected Time |
|-------------|---------------------|---------------|
| 4GB RAM | Chunk Size: 1000 | ~3x slower |
| 8GB RAM | Chunk Size: 2000 | ~2x slower |
| 16GB RAM | Chunk Size: 4000 | ~1.5x slower |
| 32GB+ RAM | Disable (Normal Mode) | Normal speed |

## Monitoring

When Low Context Mode is active, you'll see:

```
⚙️  Low Context Mode: ENABLED - Processing will be sequential
   Chunk Size: 2000 tokens
   Note: This will take longer but use less memory

⏳ Processing in low context mode - waiting for LLM...
📊 Split data into 3 chunks for low context mode
⏳ Processing chunk 1/3
✅ Step 1 completed successfully
⏳ Processing chunk 2/3
✅ Step 2 completed successfully
...
```

## Tips for Optimal Performance

1. **Start Conservative**: Begin with smaller chunk sizes (1000-1500 tokens)
2. **Monitor Resources**: Watch your RAM usage and adjust accordingly
3. **Local LLMs**: Essential for most local models with limited context
4. **API Usage**: Be aware that chunking increases API calls
5. **Test First**: Run a small test scan to find optimal settings

## Troubleshooting

### Still Getting Memory Errors?
- Reduce chunk size further (try 500-1000 tokens)
- Close other applications
- Use a smaller/quantized model
- Consider using a cloud API instead of local LLM

### Too Slow?
- Increase chunk size if you have available RAM
- Disable low context mode if your system can handle it
- Use a faster model
- Process smaller targets first

### Results Look Incomplete?
- Check the logs for chunk processing status
- Verify all chunks were processed successfully
- Try increasing chunk overlap (future feature)

## Example Use Cases

### Use Case 1: Local LLM on 8GB Laptop
```yaml
llm:
  low_context_mode: true
  low_context_chunk_size: 1500
```

### Use Case 2: Quantized Model (Q4)
```yaml
llm:
  low_context_mode: true
  low_context_chunk_size: 2500
```

### Use Case 3: High-End Workstation
```yaml
llm:
  low_context_mode: false  # Disabled for best performance
```

## Support

If you continue experiencing issues:
1. Check the logs in `logs/sec-ai.log`
2. Verify your model supports the context length
3. Test with an even smaller chunk size
4. Consider using an API-based provider for large scans

## Future Enhancements

Planned improvements:
- Intelligent chunk overlap for better context continuity
- Adaptive chunk sizing based on available memory
- Progress indicators with time estimates
- Chunk caching to avoid reprocessing
- Parallel chunk processing for multi-GPU setups
