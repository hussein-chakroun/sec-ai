"""
Test Local LLM Connection
Verify LM Studio or Ollama is working correctly
"""
import os
import sys

def test_lmstudio():
    """Test LM Studio connection"""
    print("\n" + "="*60)
    print("Testing LM Studio Connection")
    print("="*60)
    
    from core.llm_orchestrator import LMStudioProvider
    
    base_url = os.getenv("LMSTUDIO_BASE_URL", "http://localhost:1234/v1")
    model = os.getenv("LMSTUDIO_MODEL", "local-model")
    
    print(f"\nConnecting to: {base_url}")
    print(f"Model: {model}")
    
    try:
        provider = LMStudioProvider(base_url=base_url, model=model)
        
        print("\n📡 Sending test prompt...")
        response = provider.generate(
            "What are the top 3 web application vulnerabilities? Answer in one sentence.",
            system_prompt="You are a cybersecurity expert."
        )
        
        print("\n✅ SUCCESS! LM Studio is working!")
        print(f"\nResponse:\n{response}\n")
        return True
        
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        print("\nTroubleshooting:")
        print("1. Make sure LM Studio is running")
        print("2. Check that the local server is started (green indicator)")
        print("3. Verify the base URL is correct (default: http://localhost:1234/v1)")
        print("4. Load a model in LM Studio before starting the server")
        return False


def test_ollama():
    """Test Ollama connection"""
    print("\n" + "="*60)
    print("Testing Ollama Connection")
    print("="*60)
    
    from core.llm_orchestrator import OllamaProvider
    
    base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    model = os.getenv("OLLAMA_MODEL", "llama2")
    
    print(f"\nConnecting to: {base_url}")
    print(f"Model: {model}")
    
    try:
        provider = OllamaProvider(base_url=base_url, model=model)
        
        print("\n📡 Sending test prompt...")
        response = provider.generate(
            "What are the top 3 web application vulnerabilities? Answer in one sentence.",
            system_prompt="You are a cybersecurity expert."
        )
        
        print("\n✅ SUCCESS! Ollama is working!")
        print(f"\nResponse:\n{response}\n")
        return True
        
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        print("\nTroubleshooting:")
        print("1. Make sure Ollama is installed: curl https://ollama.ai/install.sh | sh")
        print(f"2. Pull the model: ollama pull {model}")
        print("3. Start Ollama server: ollama serve")
        print("4. Verify the base URL is correct (default: http://localhost:11434)")
        return False


def test_openai():
    """Test OpenAI connection"""
    print("\n" + "="*60)
    print("Testing OpenAI Connection")
    print("="*60)
    
    from core.llm_orchestrator import OpenAIProvider
    
    api_key = os.getenv("OPENAI_API_KEY", "")
    model = os.getenv("LLM_MODEL", "gpt-4-turbo-preview")
    
    if not api_key:
        print("\n⚠️  OPENAI_API_KEY not set in environment")
        return False
    
    print(f"\nModel: {model}")
    print(f"API Key: {api_key[:8]}...{api_key[-4:]}")
    
    try:
        provider = OpenAIProvider(api_key=api_key, model=model)
        
        print("\n📡 Sending test prompt...")
        response = provider.generate(
            "What are the top 3 web application vulnerabilities? Answer in one sentence.",
            system_prompt="You are a cybersecurity expert."
        )
        
        print("\n✅ SUCCESS! OpenAI is working!")
        print(f"\nResponse:\n{response}\n")
        return True
        
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        print("\nTroubleshooting:")
        print("1. Verify your API key is correct")
        print("2. Check you have credits/billing enabled")
        print("3. Ensure internet connection is working")
        return False


def test_anthropic():
    """Test Anthropic connection"""
    print("\n" + "="*60)
    print("Testing Anthropic Connection")
    print("="*60)
    
    from core.llm_orchestrator import AnthropicProvider
    
    api_key = os.getenv("ANTHROPIC_API_KEY", "")
    model = os.getenv("LLM_MODEL", "claude-3-opus-20240229")
    
    if not api_key:
        print("\n⚠️  ANTHROPIC_API_KEY not set in environment")
        return False
    
    print(f"\nModel: {model}")
    print(f"API Key: {api_key[:8]}...{api_key[-4:]}")
    
    try:
        provider = AnthropicProvider(api_key=api_key, model=model)
        
        print("\n📡 Sending test prompt...")
        response = provider.generate(
            "What are the top 3 web application vulnerabilities? Answer in one sentence.",
            system_prompt="You are a cybersecurity expert."
        )
        
        print("\n✅ SUCCESS! Anthropic is working!")
        print(f"\nResponse:\n{response}\n")
        return True
        
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        print("\nTroubleshooting:")
        print("1. Verify your API key is correct")
        print("2. Check you have credits enabled")
        print("3. Ensure internet connection is working")
        return False


def main():
    """Main test function"""
    print("\n" + "="*60)
    print("🧪 LLM PROVIDER CONNECTION TESTER")
    print("="*60)
    
    # Load .env file
    from dotenv import load_dotenv
    load_dotenv()
    
    provider = os.getenv("LLM_PROVIDER", "").lower()
    
    if not provider:
        print("\n⚠️  LLM_PROVIDER not set in .env file")
        print("\nAvailable providers:")
        print("  - lmstudio (local, free)")
        print("  - ollama (local, free)")
        print("  - openai (cloud, paid)")
        print("  - anthropic (cloud, paid)")
        print("\nSet LLM_PROVIDER in your .env file and try again.")
        return
    
    print(f"\nConfigured Provider: {provider}")
    print("-" * 60)
    
    success = False
    
    if provider == "lmstudio":
        success = test_lmstudio()
    elif provider == "ollama":
        success = test_ollama()
    elif provider == "openai":
        success = test_openai()
    elif provider == "anthropic":
        success = test_anthropic()
    else:
        print(f"\n❌ Unknown provider: {provider}")
        print("Valid options: lmstudio, ollama, openai, anthropic")
    
    print("\n" + "="*60)
    if success:
        print("✅ All tests passed! Your LLM provider is ready to use.")
        print("\nYou can now run the pentesting platform:")
        print("  python main.py --target example.com")
    else:
        print("❌ Tests failed. Please fix the issues above.")
        print("\nFor local LLM setup instructions, see:")
        print("  LOCAL-LLM-GUIDE.md")
    print("="*60 + "\n")


if __name__ == "__main__":
    main()
