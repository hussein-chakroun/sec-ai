"""
Configuration Manager
"""
import os
import yaml
from pathlib import Path
from typing import Dict, Any
from dotenv import load_dotenv
from loguru import logger


class Config:
    """Configuration management"""
    
    def __init__(self, config_path: str = None):
        self.base_dir = Path(__file__).parent.parent
        self.config_path = config_path or self.base_dir / "config" / "config.yaml"
        
        # Load environment variables
        load_dotenv(self.base_dir / ".env")
        
        # Load YAML config
        self.config = self._load_config()
        
        # Setup logging
        self._setup_logging()
        
        logger.info("Configuration loaded successfully")
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        if not self.config_path.exists():
            logger.warning(f"Config file not found: {self.config_path}")
            return {}
        
        with open(self.config_path, 'r') as f:
            return yaml.safe_load(f)
    
    def _setup_logging(self):
        """Setup logging configuration"""
        log_level = os.getenv("LOG_LEVEL", "INFO")
        log_dir = self.base_dir / "logs"
        log_dir.mkdir(exist_ok=True)
        
        logger.add(
            log_dir / "sec-ai.log",
            rotation="10 MB",
            retention="10 days",
            level=log_level
        )
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by key (supports dot notation)"""
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
            else:
                return default
        
        return value if value is not None else default
    
    @property
    def llm_provider(self) -> str:
        """Get LLM provider (openai, anthropic, lmstudio, ollama)"""
        return os.getenv("LLM_PROVIDER", "openai")
    
    @llm_provider.setter
    def llm_provider(self, value: str):
        """Set LLM provider"""
        os.environ["LLM_PROVIDER"] = value
    
    @property
    def llm_model(self) -> str:
        """Get LLM model"""
        return os.getenv("LLM_MODEL", "gpt-4-turbo-preview")
    
    @llm_model.setter
    def llm_model(self, value: str):
        """Set LLM model"""
        os.environ["LLM_MODEL"] = value
    
    @property
    def openai_api_key(self) -> str:
        """Get OpenAI API key"""
        return os.getenv("OPENAI_API_KEY", "")
    
    @openai_api_key.setter
    def openai_api_key(self, value: str):
        """Set OpenAI API key"""
        os.environ["OPENAI_API_KEY"] = value
    
    @property
    def anthropic_api_key(self) -> str:
        """Get Anthropic API key"""
        return os.getenv("ANTHROPIC_API_KEY", "")
    
    @anthropic_api_key.setter
    def anthropic_api_key(self, value: str):
        """Set Anthropic API key"""
        os.environ["ANTHROPIC_API_KEY"] = value
    
    @property
    def lmstudio_base_url(self) -> str:
        """Get LM Studio base URL"""
        return os.getenv("LMSTUDIO_BASE_URL", "http://localhost:1234/v1")
    
    @lmstudio_base_url.setter
    def lmstudio_base_url(self, value: str):
        """Set LM Studio base URL"""
        os.environ["LMSTUDIO_BASE_URL"] = value
    
    @property
    def lmstudio_model(self) -> str:
        """Get LM Studio model name"""
        return os.getenv("LMSTUDIO_MODEL", "local-model")
    
    @lmstudio_model.setter
    def lmstudio_model(self, value: str):
        """Set LM Studio model name"""
        os.environ["LMSTUDIO_MODEL"] = value
    
    @property
    def lmstudio_host(self) -> str:
        """Get LM Studio host (without /v1)"""
        base_url = self.lmstudio_base_url
        return base_url.replace('/v1', '') if base_url.endswith('/v1') else base_url
    
    @lmstudio_host.setter
    def lmstudio_host(self, value: str):
        """Set LM Studio host"""
        # Ensure it doesn't end with /v1 for host property
        value = value.rstrip('/')
        if not value.endswith('/v1'):
            os.environ["LMSTUDIO_BASE_URL"] = f"{value}/v1"
        else:
            os.environ["LMSTUDIO_BASE_URL"] = value
    
    @property
    def ollama_base_url(self) -> str:
        """Get Ollama base URL"""
        return os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    
    @property
    def ollama_model(self) -> str:
        """Get Ollama model name"""
        return os.getenv("OLLAMA_MODEL", "llama2")
    
    @property
    def low_context_mode(self) -> bool:
        """Get low context mode setting"""
        env_value = os.getenv("LOW_CONTEXT_MODE", "false").lower()
        if env_value in ["true", "1", "yes"]:
            return True
        return self.get("llm.low_context_mode", False)
    
    @low_context_mode.setter
    def low_context_mode(self, value: bool):
        """Set low context mode"""
        os.environ["LOW_CONTEXT_MODE"] = str(value)
    
    @property
    def low_context_chunk_size(self) -> int:
        """Get low context chunk size"""
        env_value = os.getenv("LOW_CONTEXT_CHUNK_SIZE")
        if env_value:
            return int(env_value)
        return self.get("llm.low_context_chunk_size", 2000)
    
    @property
    def report_output_dir(self) -> Path:
        """Get report output directory"""
        path = Path(os.getenv("REPORT_OUTPUT_DIR", "./reports_output"))
        path.mkdir(parents=True, exist_ok=True)
        return path


# Global config instance
config = Config()


def load_config() -> Dict[str, Any]:
    """Load configuration and return dict with provider instance"""
    from core.llm_orchestrator import (
        OpenAIProvider, 
        AnthropicProvider, 
        LMStudioProvider,
        OllamaProvider
    )
    
    provider_name = config.llm_provider.lower()
    
    # Initialize the appropriate provider
    if provider_name == "openai":
        if not config.openai_api_key:
            raise ValueError("OPENAI_API_KEY not set in environment")
        provider = OpenAIProvider(
            api_key=config.openai_api_key,
            model=config.llm_model
        )
    
    elif provider_name == "anthropic":
        if not config.anthropic_api_key:
            raise ValueError("ANTHROPIC_API_KEY not set in environment")
        provider = AnthropicProvider(
            api_key=config.anthropic_api_key,
            model=config.llm_model
        )
    
    elif provider_name == "lmstudio":
        provider = LMStudioProvider(
            base_url=config.lmstudio_base_url,
            model=config.lmstudio_model
        )
        logger.info(f"Using LM Studio at {config.lmstudio_base_url}")
    
    elif provider_name == "ollama":
        provider = OllamaProvider(
            base_url=config.ollama_base_url,
            model=config.ollama_model
        )
        logger.info(f"Using Ollama at {config.ollama_base_url}")
    
    else:
        raise ValueError(f"Unknown LLM provider: {provider_name}. Use 'openai', 'anthropic', 'lmstudio', or 'ollama'")
    
    return {
        "llm_provider": provider,
        "config": config
    }
