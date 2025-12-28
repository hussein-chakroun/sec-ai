"""
LLM Orchestrator - Core AI decision-making engine
"""
import os
from typing import List, Dict, Any, Optional
from abc import ABC, abstractmethod
import json
from loguru import logger


class BaseLLMProvider(ABC):
    """Abstract base class for LLM providers"""
    
    @abstractmethod
    def generate(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """Generate response from LLM"""
        pass
    
    @abstractmethod
    def generate_with_tools(self, prompt: str, tools: List[Dict], system_prompt: Optional[str] = None) -> Dict:
        """Generate response with tool calling capability"""
        pass


class OpenAIProvider(BaseLLMProvider):
    """OpenAI LLM Provider"""
    
    def __init__(self, api_key: str, model: str = "gpt-4-turbo-preview"):
        from openai import OpenAI
        self.client = OpenAI(api_key=api_key)
        self.model = model
        logger.info(f"Initialized OpenAI provider with model: {model}")
    
    def generate(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """Generate response from OpenAI"""
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        
        response = self.client.chat.completions.create(
            model=self.model,
            messages=messages
        )
        return response.choices[0].message.content
    
    def generate_with_tools(self, prompt: str, tools: List[Dict], system_prompt: Optional[str] = None) -> Dict:
        """Generate response with tool calling"""
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        
        response = self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            tools=tools,
            tool_choice="auto"
        )
        
        message = response.choices[0].message
        
        result = {
            "content": message.content,
            "tool_calls": []
        }
        
        if message.tool_calls:
            for tool_call in message.tool_calls:
                result["tool_calls"].append({
                    "id": tool_call.id,
                    "name": tool_call.function.name,
                    "arguments": json.loads(tool_call.function.arguments)
                })
        
        return result


class AnthropicProvider(BaseLLMProvider):
    """Anthropic Claude LLM Provider"""
    
    def __init__(self, api_key: str, model: str = "claude-3-opus-20240229"):
        from anthropic import Anthropic
        self.client = Anthropic(api_key=api_key)
        self.model = model
        logger.info(f"Initialized Anthropic provider with model: {model}")
    
    def generate(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """Generate response from Anthropic"""
        kwargs = {"model": self.model, "max_tokens": 4096, "messages": [{"role": "user", "content": prompt}]}
        if system_prompt:
            kwargs["system"] = system_prompt
            
        response = self.client.messages.create(**kwargs)
        return response.content[0].text
    
    def generate_with_tools(self, prompt: str, tools: List[Dict], system_prompt: Optional[str] = None) -> Dict:
        """Generate response with tool calling"""
        kwargs = {
            "model": self.model,
            "max_tokens": 4096,
            "messages": [{"role": "user", "content": prompt}],
            "tools": tools
        }
        if system_prompt:
            kwargs["system"] = system_prompt
            
        response = self.client.messages.create(**kwargs)
        
        result = {
            "content": "",
            "tool_calls": []
        }
        
        for block in response.content:
            if block.type == "text":
                result["content"] = block.text
            elif block.type == "tool_use":
                result["tool_calls"].append({
                    "id": block.id,
                    "name": block.name,
                    "arguments": block.input
                })
        
        return result


class LMStudioProvider(BaseLLMProvider):
    """LM Studio Local LLM Provider (OpenAI-compatible API)"""
    
    def __init__(self, base_url: str = "http://localhost:1234/v1", model: str = "local-model", api_key: str = "lm-studio"):
        from openai import OpenAI
        self.client = OpenAI(base_url=base_url, api_key=api_key)
        self.model = model
        self.base_url = base_url
        logger.info(f"Initialized LM Studio provider at {base_url} with model: {model}")
    
    def generate(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """Generate response from LM Studio"""
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=0.7,
                max_tokens=4096
            )
            return response.choices[0].message.content
        except Exception as e:
            logger.error(f"LM Studio API error: {e}")
            logger.warning(f"Make sure LM Studio is running and serving at {self.base_url}")
            raise
    
    def generate_with_tools(self, prompt: str, tools: List[Dict], system_prompt: Optional[str] = None) -> Dict:
        """Generate response with tool calling (if supported by model)"""
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        
        try:
            # Try with tool calling first (some models support it)
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                tools=tools,
                tool_choice="auto",
                temperature=0.7,
                max_tokens=4096
            )
            
            message = response.choices[0].message
            
            result = {
                "content": message.content,
                "tool_calls": []
            }
            
            if hasattr(message, 'tool_calls') and message.tool_calls:
                for tool_call in message.tool_calls:
                    result["tool_calls"].append({
                        "id": tool_call.id,
                        "name": tool_call.function.name,
                        "arguments": json.loads(tool_call.function.arguments)
                    })
            
            return result
            
        except Exception as e:
            # Fallback to regular generation if tool calling not supported
            logger.warning(f"Tool calling not supported, falling back to regular generation: {e}")
            content = self.generate(prompt, system_prompt)
            return {
                "content": content,
                "tool_calls": []
            }


class OllamaProvider(BaseLLMProvider):
    """Ollama Local LLM Provider"""
    
    def __init__(self, base_url: str = "http://localhost:11434", model: str = "llama2"):
        self.base_url = base_url
        self.model = model
        logger.info(f"Initialized Ollama provider at {base_url} with model: {model}")
    
    def generate(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """Generate response from Ollama"""
        import requests
        
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False
        }
        
        if system_prompt:
            payload["system"] = system_prompt
        
        try:
            response = requests.post(
                f"{self.base_url}/api/generate",
                json=payload,
                timeout=120
            )
            response.raise_for_status()
            return response.json()["response"]
        except Exception as e:
            logger.error(f"Ollama API error: {e}")
            logger.warning(f"Make sure Ollama is running and serving at {self.base_url}")
            raise
    
    def generate_with_tools(self, prompt: str, tools: List[Dict], system_prompt: Optional[str] = None) -> Dict:
        """Generate response (Ollama doesn't natively support tool calling)"""
        # Ollama doesn't support tool calling, so we just return regular generation
        content = self.generate(prompt, system_prompt)
        return {
            "content": content,
            "tool_calls": []
        }


class LLMOrchestrator:
    """Main orchestrator for LLM-based pentesting decisions"""
    
    def __init__(self, provider: BaseLLMProvider):
        self.provider = provider
        self.conversation_history = []
        logger.info("LLM Orchestrator initialized")
    
    def analyze_target(self, target: str) -> Dict[str, Any]:
        """Analyze target and determine initial scanning strategy"""
        system_prompt = """You are an expert penetration tester. Analyze the given target 
        and suggest an appropriate scanning strategy. Consider the target type (IP, domain, URL) 
        and recommend the sequence of tools to use.
        
        IMPORTANT: You must respond ONLY with valid JSON. Do not include any text before or after the JSON."""
        
        prompt = f"""Target: {target}
        
        Please analyze this target and provide:
        1. Target type identification
        2. Recommended initial scan (nmap flags)
        3. Potential attack vectors to investigate
        4. Risk assessment
        
        Respond ONLY with valid JSON in this exact format:
        {{
            "target_type": "domain/ip/url",
            "nmap_flags": "-sV -sC -p-",
            "attack_vectors": ["SQL injection", "XSS", "etc"],
            "risk_level": "low/medium/high",
            "reasoning": "explanation here"
        }}"""
        
        response = self.provider.generate(prompt, system_prompt)
        self.conversation_history.append({"role": "user", "content": prompt})
        self.conversation_history.append({"role": "assistant", "content": response})
        
        # Try to extract JSON from response
        try:
            # First, try direct parsing
            return json.loads(response)
        except json.JSONDecodeError:
            # Try to extract JSON from markdown code blocks
            import re
            json_match = re.search(r'```(?:json)?\s*({.*?})\s*```', response, re.DOTALL)
            if json_match:
                try:
                    return json.loads(json_match.group(1))
                except json.JSONDecodeError:
                    pass
            
            # Try to find JSON object in the response
            json_match = re.search(r'{.*}', response, re.DOTALL)
            if json_match:
                try:
                    return json.loads(json_match.group(0))
                except json.JSONDecodeError:
                    pass
            
            logger.warning("Failed to parse JSON response, returning structured fallback")
            return {
                "target_type": "unknown",
                "nmap_flags": "-sV -sC",
                "attack_vectors": ["web vulnerabilities", "network services"],
                "risk_level": "medium",
                "reasoning": "Unable to parse LLM response",
                "raw_response": response
            }
    
    def decide_next_action(self, scan_results: Dict[str, Any], context: Optional[Dict] = None) -> Dict[str, Any]:
        """Decide next action based on scan results"""
        system_prompt = """You are an autonomous penetration testing AI. Based on the scan results,
        decide what action to take next. You can choose to run additional scans, attempt exploits,
        or conclude the assessment. Always prioritize safety and authorized testing."""
        
        context_str = json.dumps(context, indent=2) if context else "None"
        results_str = json.dumps(scan_results, indent=2)
        
        prompt = f"""Previous Context: {context_str}
        
        Latest Scan Results:
        {results_str}
        
        Based on these results, what should be the next action? Provide:
        1. Next tool to use (nmap/sqlmap/hydra/metasploit/none)
        2. Specific parameters for the tool
        3. Reasoning for this choice
        4. Expected outcome
        
        Respond ONLY with valid JSON in this exact format:
        {{
            "tool": "nmap/sqlmap/hydra/metasploit/none",
            "parameters": ["--param1", "--param2"],
            "reasoning": "explanation here",
            "expected_outcome": "what we expect to find"
        }}"""
        
        response = self.provider.generate(prompt, system_prompt)
        self.conversation_history.append({"role": "user", "content": prompt})
        self.conversation_history.append({"role": "assistant", "content": response})
        
        # Try to extract JSON from response
        try:
            return json.loads(response)
        except json.JSONDecodeError:
            import re
            # Try to extract JSON from markdown code blocks
            json_match = re.search(r'```(?:json)?\s*({.*?})\s*```', response, re.DOTALL)
            if json_match:
                try:
                    return json.loads(json_match.group(1))
                except json.JSONDecodeError:
                    pass
            
            # Try to find JSON object in the response
            json_match = re.search(r'{.*}', response, re.DOTALL)
            if json_match:
                try:
                    return json.loads(json_match.group(0))
                except json.JSONDecodeError:
                    pass
            
            logger.warning("Failed to parse JSON response, returning structured fallback")
            return {
                "tool": "none",
                "parameters": [],
                "reasoning": "Unable to parse LLM response",
                "expected_outcome": "No action",
                "raw_response": response
            }
    
    def generate_recommendations(self, all_results: List[Dict]) -> Dict[str, Any]:
        """Generate final recommendations based on all scan results"""
        system_prompt = """You are a senior penetration tester writing a technical report.
        Analyze all findings and provide actionable security recommendations.
        
        IMPORTANT: You must respond ONLY with valid JSON. Do not include any text before or after the JSON."""
        
        results_str = json.dumps(all_results, indent=2)
        
        prompt = f"""Complete Scan Results:
        {results_str}
        
        Please provide:
        1. Executive summary
        2. Identified vulnerabilities (with severity ratings)
        3. Exploitable vulnerabilities
        4. Remediation recommendations
        5. Risk assessment
        
        Respond ONLY with valid JSON in this exact format:
        {{
            "executive_summary": "brief overview",
            "vulnerabilities": [
                {{"name": "vuln name", "severity": "critical/high/medium/low", "description": "details"}}
            ],
            "exploitable": ["list of exploitable vulnerabilities"],
            "remediation": ["list of recommendations"],
            "risk_level": "critical/high/medium/low"
        }}"""
        
        response = self.provider.generate(prompt, system_prompt)
        
        # Try to extract JSON from response
        try:
            return json.loads(response)
        except json.JSONDecodeError:
            import re
            # Try to extract JSON from markdown code blocks
            json_match = re.search(r'```(?:json)?\\s*({.*?})\\s*```', response, re.DOTALL)
            if json_match:
                try:
                    return json.loads(json_match.group(1))
                except json.JSONDecodeError:
                    pass
            
            # Try to find JSON object in the response
            json_match = re.search(r'{.*}', response, re.DOTALL)
            if json_match:
                try:
                    return json.loads(json_match.group(0))
                except json.JSONDecodeError:
                    pass
            
            logger.warning("Failed to parse JSON response, returning structured fallback")
            return {
                "executive_summary": "Unable to parse LLM response",
                "vulnerabilities": [],
                "exploitable": [],
                "remediation": ["Review raw response for findings"],
                "risk_level": "unknown",
                "raw_response": response
            }
    
    def clear_history(self):
        """Clear conversation history"""
        self.conversation_history = []
        logger.info("Conversation history cleared")
