#!/usr/bin/env python3
"""
Unified LLM Client for BinarySum.

This module provides a base class for LLM interactions with:
- Unified retry logic
- Consistent error handling
- Timeout management

Usage:
    from llm_client import BaseLLMClient
    
    client = BaseLLMClient(api_key="...", model_name="gpt-4", base_url="...")
    response = client.chat("Your prompt here", temperature=0.1)
"""

import time
import json
from typing import Optional, Dict, Any, Tuple
import openai


class BaseLLMClient:
    """
    Base class for LLM interactions with unified retry and error handling.
    
    Attributes:
        client: OpenAI client instance
        model_name: Model name to use
        max_retries: Maximum number of retry attempts
        retry_delay: Base delay between retries (seconds)
        timeout: Request timeout (seconds)
    """
    
    def __init__(
        self, 
        api_key: str, 
        model_name: str, 
        base_url: str,
        timeout: int = 60,
        max_retries: int = 3,
        retry_delay: int = 5
    ):
        """
        Initialize the LLM client.
        
        Args:
            api_key: OpenAI API key
            model_name: Model name (e.g., "gpt-4", "gpt-3.5-turbo")
            base_url: API base URL
            timeout: Request timeout in seconds
            max_retries: Maximum retry attempts
            retry_delay: Base delay between retries (doubled for rate limits)
        """
        self.client = openai.OpenAI(api_key=api_key, base_url=base_url, timeout=timeout)
        self.model_name = model_name
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.timeout = timeout
    
    def chat(
        self, 
        prompt: str, 
        temperature: float = 0.1,
        is_json: bool = False,
        system_prompt: str = "You are an experienced binary reverse engineer."
    ) -> Tuple[str, float, int]:
        """
        Send a chat completion request with retry logic.
        
        Args:
            prompt: User prompt
            temperature: Sampling temperature
            is_json: Whether to request JSON response
            system_prompt: System prompt to use
            
        Returns:
            Tuple of (response_content, duration_seconds, total_tokens)
            On failure, returns ("", 0, 0)
        """
        start_time = time.time()
        response_format = {"type": "json_object"} if is_json else {"type": "text"}
        
        for attempt in range(self.max_retries):
            try:
                response = self.client.chat.completions.create(
                    model=self.model_name,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=temperature,
                    response_format=response_format
                )
                
                end_time = time.time()
                content = response.choices[0].message.content.strip()
                tokens = response.usage.total_tokens if hasattr(response, "usage") else -1
                duration = end_time - start_time
                
                return content, duration, tokens
                
            except openai.APIConnectionError as e:
                print(f"Connection error (attempt {attempt+1}/{self.max_retries}): {e}")
                if attempt < self.max_retries - 1:
                    time.sleep(self.retry_delay)
                    
            except openai.RateLimitError as e:
                print(f"Rate limit error (attempt {attempt+1}/{self.max_retries}): {e}")
                if attempt < self.max_retries - 1:
                    time.sleep(self.retry_delay * 2)  # Double delay for rate limits
                    
            except openai.APITimeoutError as e:
                print(f"Timeout error (attempt {attempt+1}/{self.max_retries}): {e}")
                if attempt < self.max_retries - 1:
                    time.sleep(self.retry_delay)
                    
            except openai.APIStatusError as e:
                # Non-retryable errors (e.g., invalid API key, bad request)
                print(f"API error (non-retryable): {e}")
                return "", 0, 0
                
            except Exception as e:
                print(f"Unexpected error in LLM call: {e}")
                return "", 0, 0
        
        print(f"Failed after {self.max_retries} retries")
        return "", 0, 0
    
    def chat_simple(self, prompt: str, temperature: float = 0.1) -> str:
        """
        Simple chat interface that returns only the content.
        
        Args:
            prompt: User prompt
            temperature: Sampling temperature
            
        Returns:
            Response content string, or empty string on failure
        """
        content, _, _ = self.chat(prompt, temperature)
        return content
    
    def chat_json(
        self, 
        prompt: str, 
        temperature: float = 0.1,
        default: Optional[Dict] = None
    ) -> Tuple[Dict[str, Any], float, int]:
        """
        Chat with JSON response parsing.
        
        Args:
            prompt: User prompt
            temperature: Sampling temperature
            default: Default value to return on JSON parse failure
            
        Returns:
            Tuple of (parsed_json, duration_seconds, total_tokens)
        """
        content, duration, tokens = self.chat(prompt, temperature, is_json=True)
        
        if not content:
            return default or {}, duration, tokens
        
        try:
            return json.loads(content), duration, tokens
        except json.JSONDecodeError as e:
            print(f"Failed to parse JSON response: {e}")
            return default or {"error": "JSON parse failed", "raw": content}, duration, tokens


def create_client_from_config(module: str = "synthesis", profile: str = None) -> BaseLLMClient:
    """
    Factory function to create an LLM client from configuration.
    
    Args:
        module: Module name for generation config ("hpss", "synthesis", "sdn")
        profile: OpenAI profile name (default: from env or "default")
        
    Returns:
        Configured BaseLLMClient instance
        
    Example:
        from llm_client import create_client_from_config
        client = create_client_from_config("hpss")
        response = client.chat_simple("Explain this code...")
    """
    # Import here to avoid circular imports
    from config import get_module_config
    
    config = get_module_config(module, profile)
    
    return BaseLLMClient(
        api_key=config["api_key"],
        model_name=config["model_name"],
        base_url=config["base_url"],
        timeout=60,
        max_retries=3,
        retry_delay=5
    )
