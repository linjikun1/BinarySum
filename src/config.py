#!/usr/bin/env python3
"""
Configuration utility for BinarySum.

Reads API keys and settings from config.ini.
Copy config.ini.example to config.ini and fill in your values.
"""

import configparser
import os
from pathlib import Path
from typing import Dict, Any

# Config file paths
ROOT_DIR = Path(__file__).parent.parent.resolve()
CONFIG_FILE = ROOT_DIR / "config.ini"


def load_config() -> configparser.ConfigParser:
    """
    Load configuration from config.ini.
    """
    config = configparser.ConfigParser()
    
    if CONFIG_FILE.exists():
        config.read(CONFIG_FILE)
    else:
        print(f"Warning: No config file found.")
    
    return config


# Global config (loaded once)
_CONFIG = None


def get_config() -> configparser.ConfigParser:
    """Get the global configuration (lazy loading)."""
    global _CONFIG
    if _CONFIG is None:
        _CONFIG = load_config()
    return _CONFIG


def reload_config() -> configparser.ConfigParser:
    """Force reload configuration from file."""
    global _CONFIG
    _CONFIG = load_config()
    return _CONFIG


def get_openai_config(profile: str = "gpt") -> Dict[str, str]:
    """
    Get OpenAI configuration for a profile from config.ini.
    Environment variables OPENAI_API_KEY / OPENAI_BASE_URL / MODEL_NAME take precedence.
    """
    config = get_config()
    
    # Get values from config file (with defaults)
    # Section name is the profile directly (e.g., "gpt")
    api_key = config.get(profile, "api_key", fallback="YOUR_API_KEY_HERE") if config.has_section(profile) else "YOUR_API_KEY_HERE"
    base_url = config.get(profile, "base_url", fallback="https://api.openai.com/v1") if config.has_section(profile) else "https://api.openai.com/v1"
    model_name = config.get(profile, "model_name", fallback="gpt-5") if config.has_section(profile) else "gpt-5"
    
    # Environment variables override config file
    result = {
        "api_key": os.environ.get("OPENAI_API_KEY") or api_key,
        "base_url": os.environ.get("OPENAI_BASE_URL") or base_url,
        "model_name": os.environ.get("MODEL_NAME") or model_name
    }
    
    return result


def get_generation_config(stage: str = "synthesis") -> Dict[str, Any]:
    """Get generation parameters for a stage (hpss / synthesis / sdn)."""
    config = get_config()
    section = f"generation_{stage}"
    
    if not config.has_section(section):
        return {"temperature": 0.1, "max_tokens": 512}
    
    result = {}
    for key in config.options(section):
        value = config.get(section, key)
        # Try to convert to appropriate type
        try:
            if '.' in value:
                result[key] = float(value)
            else:
                result[key] = int(value)
        except ValueError:
            result[key] = value
    
    return result


def get_module_config(module: str = "synthesis", profile: str = None) -> Dict[str, Any]:
    """
    Convenience function combining OpenAI config + generation config for a module.
    Returns dict with keys: api_key, base_url, model_name, temperature, max_tokens.
    """
    if profile is None:
        profile = os.environ.get("BINARYSUM_CONFIG_PROFILE", "default")
    
    openai_config = get_openai_config(profile)
    gen_config = get_generation_config(module)
    
    return {
        "api_key": openai_config["api_key"],
        "base_url": openai_config["base_url"],
        "model_name": openai_config["model_name"],
        "temperature": gen_config.get("temperature", 0.1),
        "max_tokens": gen_config.get("max_tokens", 512)
    }


def list_openai_profiles() -> list:
    """List available OpenAI configuration profiles."""
    config = get_config()
    profiles = []
    for section in config.sections():
        # Skip generation_* sections
        if not section.startswith("generation_"):
            profiles.append(section)
    return profiles if profiles else ["default"]


# Convenience function
def get_api_config(profile: str = "default") -> Dict[str, str]:
    """Legacy function name for get_openai_config."""
    return get_openai_config(profile)


if __name__ == "__main__":
    # Test the configuration
    print("=== BinarySum Configuration ===")
    print(f"Config file: {CONFIG_FILE}")
    print(f"Config exists: {CONFIG_FILE.exists()}")
    print()
    
    print("Available OpenAI profiles:", list_openai_profiles())
    print()
    
    for profile in list_openai_profiles():
        cfg = get_openai_config(profile)
        masked_key = cfg["api_key"][:8] + "..." if len(cfg["api_key"]) > 8 else cfg["api_key"]
        print(f"[{profile}]")
        print(f"  api_key: {masked_key}")
        print(f"  base_url: {cfg['base_url']}")
        print(f"  model_name: {cfg['model_name']}")
        print()
    
    print("Generation configs:")
    for stage in ["hpss", "synthesis", "sdn"]:
        gen_cfg = get_generation_config(stage)
        print(f"  [{stage}]: {gen_cfg}")
