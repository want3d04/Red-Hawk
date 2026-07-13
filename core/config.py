#!/usr/bin/env python3

import json
import os

class Config:
    DEFAULT_CONFIG = {
        "app": {"name": "RedHawk", "version": "3.0.0"},
        "scanner": {"threads": 50, "timeout": 30},
        "network": {"user_agent": "Mozilla/5.0"}
    }
    
    def __init__(self, config_path="config.json"):
        self.config_path = config_path
        self.config = self.load()
    
    def load(self):
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r') as f:
                    return json.load(f)
            except:
                self.save(self.DEFAULT_CONFIG)
                return self.DEFAULT_CONFIG
        else:
            self.save(self.DEFAULT_CONFIG)
            return self.DEFAULT_CONFIG
    
    def save(self, config=None):
        if config is None:
            config = self.config
        with open(self.config_path, 'w') as f:
            json.dump(config, f, indent=4)
    
    def get(self, key, default=None):
        keys = key.split('.')
        value = self.config
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
                if value is None:
                    return default
            else:
                return default
        return value
    
    def set(self, key, value):
        keys = key.split('.')
        config = self.config
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        config[keys[-1]] = value
        self.save()