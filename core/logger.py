#!/usr/bin/env python3

import logging
import sys
from datetime import datetime

class Logger:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._setup()
        return cls._instance
    
    def _setup(self):
        self.logger = logging.getLogger('RedHawk')
        self.logger.setLevel(logging.DEBUG)
        
        console = logging.StreamHandler(sys.stdout)
        console.setLevel(logging.DEBUG)
        formatter = logging.Formatter('[%(asctime)s] %(message)s', datefmt='%H:%M:%S')
        console.setFormatter(formatter)
        self.logger.addHandler(console)
        
        try:
            file_handler = logging.FileHandler('redhawk.log', encoding='utf-8')
            file_handler.setLevel(logging.DEBUG)
            file_formatter = logging.Formatter('[%(asctime)s] %(message)s')
            file_handler.setFormatter(file_formatter)
            self.logger.addHandler(file_handler)
        except:
            file_handler = logging.FileHandler('redhawk.log')
            file_handler.setLevel(logging.DEBUG)
            file_formatter = logging.Formatter('[%(asctime)s] %(message)s')
            file_handler.setFormatter(file_formatter)
            self.logger.addHandler(file_handler)
    
    def info(self, msg): 
        self.logger.info(msg)
    
    def warning(self, msg): 
        self.logger.warning(msg)
    
    def error(self, msg): 
        self.logger.error(msg)
    
    def debug(self, msg): 
        self.logger.debug(msg)

logger = Logger()