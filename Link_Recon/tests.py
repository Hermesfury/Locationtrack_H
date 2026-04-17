#!/usr/bin/env python3
"""
Link Recon - Unit Tests
Run with: python -m pytest tests.py -v
"""

import unittest
import tempfile
import json
import os
from infogather import Config

class TestConfig(unittest.TestCase):
    def test_default_config(self):
        """Test default configuration values."""
        config = Config()
        self.assertEqual(config.host, "0.0.0.0")
        self.assertEqual(config.port, 5000)
        self.assertTrue(config.use_https)  # Should be True by default now
        self.assertEqual(config.output_dir, "reports")

    def test_config_validation_valid(self):
        """Test valid configuration loading."""
        config_data = {
            "host": "127.0.0.1",
            "port": 8080,
            "use_https": False,
            "rate_limit": 100
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(config_data, f)
            config_file = f.name

        try:
            config = Config().load_from_file(config_file)
            self.assertEqual(config.host, "127.0.0.1")
            self.assertEqual(config.port, 8080)
            self.assertFalse(config.use_https)
            self.assertEqual(config.rate_limit, 100)
        finally:
            os.unlink(config_file)

    def test_config_validation_invalid_port(self):
        """Test invalid port validation."""
        config_data = {"port": 70000}  # Invalid port

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(config_data, f)
            config_file = f.name

        try:
            with self.assertRaises(ValueError) as cm:
                Config().load_from_file(config_file)
            self.assertIn("port must be an integer between 1 and 65535", str(cm.exception))
        finally:
            os.unlink(config_file)

    def test_config_validation_invalid_type(self):
        """Test invalid type validation."""
        config_data = {"use_https": "true"}  # Should be boolean

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(config_data, f)
            config_file = f.name

        try:
            with self.assertRaises(ValueError) as cm:
                Config().load_from_file(config_file)
            self.assertIn("use_https must be a boolean", str(cm.exception))
        finally:
            os.unlink(config_file)

class TestRateLimiter(unittest.TestCase):
    def test_rate_limiter_allow(self):
        """Test rate limiter allows requests within limit."""
        from infogather import RateLimiter
        limiter = RateLimiter(limit=2)

        # Should allow first two requests
        self.assertTrue(limiter.is_allowed("192.168.1.1"))
        self.assertTrue(limiter.is_allowed("192.168.1.1"))

        # Should deny third request
        self.assertFalse(limiter.is_allowed("192.168.1.1"))

if __name__ == '__main__':
    unittest.main()