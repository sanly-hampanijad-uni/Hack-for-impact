import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from spark_cve.config import load_nvd_key


class KeyConfigTests(unittest.TestCase):
    def test_file_loaded_without_exporting_to_test_environment(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / ".env"
            path.write_text('# config\nexport NVD_API_KEY="fixture-key" # comment\nOLLAMA_URL=http://ignored\n')
            with patch.dict(os.environ, {}, clear=True):
                self.assertEqual(load_nvd_key(env_file=path), "fixture-key")
                self.assertNotIn("NVD_API_KEY", os.environ)
                self.assertNotIn("OLLAMA_URL", os.environ)

    def test_environment_and_explicit_prompt_override_file(self):
        with patch.dict(os.environ, {"NVD_API_KEY": "environment-key"}), patch("spark_cve.config.getpass.getpass", return_value="prompt-key"):
            self.assertEqual(load_nvd_key(env_file="nonexistent.env"), "environment-key")
            self.assertEqual(load_nvd_key(env_file="nonexistent.env", prompt=True), "prompt-key")

    def test_default_missing_file_allows_keyless_requests(self):
        with tempfile.TemporaryDirectory() as root, patch.dict(os.environ, {}, clear=True):
            with patch("spark_cve.config.DEFAULT_ENV_FILE", Path(root) / ".env"):
                self.assertIsNone(load_nvd_key())

    def test_explicit_missing_file_is_reported(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(FileNotFoundError):
                load_nvd_key(env_file="/does-not-exist/settings.env")

    def test_bad_quoting_does_not_expose_key_in_error(self):
        with tempfile.TemporaryDirectory() as root, patch.dict(os.environ, {}, clear=True):
            path = Path(root) / ".env"
            path.write_text('NVD_API_KEY="fixture-secret\n')
            with self.assertRaises(ValueError) as error:
                load_nvd_key(env_file=path)
            self.assertNotIn("fixture-secret", str(error.exception))


if __name__ == "__main__":
    unittest.main()
