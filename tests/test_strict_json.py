import unittest
from tests import _util  # noqa
from agent_security_toolkit import strict_json as sj
from agent_security_toolkit.errors import ConfigError


class StrictJson(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(sj.loads('{"a": [1, "x"]}'), {"a": [1, "x"]})

    def test_rejects(self):
        for bad in ['{"a":1,"a":2}', '{"a": NaN}', '{"a": Infinity}', '[' * 40 + ']' * 40,
                    b'\xff\xfe', '', '{"a":', '{"a":1} trailing']:
            with self.subTest(bad=bad[:20]):
                with self.assertRaises(ConfigError):
                    sj.loads(bad)

    def test_size_limit(self):
        with self.assertRaises(ConfigError):
            sj.loads('"' + "a" * (1 << 20) + '"')

    def test_canonical_stable(self):
        self.assertEqual(sj.canonical({"b": 1, "a": 2}), sj.canonical({"a": 2, "b": 1}))

    def test_require_keys(self):
        with self.assertRaises(ConfigError):
            sj.require_keys({"a": 1, "z": 2}, ("a",), (), "x")
        with self.assertRaises(ConfigError):
            sj.require_keys({}, ("a",), (), "x")
        with self.assertRaises(ConfigError):
            sj.require_keys([], ("a",), (), "x")
