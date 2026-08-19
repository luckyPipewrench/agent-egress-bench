"""Every test module must define all of its test classes before it runs them.

A ``if __name__ == "__main__": unittest.main()`` block placed above later class definitions
still executes and still reports success: the classes below it do not exist yet when
``unittest.main()`` collects, so they are silently skipped under direct execution. The module
looks green while part of it never ran. Discovery-based runners import the whole module and are
unaffected, which is exactly why the gap survives review.
"""

from __future__ import annotations

import ast
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent


def _definitions_after_main_guard(source: str) -> list[str]:
    tree = ast.parse(source)
    guard_line = None
    for node in tree.body:
        if isinstance(node, ast.If) and ast.dump(node.test).find("__name__") != -1:
            guard_line = node.lineno
            break
    if guard_line is None:
        return []
    return [
        node.name
        for node in tree.body
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
        and node.lineno > guard_line
    ]


class TestLayoutTest(unittest.TestCase):
    def test_no_test_module_defines_a_class_below_its_main_guard(self) -> None:
        offenders = {}
        for path in sorted(SCRIPTS.glob("*_test.py")):
            names = _definitions_after_main_guard(path.read_text(encoding="utf-8"))
            if names:
                offenders[path.name] = names
        self.assertEqual({}, offenders)


if __name__ == "__main__":
    unittest.main()
