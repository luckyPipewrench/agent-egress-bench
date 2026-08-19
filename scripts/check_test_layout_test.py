"""Every test module must define all of its test classes before it runs them.

A ``unittest.main()`` call placed above later class definitions still executes and still reports
success: the classes below it do not exist yet when ``unittest.main()`` collects, so they are
silently skipped under direct execution. The module looks green while part of it never ran.
Discovery-based runners import the whole module and are unaffected, which is exactly why the gap
survives review.

The check anchors on the RUNNER CALL, not on the ``__name__`` guard around it. Matching the guard
condition can be walked around without changing what the module does, by naming the condition
first (``is_main = __name__ == "__main__"``) or by invoking the runner under any other top-level
condition. The call is the thing that ends collection, so the call is what the check looks for.

Import form is part of that call, not decoration around it. ``from unittest import main`` binds a
bare name and ``import unittest as ut`` renames the module, so the local names are resolved first
and the call is matched against those rather than against a literal spelling.
"""

from __future__ import annotations

import ast
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent

# Calls that collect and run the tests defined so far. A module that reaches one of these has
# already decided what it will run.
RUNNER_MODULES = {"unittest", "pytest"}
RUNNER_ATTRIBUTES = {"main", "TextTestRunner"}


def _runner_names(tree: ast.Module) -> tuple[set[str], set[str]]:
    """Return the local names bound to a runner module and to a runner callable.

    Import forms are part of the grammar this check reads. ``from unittest import main``
    binds a bare ``main`` that no attribute matcher sees, and ``import unittest as ut``
    renames the module, so keying on the literal spelling misses both while the module
    still ends collection at that call.
    """
    modules: set[str] = set()
    callables: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in RUNNER_MODULES:
                    modules.add(alias.asname or alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module not in RUNNER_MODULES:
                continue
            for alias in node.names:
                if alias.name in RUNNER_ATTRIBUTES:
                    callables.add(alias.asname or alias.name)
    return modules, callables


def _runner_call_line(node: ast.AST, modules: set[str], callables: set[str]) -> int | None:
    for descendant in ast.walk(node):
        if not isinstance(descendant, ast.Call):
            continue
        function = descendant.func
        if isinstance(function, ast.Attribute) and isinstance(function.value, ast.Name):
            if function.value.id in modules and function.attr in RUNNER_ATTRIBUTES:
                return descendant.lineno
        elif isinstance(function, ast.Name) and function.id in callables:
            return descendant.lineno
    return None


def _definitions_after_the_runner(source: str) -> list[str]:
    tree = ast.parse(source)
    modules, callables = _runner_names(tree)
    runner_line = None
    for node in tree.body:
        line = _runner_call_line(node, modules, callables)
        if line is not None:
            runner_line = line
            break
    if runner_line is None:
        return []
    return [
        node.name
        for node in tree.body
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
        and node.lineno > runner_line
    ]


class TestLayoutTest(unittest.TestCase):
    def test_no_test_module_defines_a_class_below_its_runner_call(self) -> None:
        offenders = {}
        for path in sorted(SCRIPTS.glob("*_test.py")):
            names = _definitions_after_the_runner(path.read_text(encoding="utf-8"))
            if names:
                offenders[path.name] = names
        self.assertEqual({}, offenders)

    def test_an_aliased_guard_does_not_hide_a_late_definition(self) -> None:
        """The bypass the earlier version of this check allowed.

        Keying on the guard CONDITION meant a module could compute it into a name first and place
        classes below the runner call unnoticed.
        """
        aliased = (
            "import unittest\n"
            "class Early(unittest.TestCase):\n"
            "    pass\n"
            "is_main = __name__ == '__main__'\n"
            "if is_main:\n"
            "    unittest.main()\n"
            "class Late(unittest.TestCase):\n"
            "    pass\n"
        )
        self.assertEqual(["Late"], _definitions_after_the_runner(aliased))

    def test_an_unguarded_runner_call_also_counts(self) -> None:
        unguarded = (
            "import unittest\n"
            "unittest.main()\n"
            "class Late(unittest.TestCase):\n"
            "    pass\n"
        )
        self.assertEqual(["Late"], _definitions_after_the_runner(unguarded))

    def test_a_module_whose_classes_all_precede_the_runner_is_clean(self) -> None:
        ordered = (
            "import unittest\n"
            "class Early(unittest.TestCase):\n"
            "    pass\n"
            "if __name__ == '__main__':\n"
            "    unittest.main()\n"
        )
        self.assertEqual([], _definitions_after_the_runner(ordered))

    def test_an_imported_runner_name_is_recognized(self) -> None:
        """``from unittest import main`` binds a bare name no attribute matcher sees."""
        imported = (
            "from unittest import main\n"
            "import unittest\n"
            "class Early(unittest.TestCase):\n"
            "    pass\n"
            "if __name__ == '__main__':\n"
            "    main()\n"
            "class Late(unittest.TestCase):\n"
            "    pass\n"
        )
        self.assertEqual(["Late"], _definitions_after_the_runner(imported))

    def test_a_renamed_runner_module_is_recognized(self) -> None:
        renamed = (
            "import unittest as ut\n"
            "class Early(ut.TestCase):\n"
            "    pass\n"
            "if __name__ == '__main__':\n"
            "    ut.main()\n"
            "class Late(ut.TestCase):\n"
            "    pass\n"
        )
        self.assertEqual(["Late"], _definitions_after_the_runner(renamed))

    def test_an_unrelated_main_call_is_not_a_runner(self) -> None:
        """Availability direction: a module with its own main() is not running tests."""
        unrelated = (
            "import unittest\n"
            "from mytool import main\n"
            "main()\n"
            "class Late(unittest.TestCase):\n"
            "    pass\n"
        )
        self.assertEqual([], _definitions_after_the_runner(unrelated))

    def test_a_module_with_no_runner_call_is_clean(self) -> None:
        # Discovery-only modules never collect for themselves, so ordering cannot hide anything.
        library = "import unittest\nclass Only(unittest.TestCase):\n    pass\n"
        self.assertEqual([], _definitions_after_the_runner(library))


if __name__ == "__main__":
    unittest.main()
