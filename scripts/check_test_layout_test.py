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
"""

from __future__ import annotations

import ast
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent

# Calls that collect and run the tests defined so far. A module that reaches one of these has
# already decided what it will run.
RUNNERS = {("unittest", "main"), ("pytest", "main")}
TEXT_TEST_RUNNER = ("unittest", "TextTestRunner")


def _definition_header_nodes(node: ast.AST) -> list[ast.AST]:
    """Return expressions evaluated while a definition is being created."""
    if isinstance(node, ast.ClassDef):
        return [*node.decorator_list, *node.bases, *(keyword.value for keyword in node.keywords)]
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        arguments = node.args
        annotations = [argument.annotation for argument in (*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs)]
        return [
            *node.decorator_list,
            *arguments.defaults,
            *(default for default in arguments.kw_defaults if default is not None),
            *(annotation for annotation in annotations if annotation is not None),
            *([node.returns] if node.returns is not None else []),
        ]
    return []


def _record_runner_imports(
    node: ast.AST, module_names: dict[str, str], function_names: set[str], class_names: set[str]
) -> None:
    if isinstance(node, ast.Import):
        for alias in node.names:
            if alias.name in {"unittest", "pytest"}:
                module_names[alias.asname or alias.name] = alias.name
    elif isinstance(node, ast.ImportFrom) and node.module in {"unittest", "pytest"}:
        for alias in node.names:
            if alias.name == "main":
                function_names.add(alias.asname or alias.name)
            if node.module == "unittest" and alias.name == "TextTestRunner":
                class_names.add(alias.asname or alias.name)


def _is_text_test_runner_call(
    function: ast.AST, module_names: dict[str, str], class_names: set[str]
) -> bool:
    if not isinstance(function, ast.Attribute) or function.attr != "run" or not isinstance(function.value, ast.Call):
        return False
    constructor = function.value.func
    if isinstance(constructor, ast.Attribute) and isinstance(constructor.value, ast.Name):
        return (module_names.get(constructor.value.id, constructor.value.id), constructor.attr) == TEXT_TEST_RUNNER
    return isinstance(constructor, ast.Name) and constructor.id in class_names


def _runner_call_line(
    node: ast.AST, module_names: dict[str, str], function_names: set[str], class_names: set[str]
) -> int | None:
    """Find a runner executed while the module itself is loading.

    A runner in a function or class body does not collect the module while it
    loads, even if that definition appears before another test class. Its
    decorators, bases, and default values do run at definition time, so those
    header expressions must still be checked.
    """
    pending = [node]
    while pending:
        descendant = pending.pop()
        if isinstance(descendant, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            pending.extend(_definition_header_nodes(descendant))
            continue
        if isinstance(descendant, ast.Lambda):
            # The BODY is deferred until the lambda is called, so it cannot end collection while
            # the module loads. The DEFAULTS are not: they are evaluated where the lambda is
            # written, so a module-level `lambda value=unittest.main(): value` runs the runner
            # right there. Skipping the whole node missed that.
            pending.extend(descendant.args.defaults)
            pending.extend(default for default in descendant.args.kw_defaults if default is not None)
            continue
        if isinstance(descendant, ast.Call):
            function = descendant.func
            if isinstance(function, ast.Attribute) and isinstance(function.value, ast.Name):
                if (module_names.get(function.value.id, function.value.id), function.attr) in RUNNERS:
                    return descendant.lineno
            if isinstance(function, ast.Name) and function.id in function_names:
                return descendant.lineno
            if _is_text_test_runner_call(function, module_names, class_names):
                return descendant.lineno
        pending.extend(ast.iter_child_nodes(descendant))
    return None


def _definitions_after_the_runner(source: str) -> list[str]:
    tree = ast.parse(source)
    runner_line = None
    module_names = {"unittest": "unittest", "pytest": "pytest"}
    function_names: set[str] = set()
    class_names: set[str] = set()
    for node in tree.body:
        _record_runner_imports(node, module_names, function_names, class_names)
        line = _runner_call_line(node, module_names, function_names, class_names)
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

    def test_a_runner_in_a_lambda_default_counts(self) -> None:
        """A lambda default runs where the lambda is written, not when it is called."""
        in_default = (
            "import unittest\n"
            "handler = lambda value=unittest.main(): value\n"
            "class Late(unittest.TestCase):\n"
            "    pass\n"
        )
        self.assertEqual(["Late"], _definitions_after_the_runner(in_default))

    def test_a_runner_in_a_lambda_body_does_not_count(self) -> None:
        """The body is deferred, so it cannot end collection while the module loads."""
        in_body = (
            "import unittest\n"
            "handler = lambda: unittest.main()\n"
            "class Late(unittest.TestCase):\n"
            "    pass\n"
        )
        self.assertEqual([], _definitions_after_the_runner(in_body))

    def test_an_unguarded_runner_call_also_counts(self) -> None:
        unguarded = (
            "import unittest\n"
            "unittest.main()\n"
            "class Late(unittest.TestCase):\n"
            "    pass\n"
        )
        self.assertEqual(["Late"], _definitions_after_the_runner(unguarded))

    def test_an_imported_runner_alias_also_counts(self) -> None:
        imported = (
            "from unittest import main as run\n"
            "run()\n"
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
        """Availability direction: a module with its own entry point is not running tests.

        Import tracking is what keeps this apart from the runner cases above, and a behavior
        with no test behind it can regress into refusing modules nobody can fix.
        """
        unrelated = (
            "import unittest\n"
            "from mytool import main\n"
            "main()\n"
            "class Late(unittest.TestCase):\n"
            "    pass\n"
        )
        self.assertEqual([], _definitions_after_the_runner(unrelated))

    def test_constructing_a_text_runner_does_not_hide_a_late_definition(self) -> None:
        constructed = (
            "import unittest\n"
            "runner = unittest.TextTestRunner()\n"
            "class Late(unittest.TestCase):\n"
            "    pass\n"
        )
        self.assertEqual([], _definitions_after_the_runner(constructed))

    def test_running_a_text_runner_does_hide_later_definitions(self) -> None:
        executed = (
            "import unittest\n"
            "unittest.TextTestRunner().run(unittest.TestSuite())\n"
            "class Late(unittest.TestCase):\n"
            "    pass\n"
        )
        self.assertEqual(["Late"], _definitions_after_the_runner(executed))

    def test_a_runner_in_an_uninvoked_function_does_not_hide_a_late_definition(self) -> None:
        deferred = (
            "import unittest\n"
            "def helper():\n"
            "    unittest.main()\n"
            "class Late(unittest.TestCase):\n"
            "    pass\n"
        )
        self.assertEqual([], _definitions_after_the_runner(deferred))

    def test_a_runner_in_a_definition_decorator_is_not_deferred(self) -> None:
        decorated = (
            "import unittest\n"
            "@unittest.main()\n"
            "class Early(unittest.TestCase):\n"
            "    pass\n"
            "class Late(unittest.TestCase):\n"
            "    pass\n"
        )
        self.assertEqual(["Early", "Late"], _definitions_after_the_runner(decorated))

    def test_a_module_whose_classes_all_precede_the_runner_is_clean(self) -> None:
        ordered = (
            "import unittest\n"
            "class Early(unittest.TestCase):\n"
            "    pass\n"
            "if __name__ == '__main__':\n"
            "    unittest.main()\n"
        )
        self.assertEqual([], _definitions_after_the_runner(ordered))

    def test_a_module_with_no_runner_call_is_clean(self) -> None:
        # Discovery-only modules never collect for themselves, so ordering cannot hide anything.
        library = "import unittest\nclass Only(unittest.TestCase):\n    pass\n"
        self.assertEqual([], _definitions_after_the_runner(library))


if __name__ == "__main__":
    unittest.main()
