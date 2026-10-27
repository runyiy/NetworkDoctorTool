"""S1 mutation-boundary tests; safe with the standard library alone.

Legacy modules are parsed, not imported: importing the old optimizer can load
optional dependencies. Each original function body is compiled in isolation
and invoked with inputs that fail on any access. The first executable action
must reject the operation, before command, registry, privilege or input work.
"""

from __future__ import annotations

import ast
import copy
import importlib.util
import inspect
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "src" / "losshound" / "core"
_SPEC = importlib.util.spec_from_file_location(
    "s1_read_only_policy", CORE / "read_only_policy.py"
)
assert _SPEC is not None and _SPEC.loader is not None
_POLICY = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_POLICY)

MUTATORS = {
    "optimizer.py": {
        "_write_dns_state", "apply_dns", "disable_tcp_heuristics",
        "optimize_tcp", "optimize_adapter", "optimize_winsock_datagram_threshold",
        "optimize_eee", "optimize_rsc", "optimize_lso", "flush_dns_cache",
        "flush_arp_cache", "apply_system_responsiveness",
        "benchmark_optimal_responsiveness", "disable_network_throttling",
        "optimize_nagle", "apply_mtu", "restore_backup", "optimize_all",
    },
    "qos.py": {
        "apply_rule", "remove_rule", "remove_all_losshound_policies",
        "apply_all_active_rules",
    },
    "firewall.py": {
        "_run_powershell", "ensure_lan_discovery_firewall_rules",
        "remove_lan_discovery_firewall_rules", "apply_firewall_preference",
    },
}


class _Untouchable:
    def __getattribute__(self, name):
        raise AssertionError(f"Operation touched input before rejecting: {name}")

    def __bool__(self):
        raise AssertionError("Operation tested input before rejecting")

    def __str__(self):
        raise AssertionError("Operation formatted input before rejecting")


class ReadOnlyPolicyTests(unittest.TestCase):
    def test_policy_always_refuses_without_reading_configuration(self):
        for operation in ("optimizer.apply_dns", "qos.apply_rule", "firewall.remove"):
            with self.subTest(operation=operation):
                with self.assertRaisesRegex(
                    _POLICY.NetworkModificationDisabledError,
                    "S1 permits read-only diagnostics only",
                ):
                    _POLICY.reject_network_modification(operation)

    def test_every_legacy_mutator_refuses_before_any_other_work(self):
        for filename, names in MUTATORS.items():
            tree = ast.parse((CORE / filename).read_text(encoding="utf-8"))
            functions = {
                node.name: node
                for node in ast.walk(tree)
                if isinstance(node, ast.FunctionDef) and node.name in names
            }
            self.assertEqual(set(functions), names)
            for name, original in functions.items():
                with self.subTest(module=filename, function=name):
                    node = copy.deepcopy(original)
                    node.decorator_list = []
                    first_index = int(ast.get_docstring(node) is not None)
                    first = node.body[first_index]
                    self.assertIsInstance(first, ast.Expr)
                    self.assertIsInstance(first.value, ast.Call)
                    self.assertIsInstance(first.value.func, ast.Name)
                    self.assertEqual(first.value.func.id, "reject_network_modification")
                    unit = ast.Module(
                        body=[
                            ast.ImportFrom(
                                module="__future__",
                                names=[ast.alias(name="annotations")], level=0,
                            ),
                            node,
                        ],
                        type_ignores=[],
                    )
                    ast.fix_missing_locations(unit)
                    namespace = {
                        "reject_network_modification": _POLICY.reject_network_modification
                    }
                    exec(compile(unit, filename, "exec"), namespace)
                    function = namespace[name]
                    arguments = {
                        parameter.name: _Untouchable()
                        for parameter in inspect.signature(function).parameters.values()
                        if parameter.default is inspect.Parameter.empty
                        and parameter.kind not in (
                            inspect.Parameter.VAR_POSITIONAL,
                            inspect.Parameter.VAR_KEYWORD,
                        )
                    }
                    with self.assertRaises(_POLICY.NetworkModificationDisabledError):
                        function(**arguments)

    def test_all_existing_registry_write_sites_are_inside_guarded_entries(self):
        tree = ast.parse((CORE / "optimizer.py").read_text(encoding="utf-8"))
        checked = []

        def visit(node, enclosing=()):
            if isinstance(node, ast.FunctionDef):
                enclosing += (node.name,)
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "winreg"
                and node.func.attr in {"SetValueEx", "DeleteValue", "CreateKeyEx"}
            ):
                checked.append(node.lineno)
                self.assertTrue(
                    set(enclosing) & MUTATORS["optimizer.py"],
                    f"Registry write at line {node.lineno} lacks a guarded entry",
                )
            for child in ast.iter_child_nodes(node):
                visit(child, enclosing)

        visit(tree)
        self.assertGreater(len(checked), 0)

    def test_read_only_queries_remain_unguarded(self):
        expected = {
            "optimizer.py": {"get_current_dns", "get_tcp_settings", "get_active_adapter", "get_optimization_status"},
            "qos.py": {"get_existing_policies", "load_saved_rules"},
        }
        for filename, names in expected.items():
            tree = ast.parse((CORE / filename).read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef) and node.name in names:
                    with self.subTest(module=filename, function=node.name):
                        index = int(ast.get_docstring(node) is not None)
                        first = node.body[index]
                        self.assertFalse(
                            isinstance(first, ast.Expr)
                            and isinstance(first.value, ast.Call)
                            and isinstance(first.value.func, ast.Name)
                            and first.value.func.id == "reject_network_modification"
                        )


if __name__ == "__main__":
    unittest.main()
