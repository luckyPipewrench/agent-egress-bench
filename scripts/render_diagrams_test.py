"""Tests for the README asset generator.

The generator exists to stop failures that are all invisible in review: a
light and dark diagram pair drifting apart, a drawing describing a corpus that
has moved on, a count painted into an asset going stale, a terminal mock-up
showing checks the doctor no longer runs, and a raster exported from an older
vector. Each is asserted here, including the case where the gate itself would
pass while proving nothing.
"""

from __future__ import annotations

import importlib.util
import json
import math
import re
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

# Every input parsed here is a string this same module just generated from a
# literal template, so the stdlib parser sees no untrusted document and the
# repository keeps its stdlib-only tooling rule.
import xml.etree.ElementTree as ElementTree
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "render_diagrams.py"

spec = importlib.util.spec_from_file_location("render_diagrams", SCRIPT)
assert spec and spec.loader
generator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(generator)

SVG = "{http://www.w3.org/2000/svg}"


def _strings(svg: str) -> list[str]:
    """Every rendered text run, in document order."""
    return [(node.text or "").strip() for node in ElementTree.fromstring(svg).iter(SVG + "text")]


def _extents(node) -> list:
    """Bounding boxes for the primitives this generator draws.

    Rects and circles have exact boxes. Paths, polygons and text do not without
    a full SVG engine, so they are left out rather than approximated: a wrong
    box would either fire falsely or hide a real overrun.
    """
    tag = node.tag.rsplit("}", 1)[-1]
    try:
        if tag == "rect":
            x, y = float(node.get("x", 0)), float(node.get("y", 0))
            return [(x, y, x + float(node.get("width", 0)), y + float(node.get("height", 0)))]
        if tag == "circle":
            cx, cy, r = float(node.get("cx", 0)), float(node.get("cy", 0)), float(node.get("r", 0))
            return [(cx - r, cy - r, cx + r, cy + r)]
        if tag == "ellipse":
            cx, cy = float(node.get("cx", 0)), float(node.get("cy", 0))
            rx, ry = float(node.get("rx", 0)), float(node.get("ry", 0))
            return [(cx - rx, cy - ry, cx + rx, cy + ry)]
    except (TypeError, ValueError):
        return []
    return []


GEOMETRY_ATTRS = ("x", "y", "width", "height", "cx", "cy", "r", "rx", "ry",
                  "x1", "y1", "x2", "y2", "d", "points", "transform", "text-anchor")


def _geometry(root) -> list:
    """Tag plus every position-bearing attribute, ignoring color and opacity.

    Comparing tag sequences alone let a light and dark pair differ in every
    coordinate while the parity gate passed.
    """
    return [
        (node.tag, tuple((a, node.get(a)) for a in GEOMETRY_ATTRS if node.get(a) is not None))
        for node in root.iter()
    ]


class _swap:
    """Temporarily replace a generator attribute; restores on exit."""

    def __init__(self, attribute, value):
        self.attribute, self.value = attribute, value

    def __enter__(self):
        self.saved = getattr(generator, self.attribute)
        setattr(generator, self.attribute, self.value)

    def __exit__(self, *_):
        setattr(generator, self.attribute, self.saved)


class WellFormedTest(unittest.TestCase):
    def test_every_generated_asset_parses(self):
        for path, content in generator.build().items():
            with self.subTest(asset=path.name):
                ElementTree.fromstring(content)

    def test_every_asset_declares_an_accessible_label(self):
        for path, content in generator.build().items():
            with self.subTest(asset=path.name):
                root = ElementTree.fromstring(content)
                self.assertEqual(root.get("role"), "img")
                self.assertTrue((root.get("aria-label") or "").strip())

    def test_no_asset_depends_on_an_svg_marker(self):
        # Arrowheads are drawn as paths. Some renderers and sanitizers drop
        # <marker>, which removes every arrowhead while leaving a well-formed
        # file and a green check.
        for path, content in generator.build().items():
            with self.subTest(asset=path.name):
                self.assertNotIn("<marker", content)
                self.assertNotIn("marker-end", content)

    def test_no_asset_uses_rgba_notation(self):
        # An SVG 1.1 presentation attribute takes a CSS2 <color>, which has no
        # rgba(). Browsers accept it, so GitHub looked right while Inkscape and
        # other converters painted the light-theme cards solid black.
        for path, content in generator.build().items():
            with self.subTest(asset=path.name):
                self.assertNotIn("rgba(", content)

    def test_every_asset_fits_its_own_canvas(self):
        # A shape past the right edge is clipped silently by the viewBox.
        for path, content in generator.build().items():
            with self.subTest(asset=path.name):
                root = ElementTree.fromstring(content)
                _, _, width, height = (float(v) for v in root.get("viewBox").split())
                for node in root.iter():
                    for x0, y0, x1, y1 in _extents(node):
                        self.assertGreaterEqual(x0, -0.5, f"{path.name}: {node.tag} is left of the canvas")
                        self.assertGreaterEqual(y0, -0.5, f"{path.name}: {node.tag} is above the canvas")
                        self.assertLessEqual(x1, width + 0.5, f"{path.name}: {node.tag} overruns the right edge")
                        self.assertLessEqual(y1, height + 0.5, f"{path.name}: {node.tag} overruns the bottom edge")

    def test_the_hero_and_logo_carry_no_corpus_count(self):
        # They are hand-exported rasters that change rarely, so a number in
        # them would rot silently. Counts belong in the stats strip.
        for name in ("social-preview.svg", "logo.svg"):
            text = " ".join(_strings(generator.SINGLES[name]()))
            with self.subTest(asset=name):
                self.assertNotIn(str(generator.live_case_total()), text)
                self.assertNotIn(f"{len(generator.live_categories())} ", text)

    def test_the_hero_uses_the_brand_treatment(self):
        hero = generator.social_preview()
        self.assertIn(generator.BRAND["bg"], hero)
        self.assertIn(generator.BRAND["accent"], hero)
        self.assertIn(generator.BRAND["purple"], hero)  # hero radial only
        self.assertIn("PipeLab", hero)
        self.assertNotIn("Pipelab", hero)

    def test_the_hero_wordmark_reads_as_three_separate_words(self):
        """The wordmark is one text run coloured with tspans, so spacing is fragile.

        Without xml:space="preserve" the renderer collapses the trailing space
        inside the first tspan and the mark reads "EgressBench". Concatenating
        the tspan text is what catches that; checking the source string would
        pass, because the space is present in the file either way.
        """
        root = ElementTree.fromstring(generator.social_preview())
        runs = ["".join(node.itertext()) for node in root.iter(SVG + "text")]
        wordmark = next((run for run in runs if "Bench" in run and "Agent" in run), None)
        self.assertIsNotNone(wordmark, f"no wordmark run found in {runs}")
        self.assertEqual(wordmark.split(), ["Agent", "Egress", "Bench"])
        self.assertIn("Agent Egress Bench", wordmark)

    def test_the_hero_wordmark_is_a_single_line(self):
        """One line, so there is no second line to centre and mis-centre.

        The two-line version positioned "Bench" using a width computed from an
        assumed glyph advance, which did not match the font, so it sat visibly
        off-centre while the arithmetic looked right.
        """
        root = ElementTree.fromstring(generator.social_preview())
        carrying = [node for node in root.iter(SVG + "text")
                    if "Bench" in "".join(node.itertext())
                    or "Agent Egress" in "".join(node.itertext())]
        self.assertEqual(len(carrying), 1, "the wordmark spans more than one text element")

    def test_every_explicit_asset_color_is_a_brand_token_or_light_adaptation(self):
        approved = (set(generator.BRAND.values()) | generator.LIGHT_THEME_DERIVATIVES
                    | generator.OVERLAY_BASES)
        for path, content in generator.build().items():
            with self.subTest(asset=path.name):
                colors = set(re.findall(r"#[0-9a-f]{6}\b", content.lower()))
                # Without this the regex could match nothing and the subset
                # check below would pass while proving nothing, which is how
                # this gate shipped vacuous the first time.
                self.assertTrue(colors, f"{path.name}: the color scan matched nothing")
                self.assertTrue(colors <= approved, colors - approved)


class ThemeParityTest(unittest.TestCase):
    """A pair that says different things is the failure the generator prevents."""

    def test_light_and_dark_carry_identical_copy(self):
        for name, render in generator.DIAGRAMS.items():
            with self.subTest(diagram=name):
                self.assertEqual(_strings(render(generator.PALETTES["light"])),
                                 _strings(render(generator.PALETTES["dark"])))

    def test_light_and_dark_carry_identical_geometry(self):
        for name, render in generator.DIAGRAMS.items():
            with self.subTest(diagram=name):
                light = ElementTree.fromstring(render(generator.PALETTES["light"]))
                dark = ElementTree.fromstring(render(generator.PALETTES["dark"]))
                self.assertEqual(_geometry(light), _geometry(dark))

    def test_the_two_palettes_actually_differ(self):
        light, dark = generator.PALETTES["light"], generator.PALETTES["dark"]
        self.assertEqual(set(light), set(dark))
        self.assertNotEqual(light["text"], dark["text"])
        self.assertNotEqual(light["accent_text"], dark["accent_text"])

    def test_readme_diagrams_are_transparent(self):
        # A painted canvas reads as a pasted rectangle on the other theme.
        for theme in generator.PALETTES.values():
            self.assertEqual(theme["canvas"], "none")


class CorpusAgreementTest(unittest.TestCase):
    def test_the_committed_assets_match_the_live_corpus(self):
        self.assertEqual(generator.verify_against_corpus(), [])

    def test_a_new_category_without_a_group_is_reported(self):
        real = generator.live_category_counts
        with _swap("live_category_counts", lambda: {**real(), "brand_new_surface": 3}):
            problems = generator.verify_against_corpus()
        self.assertTrue(any("brand_new_surface" in p for p in problems), problems)

    def test_a_group_entry_with_no_cases_is_reported(self):
        counts = generator.live_category_counts()
        removed = sorted(counts)[0]
        counts.pop(removed)
        with _swap("live_category_counts", lambda: counts):
            problems = generator.verify_against_corpus()
        self.assertTrue(any(removed in p for p in problems), problems)

    def test_a_category_in_two_groups_is_reported(self):
        doubled = generator.COVERAGE_GROUPS + (("dup", "Duplicate", (("url", "URL again"),)),)
        with _swap("COVERAGE_GROUPS", doubled):
            problems = generator.verify_against_corpus()
        self.assertTrue(any("more than one group" in p for p in problems), problems)

    def test_the_coverage_chart_absorbs_a_new_group(self):
        # The treemap is data-driven: a new group gets a tile and every other
        # tile shrinks to make room, inside the same canvas. Nothing clips.
        base = generator.coverage(generator.PALETTES["dark"])
        grown = generator.COVERAGE_GROUPS + (("future", "A surface not yet attacked", (("url", "URL"),)),)
        counts = generator.live_category_counts
        with _swap("COVERAGE_GROUPS", grown), _swap("live_category_counts", lambda: {**counts(), "url": 20}):
            more = generator.coverage(generator.PALETTES["dark"])
        self.assertIn("FUTURE", " ".join(_strings(more)))
        self.assertEqual(ElementTree.fromstring(base).get("height"), ElementTree.fromstring(more).get("height"))

    def test_the_stats_strip_carries_the_live_numbers(self):
        text = _strings(generator.stats_strip(generator.PALETTES["dark"]))
        self.assertIn(str(generator.live_case_total()), text)
        self.assertIn(str(len(generator.live_categories())), text)
        self.assertIn(str(len(generator.live_transports())), text)

    def test_a_stats_snapshot_that_disagrees_with_the_runner_is_reported(self):
        stale = generator.STATS_FILE.read_text(encoding="utf-8") + "stale\n"
        completed = SimpleNamespace(returncode=0, stdout=stale, stderr="")
        with mock.patch.object(generator.subprocess, "run", return_value=completed):
            problems = generator.runner_stats_problems()
        self.assertTrue(any("does not match the runner" in problem for problem in problems), problems)

    def test_the_transport_scan_reads_multi_file_cases_too(self):
        yaml_cases = list((generator.REPO_ROOT / "cases" / "mcp-drift").rglob("case.yaml"))
        self.assertTrue(yaml_cases, "expected multi-file drift cases")
        text = "\n".join(p.read_text(encoding="utf-8") for p in yaml_cases)
        found = {m.group(1) or m.group(2) for m in generator.TRANSPORT_FIELD.finditer(text)}
        self.assertTrue(found, "the transport regex matched nothing in case.yaml")
        self.assertTrue(found <= generator.live_transports())


class DoctorTerminalTest(unittest.TestCase):
    def test_the_drawing_lists_exactly_the_checks_the_script_reports(self):
        self.assertEqual([name for name, _ in generator.DOCTOR_LINES], generator.doctor_check_names())

    def test_the_script_parser_expands_the_command_loop(self):
        names = generator.doctor_check_names()
        self.assertIn("platform_linux", names)
        self.assertIn("command_git", names)
        self.assertIn("release_pin", names)
        self.assertNotIn("command_socat", names)  # bridge probe reports one literal name
        self.assertIn("mcp_stdio_bridge", names)

    def test_the_doctor_output_not_shell_comments_drives_the_drawing(self):
        with tempfile.TemporaryDirectory() as directory:
            doctor = Path(directory) / "doctor"
            doctor.write_text(
                "#!/bin/sh\n"
                "# add_doctor_result \"stale_comment\" ok\n"
                "printf '%s\\n' '{\"checks\":[{\"code\":\"real_check\"}]}'\n",
                encoding="utf-8",
            )
            doctor.chmod(0o755)
            with _swap("DOCTOR_SCRIPT", doctor):
                self.assertEqual(generator.doctor_check_names(), ["real_check"])

    def test_the_doctor_json_list_is_usable_when_prerequisites_fail(self):
        # --doctor-json deliberately exits nonzero when a host is missing a
        # prerequisite. It must still provide the complete check vocabulary so
        # the generated terminal can describe a host even when jq is absent.
        with tempfile.TemporaryDirectory() as directory:
            doctor = Path(directory) / "doctor"
            doctor.write_text(
                "#!/bin/sh\n"
                "printf '%s\\n' '{\"checks\":[{\"code\":\"command_jq\"}]}'\n"
                "exit 1\n",
                encoding="utf-8",
            )
            doctor.chmod(0o755)
            with _swap("DOCTOR_SCRIPT", doctor):
                self.assertEqual(generator.doctor_check_names(), ["command_jq"])

    def test_a_check_the_script_dropped_is_reported(self):
        with _swap("doctor_check_names", lambda: ["platform_linux"]):
            problems = generator.verify_against_corpus()
        self.assertTrue(any("no longer reports" in p for p in problems), problems)

    def test_a_check_the_script_grew_is_reported(self):
        grown = generator.doctor_check_names() + ["disk_space"]
        with _swap("doctor_check_names", lambda: grown):
            problems = generator.verify_against_corpus()
        self.assertTrue(any("disk_space" in p for p in problems), problems)


class CommittedAssetTest(unittest.TestCase):
    def setUp(self) -> None:
        self.readme = (generator.REPO_ROOT / "README.md").read_text(encoding="utf-8")

    def test_the_repository_assets_are_current(self):
        stale = [str(path.relative_to(generator.REPO_ROOT)) for path, content in generator.build().items()
                 if not path.exists() or path.read_text(encoding="utf-8") != content]
        self.assertEqual(stale, [], "run scripts/render_diagrams.py")

    def test_no_orphaned_generated_asset_remains(self):
        # A retired drawing left on disk keeps rendering somewhere forever.
        expected = {path.name for path in generator.build()}
        expected |= set(generator.PNG_EXPORTS) | {f"{png}.source" for png in generator.PNG_EXPORTS}
        on_disk = {path.name for path in generator.ASSET_DIR.iterdir()}
        self.assertEqual(on_disk - expected, set())

    def test_the_readme_embeds_both_themes_of_every_diagram(self):
        for name in generator.DIAGRAMS:
            with self.subTest(diagram=name):
                self.assertIn(f"assets/diagram-{name}-dark.svg", self.readme)
                self.assertIn(f"assets/diagram-{name}-light.svg", self.readme)

    def test_the_readme_embeds_the_hero_and_terminal(self):
        self.assertIn("assets/social-preview.svg", self.readme)
        self.assertIn("assets/terminal-doctor.svg", self.readme)

    def test_every_png_matches_its_source(self):
        self.assertEqual(generator.png_problems(), [])
        for png in generator.PNG_EXPORTS:
            self.assertGreater((generator.ASSET_DIR / png).stat().st_size, 1024)

    def test_a_stale_png_sidecar_is_reported(self):
        side = generator.sidecar("logo-256.png")
        real = side.read_text(encoding="utf-8")
        try:
            side.write_text("0" * 64 + "\n", encoding="utf-8")
            problems = generator.png_problems()
        finally:
            side.write_text(real, encoding="utf-8")
        self.assertTrue(any("older" in p for p in problems), problems)


class ReadmeFactsTest(unittest.TestCase):
    """Facts the README states that nothing else re-checks."""

    def setUp(self) -> None:
        self.readme = (generator.REPO_ROOT / "README.md").read_text(encoding="utf-8")

    def test_the_go_badge_matches_the_runner_module(self):
        go_mod = (generator.REPO_ROOT / "runner" / "go.mod").read_text(encoding="utf-8")
        declared = next(line.split()[1] for line in go_mod.splitlines() if line.startswith("go "))
        major_minor = ".".join(declared.split(".")[:2])
        self.assertIn(f"Go-{major_minor}%2B", self.readme,
                      f"the Go badge does not say {major_minor}+, which runner/go.mod requires")

    def test_the_required_badges_survive(self):
        # check_claim_language.py also asserts these. Duplicated on purpose:
        # a badge row rewrite is exactly when one gets dropped.
        for required in ("actions/workflows/pipelock.yaml",
                         "https://codecov.io/gh/luckyPipewrench/agent-egress-bench/graph/badge.svg"):
            with self.subTest(badge=required):
                self.assertIn(required, self.readme)

    def test_no_badge_points_at_a_retired_service(self):
        self.assertNotIn("goreportcard.com", self.readme)

    def test_the_readme_uses_the_brand_casing(self):
        # PipeLab is the company; the design system calls the casing
        # non-negotiable and the live site follows it.
        self.assertIn("maintained by [PipeLab](https://pipelab.org)", self.readme)
        self.assertNotRegex(self.readme, r"\bPipelab\b")
        self.assertNotRegex(self.readme, r"\bPipeLock\b")


class TreemapTest(unittest.TestCase):
    """The coverage treemap is a layout algorithm, so its invariants are asserted directly."""

    def test_tiles_stay_inside_the_region_and_fill_it(self):
        items = [("a", 27), ("b", 24), ("c", 20), ("d", 17), ("e", 6), ("f", 1)]
        tiles = generator._squarify(items, 10, 20, 400, 300)
        self.assertEqual([k for k, *_ in tiles], [k for k, _ in items])
        area = 0
        for _, _, x, y, w, h in tiles:
            self.assertGreaterEqual(x, 10 - 1e-6)
            self.assertGreaterEqual(y, 20 - 1e-6)
            self.assertLessEqual(x + w, 410 + 1e-6)
            self.assertLessEqual(y + h, 320 + 1e-6)
            area += w * h
        self.assertAlmostEqual(area, 400 * 300, places=3)

    def test_tile_area_is_proportional_to_count(self):
        tiles = generator._squarify([("big", 30), ("small", 10)], 0, 0, 200, 100)
        by_key = {k: w * h for k, _, x, y, w, h in tiles}
        self.assertAlmostEqual(by_key["big"] / by_key["small"], 3.0, places=6)

    def test_zero_counts_remain_finite_and_nonnegative(self):
        # A category may be introduced before it has cases. A zero must not
        # turn the layout into a division-by-zero or a made-up proportion.
        cases = (
            [("only", 0)],
            [("zero", 0), ("live", 1)],
            [("a", 0), ("b", 0), ("c", 0)],
        )
        for items in cases:
            with self.subTest(items=items):
                tiles = generator._squarify(items, 10, 20, 400, 300)
                self.assertEqual([key for key, *_ in tiles], [key for key, _ in items])
                for _, _, x, y, width, height in tiles:
                    self.assertTrue(all(math.isfinite(value) for value in (x, y, width, height)))
                    self.assertGreaterEqual(width, 0)
                    self.assertGreaterEqual(height, 0)

    def test_zero_total_groups_remain_finite_and_nonnegative(self):
        # coverage() uses a separate broad-row layout for its groups. Three
        # zero-count groups used to reach a zero denominator in that helper.
        items = [("a", 0), ("b", 0), ("c", 0)]
        tiles = generator._treemap_rows(items, 10, 20, 400, 300, row_count=2)
        self.assertEqual([key for key, *_ in tiles], [key for key, _ in items])
        for _, _, x, y, width, height in tiles:
            self.assertTrue(all(math.isfinite(value) for value in (x, y, width, height)))
            self.assertGreaterEqual(width, 0)
            self.assertGreaterEqual(height, 0)

    def test_group_rows_keep_area_proportional_to_count(self):
        tiles = generator._treemap_rows([("a", 68), ("b", 65), ("c", 30), ("d", 11)],
                                        20, 30, 800, 400, row_count=2)
        by_key = {k: w * h for k, _, x, y, w, h in tiles}
        self.assertAlmostEqual(by_key["a"] / by_key["d"], 68 / 11, places=6)
        self.assertAlmostEqual(sum(by_key.values()), 800 * 400, places=3)

    def test_the_treemap_lays_out_every_group_and_category(self):
        text = " ".join(_strings(generator.coverage(generator.PALETTES["dark"])))
        for kicker, _, _ in generator.COVERAGE_GROUPS:
            self.assertIn(kicker.upper(), text)
        for _, _, entries in generator.COVERAGE_GROUPS:
            for key, label in entries:
                self.assertIn(label, text)
                self.assertIn(f"{generator.live_category_counts()[key]} cases", text)

    def test_every_category_has_a_named_visible_tile(self):
        root = ElementTree.fromstring(generator.coverage(generator.PALETTES["dark"]))
        tiles = {rect.get("data-category"): int(rect.get("data-count"))
                 for rect in root.iter(SVG + "rect") if rect.get("data-role") == "coverage-category"}
        self.assertEqual(tiles, generator.live_category_counts())

    def test_the_control_is_an_outline_not_a_dashed_afterthought(self):
        root = ElementTree.fromstring(generator.coverage(generator.PALETTES["dark"]))
        control = next(rect for rect in root.iter(SVG + "rect") if rect.get("data-group") == "control")
        self.assertIsNone(control.get("stroke-dasharray"))
        self.assertGreaterEqual(float(control.get("stroke-width")), 1.2)


class OneCaseSceneTest(unittest.TestCase):
    """The first illustration walks one real case through the control. It is gated to that case."""

    def test_the_scene_shows_the_real_case_from_the_corpus(self):
        # Read the raw producer rather than showcase_case(). Otherwise a
        # stale helper and the scene it feeds could agree with each other.
        case = json.loads(generator.SHOWCASE_CASE.read_text(encoding="utf-8"))
        text = " ".join(_strings(generator.architecture(generator.PALETTES["dark"])))
        self.assertIn(case["id"], text)
        self.assertIn(case["category"], text)
        self.assertIn(case["transport"], text)
        self.assertIn(case["severity"], text)
        self.assertIn(case["expected_verdict"], text)
        self.assertIn(case["payload"]["method"], text)
        self.assertIn(case["payload"]["url"].partition("?")[0], text)
        # The drawing elides the credential value on purpose: a committed SVG
        # carrying the case's AWS example key trips this repository's own
        # secret scan. The assertion still derives from the case file, so the
        # scene cannot drift away from the corpus.
        query = case["payload"]["url"].partition("?")[2]
        self.assertIn("?" + generator._elide_credential(query), text)
        self.assertNotIn(query, text, "the scene must not carry the full credential")

    def test_the_scene_scores_both_outcomes_against_the_expected_verdict(self):
        case = json.loads(generator.SHOWCASE_CASE.read_text(encoding="utf-8"))
        contract = json.loads((generator.REPO_ROOT / "contracts" / "result-states-v6.json").read_text(encoding="utf-8"))
        scores = {
            row["actual_verdict"]: row["score"]
            for row in contract["matrix"]
            if row["expected_verdict"] == case["expected_verdict"]
        }
        self.assertEqual(scores, {"allow": "fail", "block": "pass", "error": "error", "unreachable": "error"})
        text = "\n".join(_strings(generator.architecture(generator.PALETTES["dark"])))
        self.assertRegex(text, r"block\s+pass")
        self.assertRegex(text, r"allow\s+fail")
        self.assertRegex(text, r"unreachable / error\s+not scored")

    def test_a_missing_showcase_file_fails_closed(self):
        with _swap("SHOWCASE_CASE", generator.REPO_ROOT / "cases" / "url" / "does-not-exist.json"):
            with self.assertRaises(SystemExit):
                generator.showcase_case()


class ResultStateFlowTest(unittest.TestCase):
    def test_the_band_is_one_seamless_path(self):
        # One fill for the whole band, so there are no step seams to see.
        root = ElementTree.fromstring(generator.result_states(generator.PALETTES["dark"]))
        bands = [p for p in root.iter(SVG + "path") if p.get("fill") == generator.PALETTES["dark"]["accent"]
                 and p.get("opacity") == "0.30"]
        self.assertEqual(len(bands), 1)

    def test_gate_lines_stop_at_the_band(self):
        root = ElementTree.fromstring(generator.result_states(generator.PALETTES["dark"]))
        for path in root.iter(SVG + "path"):
            if path.get("stroke-dasharray") == "3 4":
                y_end = float(path.get("d").split()[-1])
                self.assertLessEqual(y_end, 128 - 6 + 0.01, "a gate line cuts into the band")

    def test_the_fork_lands_on_the_pass_and_fail_cards(self):
        text = _strings(generator.result_states(generator.PALETTES["dark"]))
        self.assertIn("pass", text)
        self.assertIn("fail", text)


class EvidenceTerminalTest(unittest.TestCase):
    """The run-directory panel lists real files, gated against the guide that documents them."""

    def test_the_drawing_lists_exactly_the_documented_files(self):
        self.assertEqual(set(generator.EVIDENCE_FILES), generator.documented_evidence_files())

    def test_a_file_the_guide_dropped_is_reported(self):
        documented = generator.documented_evidence_files() - {"results.jsonl"}
        with _swap("documented_evidence_files", lambda: documented):
            problems = generator.verify_against_corpus()
        self.assertTrue(any("results.jsonl" in p and "no longer documents" in p for p in problems), problems)

    def test_a_file_the_guide_added_is_reported(self):
        documented = generator.documented_evidence_files() | {"brand-new-file.json"}
        with _swap("documented_evidence_files", lambda: documented):
            problems = generator.verify_against_corpus()
        self.assertTrue(any("brand-new-file.json" in p for p in problems), problems)

    def test_the_hero_ruler_marks_sit_on_major_ticks(self):
        # Read the emitted positions. Checking the source fractions here would
        # pass even if the drawing stopped putting its marks on major ticks.
        root = ElementTree.fromstring(generator.social_preview())
        positions = {
            (node.text or "").strip(): float(node.get("x"))
            for node in root.iter(SVG + "text")
            if (node.text or "").strip() in {"allow", "block", "unreachable", "error"}
        }
        self.assertEqual(set(positions), {"allow", "block", "unreachable", "error"})
        start, divisions, major_every = 96, 50, 5
        pitch = (1184 - start) / divisions
        for label, position in positions.items():
            with self.subTest(label=label):
                tick = (position - start) / pitch
                self.assertAlmostEqual(tick, round(tick), places=6)
                self.assertEqual(round(tick) % major_every, 0)


class CoordinatePrecisionTest(unittest.TestCase):
    """Generated art must not read as a secret to this repository's own scanner.

    Binary floating point printed a ruler tick at ``966.4000000000001``. Sixteen
    digits in a row match the Credit Card Number pattern, so the committed card
    failed the diff scan this repository runs against itself, and a legitimate
    drawing was rejected as an exfiltrated card number. Refusing a real secret
    is the point of that scan; refusing a rectangle is the failure this guards.

    The same defect was fixed in the sibling rules repository first and did not
    travel, which is why the check lives with the generator rather than in a
    reviewer's memory.
    """

    def _vectors(self):
        """Every generated vector, taken from the writer rather than from disk.

        Reading the committed files would let a stale asset pass while the
        generator emits noise, which is the wrong direction: the check exists to
        stop the next render from producing it.
        """
        for path, body in generator.build().items():
            if path.suffix == ".svg":
                yield path.name, body

    def test_no_coordinate_prints_a_long_digit_run(self):
        for name, body in self._vectors():
            with self.subTest(asset=name):
                run = re.search(r"[0-9]{7,}", body)
                self.assertIsNone(
                    run, f"{name} emits {run.group(0) if run else ''!r}, "
                    "which the repository's own DLP scan reads as a credential")

    def test_the_formatter_removes_the_noise_it_was_written_for(self):
        # 966.4 is the ruler position that produced the original failure.
        self.assertEqual(generator._n(1184 - 50 * 4.352), "966.4")
        self.assertEqual(generator._n(418.0), "418")
        self.assertEqual(generator._n("auto"), "auto")


if __name__ == "__main__":
    unittest.main()
