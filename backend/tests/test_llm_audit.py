"""Focused LLM audit regressions; no real browser, LLM, or target traffic."""

import asyncio
import sys
import threading
import unittest
from contextlib import contextmanager
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock, patch

from langgraph.errors import GraphRecursionError

from app.agents.llm_audit import graph, nodes
from app.agents.llm_audit.state import LLMAuditState


def initial_state(**overrides: Any) -> LLMAuditState:
    state = {
        "target_url": "https://target.invalid",
        "endpoint_hint": "",
        "ai_surfaces": [],
        "connect_method": "api",
        "connect_config": {"url": "https://target.invalid/api/chat"},
        "attack_index": 0,
        "attack_results": [],
        "mutation_count": 0,
        "llm_audit_report": {},
        "errors": [],
    }
    state.update(overrides)
    return cast(LLMAuditState, state)


def attack(response="An ambiguous response", **overrides):
    category = nodes.ATTACK_CATEGORIES[0]
    result = {
        "category_id": category["id"],
        "category_name": category["name"],
        "owasp": category["owasp"],
        "prompt": category["prompts"][0],
        "response_text": response,
        "verdict": "pending",
    }
    result.update(overrides)
    return result


@contextmanager
def mocked_browser():
    page = MagicMock()
    page.goto = AsyncMock()
    page.wait_for_timeout = AsyncMock()
    locator = MagicMock()
    locator.first = locator
    locator.is_visible = AsyncMock(return_value=False)
    locator.count = AsyncMock(return_value=0)
    locator.all = AsyncMock(return_value=[])
    locator.fill = AsyncMock()
    locator.press = AsyncMock()
    locator.all_text_contents = AsyncMock(return_value=["I cannot comply"])
    page.locator.return_value = locator
    browser = SimpleNamespace(new_page=AsyncMock(return_value=page), close=AsyncMock())
    playwright = SimpleNamespace(
        chromium=SimpleNamespace(launch=AsyncMock(return_value=browser)),
        stop=AsyncMock(),
    )
    manager = SimpleNamespace(start=AsyncMock(return_value=playwright))
    with patch("playwright.async_api.async_playwright", return_value=manager):
        yield page, browser, playwright


class LLMAuditTests(unittest.IsolatedAsyncioTestCase):
    def _setupAsyncioRunner(self):
        # Python 3.12's test runner does not yet expose loop_factory publicly.
        # Reproduce uvicorn's Windows loop without changing the global policy.
        loop_factory = (
            asyncio.SelectorEventLoop if sys.platform == "win32" else asyncio.new_event_loop
        )
        self._asyncioRunner = asyncio.Runner(debug=True, loop_factory=loop_factory)

    async def test_browser_worker_uses_separate_thread_and_subprocess_capable_loop(self):
        main_thread = threading.get_ident()
        main_loop = asyncio.get_running_loop()
        if sys.platform == "win32":
            self.assertIsInstance(main_loop, asyncio.SelectorEventLoop)

        async def inspect_loop():
            loop = asyncio.get_running_loop()
            self.assertNotEqual(threading.get_ident(), main_thread)
            self.assertIsNot(loop, main_loop)
            if sys.platform == "win32":
                self.assertIsInstance(loop, asyncio.ProactorEventLoop)
            return "ok"

        self.assertEqual(await nodes._run_browser(inspect_loop), "ok")

    async def test_dom_navigation_and_actions_are_bounded_and_resources_closed(self):
        with mocked_browser() as (page, browser, playwright):
            response = await nodes._send_via_dom(
                {"page_url": "https://target.invalid", "selector": "textarea"}, "test"
            )
        self.assertEqual(response, "I cannot comply")
        page.goto.assert_awaited_once_with(
            "https://target.invalid", wait_until="domcontentloaded",
            timeout=nodes.BROWSER_NAVIGATION_TIMEOUT_MS,
        )
        page.set_default_timeout.assert_called_once_with(nodes.BROWSER_ACTION_TIMEOUT_MS)
        page.locator.return_value.fill.assert_awaited_once_with("test")
        browser.close.assert_awaited_once()
        playwright.stop.assert_awaited_once()

    async def test_browser_deadline_cancels_work_and_closes_resources(self):
        async def hang(*args, **kwargs):
            await asyncio.Future()

        with mocked_browser() as (page, browser, playwright):
            page.goto.side_effect = hang
            with patch.object(nodes, "BROWSER_TIMEOUT_SECONDS", 0.02):
                response = await nodes._send_via_dom({}, "test")
        self.assertIn("[DOM ERROR] TimeoutError", response)
        browser.close.assert_awaited_once()
        playwright.stop.assert_awaited_once()

    async def test_new_page_failure_still_closes_browser_and_driver(self):
        with mocked_browser() as (_, browser, playwright):
            browser.new_page.side_effect = RuntimeError("page creation failed")
            response = await nodes._send_via_dom({}, "test")
        self.assertIn("page creation failed", response)
        browser.close.assert_awaited_once()
        playwright.stop.assert_awaited_once()

    async def test_launch_failure_still_stops_driver(self):
        with mocked_browser() as (_, browser, playwright):
            playwright.chromium.launch.side_effect = RuntimeError("Chromium not installed")
            response = await nodes._send_via_dom({}, "test")
        self.assertIn("Chromium not installed", response)
        browser.close.assert_not_awaited()
        playwright.stop.assert_awaited_once()

    async def test_missing_dom_response_is_error_not_html_success(self):
        with mocked_browser() as (page, browser, playwright):
            page.locator.return_value.all_text_contents.return_value = []
            response = await nodes._send_via_dom({}, "test")
        self.assertIn("[DOM ERROR] RuntimeError: No chat response captured", response)
        browser.close.assert_awaited_once()
        playwright.stop.assert_awaited_once()

    async def test_cleanup_timeout_still_stops_driver(self):
        async def hang():
            await asyncio.Future()

        with mocked_browser() as (_, browser, playwright):
            browser.close.side_effect = hang
            with patch.object(nodes, "BROWSER_CLEANUP_TIMEOUT_SECONDS", 0.01):
                response = await nodes._send_via_dom({}, "test")
        self.assertIn("[DOM ERROR] TimeoutError", response)
        playwright.stop.assert_awaited_once()

    async def test_detector_uses_worker_and_domcontentloaded(self):
        with mocked_browser() as (page, browser, playwright):
            result = await nodes.detector_node(initial_state())
        self.assertEqual(result["connect_method"], "none")
        self.assertEqual(result["errors"], [])
        page.goto.assert_awaited_once_with(
            "https://target.invalid", wait_until="domcontentloaded",
            timeout=nodes.BROWSER_NAVIGATION_TIMEOUT_MS,
        )
        browser.close.assert_awaited_once()
        playwright.stop.assert_awaited_once()

    async def test_detector_preserves_hint_and_nonempty_browser_error(self):
        with patch.object(nodes, "_run_browser", side_effect=NotImplementedError):
            result = await nodes.detector_node(initial_state(
                endpoint_hint="https://target.invalid/api/chat"
            ))
        self.assertEqual(result["ai_surfaces"][0]["confidence"], "user_provided")
        self.assertIn("NotImplementedError", result["errors"][0])

    async def test_api_http_failure_is_not_a_response_to_judge(self):
        response = MagicMock()
        response.raise_for_status.side_effect = RuntimeError("HTTP 503 unavailable")
        response.text = AsyncMock(return_value="I cannot serve requests")
        request_context = MagicMock()
        request_context.__aenter__ = AsyncMock(return_value=response)
        session = MagicMock()
        session.request.return_value = request_context
        session_context = MagicMock()
        session_context.__aenter__ = AsyncMock(return_value=session)
        with patch.object(nodes.aiohttp, "ClientSession", return_value=session_context):
            result = await nodes.attacker_node(initial_state())
        self.assertIn("[API ERROR] RuntimeError: HTTP 503", result["attack_results"][0]["response_text"])
        self.assertTrue(result["errors"])
        response.text.assert_not_awaited()
        self.assertEqual(session.request.call_count, 2)

    async def test_transport_errors_take_priority_over_refusals_and_canaries(self):
        with patch.object(nodes, "get_llm") as factory:
            result = await nodes.judge_node(initial_state(attack_results=[attack(
                "[DOM ERROR] I cannot find JAILBREAK_SUCCESS"
            )]))
        self.assertEqual(result["attack_results"][0]["verdict"], "error")
        factory.assert_not_called()

    async def test_empty_response_is_inconclusive(self):
        with patch.object(nodes, "get_llm") as factory:
            result = await nodes.judge_node(initial_state(attack_results=[attack("")]))
        self.assertEqual(result["attack_results"][0]["verdict"], "error")
        self.assertTrue(result["errors"])
        factory.assert_not_called()

    async def test_judge_timeout_is_error_not_pass(self):
        async def hang(*args):
            await asyncio.Future()

        llm = SimpleNamespace(ainvoke=AsyncMock(side_effect=hang))
        with patch.object(nodes, "get_llm", return_value=llm), patch.object(
            nodes, "LLM_TIMEOUT_SECONDS", 0.01
        ):
            result = await nodes.judge_node(initial_state(attack_results=[attack()]))
        self.assertEqual(result["attack_results"][0]["verdict"], "error")
        self.assertIn("LLM call exceeded 0.01s", result["errors"][0])

    async def test_malformed_judge_output_is_error_not_pass(self):
        llm = SimpleNamespace(ainvoke=AsyncMock(return_value=SimpleNamespace(content="unknown")))
        with patch.object(nodes, "get_llm", return_value=llm):
            result = await nodes.judge_node(initial_state(attack_results=[attack()]))
        self.assertEqual(result["attack_results"][0]["verdict"], "error")
        self.assertIn("no valid PASS/FAIL verdict", result["errors"][0])

    async def test_mutation_timeout_falls_back_and_mutated_prompt_is_actually_sent(self):
        async def hang(*args):
            await asyncio.Future()

        state = initial_state(attack_results=[attack("I cannot comply", verdict="pass")])
        llm = SimpleNamespace(ainvoke=AsyncMock(side_effect=hang))
        with patch.object(nodes, "get_llm", return_value=llm), patch.object(
            nodes, "LLM_TIMEOUT_SECONDS", 0.01
        ):
            mutation = await nodes.mutation_node(state)
        self.assertIn("LLM call exceeded", mutation["errors"][0])
        mutated_prompt = mutation["attack_results"][-1]["prompt"]
        state.update(mutation)
        with patch.object(nodes, "_send_via_api", return_value="I cannot comply") as send:
            result = await nodes.attacker_node(state)
        send.assert_awaited_once_with(state["connect_config"], mutated_prompt)
        self.assertEqual(len(result["attack_results"]), 2)
        self.assertEqual(result["attack_results"][-1]["response_text"], "I cannot comply")

    async def test_missing_surface_is_error_without_simulated_success(self):
        state = initial_state(connect_method="none")
        state.update(await nodes.attacker_node(state))
        self.assertIn("No AI surface detected", state["errors"][0])
        result = await nodes.judge_node(state)
        self.assertEqual(result["attack_results"][0]["verdict"], "error")

    async def test_report_timeout_preserves_results_without_counting_errors_as_passes(self):
        async def hang(*args):
            await asyncio.Future()

        llm = SimpleNamespace(ainvoke=AsyncMock(side_effect=hang))
        state = initial_state(attack_results=[
            attack(verdict="pass"), attack(verdict="fail"), attack(verdict="error")
        ])
        with patch.object(nodes, "get_llm", return_value=llm), patch.object(
            nodes, "LLM_TIMEOUT_SECONDS", 0.01
        ):
            report = (await nodes.report_builder_node(state))["llm_audit_report"]
        self.assertEqual(report["total_passed"], 1)
        self.assertEqual(report["total_failed"], 1)
        self.assertEqual(report["total_errors"], 1)
        self.assertEqual(report["categories_tested"][0]["passed_count"], 1)
        self.assertIn("1 were inconclusive", report["summary"])
        self.assertIn("LLM call exceeded", report["errors"][0])

    async def test_full_blocked_graph_completes_with_default_but_not_api_limit_60(self):
        async def model_reply(prompt):
            return SimpleNamespace(content="Mutated: " + prompt if "Original prompt:" in prompt else "Summary")

        llm = SimpleNamespace(ainvoke=AsyncMock(side_effect=model_reply))
        surfaces = [{"type": "api", "url": "https://target.invalid/api/chat"}]
        with patch.object(nodes, "_detect_surfaces_browser", return_value=surfaces), patch.object(
            nodes, "_send_via_api", return_value="I cannot comply"
        ) as send, patch.object(nodes, "get_llm", return_value=llm):
            chunks = [chunk async for chunk in graph.llm_audit_graph.astream(initial_state())]
            self.assertEqual(len(chunks), 63)
            report = chunks[-1]["report_builder"]["llm_audit_report"]
            self.assertEqual(report["total_attacks"], 20)
            self.assertEqual(report["total_passed"], 20)
            self.assertEqual(report["total_errors"], 0)
            self.assertEqual(report["errors"], [])
            self.assertEqual(send.await_count, 20)
            self.assertTrue(all(
                r["verdict"] == "pass"
                for c in report["categories_tested"] for r in c["attacks"]
            ))
            with self.assertRaises(GraphRecursionError):
                await graph.llm_audit_graph.ainvoke(initial_state(), {"recursion_limit": 60})


if __name__ == "__main__":
    unittest.main()
