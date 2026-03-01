"""JUnit XML output — CI/CD compatible test reports."""

from __future__ import annotations

import xml.etree.ElementTree as ET


def audit_to_junit(audit_results: list[dict]) -> str:
    """Convert audit results to JUnit XML format.

    Each scenario becomes a test case; failures include the reason.
    """
    testsuite = ET.Element("testsuite")
    testsuite.set("name", "ButterFence Audit")
    testsuite.set("tests", str(len(audit_results)))

    failures = sum(1 for r in audit_results if not r.get("passed", False))
    testsuite.set("failures", str(failures))
    testsuite.set("errors", "0")

    for r in audit_results:
        testcase = ET.SubElement(testsuite, "testcase")
        testcase.set("name", r.get("name", r.get("id", "unknown")))
        testcase.set("classname", f"butterfence.{r.get('category', 'unknown')}")

        if not r.get("passed", False):
            failure = ET.SubElement(testcase, "failure")
            failure.set("type", r.get("severity", "high"))
            failure.set(
                "message",
                f"Expected {r.get('expected_decision', 'block')}, "
                f"got {r.get('actual_decision', 'allow')}",
            )
            failure.text = r.get("reason", "")

    tree = ET.ElementTree(testsuite)
    import io

    buf = io.StringIO()
    tree.write(buf, encoding="unicode", xml_declaration=True)
    return buf.getvalue()
