"""Configuration health score.

The score is a plain, explainable deduction from 100: every finding
subtracts its severity weight (see `SEVERITY_WEIGHT`), floored at zero, both
overall and per category. There is no hidden ML model and no randomness -
the UI can always show exactly which findings produced a given number, which
the project spec explicitly requires.
"""

from __future__ import annotations

from pydantic import BaseModel

from app.models.findings import SEVERITY_WEIGHT, Category, Finding


class CategoryScore(BaseModel):
    category: str
    score: int
    deduction: int
    finding_count: int


class HealthScore(BaseModel):
    overall: int
    categories: list[CategoryScore]
    total_findings: int
    critical: int
    high: int
    medium: int
    low: int
    info: int


def compute_health_score(findings: list[Finding]) -> HealthScore:
    total_deduction = sum(SEVERITY_WEIGHT[f.severity] for f in findings)
    overall = max(0, min(100, 100 - total_deduction))

    by_category: dict[str, list[Finding]] = {}
    for f in findings:
        by_category.setdefault(f.category.value, []).append(f)

    categories: list[CategoryScore] = []
    for category in Category:
        cat_findings = by_category.get(category.value, [])
        deduction = sum(SEVERITY_WEIGHT[f.severity] for f in cat_findings)
        categories.append(
            CategoryScore(
                category=category.value,
                score=max(0, min(100, 100 - deduction)),
                deduction=deduction,
                finding_count=len(cat_findings),
            )
        )

    def count(sev: str) -> int:
        return sum(1 for f in findings if f.severity.value == sev)

    return HealthScore(
        overall=overall,
        categories=categories,
        total_findings=len(findings),
        critical=count("CRITICAL"),
        high=count("HIGH"),
        medium=count("MEDIUM"),
        low=count("LOW"),
        info=count("INFO"),
    )
