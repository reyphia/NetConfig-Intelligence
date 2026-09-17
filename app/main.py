"""FastAPI web app. Configurations stay in process memory only."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Annotated

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from app.analyzers.topology import render_topology_svg
from app.services import analyze, get_renderer, get_session, render_device, update_interface
from app.services.diff import configuration_diff
from app.services.replay import build_replay_plan
from app.services.validation import validate_device

ROOT = Path(getattr(sys, "_MEIPASS", Path(__file__).parent)) / "app" if hasattr(sys, "_MEIPASS") else Path(__file__).parent
app = FastAPI(title="NetConfig Intelligence", version="0.1.0")
app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return (ROOT / "templates" / "index.html").read_text(encoding="utf-8")


@app.post("/api/analyze")
async def analyze_configuration(
    text: Annotated[str, Form()] = "",
    vendor: Annotated[str, Form()] = "auto",
    file: Annotated[UploadFile | None, File()] = None,
) -> dict:
    raw_text = text.strip()

    # If no configuration was pasted, use the uploaded file.
    if not raw_text and file and file.filename:
        raw_text = (await file.read()).decode("utf-8", errors="replace")

    # Require at least one configuration source.
    if not raw_text:
        raise HTTPException(
            status_code=422,
            detail="Provide a configuration file or paste configuration text.",
        )

    try:
        session = analyze(raw_text, vendor)
    except (ValueError, UnicodeError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    summary = session.sanitization.summary.model_dump()

    return {
        "session_id": session.id,
        "vendor": session.vendor.value,
        "hostname": session.device.hostname or "Unknown device",
        "detection": "Local parser selected the vendor; no configuration was transmitted.",
        "summary": summary,
        "health": session.health.model_dump(),
        "findings": [f.model_dump() for f in session.findings],
        "sanitized": session.sanitization.sanitized_text,
        "interfaces": [i.model_dump() for i in session.device.interfaces],
    }


@app.post("/api/sessions/{session_id}/reveal")
def reveal_recoverable_credentials(session_id: str, acknowledged: bool = Form(False)) -> dict:
    if not acknowledged:
        raise HTTPException(status_code=400, detail="Explicit local confirmation is required to reveal credentials.")
    try:
        session = get_session(session_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    values = []
    for value in session.sanitization.values:
        if value.revealed_value and value.category.value == "credential":
            values.append({"context": value.context, "value": value.revealed_value, "type": value.secret_type})
    return {"credentials": values, "notice": "Shown locally for this session only. One-way hashes are never cracked or revealed."}


@app.get("/api/sessions/{session_id}/export/sanitized")
def export_sanitized(session_id: str) -> PlainTextResponse:
    """Credentials and device identifiers (MAC addresses) are masked; IP
    addressing and the hostname are preserved because a colleague usually
    still needs those to reason about the topology."""
    try:
        session = get_session(session_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    suffix = "rsc" if session.vendor.value == "mikrotik_routeros" else "cfg"
    return PlainTextResponse(
        session.sanitization.sanitized_text,
        headers={"Content-Disposition": f'attachment; filename="netconfig-sanitized.{suffix}"'},
    )


@app.get("/api/sessions/{session_id}/export/anonymized")
def export_anonymized(session_id: str) -> PlainTextResponse:
    """Additionally masks the hostname and any public IP addresses - the
    safest option when sharing a configuration outside the team."""
    try:
        session = get_session(session_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    suffix = "rsc" if session.vendor.value == "mikrotik_routeros" else "cfg"
    return PlainTextResponse(
        session.sanitization.anonymized_text,
        headers={"Content-Disposition": f'attachment; filename="netconfig-anonymized.{suffix}"'},
    )


@app.get("/api/sessions/{session_id}/validation")
def validation(session_id: str) -> dict:
    try:
        session = get_session(session_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    checks = validate_device(session.device)
    return {"checks": checks, "export_blocked": any(item["status"] == "blocking" for item in checks)}


@app.get("/api/sessions/{session_id}/topology")
def topology(session_id: str) -> dict:
    try:
        session = get_session(session_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"svg": render_topology_svg(session.device)}


@app.get("/api/sessions/{session_id}/replay")
def replay_plan(session_id: str) -> dict:
    try:
        session = get_session(session_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    renderer = get_renderer(session.vendor)
    return {
        "notice": "The original CLI command history is not stored in a running configuration. This is a dependency-aware reconstruction order that can reproduce the resulting configuration.",
        "target_platform": renderer.target_platform,
        "compatibility_warning": renderer.compatibility_warning(),
        "steps": build_replay_plan(session.device),
    }


@app.get("/api/sessions/{session_id}/diff")
def diff(session_id: str) -> dict:
    try:
        session = get_session(session_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return configuration_diff(session.original_rendered_text, session.rendered_text or session.original_rendered_text)


@app.post("/api/diff")
async def compare_configurations(
    old_text: Annotated[str, Form()] = "",
    new_text: Annotated[str, Form()] = "",
    old_file: Annotated[UploadFile | None, File()] = None,
    new_file: Annotated[UploadFile | None, File()] = None,
    vendor: Annotated[str, Form()] = "auto",
) -> dict:
    """Compare two independently-uploaded configurations - e.g. last week's
    backup against today's running-config - without touching the editor or
    any existing session. Same renderer-normalized comparison the CLI's
    `netconfig diff` command uses, so formatting noise (comment markers,
    line ordering) doesn't drown out the actual changes."""
    old_raw = old_text.strip()
    if not old_raw and old_file and old_file.filename:
        old_raw = (await old_file.read()).decode("utf-8", errors="replace")

    new_raw = new_text.strip()
    if not new_raw and new_file and new_file.filename:
        new_raw = (await new_file.read()).decode("utf-8", errors="replace")

    if not old_raw or not new_raw:
        raise HTTPException(
            status_code=422,
            detail="Provide both an old and a new configuration (file or pasted text).",
        )

    try:
        old_session = analyze(old_raw, vendor)
        new_session = analyze(new_raw, vendor)
    except (ValueError, UnicodeError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    result = configuration_diff(old_session.original_rendered_text, new_session.original_rendered_text)
    return {
        "old": {
            "hostname": old_session.device.hostname or "Unknown device",
            "vendor": old_session.vendor.value,
        },
        "new": {
            "hostname": new_session.device.hostname or "Unknown device",
            "vendor": new_session.vendor.value,
        },
        "vendor_mismatch": old_session.vendor != new_session.vendor,
        **result,
    }


@app.post("/api/sessions/{session_id}/interfaces/{name:path}")
def edit_interface(session_id: str, name: str, address: str = Form(...), prefix_length: int = Form(...)) -> dict:
    try:
        session = update_interface(get_session(session_id), name, address, prefix_length)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"interfaces": [iface.model_dump() for iface in session.device.interfaces], "health": session.health.model_dump(), "validation": validate_device(session.device)}


@app.post("/api/sessions/{session_id}/export/modified")
def export_modified(session_id: str, confirmed: bool = Form(False)) -> PlainTextResponse:
    if not confirmed:
        raise HTTPException(status_code=400, detail="Confirm that this local export may contain secrets.")
    try:
        session = get_session(session_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    checks = validate_device(session.device)
    if any(item["status"] == "blocking" for item in checks):
        raise HTTPException(status_code=409, detail="Export blocked until validation errors are fixed.")
    suffix = "rsc" if session.vendor.value == "mikrotik_routeros" else "cfg"
    renderer = get_renderer(session.vendor)
    return PlainTextResponse(
        render_device(session.device),
        headers={
            "Content-Disposition": f'attachment; filename="netconfig-modified.{suffix}"',
            "X-Target-Platform": renderer.target_platform,
            "X-Compatibility-Warning": renderer.compatibility_warning(),
        },
    )
