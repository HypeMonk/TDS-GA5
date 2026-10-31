"""Fixed Q2 hypotheses with independent task stores and public URL aliases."""
from collections import deque
from dataclasses import dataclass
import hashlib
import importlib.util
import json
import os
from pathlib import Path
from types import MappingProxyType

from fastapi import APIRouter, HTTPException, Request
from fastapi.routing import APIRoute


@dataclass(frozen=True)
class VariantConfig:
    id: str
    marker: str
    rationale_style: str
    vendor_binding: str
    solver_version: str
    reference: str | None = None

    @property
    def digest(self):
        policy = {"id": self.id, "marker": self.marker, "rationaleStyle": self.rationale_style,
                  "vendorBinding": self.vendor_binding, "solverVersion": self.solver_version,
                  "policyRevision": 1, "renderOrder": "legacy-facts-render-bind-mark"}
        return hashlib.sha256(json.dumps(policy, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    @property
    def bases(self):
        return ("/", "/a2a/") if self.id == "baseline" else (f"/a2a/{self.id}/", f"/{self.id}/")

    def public(self, origin=""):
        return {"variantId": self.id, "solverVersion": self.solver_version, "configDigest": self.digest,
                "missingIdentityMarker": self.marker, "rationaleStyle": self.rationale_style,
                "vendorBinding": self.vendor_binding, "reference": self.reference,
                "status": "historical" if self.reference and self.id != "v6" else "experimental",
                "urls": [origin + base for base in self.bases]}


BASELINE = VariantConfig("baseline", "", "no-footer", "legacy", "offline-v36-d", "89c0979")
REGISTRY = (
    VariantConfig("v1", "unknown", "excerpts", "legacy", "offline-v32", "31a38a4"),
    VariantConfig("v2", "unknown", "concise", "legacy", "offline-v33-a", "da78bc5"),
    VariantConfig("v3", "not provided", "excerpts", "legacy", "offline-v34-b", "366ded8"),
    VariantConfig("v4", "unknown", "no-footer", "legacy", "offline-v35-c", "faeb62c"),
    VariantConfig("v5", "", "no-footer", "legacy", "offline-v36-d", "89c0979"),
    VariantConfig("v6", "", "no-footer", "current-order", "offline-v37-e", "local-trial-e"),
    VariantConfig("v7", "unknown", "excerpts", "current-order", "q2-combo-v7"),
    VariantConfig("v8", "unknown", "no-footer", "current-order", "q2-combo-v8"),
    VariantConfig("v9", "unknown", "concise", "current-order", "q2-combo-v9"),
    VariantConfig("v10", "not provided", "excerpts", "current-order", "q2-combo-v10"),
    VariantConfig("v11", "not provided", "no-footer", "legacy", "q2-combo-v11"),
    VariantConfig("v12", "not provided", "no-footer", "current-order", "q2-combo-v12"),
    VariantConfig("v13", "not provided", "concise", "legacy", "q2-combo-v13"),
    VariantConfig("v14", "not provided", "concise", "current-order", "q2-combo-v14"),
    VariantConfig("v15", "", "excerpts", "legacy", "q2-combo-v15"),
    VariantConfig("v16", "", "excerpts", "current-order", "q2-combo-v16"),
    VariantConfig("v17", "", "concise", "legacy", "q2-combo-v17"),
    VariantConfig("v18", "", "concise", "current-order", "q2-combo-v18"),
)
assert len({(c.marker, c.rationale_style, c.vendor_binding) for c in REGISTRY}) == 18
CONFIGS = MappingProxyType({c.id: c for c in (BASELINE, *REGISTRY)})
TRANSPORT_PATHS = frozenset(("/.well-known/agent-card.json", "/.well-known/agent.json",
                            "/message:send", "/tasks", "/tasks/{task_id}", "/tasks/{task_id}:cancel"))


def load_instance(config, *, db_path, trace_path, debug_key="", external_origin=None):
    spec = importlib.util.spec_from_file_location("q10_instance_" + config.id, Path(__file__).with_name("q10.py"))
    module = importlib.util.module_from_spec(spec)
    settings = {"variant_id": config.id, "marker": config.marker, "rationale_style": config.rationale_style,
                "vendor_binding": config.vendor_binding, "solver_version": config.solver_version,
                "config_digest": config.digest, "public_bases": config.bases,
                "task_namespace": "q10-task-v1" if config.id == "baseline" else "q10-task-variant-" + config.id,
                "db_path": str(db_path), "trace_path": str(trace_path), "debug_key": debug_key,
                "external_origin": external_origin, "wire_enabled": config.id == "baseline"}
    if config.id != "baseline":
        settings.update(trace_storage_limit=2 * 1024 * 1024, trace_row_limit=100)
    module._INSTANCE_CONFIG = MappingProxyType(settings)
    spec.loader.exec_module(module)
    return module


def _readiness(config):
    async def endpoint():
        return {"status": "ok", **config.public()}
    return endpoint


class VariantSuite:
    def __init__(self, engine):
        state_root = Path(engine.DB_PATH + ".variants")
        trace_root = Path(engine._TRACE_DB_PATH + ".variants")
        paths = {"baseline": (Path(engine.DB_PATH), Path(engine._TRACE_DB_PATH))}
        paths.update({c.id: (state_root / (c.id + ".db"), trace_root / (c.id + ".db")) for c in REGISTRY})
        normalized = [os.path.normcase(os.path.realpath(path)) for pair in paths.values() for path in pair]
        if len(set(normalized)) != len(normalized):
            raise ValueError("Q2 task and trace paths must be distinct")
        self.instances = MappingProxyType({c.id: load_instance(c, db_path=paths[c.id][0], trace_path=paths[c.id][1],
            debug_key=engine._Q10_WIRE_KEY, external_origin=engine._EXTERNAL_ORIGIN) for c in (BASELINE, *REGISTRY)})
        self.logs = {c.id: deque(maxlen=100) for c in REGISTRY}

    def close(self):
        for instance in self.instances.values():
            with instance._db_lock:
                if instance._conn is not None:
                    instance._conn.close()
                    instance._conn = None

    def variant_for_path(self, path):
        parts = path.strip("/").split("/")
        if parts[0] == "a2a" and len(parts) > 1:
            variant, tail = parts[1], parts[2:]
        else:
            variant, tail = parts[0], parts[1:]
        if variant not in self.logs:
            return None
        if not tail or tail == ["health"] or tail == ["message:send"] or tail[0] == "tasks":
            return variant
        if tail in ([".well-known", "agent-card.json"], [".well-known", "agent.json"]):
            return variant
        return None

    def register(self, app):
        app.include_router(self.instances["baseline"].router)
        for config in REGISTRY:
            instance = self.instances[config.id]
            for base in config.bases:
                router = APIRouter(route_class=instance.A2ARoute)
                for route in instance.router.routes:
                    if isinstance(route, APIRoute) and route.path in TRANSPORT_PATHS:
                        router.add_api_route(route.path, route.endpoint, methods=list(route.methods),
                            response_model=route.response_model, response_class=route.response_class,
                            status_code=route.status_code, dependencies=route.dependencies,
                            name=config.id + "_" + route.name, route_class_override=type(route))
                app.include_router(router, prefix=base.rstrip("/"))
                readiness = _readiness(config)
                for path in (base.rstrip("/"), base, base + "health"):
                    app.add_api_route(path, readiness, methods=["GET", "HEAD", "OPTIONS"], include_in_schema=False)
            diagnostics = APIRouter(route_class=instance.A2ARoute)
            for suffix, endpoint in (("/traces", instance.q10_trace_index),
                                     ("/traces/{trace_id}", instance.q10_trace_detail)):
                diagnostics.add_api_route(suffix, endpoint, methods=["GET"], include_in_schema=False)
            app.include_router(diagnostics, prefix="/debug/q10/variants/" + config.id)
        app.add_event_handler("shutdown", self.close)

        @app.get("/debug/q10/variants")
        def registry(request: Request):
            origin = self.instances["baseline"]._origin(request)
            return {"baseline": BASELINE.public(origin), "variants": [c.public(origin) for c in REGISTRY],
                    "experimentalTracePayloadBudgetBytes": 36 * 1024 * 1024,
                    "eachUrlRequiresSeparateCheck": True}

        @app.get("/debug/q10/variants/{variant_id}/logs")
        def logs(variant_id: str, request: Request, limit: int = 25, before: float | None = None):
            if variant_id not in self.logs:
                raise HTTPException(404, "Unknown Q2 variant")
            instance = self.instances[variant_id]
            if not instance._trace_authorized(request):
                raise HTTPException(403, "Forbidden")
            rows = [row for row in self.logs[variant_id] if before is None or row["timestamp"] < before]
            return {"variantId": variant_id, "configDigest": instance._CONFIG_DIGEST,
                    "rows": rows[-max(1, min(limit, 100)):], "metadataOnly": True}
