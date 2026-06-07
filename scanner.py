from __future__ import annotations

import concurrent.futures
import ipaddress
import socket
from dataclasses import dataclass
from typing import Iterable, Optional

try:
    import requests  # type: ignore
except Exception:  # pragma: no cover
    requests = None  # type: ignore

from docker_scanner.findings import Finding, Severity
from docker_scanner.patterns import default_secret_patterns, iter_matches


@dataclass(frozen=True)
class DockerExposureConfig:
    targets: list[str]
    timeout: float
    concurrency: int
    inspect: bool


def _expand_targets(targets: list[str]) -> list[str]:
    out: list[str] = []
    for t in targets:
        t = t.strip()
        if not t:
            continue
        if "/" in t:
            try:
                net = ipaddress.ip_network(t, strict=False)
            except ValueError:
                out.append(t)
                continue
            for ip in net.hosts():
                out.append(str(ip))
        else:
            out.append(t)
    return out


def _tcp_probe(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def _http_get_json(url: str, timeout: float) -> Optional[dict]:
    if requests is None:
        return None
    try:
        r = requests.get(url, timeout=timeout)
        if r.status_code != 200:
            return None
        return r.json()
    except Exception:
        return None


def _docker_api_base(host: str) -> str:
    return f"http://{host}:2375"


def _inspect_docker_api(host: str, timeout: float) -> Iterable[Finding]:
    base = _docker_api_base(host)
    ver = _http_get_json(f"{base}/version", timeout=timeout)
    if ver is None:
        return

    yield Finding(
        check="docker_api_open",
        severity=Severity.CRITICAL,
        resource=f"docker://{host}:2375",
        summary="Unauthenticated Docker API appears reachable (common compromise vector)",
        details={"version": ver},
    )

    containers = _http_get_json(f"{base}/containers/json?all=1", timeout=timeout) or []
    if isinstance(containers, list) and containers:
        yield Finding(
            check="docker_api_containers_listable",
            severity=Severity.HIGH,
            resource=f"docker://{host}:2375",
            summary="Containers list is accessible via unauthenticated Docker API",
            details={"count": len(containers)},
        )

    patterns = default_secret_patterns()

    if isinstance(containers, list):
        for c in containers[:50]:
            cid = c.get("Id") or ""
            if not cid:
                continue
            info = _http_get_json(f"{base}/containers/{cid}/json", timeout=timeout)
            if not info:
                continue
            cfg = info.get("Config") or {}
            env = cfg.get("Env") or []
            if not isinstance(env, list):
                continue
            blob = "\n".join(str(x) for x in env)
            matches = list(iter_matches(blob, patterns))
            if matches:
                yield Finding(
                    check="docker_container_env_possible_secret",
                    severity=Severity.CRITICAL,
                    resource=f"docker://{host}:2375/container/{cid}",
                    summary="Container environment variables match secret/key pattern(s)",
                    details={
                        "image": cfg.get("Image"),
                        "name": (info.get("Name") or "").lstrip("/"),
                        "matched": [
                            {"pattern": p.name, "severity": p.severity, "snippet": snippet}
                            for p, snippet in matches[:5]
                        ],
                    },
                )


def run_docker_exposure(cfg: DockerExposureConfig) -> Iterable[Finding]:
    if requests is None and cfg.inspect:
        yield Finding(
            check="docker_dependency_missing",
            severity=Severity.MEDIUM,
            resource="docker://",
            summary="Missing dependency: requests (pip install 'docker-exposure-scanner[inspect]'); continuing with TCP probes only",
            details={},
        )

    hosts = _expand_targets(cfg.targets)
    timeout = float(cfg.timeout)

    def work(host: str) -> list[Finding]:
        fs: list[Finding] = []
        docker_open = _tcp_probe(host, 2375, timeout=timeout)
        reg_open = _tcp_probe(host, 5000, timeout=timeout)
        if docker_open:
            fs.append(
                Finding(
                    check="docker_port_2375_open",
                    severity=Severity.CRITICAL,
                    resource=f"tcp://{host}:2375",
                    summary="Docker API port 2375 is open (often unauthenticated)",
                    details={},
                )
            )
            if cfg.inspect:
                fs.extend(list(_inspect_docker_api(host, timeout=timeout)))
        if reg_open:
            fs.append(
                Finding(
                    check="docker_registry_port_5000_open",
                    severity=Severity.HIGH,
                    resource=f"tcp://{host}:5000",
                    summary="Docker registry port 5000 is open (verify auth/access controls)",
                    details={},
                )
            )
        return fs

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, min(cfg.concurrency, 2048))) as ex:
        futs = [ex.submit(work, h) for h in hosts]
        for f in concurrent.futures.as_completed(futs):
            for finding in f.result():
                yield finding
