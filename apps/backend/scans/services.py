from __future__ import annotations

import shutil
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from django.conf import settings
from django.core.files.uploadedfile import UploadedFile
from django.db import close_old_connections
from django.utils import timezone

from sast_scan.core.config import load_config
from sast_scan.core.orchestrator import ScanOrchestrator

from .models import ScanJob
from .pdf import write_scan_pdf


EXECUTOR = ThreadPoolExecutor(max_workers=1, thread_name_prefix="sast-web-scan")
_SUBMITTED: set[str] = set()
_LOCK = threading.Lock()


def create_scan_job(*, target_type: str, github_url: str = "", local_path: str = "", files: list[UploadedFile] | None = None, relative_paths: list[str] | None = None) -> ScanJob:
    job_id = uuid.uuid4()
    upload_root = Path(settings.SAST_WEB_UPLOAD_ROOT) / str(job_id)
    output_dir = Path(settings.SAST_WEB_REPORT_ROOT)
    output_dir.mkdir(parents=True, exist_ok=True)

    if target_type == ScanJob.TargetType.GITHUB:
        resolved_target = github_url.strip()
    elif target_type == ScanJob.TargetType.LOCAL_PATH:
        resolved_target = _safe_local_path(local_path)
    elif target_type == ScanJob.TargetType.FILE:
        resolved_target = str(_save_single_file(upload_root, files or []))
    elif target_type == ScanJob.TargetType.FOLDER:
        resolved_target = str(_save_folder(upload_root, files or [], relative_paths or []))
    else:
        raise ValueError(f"Unsupported target_type: {target_type}")

    job = ScanJob.objects.create(
        id=job_id,
        target_type=target_type,
        target_display=_target_display(target_type, github_url, local_path, files),
        resolved_target=resolved_target,
        output_dir=str(output_dir),
        report_json_path=str(output_dir / "scan.json"),
        report_html_path=str(output_dir / "scan.html"),
        report_sarif_path=str(output_dir / "scan.sarif"),
    )
    submit_scan(job.id)
    return job


def submit_scan(job_id) -> None:
    key = str(job_id)
    with _LOCK:
        if key in _SUBMITTED:
            return
        _SUBMITTED.add(key)
    EXECUTOR.submit(run_scan_job, key)


def run_scan_job(job_id: str) -> None:
    close_old_connections()
    job = ScanJob.objects.get(id=job_id)
    job.status = ScanJob.Status.RUNNING
    job.progress_message = "Running OpenGrep and Trivy scanners"
    job.started_at = timezone.now()
    job.save(update_fields=["status", "progress_message", "started_at"])

    try:
        config = load_config(Path(settings.SAST_CONFIG_PATH))
        config.report.output_dir = Path(job.output_dir)
        report = ScanOrchestrator(config=config).scan(job.resolved_target)
        report_data = report.to_dict()
        write_scan_pdf(report_data, Path(job.output_dir) / "scan.pdf")
        job.status = report.status
        job.summary = report_data.get("summary", {})
        job.coverage = report_data.get("coverage", {})
        job.integrity = report_data.get("integrity", {})
        job.progress_message = "Scan completed"
    except Exception as exc:  # noqa: BLE001
        job.status = ScanJob.Status.ERROR
        job.error = str(exc)
        job.progress_message = "Scan failed"
    finally:
        job.finished_at = timezone.now()
        job.save(update_fields=["status", "summary", "coverage", "integrity", "progress_message", "error", "finished_at"])
        with _LOCK:
            _SUBMITTED.discard(job_id)
        close_old_connections()


def job_payload(job: ScanJob) -> dict:
    return {
        "id": str(job.id),
        "target_type": job.target_type,
        "target": job.target_display,
        "status": job.status,
        "progress_message": job.progress_message,
        "summary": job.summary,
        "coverage": job.coverage,
        "integrity": job.integrity,
        "error": job.error,
        "created_at": job.created_at.isoformat(),
        "started_at": job.started_at.isoformat() if job.started_at else None,
        "finished_at": job.finished_at.isoformat() if job.finished_at else None,
        "reports": {
            "json": f"/api/scans/{job.id}/report/json/",
            "html": f"/api/scans/{job.id}/report/html/",
            "sarif": f"/api/scans/{job.id}/report/sarif/",
            "pdf": f"/api/scans/{job.id}/report/pdf/",
        },
    }


def _target_display(target_type: str, github_url: str, local_path: str, files: list[UploadedFile] | None) -> str:
    if target_type == ScanJob.TargetType.GITHUB:
        return github_url.strip()
    if target_type == ScanJob.TargetType.LOCAL_PATH:
        return local_path.strip()
    if files:
        return files[0].name if len(files) == 1 else f"{len(files)} uploaded files"
    return target_type


def _save_single_file(upload_root: Path, files: list[UploadedFile]) -> Path:
    if len(files) != 1:
        raise ValueError("File scan requires exactly one uploaded file.")
    upload_root.mkdir(parents=True, exist_ok=True)
    return _write_upload(upload_root / _safe_name(files[0].name), files[0])


def _save_folder(upload_root: Path, files: list[UploadedFile], relative_paths: list[str]) -> Path:
    if not files:
        raise ValueError("Folder scan requires uploaded files.")
    upload_root.mkdir(parents=True, exist_ok=True)
    for index, uploaded in enumerate(files):
        relative = relative_paths[index] if index < len(relative_paths) else uploaded.name
        destination = _safe_join(upload_root, relative)
        destination.parent.mkdir(parents=True, exist_ok=True)
        _write_upload(destination, uploaded)
    return upload_root


def _write_upload(path: Path, uploaded: UploadedFile) -> Path:
    size = 0
    with path.open("wb") as handle:
        for chunk in uploaded.chunks():
            size += len(chunk)
            if size > settings.SAST_WEB_MAX_UPLOAD_BYTES:
                shutil.rmtree(path.parent, ignore_errors=True)
                raise ValueError("Uploaded content exceeds configured size limit.")
            handle.write(chunk)
    return path


def _safe_join(root: Path, relative: str) -> Path:
    clean = Path(relative.replace("\\", "/"))
    if clean.is_absolute() or ".." in clean.parts:
        raise ValueError("Unsafe upload path.")
    return root / clean


def _safe_name(name: str) -> str:
    return Path(name.replace("\\", "/")).name


def _safe_local_path(local_path: str) -> str:
    candidate = Path(local_path).expanduser().resolve()
    repo_root = Path(settings.SAST_REPO_ROOT).resolve()
    if not candidate.exists():
        raise ValueError("Local path does not exist.")
    try:
        candidate.relative_to(repo_root)
    except ValueError as exc:
        raise ValueError("Local path scans are restricted to the scanner workspace.") from exc
    return str(candidate)
