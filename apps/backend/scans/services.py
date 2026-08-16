from __future__ import annotations

import shutil
import threading
import uuid
import zipfile
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
    elif target_type == ScanJob.TargetType.ZIP:
        resolved_target = str(_save_zip_archive(upload_root, files or []))
    else:
        raise ValueError(f"Unsupported target_type: {target_type}")

    job = ScanJob.objects.create(
        id=job_id,
        target_type=target_type,
        target_display=_target_display(target_type, github_url, local_path, files),
        resolved_target=resolved_target,
        upload_dir=str(upload_root) if target_type in {ScanJob.TargetType.FILE, ScanJob.TargetType.FOLDER, ScanJob.TargetType.ZIP} else "",
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
        _cleanup_upload_dir(job)
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
    _validate_uploaded_file(files[0], settings.SAST_WEB_MAX_FILE_BYTES, "File")
    upload_root.mkdir(parents=True, exist_ok=True)
    return _write_upload(upload_root / _safe_name(files[0].name), files[0], settings.SAST_WEB_MAX_FILE_BYTES)


def _save_folder(upload_root: Path, files: list[UploadedFile], relative_paths: list[str]) -> Path:
    if not files:
        raise ValueError("Folder scan requires uploaded files.")
    _validate_total_upload_size(files, settings.SAST_WEB_MAX_FOLDER_BYTES, "Folder")
    upload_root.mkdir(parents=True, exist_ok=True)
    for index, uploaded in enumerate(files):
        relative = relative_paths[index] if index < len(relative_paths) else uploaded.name
        destination = _safe_join(upload_root, relative)
        destination.parent.mkdir(parents=True, exist_ok=True)
        _write_upload(destination, uploaded, settings.SAST_WEB_MAX_FOLDER_BYTES)
    return upload_root


def _save_zip_archive(upload_root: Path, files: list[UploadedFile]) -> Path:
    if len(files) != 1:
        raise ValueError("ZIP scan requires exactly one uploaded .zip file.")
    uploaded = files[0]
    if not uploaded.name.lower().endswith(".zip"):
        raise ValueError("Only .zip archives are supported for archive scans.")
    _validate_uploaded_file(uploaded, settings.SAST_WEB_MAX_ZIP_BYTES, "ZIP archive")

    archive_dir = upload_root / "archive"
    extract_root = upload_root / "extracted"
    archive_dir.mkdir(parents=True, exist_ok=True)
    archive_path = _write_upload(archive_dir / _safe_name(uploaded.name), uploaded, settings.SAST_WEB_MAX_ZIP_BYTES)
    if not zipfile.is_zipfile(archive_path):
        shutil.rmtree(upload_root, ignore_errors=True)
        raise ValueError("Uploaded file is not a valid ZIP archive.")
    _extract_zip_safely(archive_path, extract_root)
    return extract_root


def _write_upload(path: Path, uploaded: UploadedFile, max_bytes: int) -> Path:
    size = 0
    with path.open("wb") as handle:
        for chunk in uploaded.chunks():
            size += len(chunk)
            if size > max_bytes or size > settings.SAST_WEB_MAX_UPLOAD_BYTES:
                shutil.rmtree(path.parent, ignore_errors=True)
                raise ValueError("Uploaded content exceeds configured size limit.")
            handle.write(chunk)
    return path


def _extract_zip_safely(archive_path: Path, extract_root: Path) -> None:
    extract_root.mkdir(parents=True, exist_ok=True)
    extracted_bytes = 0
    extracted_files = 0

    with zipfile.ZipFile(archive_path) as archive:
        entries = archive.infolist()
        for entry in entries:
            if entry.is_dir():
                continue
            extracted_files += 1
            if extracted_files > settings.SAST_WEB_MAX_ZIP_FILES:
                shutil.rmtree(extract_root, ignore_errors=True)
                raise ValueError(f"ZIP archive contains too many files. Limit is {settings.SAST_WEB_MAX_ZIP_FILES}.")
            if _is_zip_symlink(entry):
                shutil.rmtree(extract_root, ignore_errors=True)
                raise ValueError("ZIP archive contains unsupported symbolic links.")
            if entry.file_size > settings.SAST_WEB_MAX_FILE_BYTES:
                shutil.rmtree(extract_root, ignore_errors=True)
                raise ValueError(f"ZIP entry '{entry.filename}' exceeds the per-file size limit.")
            extracted_bytes += entry.file_size
            if extracted_bytes > settings.SAST_WEB_MAX_ZIP_EXTRACTED_BYTES:
                shutil.rmtree(extract_root, ignore_errors=True)
                raise ValueError("ZIP extracted content exceeds configured size limit.")

            destination = _safe_join(extract_root, entry.filename)
            destination.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(entry) as source, destination.open("wb") as target:
                shutil.copyfileobj(source, target, length=1024 * 1024)

    if extracted_files == 0:
        shutil.rmtree(extract_root, ignore_errors=True)
        raise ValueError("ZIP archive does not contain any scan files.")


def _is_zip_symlink(entry: zipfile.ZipInfo) -> bool:
    return ((entry.external_attr >> 16) & 0o170000) == 0o120000


def _validate_uploaded_file(uploaded: UploadedFile, max_bytes: int, label: str) -> None:
    size = uploaded.size or 0
    if size <= 0:
        raise ValueError(f"{label} upload is empty.")
    if size > max_bytes:
        raise ValueError(f"{label} exceeds configured size limit.")


def _validate_total_upload_size(files: list[UploadedFile], max_bytes: int, label: str) -> None:
    total = sum(file.size or 0 for file in files)
    if total <= 0:
        raise ValueError(f"{label} upload is empty.")
    if total > max_bytes:
        raise ValueError(f"{label} upload exceeds configured size limit.")


def _cleanup_upload_dir(job: ScanJob) -> None:
    if not job.upload_dir:
        return
    upload_root = Path(settings.SAST_WEB_UPLOAD_ROOT).resolve()
    candidate = Path(job.upload_dir).resolve()
    try:
        candidate.relative_to(upload_root)
    except ValueError:
        return
    if candidate == upload_root:
        return
    shutil.rmtree(candidate, ignore_errors=True)


def _safe_join(root: Path, relative: str) -> Path:
    clean = Path(relative.replace("\\", "/"))
    if clean.is_absolute() or clean.drive or ".." in clean.parts:
        raise ValueError("Unsafe upload path.")
    destination = (root / clean).resolve()
    root_resolved = root.resolve()
    try:
        destination.relative_to(root_resolved)
    except ValueError as exc:
        raise ValueError("Unsafe upload path.") from exc
    return destination


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
