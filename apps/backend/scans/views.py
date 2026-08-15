from __future__ import annotations

import json
from pathlib import Path

from django.conf import settings
from django.http import FileResponse, Http404, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_http_methods

from .models import ScanJob
from .pdf import write_scan_pdf
from .services import create_scan_job, job_payload


@require_GET
def health(_request):
    return JsonResponse({"status": "ok", "service": "sast-scan-api"})


@csrf_exempt
@require_http_methods(["GET", "POST"])
def scans(request):
    if request.method == "GET":
        jobs = ScanJob.objects.all()[:25]
        return JsonResponse({"results": [job_payload(job) for job in jobs]})

    try:
        content_type = request.headers.get("Content-Type", "")
        if content_type.startswith("application/json"):
            body = json.loads(request.body.decode("utf-8") or "{}")
            job = create_scan_job(
                target_type=body.get("target_type", ""),
                github_url=body.get("github_url", ""),
                local_path=body.get("local_path", ""),
            )
        else:
            target_type = request.POST.get("target_type", "")
            files = list(request.FILES.getlist("files"))
            relative_paths = request.POST.getlist("relative_paths")
            job = create_scan_job(target_type=target_type, files=files, relative_paths=relative_paths)
    except Exception as exc:  # noqa: BLE001
        return JsonResponse({"error": str(exc)}, status=400)
    return JsonResponse(job_payload(job), status=202)


@require_GET
def scan_detail(_request, job_id):
    job = _get_job(job_id)
    return JsonResponse(job_payload(job))


@require_GET
def scan_report(_request, job_id, report_type: str):
    job = _get_job(job_id)
    path_by_type = {
        "json": job.report_json_path,
        "html": job.report_html_path,
        "sarif": job.report_sarif_path,
        "pdf": str(Path(job.output_dir) / "scan.pdf"),
    }
    if report_type not in path_by_type:
        raise Http404("Unknown report type.")
    path = Path(path_by_type[report_type])
    if report_type == "pdf":
        _ensure_pdf(path, Path(job.report_json_path))
    if not path.exists():
        raise Http404("Report is not available yet.")
    content_types = {
        "json": "application/json",
        "html": "text/html",
        "sarif": "application/sarif+json",
        "pdf": "application/pdf",
    }
    return FileResponse(
        path.open("rb"),
        as_attachment=report_type == "pdf",
        filename="sast-scan-report.pdf" if report_type == "pdf" else None,
        content_type=content_types[report_type],
    )


@require_GET
def latest_report(_request):
    path = Path(settings.SAST_WEB_REPORT_ROOT) / "scan.json"
    if not path.exists():
        raise Http404("Latest JSON report is not available yet.")
    return JsonResponse(json.loads(path.read_text(encoding="utf-8")))


@require_GET
def latest_report_file(_request, report_type: str):
    path_by_type = {
        "json": Path(settings.SAST_WEB_REPORT_ROOT) / "scan.json",
        "html": Path(settings.SAST_WEB_REPORT_ROOT) / "scan.html",
        "sarif": Path(settings.SAST_WEB_REPORT_ROOT) / "scan.sarif",
        "pdf": Path(settings.SAST_WEB_REPORT_ROOT) / "scan.pdf",
    }
    if report_type not in path_by_type:
        raise Http404("Unknown report type.")
    path = path_by_type[report_type]
    if report_type == "pdf":
        _ensure_pdf(path, path_by_type["json"])
    if not path.exists():
        raise Http404("Latest report file is not available yet.")
    content_types = {
        "json": "application/json",
        "html": "text/html",
        "sarif": "application/sarif+json",
        "pdf": "application/pdf",
    }
    return FileResponse(
        path.open("rb"),
        as_attachment=report_type == "pdf",
        filename="sast-scan-report.pdf" if report_type == "pdf" else None,
        content_type=content_types[report_type],
    )


def _get_job(job_id) -> ScanJob:
    try:
        return ScanJob.objects.get(id=job_id)
    except ScanJob.DoesNotExist as exc:
        raise Http404("Scan job not found.") from exc


def _ensure_pdf(pdf_path: Path, json_path: Path) -> None:
    if pdf_path.exists() and json_path.exists() and pdf_path.stat().st_mtime >= json_path.stat().st_mtime:
        return
    if not json_path.exists():
        return
    write_scan_pdf(json.loads(json_path.read_text(encoding="utf-8")), pdf_path)
