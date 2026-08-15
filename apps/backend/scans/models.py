from __future__ import annotations

import uuid

from django.db import models


class ScanJob(models.Model):
    class Status(models.TextChoices):
        QUEUED = "QUEUED"
        RUNNING = "RUNNING"
        SUCCESS = "SUCCESS"
        FAILED = "FAILED"
        PARTIAL = "PARTIAL"
        ERROR = "ERROR"

    class TargetType(models.TextChoices):
        GITHUB = "github"
        FILE = "file"
        FOLDER = "folder"
        LOCAL_PATH = "local_path"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    target_type = models.CharField(max_length=32, choices=TargetType.choices)
    target_display = models.TextField()
    resolved_target = models.TextField(blank=True)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.QUEUED)
    progress_message = models.CharField(max_length=255, blank=True)
    output_dir = models.TextField(blank=True)
    report_json_path = models.TextField(blank=True)
    report_html_path = models.TextField(blank=True)
    report_sarif_path = models.TextField(blank=True)
    summary = models.JSONField(default=dict, blank=True)
    coverage = models.JSONField(default=dict, blank=True)
    integrity = models.JSONField(default=dict, blank=True)
    error = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"{self.id} {self.target_type} {self.status}"
