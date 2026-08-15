from __future__ import annotations

import uuid

from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="ScanJob",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("target_type", models.CharField(choices=[("github", "Github"), ("file", "File"), ("folder", "Folder"), ("local_path", "Local Path")], max_length=32)),
                ("target_display", models.TextField()),
                ("resolved_target", models.TextField(blank=True)),
                ("status", models.CharField(choices=[("QUEUED", "Queued"), ("RUNNING", "Running"), ("SUCCESS", "Success"), ("FAILED", "Failed"), ("PARTIAL", "Partial"), ("ERROR", "Error")], default="QUEUED", max_length=16)),
                ("progress_message", models.CharField(blank=True, max_length=255)),
                ("output_dir", models.TextField(blank=True)),
                ("report_json_path", models.TextField(blank=True)),
                ("report_html_path", models.TextField(blank=True)),
                ("report_sarif_path", models.TextField(blank=True)),
                ("summary", models.JSONField(blank=True, default=dict)),
                ("coverage", models.JSONField(blank=True, default=dict)),
                ("integrity", models.JSONField(blank=True, default=dict)),
                ("error", models.TextField(blank=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("started_at", models.DateTimeField(blank=True, null=True)),
                ("finished_at", models.DateTimeField(blank=True, null=True)),
            ],
            options={"ordering": ["-created_at"]},
        ),
    ]
