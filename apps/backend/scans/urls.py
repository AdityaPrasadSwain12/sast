from __future__ import annotations

from django.urls import path

from . import views

urlpatterns = [
    path("health/", views.health),
    path("scans/", views.scans),
    path("scans/<uuid:job_id>/", views.scan_detail),
    path("scans/<uuid:job_id>/report/<str:report_type>/", views.scan_report),
    path("reports/latest/", views.latest_report),
    path("reports/latest/<str:report_type>/", views.latest_report_file),
]
