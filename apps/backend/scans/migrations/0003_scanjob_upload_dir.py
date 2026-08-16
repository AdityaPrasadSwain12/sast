from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("scans", "0002_add_zip_target_type"),
    ]

    operations = [
        migrations.AddField(
            model_name="scanjob",
            name="upload_dir",
            field=models.TextField(blank=True),
        ),
    ]
