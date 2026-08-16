from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("scans", "0001_initial"),
    ]

    operations = [
        migrations.AlterField(
            model_name="scanjob",
            name="target_type",
            field=models.CharField(
                choices=[
                    ("github", "Github"),
                    ("file", "File"),
                    ("folder", "Folder"),
                    ("zip", "Zip"),
                    ("local_path", "Local Path"),
                ],
                max_length=32,
            ),
        ),
    ]
