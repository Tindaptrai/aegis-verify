from django.db import migrations


def seed(apps, schema_editor):
    apps.get_model("control", "DispatchLock").objects.create(pk=1)


class Migration(migrations.Migration):
    dependencies = [("control", "0001_initial")]
    operations = [migrations.RunPython(seed, migrations.RunPython.noop)]
