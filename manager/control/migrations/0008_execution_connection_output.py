from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [('control', '0007_execution_owner_decision')]
    operations = [migrations.AddField(model_name='registeredexecutionconnection', name='output_root_path',
        field=models.TextField(blank=True, default='')),
        migrations.AddField(model_name='collectionworkerlease', name='source_probe_scope_sha256',
            field=models.CharField(max_length=64, blank=True, default=''))]
