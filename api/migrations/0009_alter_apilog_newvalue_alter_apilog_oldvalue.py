# Generated by Django 4.1.6 on 2023-03-13 22:28

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0008_alter_apilog_user'),
    ]

    operations = [
        migrations.AlterField(
            model_name='apilog',
            name='newValue',
            field=models.CharField(blank=True, default=None, max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='apilog',
            name='oldValue',
            field=models.CharField(blank=True, default=None, max_length=100, null=True),
        ),
    ]