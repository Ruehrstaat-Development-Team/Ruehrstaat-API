# Generated by Django 4.1.6 on 2023-03-28 21:17

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='apilog',
            name='newValue',
            field=models.TextField(blank=True, default=None, max_length=1000000, null=True),
        ),
        migrations.AlterField(
            model_name='apilog',
            name='oldValue',
            field=models.TextField(blank=True, default=None, max_length=1000000, null=True),
        ),
    ]