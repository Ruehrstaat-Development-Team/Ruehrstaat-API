# Generated by Django 4.1.6 on 2023-03-21 11:45

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('backend', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='discord_tag',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
    ]