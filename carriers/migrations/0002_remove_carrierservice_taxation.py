# Generated by Django 4.0.5 on 2022-06-07 18:34

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('carriers', '0001_initial'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='carrierservice',
            name='taxation',
        ),
    ]
