# Generated by Django 4.1.6 on 2023-03-22 19:39

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('carriers', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='carrier',
            name='ownerDiscordID',
            field=models.BigIntegerField(blank=True, max_length=255, null=True),
        ),
    ]