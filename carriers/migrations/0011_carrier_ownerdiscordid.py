# Generated by Django 4.1.6 on 2023-02-01 22:08

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('carriers', '0010_rename_hasownwebsite_carrier_isflagship'),
    ]

    operations = [
        migrations.AddField(
            model_name='carrier',
            name='ownerDiscordID',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
    ]
