# Generated by Django 4.1.6 on 2023-02-02 19:21

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('carriers', '0011_carrier_ownerdiscordid'),
        ('api', '0005_rename_hasaccesstoall_apikey_haswriteaccesstoall_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='ApiLog',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('time', models.DateTimeField(auto_now_add=True)),
                ('type', models.CharField(max_length=20)),
                ('source', models.CharField(choices=[('edmc', 'EDMC'), ('discord', 'Discord'), ('admin', 'Admin'), ('other', 'Other')], default='other', max_length=20)),
                ('oldValue', models.CharField(max_length=100)),
                ('newValue', models.CharField(max_length=100)),
                ('carrier', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='carriers.carrier')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='api.apikey')),
            ],
        ),
    ]