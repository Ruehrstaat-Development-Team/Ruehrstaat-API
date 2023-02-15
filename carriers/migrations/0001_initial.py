# Generated by Django 4.0.5 on 2022-06-07 18:29

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='CarrierService',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=255)),
                ('description', models.TextField()),
                ('taxation', models.DecimalField(decimal_places=0, max_digits=3, validators=[django.core.validators.MinValueValidator(0), django.core.validators.MaxValueValidator(100)])),
                ('odyssey', models.BooleanField(default=False)),
            ],
        ),
        migrations.CreateModel(
            name='Carrier',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=255)),
                ('callsign', models.CharField(max_length=255)),
                ('currentLocation', models.CharField(max_length=255)),
                ('nextLocation', models.CharField(max_length=255)),
                ('nextDestination', models.CharField(max_length=255)),
                ('nextDestinationTime', models.DateTimeField()),
                ('departureTime', models.DateTimeField()),
                ('dockingAccess', models.BooleanField(default=True)),
                ('owner', models.CharField(max_length=255)),
                ('services', models.ManyToManyField(to='carriers.carrierservice')),
            ],
        ),
    ]
