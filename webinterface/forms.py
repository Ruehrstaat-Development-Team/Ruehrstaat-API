from django import forms

from carriers.models import Carrier, CarrierService

class EditCarrierForm(forms.ModelForm):
    class Meta:
        model = Carrier
        fields = ['name', 'currentLocation', 'previousLocation', 'services', 'dockingAccess', 'imageURL', 'category']
        labels = {
            'name': 'Name',
            'currentLocation': 'Current Location',
            'previousLocation': 'Previous Location',
            'services': 'Services',
            'dockingAccess': 'Docking Access',
            'imageURL': 'Image URL',
            'category': 'Category',
        }
        widgets = {
            'name': forms.TextInput(attrs={'class': 'darkTextArea'}),
            'currentLocation': forms.TextInput(attrs={'class': 'darkTextArea'}),
            'previousLocation': forms.TextInput(attrs={'class': 'darkTextArea'}),
            'services': forms.CheckboxSelectMultiple(),
            'dockingAccess': forms.Select(attrs={'class': 'darkTextArea'}),
            'imageURL': forms.TextInput(attrs={'class': 'darkTextArea'}),
            'category': forms.Select(attrs={'class': 'darkTextArea'}),
        }


