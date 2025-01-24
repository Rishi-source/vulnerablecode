#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from django import forms
from django.core.validators import validate_email

from vulnerabilities.models import ApiUser


class PackageSearchForm(forms.Form):
    search = forms.CharField(
        required=True,
        widget=forms.TextInput(
            attrs={
                "placeholder": "Package name, purl or purl fragment",
            },
        ),
    )
    type = forms.CharField(required=False, max_length=50)
    vulnerable_only = forms.ChoiceField(
        required=False,
        choices=(
            ("", "All Packages"),
            ("true", "Vulnerable Only"),
            ("false", "Non-Vulnerable Only"),
        ),
    )

    def clean_search(self):
        """Sanitize the search input which provide extra layer of protection from XSS attacks"""
        search = self.cleaned_data["search"].strip()
        if not search:
            raise forms.ValidationError("Search field cannot be empty")
        return search

    def clean_type(self):
        """Sanitize the type input which provide extra layer of protection from XSS attacks"""
        pkg_type = self.cleaned_data["type"].strip()
        return pkg_type


class VulnerabilitySearchForm(forms.Form):

    search = forms.CharField(
        required=True,
        widget=forms.TextInput(
            attrs={"placeholder": "Vulnerability id or alias such as CVE or GHSA"}
        ),
    )


class ApiUserCreationForm(forms.ModelForm):
    """
    Support a simplified creation for API-only users directly from the UI.
    """

    class Meta:
        model = ApiUser
        fields = (
            "email",
            "first_name",
            "last_name",
        )

    def __init__(self, *args, **kwargs):
        super(ApiUserCreationForm, self).__init__(*args, **kwargs)
        email_field = self.fields["email"]
        first_name_field = self.fields["first_name"]
        last_name_field = self.fields["last_name"]
        email_field.required = True
        email_field.label = "Email"
        email_field.widget.attrs["class"] = "input"
        email_field.widget.attrs["style"] = "width: 50%"
        email_field.widget.attrs["placeholder"] = "foo@bar.com"
        first_name_field.label = "First Name"
        first_name_field.widget.attrs["class"] = "input"
        first_name_field.widget.attrs["style"] = "width: 50%"
        first_name_field.widget.attrs["placeholder"] = "Jon"
        last_name_field.label = "Last Name"
        last_name_field.widget.attrs["class"] = "input"
        last_name_field.widget.attrs["style"] = "width: 50%"
        last_name_field.widget.attrs["placeholder"] = "Doe"

    def save(self, commit=True):
        return ApiUser.objects.create_api_user(
            username=self.cleaned_data["email"],
            first_name=self.cleaned_data["first_name"],
            last_name=self.cleaned_data["last_name"],
        )

    def clean_username(self):
        username = self.cleaned_data["email"]
        validate_email(username)
        return username

    def save_m2m(self):
        pass
