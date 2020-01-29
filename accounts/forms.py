from django import forms
from django.contrib.auth import authenticate
from django.contrib.auth.forms import UserCreationForm
from django import forms

import unicodedata

from django import forms
from django.contrib.auth import (
    authenticate, get_user_model, password_validation,
)
from django.contrib.auth.hashers import (
    UNUSABLE_PASSWORD_PREFIX, identify_hasher,
)
from django.contrib.auth.models import User
from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import EmailMultiAlternatives
from django.template import loader
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django.utils.text import capfirst
from django.utils.translation import gettext, gettext_lazy as _

UserModel = get_user_model()


def _unicode_ci_compare(s1, s2):
    """
    Perform case-insensitive comparison of two identifiers, using the
    recommended algorithm from Unicode Technical Report 36, section
    2.11.2(B)(2).
    """
    return unicodedata.normalize('NFKC', s1).casefold() == unicodedata.normalize('NFKC', s2).casefold()


class ReadOnlyPasswordHashWidget(forms.Widget):
    template_name = 'auth/widgets/read_only_password_hash.html'
    read_only = True

    def get_context(self, name, value, attrs):
        context = super().get_context(name, value, attrs)
        summary = []
        if not value or value.startswith(UNUSABLE_PASSWORD_PREFIX):
            summary.append({'label': gettext("No password set.")})
        else:
            try:
                hasher = identify_hasher(value)
            except ValueError:
                summary.append({'label': gettext("Invalid password format or unknown hashing algorithm.")})
            else:
                for key, value_ in hasher.safe_summary(value).items():
                    summary.append({'label': gettext(key), 'value': value_})
        context['summary'] = summary
        return context


class ReadOnlyPasswordHashField(forms.Field):
    widget = ReadOnlyPasswordHashWidget

    def __init__(self, *args, **kwargs):
        kwargs.setdefault("required", False)
        super().__init__(*args, **kwargs)

    def bound_data(self, data, initial):
        # Always return initial because the widget doesn't
        # render an input field.
        return initial

    def has_changed(self, initial, data):
        return False


class UsernameField(forms.CharField):
    def to_python(self, value):
        return unicodedata.normalize('NFKC', super().to_python(value))



from accounts.models import User

GENDER_CHOICES = (
    ('male', 'Male'),
    ('female', 'Female'))


class UserCreationForm1(forms.ModelForm):
    """
    A form that creates a user, with no privileges, from the given username and
    password.
    """
    error_messages = {
        'password_mismatch': _("The two password fields didn't match."),
    }
    password1 = forms.CharField(
        label=_("Password"),
        strip=False,
        widget=forms.PasswordInput,
        help_text=password_validation.password_validators_help_text_html(),
    )
    password2 = forms.CharField(
        label=_("Password confirmation"),
        widget=forms.PasswordInput,
        strip=False,
        help_text=_("Enter the same password as before, for verification."),
    )
    phone_no = forms.IntegerField(
        label=_("phone_no"),
        widget=forms.TextInput,
        help_text=_("Enter the Contact No."),
    )
    founded_by = forms.CharField(
        label=_("founded_by"),
        widget=forms.TextInput,
        strip=False,
        help_text=_("Enter in Text format."),
    )
    founded_year = forms.CharField(
        label=_("founded_year"),
        widget=forms.TextInput,
        strip=False,
        help_text=_("Enter in Text format."),
    )
    website_url = forms.CharField(
        label=_("website_url"),
        widget=forms.TextInput,
        strip=False,
        help_text=_("Enter url."),
    )
    no_emp = forms.CharField(
        label=_("no_emp"),
        widget=forms.TextInput,
        strip=False,
        help_text=_("Enter in Text format."),
    )






class EmployeeRegistrationForm(UserCreationForm):
    # gender = forms.MultipleChoiceField(widget=forms.CheckboxSelectMultiple, choices=GENDER_CHOICES)

    def __init__(self, *args, **kwargs):
        super(EmployeeRegistrationForm, self).__init__(*args, **kwargs)
        self.fields['gender'].required = True
        self.fields['first_name'].label = "First Name"
        self.fields['last_name'].label = "Last Name"
        self.fields['password1'].label = "Password"
        self.fields['password2'].label = "Confirm Password"

        # self.fields['gender'].widget = forms.CheckboxInput()

        self.fields['first_name'].widget.attrs.update(
            {
                'placeholder': 'Enter First Name',
            }
        )
        self.fields['last_name'].widget.attrs.update(
            {
                'placeholder': 'Enter Last Name',
            }
        )
        self.fields['email'].widget.attrs.update(
            {
                'placeholder': 'Enter Email',
            }
        )
        self.fields['password1'].widget.attrs.update(
            {
                'placeholder': 'Enter Password',
            }
        )
        self.fields['password2'].widget.attrs.update(
            {
                'placeholder': 'Confirm Password',
            }
        )

    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email', 'password1', 'password2', 'gender']
        error_messages = {
            'first_name': {
                'required': 'First name is required',
                'max_length': 'Name is too long'
            },
            'last_name': {
                'required': 'Last name is required',
                'max_length': 'Last Name is too long'
            },
            'gender': {
                'required': 'Gender is required'
            }
        }

    def clean_gender(self):
        gender = self.cleaned_data.get('gender')
        if not gender:
            raise forms.ValidationError("Gender is required")
        return gender

    def save(self, commit=True):
        user = super(UserCreationForm, self).save(commit=False)
        user.role = "employee"
        if commit:
            user.save()
        return user


class EmployerRegistrationForm(UserCreationForm1):

    def __init__(self, *args, **kwargs):
        super(EmployerRegistrationForm, self).__init__(*args, **kwargs)
        self.fields['first_name'].label = "Company Name"
        self.fields['last_name'].label = "Company Address"
        self.fields['password1'].label = "Password"
        self.fields['password2'].label = "Confirm Password"

        self.fields['first_name'].widget.attrs.update(
            {
                'placeholder': 'Company Name',
            }
        )
        self.fields['last_name'].widget.attrs.update(
            {
                'placeholder': 'Company Address',
            }
        )
        self.fields['email'].widget.attrs.update(
            {
                'placeholder': 'Email',
            }
        )
        self.fields['phone_no'].widget.attrs.update(
            {
                'placeholder': 'Mobile no.',
            }
        )
        self.fields['password1'].widget.attrs.update(
            {
                'placeholder': 'Enter Password',
            }
        )
        self.fields['password2'].widget.attrs.update(
            {
                'placeholder': 'Confirm Password',
            }
        )
        self.fields['website_url'].widget.attrs.update(
            {
                'placeholder': 'Website Url',
            }
        )
        self.fields['founded_by'].widget.attrs.update(
            {
                'placeholder': 'Founded By',
            }
        )

        self.fields['founded_year'].widget.attrs.update(
            {
                'placeholder': 'Founded Year',
            }
        )
        self.fields['no_emp'].widget.attrs.update(
            {
                'placeholder': 'enter phone no',
            }
        )


    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email', 'password1', 'password2']
        error_messages = {
            'first_name': {
                'required': 'First name is required',
                'max_length': 'Name is too long'
            },
            'last_name': {
                'required': 'Last name is required',
                'max_length': 'Last Name is too long'
            }
        }

    def save(self, commit=True):
        user = super(UserCreationForm1, self).save(commit=False)
        user.role = "employer"
        if commit:
            user.save()
        return user


class UserLoginForm(forms.Form):
    email = forms.EmailField()
    password = forms.CharField(
        label="Password",
        strip=False,
        widget=forms.PasswordInput,
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.user = None
        self.fields['email'].widget.attrs.update({'placeholder': 'Enter Email'})
        self.fields['password'].widget.attrs.update({'placeholder': 'Enter Password'})

    def clean(self, *args, **kwargs):
        email = self.cleaned_data.get("email")
        password = self.cleaned_data.get("password")

        if email and password:
            self.user = authenticate(email=email, password=password)

            if self.user is None:
                raise forms.ValidationError("User Does Not Exist.")
            if not self.user.check_password(password):
                raise forms.ValidationError("Password Does not Match.")
            if not self.user.is_active:
                raise forms.ValidationError("User is not Active.")

        return super(UserLoginForm, self).clean(*args, **kwargs)

    def get_user(self):
        return self.user



class Profile_update_form(forms.ModelForm):
    middle_name = forms.CharField(
        label=_("middle_name"),
        widget=forms.TextInput,
        strip=False,
        help_text=_("Enter in Text format."),
    )
    job_title = forms.CharField(
        label=_("job_title"),
        widget=forms.TextInput,
        strip=False,
        help_text=_("Enter in Text format."),
    )
    tot_exp_yr = forms.CharField(
        label=_("tot_exp_yr"),
        widget=forms.TextInput,
        strip=False,
        help_text=_("Enter in Text format."),
    )
    tot_exp_mon = forms.CharField(
        label=_("tot_exp_mon"),
        widget=forms.TextInput,
        strip=False,
        help_text=_("Enter in Text format."),
    )
    dob_city = forms.CharField(
        label=_("dob_city"),
        widget=forms.TextInput,
        strip=False,
        help_text=_("Enter in Text format."),
    )
    dob_state = forms.CharField(
        label=_("dob_state"),
        widget=forms.TextInput,
        strip=False,
        help_text=_("Enter in Text format."),
    )
    dob_country = forms.CharField(
        label=_("dob_country"),
        widget=forms.TextInput,
        strip=False,
        help_text=_("Enter in Text format."),
    )

    dob = forms.CharField(
        label=_("dob"),
        widget=forms.TextInput,
        strip=False,
        help_text=_("Enter in Text format."),
    )

    address = forms.CharField(
        label=_("address"),
        widget=forms.TextInput,
        strip=False,
        help_text=_("Enter in Text format."),
    )

    city = forms.CharField(
        label=_("city"),
        widget=forms.TextInput,
        strip=False,
        help_text=_("Enter in Text format."),
    )
    state = forms.CharField(
        label=_("state"),
        widget=forms.TextInput,
        strip=False,
        help_text=_("Enter in Text format."),
    )
    country = forms.CharField(
        label=_("country"),
        widget=forms.TextInput,
        strip=False,
        help_text=_("Enter in Text format."),
    )
    pin = forms.CharField(
        label=_("pin"),
        widget=forms.TextInput,
        strip=False,
        help_text=_("Enter in Text format."),
    )
    tel = forms.CharField(
        label=_("tel"),
        widget=forms.TextInput,
        strip=False,
        help_text=_("Enter in Text format."),
    )
    mob = forms.CharField(
        label=_("mob"),
        widget=forms.TextInput,
        strip=False,
        help_text=_("Enter in Text format."),
    )
    email = forms.CharField(
        label=_("email"),
        widget=forms.TextInput,
        strip=False,
        help_text=_("Enter in Text format."),
    )






class EmployeeProfileUpdateForm(Profile_update_form):

    def __init__(self, *args, **kwargs):
        super(EmployeeProfileUpdateForm, self).__init__(*args, **kwargs)
        self.fields['first_name'].widget.attrs.update(
            {
                'placeholder': 'Enter First Name',
            }
        )
        self.fields['last_name'].widget.attrs.update(
            {
                'placeholder': 'Enter Last Name',
            }
        )
        self.fields['middle_name'].widget.attrs.update(
            {
                'placeholder': 'Enter Last Name',
            }
        )
        self.fields['job_title'].widget.attrs.update(
            {
                'placeholder': 'Enter Last Name',
            }
        )
        self.fields['tot_exp_yr'].widget.attrs.update(
            {
                'placeholder': 'Enter Last Name',
            }
        )

        self.fields['tot_exp_mon'].widget.attrs.update(
            {
                'placeholder': 'Enter Last Name',
            }
        )
        self.fields['dob_city'].widget.attrs.update(
            {
                'placeholder': 'Enter Last Name',
            }
        )
        self.fields['dob_state'].widget.attrs.update(
            {
                'placeholder': 'Enter Last Name',
            }
        )
        self.fields['dob'].widget.attrs.update(
            {
                'placeholder': 'Enter Last Name',
            }
        )
        self.fields['address'].widget.attrs.update(
            {
                'placeholder': 'Enter Last Name',
            }
        )
        self.fields['city'].widget.attrs.update(
            {
                'placeholder': 'Enter Last Name',
            }
        )
        self.fields['state'].widget.attrs.update(
            {
                'placeholder': 'Enter Last Name',
            }
        )
        self.fields['country'].widget.attrs.update(
            {
                'placeholder': 'Enter Last Name',
            }
        )
        self.fields['pin'].widget.attrs.update(
            {
                'placeholder': 'Enter Last Name',
            }
        )
        self.fields['tel'].widget.attrs.update(
            {
                'placeholder': 'Enter Last Name',
            }
        )
        self.fields['mob'].widget.attrs.update(
            {
                'placeholder': 'Enter Last Name',
            }
        )

    class Meta:
        model = User
        fields = ["first_name", "last_name", "gender","middle_name","job_title","tot_exp_yr","tot_exp_mon","dob_city","dob_state","dob","address","city","state","country","pin","tel","mob"]
