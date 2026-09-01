from typing import ClassVar

from django import forms

from wafinstaller.models import (
    AddressEntry,
    AddressList,
    Application,
    Policy,
    PolicyBinding,
    RuleExclusion,
    TriageDecision,
)


class StyledModelForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            css_class = (
                "form-check-input"
                if isinstance(field.widget, forms.CheckboxInput)
                else "form-control"
            )
            field.widget.attrs.setdefault("class", css_class)


class AddressListForm(StyledModelForm):
    class Meta:
        model = AddressList
        fields = ("name", "purpose", "description", "enabled")
        widgets: ClassVar[dict] = {"description": forms.Textarea(attrs={"rows": 2})}


class AddressEntryForm(StyledModelForm):
    class Meta:
        model = AddressEntry
        fields = (
            "address_list",
            "network",
            "comment",
            "source",
            "starts_at",
            "expires_at",
            "enabled",
        )
        widgets: ClassVar[dict] = {
            "comment": forms.Textarea(attrs={"rows": 2}),
            "starts_at": forms.DateTimeInput(attrs={"type": "datetime-local"}),
            "expires_at": forms.DateTimeInput(attrs={"type": "datetime-local"}),
        }


class RuleExclusionForm(StyledModelForm):
    class Meta:
        model = RuleExclusion
        fields = (
            "name",
            "kind",
            "rule_id",
            "target",
            "host",
            "rule_tag",
            "path",
            "path_match",
            "method",
            "rationale",
            "owner",
            "expires_at",
            "enabled",
        )
        widgets: ClassVar[dict] = {
            "rationale": forms.Textarea(attrs={"rows": 2}),
            "expires_at": forms.DateTimeInput(attrs={"type": "datetime-local"}),
        }


class TriageDecisionForm(StyledModelForm):
    class Meta:
        model = TriageDecision
        fields = ("classification", "notes")
        widgets: ClassVar[dict] = {
            "notes": forms.Textarea(
                attrs={"rows": 2, "placeholder": "Reasoning, evidence or follow-up"}
            )
        }


class ApplicationForm(StyledModelForm):
    class Meta:
        model = Application
        fields = ("name", "hostname", "description", "enabled")
        widgets: ClassVar[dict] = {"description": forms.Textarea(attrs={"rows": 2})}


class PolicyForm(StyledModelForm):
    class Meta:
        model = Policy
        fields = (
            "name",
            "description",
            "parent",
            "engine_mode",
            "paranoia_level",
            "inbound_threshold",
            "outbound_threshold",
            "enabled",
        )
        widgets: ClassVar[dict] = {"description": forms.Textarea(attrs={"rows": 2})}


class PolicyBindingForm(StyledModelForm):
    class Meta:
        model = PolicyBinding
        fields = ("application", "policy", "overrides", "enabled")
        widgets: ClassVar[dict] = {
            "overrides": forms.Textarea(
                attrs={
                    "rows": 3,
                    "placeholder": '{"paranoia_level": 2, "inbound_threshold": 7}',
                }
            )
        }
