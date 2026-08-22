import ipaddress
import json
import re
from hashlib import sha256
from typing import ClassVar

from django.conf import settings
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.core.validators import RegexValidator
from django.db import models
from django.utils.timezone import now

# Create your models here.


# models.py
class Attack(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    ip = models.GenericIPAddressField(null=True, blank=True)
    country = models.CharField(max_length=100)
    flag = models.CharField(max_length=10)
    rule_id = models.CharField(max_length=20, default="UNKNOWN_RULE")
    message = models.TextField(default="No message")
    uri = models.CharField(max_length=2048)
    referer = models.CharField(max_length=2048, blank=True, null=True)
    status = models.CharField(max_length=20, default="Detected")
    version = models.CharField(max_length=20)
    host = models.CharField(max_length=255, null=True, blank=True)
    severity = models.IntegerField(default=2)  # 0=Info, 1=Low, 2=Medium, 3=High
    anomaly_score = models.IntegerField(default=0)
    method = models.CharField(max_length=12, blank=True)
    transaction_id = models.CharField(max_length=128, blank=True, db_index=True)
    matched_variable = models.CharField(max_length=255, blank=True)
    rule_tags = models.JSONField(default=list, blank=True)
    source_port = models.PositiveIntegerField(null=True, blank=True)
    destination_ip = models.GenericIPAddressField(null=True, blank=True)
    destination_port = models.PositiveIntegerField(null=True, blank=True)
    protocol = models.CharField(max_length=8, default="TCP")

    def __str__(self):
        return f"{self.timestamp} - {self.ip} - Severity: {self.severity}"


class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    two_factor_enabled = models.BooleanField(default=False)
    two_factor_secret = models.CharField(max_length=32, blank=True, null=True)


class CrsVersion(models.Model):
    tag = models.CharField(max_length=100, unique=True)
    published_at = models.DateTimeField()
    zip_url = models.URLField()
    fetched_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.tag


class DashboardStat(models.Model):
    fetched_at = models.DateTimeField(default=now)
    cpu_usage = models.CharField(max_length=20)
    cpu_load = models.CharField(max_length=20)
    ram_usage = models.CharField(max_length=20)
    disk_usage = models.CharField(max_length=20)
    storage_free = models.CharField(max_length=20)
    total_processes = models.CharField(max_length=20)
    total_threads = models.CharField(max_length=20)
    total_handles = models.CharField(max_length=20)

    def __str__(self):
        return f"DashboardStat at {self.fetched_at}"


class AppSetting(models.Model):
    key = models.CharField(max_length=255, unique=True)
    value = models.TextField()

    def __str__(self):
        return f"{self.key} = {self.value}"


class AuditEntry(models.Model):
    class Outcome(models.TextChoices):
        SUCCEEDED = "succeeded", "Succeeded"
        FAILED = "failed", "Failed"

    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="waf_audit_entries",
    )
    action = models.CharField(max_length=100, db_index=True)
    target = models.CharField(max_length=500)
    outcome = models.CharField(max_length=16, choices=Outcome.choices)
    remote_addr = models.GenericIPAddressField(null=True, blank=True)
    details = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ("-created_at", "-id")

    def __str__(self):
        return f"{self.created_at} {self.action} {self.outcome}"


class AddressList(models.Model):
    class Purpose(models.TextChoices):
        TRUSTED = "trusted", "Trusted (inspect, never auto-ban)"
        WAF_BYPASS = "waf_bypass", "WAF bypass"
        BLOCK = "block", "Block"
        OBSERVE = "observe", "Observe only"

    name = models.CharField(
        max_length=80,
        unique=True,
        validators=[
            RegexValidator(
                r"^[A-Za-z][A-Za-z0-9_.-]{1,79}$",
                "Use 2-80 letters, numbers, dots, underscores or hyphens.",
            )
        ],
    )
    purpose = models.CharField(max_length=16, choices=Purpose.choices)
    description = models.CharField(max_length=500)
    enabled = models.BooleanField(default=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="created_waf_address_lists",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("name",)

    def __str__(self):
        return self.name


class AddressEntry(models.Model):
    address_list = models.ForeignKey(
        AddressList, on_delete=models.CASCADE, related_name="entries"
    )
    network = models.CharField(max_length=49)
    comment = models.CharField(max_length=500)
    source = models.CharField(max_length=120, default="manual")
    enabled = models.BooleanField(default=True)
    starts_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="created_waf_address_entries",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("address_list__name", "network")
        constraints: ClassVar[list] = [
            models.UniqueConstraint(
                fields=("address_list", "network"),
                name="unique_network_per_waf_address_list",
            )
        ]

    def clean(self):
        super().clean()
        try:
            self.network = str(ipaddress.ip_network(self.network, strict=False))
        except ValueError as exc:
            raise ValidationError(
                {"network": "Enter a valid IPv4/IPv6 address or CIDR."}
            ) from exc
        if self.starts_at and self.expires_at and self.expires_at <= self.starts_at:
            raise ValidationError(
                {"expires_at": "Expiration must be after the start date."}
            )

    def is_active_at(self, moment):
        return (
            self.enabled
            and self.address_list.enabled
            and (self.starts_at is None or self.starts_at <= moment)
            and (self.expires_at is None or self.expires_at > moment)
        )

    def __str__(self):
        return f"{self.address_list.name}: {self.network}"


class RuleExclusion(models.Model):
    class Kind(models.TextChoices):
        REMOVE_RULE = "remove_rule", "Remove rule"
        REMOVE_TARGET = "remove_target", "Remove variable from rule"

    class PathMatch(models.TextChoices):
        EXACT = "exact", "Exact path"
        PREFIX = "prefix", "Path prefix"

    class Status(models.TextChoices):
        DRAFT = "draft", "Draft"
        APPROVED = "approved", "Approved"

    name = models.CharField(max_length=120, unique=True)
    kind = models.CharField(max_length=20, choices=Kind.choices)
    rule_id = models.PositiveBigIntegerField(null=True, blank=True)
    rule_tag = models.CharField(max_length=120, blank=True)
    target = models.CharField(
        max_length=255,
        blank=True,
        help_text="For example ARGS:description. Required for target exclusions.",
    )
    host = models.CharField(max_length=253, blank=True)
    path = models.CharField(max_length=2048, blank=True)
    path_match = models.CharField(
        max_length=12, choices=PathMatch.choices, default=PathMatch.PREFIX
    )
    method = models.CharField(max_length=12, blank=True)
    rationale = models.CharField(max_length=1000)
    owner = models.CharField(max_length=120)
    enabled = models.BooleanField(default=True)
    status = models.CharField(
        max_length=12, choices=Status.choices, default=Status.DRAFT
    )
    expires_at = models.DateTimeField(null=True, blank=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="created_waf_rule_exclusions",
    )
    approved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="approved_waf_rule_exclusions",
    )
    approved_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("name",)

    def clean(self):
        super().clean()
        errors = {}
        for field_name in ("name", "rationale", "owner"):
            value = getattr(self, field_name)
            if any(character in value for character in "\r\n\x00"):
                errors[field_name] = "Control characters and newlines are not allowed."
        if bool(self.rule_id) == bool(self.rule_tag):
            errors["rule_id"] = "Define exactly one rule ID or rule tag."
            errors["rule_tag"] = "Define exactly one rule ID or rule tag."
        if self.rule_id and self.rule_id > 999_999_999:
            errors["rule_id"] = "Rule ID is outside the supported range."
        if self.rule_tag and not re.fullmatch(r"[A-Za-z0-9_./:-]+", self.rule_tag):
            errors["rule_tag"] = "Enter a safe CRS rule tag."
        if self.kind == self.Kind.REMOVE_TARGET and not self.target:
            errors["target"] = "A target variable is required for this exclusion type."
        if self.kind == self.Kind.REMOVE_RULE and self.target:
            errors["target"] = (
                "A full-rule exclusion must not define a target variable."
            )
        if self.host and not re.fullmatch(r"[A-Za-z0-9.-]+", self.host):
            errors["host"] = "Enter a hostname without a scheme, port or wildcard."
        if self.path and (
            not self.path.startswith("/")
            or any(character in self.path for character in '\r\n\x00"')
        ):
            errors["path"] = (
                "Enter an absolute HTTP path without quotes or control characters."
            )
        if self.method:
            self.method = self.method.upper()
            if self.method not in {
                "GET",
                "HEAD",
                "POST",
                "PUT",
                "PATCH",
                "DELETE",
                "OPTIONS",
            }:
                errors["method"] = "Unsupported HTTP method."
        if self.target and not re.fullmatch(
            r"[A-Za-z][A-Za-z0-9_]*(?::[A-Za-z0-9_.-]+)?", self.target
        ):
            errors["target"] = (
                "Enter a safe ModSecurity variable, for example ARGS:description."
            )
        if errors:
            raise ValidationError(errors)

    def is_active_at(self, moment):
        return (
            self.enabled
            and self.status == self.Status.APPROVED
            and (self.expires_at is None or self.expires_at > moment)
        )

    def __str__(self):
        return self.name


class TriageDecision(models.Model):
    class Classification(models.TextChoices):
        CONFIRMED_ATTACK = "confirmed_attack", "Confirmed attack"
        FALSE_POSITIVE = "false_positive", "False positive"
        AUTHORISED = "authorised", "Authorised activity"
        KNOWN_SCANNER = "known_scanner", "Known scanner"
        NEEDS_ANALYSIS = "needs_analysis", "Needs analysis"

    attack = models.OneToOneField(
        Attack, on_delete=models.CASCADE, related_name="triage"
    )
    classification = models.CharField(max_length=24, choices=Classification.choices)
    notes = models.CharField(max_length=1000, blank=True)
    decided_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="waf_triage_decisions",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("-updated_at",)

    def __str__(self):
        return f"Event {self.attack_id}: {self.get_classification_display()}"


class PolicyRevision(models.Model):
    class Status(models.TextChoices):
        CANDIDATE = "candidate", "Candidate"
        APPROVED = "approved", "Approved"
        DEPLOYED = "deployed", "Deployed"
        FAILED = "failed", "Failed"
        SUPERSEDED = "superseded", "Superseded"

    checksum = models.CharField(max_length=64, unique=True)
    before_content = models.TextField()
    after_content = models.TextField()
    summary = models.JSONField(default=dict, blank=True)
    status = models.CharField(
        max_length=16, choices=Status.choices, default=Status.CANDIDATE
    )
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="created_waf_policy_revisions",
    )
    approved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="approved_waf_policy_revisions",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    approved_at = models.DateTimeField(null=True, blank=True)
    deployed_at = models.DateTimeField(null=True, blank=True)
    config_revision = models.OneToOneField(
        "ConfigRevision",
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="policy_revision",
    )
    deployment_error = models.CharField(max_length=1000, blank=True)

    class Meta:
        ordering = ("-created_at", "-id")

    def save(self, *args, **kwargs):
        expected_checksum = sha256(
            (self.before_content + "\0" + self.after_content).encode("utf-8")
        ).hexdigest()
        if self.checksum != expected_checksum:
            raise ValidationError(
                "Policy revision checksum does not match its content."
            )
        if self.pk:
            original = (
                type(self)
                .objects.only(
                    "checksum",
                    "before_content",
                    "after_content",
                    "summary",
                    "config_revision_id",
                )
                .get(pk=self.pk)
            )
            if (
                original.checksum != self.checksum
                or original.before_content != self.before_content
                or original.after_content != self.after_content
                or original.summary != self.summary
                or original.config_revision_id != self.config_revision_id
            ):
                raise ValidationError("Policy revision content is immutable.")
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.checksum[:12]} ({self.get_status_display()})"


class Application(models.Model):
    name = models.CharField(max_length=120, unique=True)
    hostname = models.CharField(max_length=253, unique=True)
    description = models.CharField(max_length=500, blank=True)
    enabled = models.BooleanField(default=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="created_waf_applications",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("name",)

    def clean(self):
        super().clean()
        self.hostname = self.hostname.lower().rstrip(".")
        if not re.fullmatch(
            r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?",
            self.hostname,
        ):
            raise ValidationError({"hostname": "Enter one exact DNS hostname."})

    def __str__(self):
        return f"{self.name} ({self.hostname})"


class Policy(models.Model):
    class EngineMode(models.TextChoices):
        OFF = "off", "Off"
        DETECTION_ONLY = "detection_only", "Detection only"
        ON = "on", "On"

    name = models.CharField(max_length=120, unique=True)
    description = models.CharField(max_length=500, blank=True)
    parent = models.ForeignKey(
        "self",
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="children",
    )
    engine_mode = models.CharField(
        max_length=20, choices=EngineMode.choices, blank=True
    )
    paranoia_level = models.PositiveSmallIntegerField(null=True, blank=True)
    inbound_threshold = models.PositiveIntegerField(null=True, blank=True)
    outbound_threshold = models.PositiveIntegerField(null=True, blank=True)
    enabled = models.BooleanField(default=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="created_waf_policies",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("name",)
        verbose_name_plural = "policies"

    def clean(self):
        super().clean()
        errors = {}
        if self.paranoia_level is not None and not 1 <= self.paranoia_level <= 4:
            errors["paranoia_level"] = "Paranoia level must be between 1 and 4."
        for field_name in ("inbound_threshold", "outbound_threshold"):
            value = getattr(self, field_name)
            if value is not None and not 1 <= value <= 1000:
                errors[field_name] = "Threshold must be between 1 and 1000."
        ancestor = self.parent
        visited = {self.pk} if self.pk else set()
        while ancestor is not None:
            if ancestor.pk in visited:
                errors["parent"] = "Policy inheritance cannot contain a cycle."
                break
            visited.add(ancestor.pk)
            ancestor = ancestor.parent
        if errors:
            raise ValidationError(errors)

    def effective_config(self):
        config = {
            "engine_mode": self.EngineMode.ON,
            "paranoia_level": 1,
            "inbound_threshold": 5,
            "outbound_threshold": 4,
        }
        chain = []
        current = self
        visited = set()
        while current is not None:
            if current.pk and current.pk in visited:
                raise ValidationError("Policy inheritance contains a cycle.")
            if current.pk:
                visited.add(current.pk)
            chain.append(current)
            current = current.parent
        for item in reversed(chain):
            for field_name in config:
                value = getattr(item, field_name)
                if value not in (None, ""):
                    config[field_name] = value
        return config

    def __str__(self):
        return self.name


class PolicyBinding(models.Model):
    OVERRIDE_KEYS: ClassVar[set[str]] = {
        "engine_mode",
        "paranoia_level",
        "inbound_threshold",
        "outbound_threshold",
    }

    application = models.OneToOneField(
        Application, on_delete=models.CASCADE, related_name="policy_binding"
    )
    policy = models.ForeignKey(
        Policy, on_delete=models.PROTECT, related_name="bindings"
    )
    overrides = models.JSONField(default=dict, blank=True)
    enabled = models.BooleanField(default=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="created_waf_policy_bindings",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("application__name",)

    def clean(self):
        super().clean()
        if not isinstance(self.overrides, dict):
            raise ValidationError({"overrides": "Overrides must be a JSON object."})
        unknown = set(self.overrides) - self.OVERRIDE_KEYS
        if unknown:
            raise ValidationError(
                {
                    "overrides": f"Unsupported override keys: {', '.join(sorted(unknown))}."
                }
            )
        config = self.effective_config()
        if config["engine_mode"] not in Policy.EngineMode.values:
            raise ValidationError({"overrides": "Invalid engine_mode override."})
        try:
            paranoia_level = int(config["paranoia_level"])
            thresholds = [
                int(config["inbound_threshold"]),
                int(config["outbound_threshold"]),
            ]
        except (TypeError, ValueError) as exc:
            raise ValidationError(
                {"overrides": "Override values must use the expected data types."}
            ) from exc
        if not 1 <= paranoia_level <= 4:
            raise ValidationError(
                {"overrides": "Paranoia level must be between 1 and 4."}
            )
        if any(not 1 <= value <= 1000 for value in thresholds):
            raise ValidationError(
                {"overrides": "Thresholds must be between 1 and 1000."}
            )

    def effective_config(self):
        config = self.policy.effective_config()
        config.update(
            {
                key: value
                for key, value in self.overrides.items()
                if value not in (None, "")
            }
        )
        return config

    def __str__(self):
        return f"{self.application.name} → {self.policy.name}"


class ConfigRevision(models.Model):
    checksum = models.CharField(max_length=64, unique=True)
    snapshot = models.JSONField()
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="created_waf_config_revisions",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ("-created_at", "-id")

    @staticmethod
    def checksum_for(snapshot):
        canonical = json.dumps(snapshot, sort_keys=True, separators=(",", ":"))
        return sha256(canonical.encode("utf-8")).hexdigest()

    def save(self, *args, **kwargs):
        if self.checksum != self.checksum_for(self.snapshot):
            raise ValidationError("Configuration revision checksum does not match.")
        if self.pk:
            original = type(self).objects.get(pk=self.pk)
            if original.checksum != self.checksum or original.snapshot != self.snapshot:
                raise ValidationError("Configuration revision is immutable.")
        super().save(*args, **kwargs)

    def __str__(self):
        return self.checksum[:12]
