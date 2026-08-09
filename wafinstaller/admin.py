from django.contrib import admin

from wafinstaller.models import AddressEntry, AddressList, AuditEntry, RuleExclusion


@admin.register(AuditEntry)
class AuditEntryAdmin(admin.ModelAdmin):
    list_display = ("created_at", "actor", "action", "target", "outcome", "remote_addr")
    list_filter = ("outcome", "action", "created_at")
    search_fields = ("actor__username", "action", "target", "remote_addr")
    readonly_fields = (
        "created_at",
        "actor",
        "action",
        "target",
        "outcome",
        "remote_addr",
        "details",
    )
    actions = None

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


class ReadOnlyPolicyAdmin(admin.ModelAdmin):
    actions = None

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(AddressList)
class AddressListAdmin(ReadOnlyPolicyAdmin):
    list_display = ("name", "purpose", "enabled", "created_by", "updated_at")
    list_filter = ("purpose", "enabled")


@admin.register(AddressEntry)
class AddressEntryAdmin(ReadOnlyPolicyAdmin):
    list_display = (
        "network",
        "address_list",
        "enabled",
        "starts_at",
        "expires_at",
        "created_by",
    )
    list_filter = ("address_list", "enabled")


@admin.register(RuleExclusion)
class RuleExclusionAdmin(ReadOnlyPolicyAdmin):
    list_display = (
        "name",
        "kind",
        "rule_id",
        "rule_tag",
        "status",
        "enabled",
        "expires_at",
        "created_by",
    )
    list_filter = ("kind", "status", "enabled")
    search_fields = ("name", "rule_id", "rule_tag", "host", "path", "rationale")
