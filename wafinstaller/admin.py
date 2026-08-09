from django.contrib import admin

from wafinstaller.models import AuditEntry


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
