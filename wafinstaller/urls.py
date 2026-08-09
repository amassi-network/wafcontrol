from django.urls import path

from wafinstaller.policy_views import (
    AddressEntryCreateView,
    AddressListCreateView,
    PolicyDeployView,
    PolicyManagementView,
    PolicyObjectMutationView,
    PolicyRevisionCreateView,
    PolicyRevisionMutationView,
    RuleExclusionCreateView,
    RuleExclusionUpdateView,
)
from wafinstaller.views import (
    AddCustomRuleView,
    AdminProfileView,
    AppSettingsView,
    CriticalWafAttacksView,
    CRSCategoriesView,
    CRSRuleListByFileView,
    CRSRuleListView,
    CrsSwitchVersionView,
    CrsUpdateSyncView,
    CrsVersionListView,
    CustomLogoutView,
    CustomRulesView,
    DashboardView,
    DeleteCustomRuleView,
    EditCustomRuleView,
    EventTriageView,
    ForceFetchCrsVersionsView,
    HomeRedirectView,
    LoginsView,
    ModSecuritySettingsView,
    ReadCRSRuleView,
    SaveCRSRuleView,
    ServerTrafficAnalysisView,
    ToggleCRSRuleView,
    TopAttackersView,
    UpdateSingleCRSRuleView,
    Verify2FAView,
    WafAttacksView,
    install_waf_page,
)

app_name = "wafinstaller"
urlpatterns = [
    path("", HomeRedirectView.as_view(), name="home"),
    # Auth
    path("login/", LoginsView.as_view(), name="login"),
    path("verify-2fa/", Verify2FAView.as_view(), name="verify_2fa"),
    path("dashboard/logout/", CustomLogoutView.as_view(), name="logout"),
    # Dashboard
    path("dashboard/", DashboardView.as_view(), name="dashboard"),
    path("dashboard/update-crs/", CrsUpdateSyncView.as_view(), name="update_crs_sync"),
    path("dashboard/dos/ddos/", ServerTrafficAnalysisView.as_view(), name="ddos"),
    # WAF install
    path("dashboard/install-waf/", install_waf_page, name="install_waf_page"),
    # Attacks
    path("dashboard/attacks/", WafAttacksView.as_view(), name="waf_attacks"),
    path(
        "dashboard/attacks/<int:attack_id>/triage/",
        EventTriageView.as_view(),
        name="event_triage",
    ),
    path(
        "dashboard/critical/", CriticalWafAttacksView.as_view(), name="critical_attacks"
    ),
    path("dashboard/top-attacker/", TopAttackersView.as_view(), name="top-attacker"),
    # CRS Rules – browse & edit
    path("dashboard/crs-rules/", CRSRuleListView.as_view(), name="crs_rules"),
    path(
        "crs/rules/view/<str:filename>/",
        ReadCRSRuleView.as_view(),
        name="view_crs_rule",
    ),
    path(
        "crs/rules/save/<str:filename>/",
        SaveCRSRuleView.as_view(),
        name="save_crs_rule",
    ),
    # Rules Setting / categories / toggle / inline update
    path(
        "dashboard/crs/categories/",
        CRSCategoriesView.as_view(),
        name="categorized_files",
    ),
    path(
        "dashboard/crs/rules/<str:filename>/",
        CRSRuleListByFileView.as_view(),
        name="rules_by_file",
    ),
    path(
        "dashboard/crs/rules/toggle/",
        ToggleCRSRuleView.as_view(),
        name="toggle_crs_rule",
    ),
    path(
        "dashboard/crs/rules/update/<str:filename>/",
        UpdateSingleCRSRuleView.as_view(),
        name="update_crs_rule",
    ),
    # CRS versions
    path("dashboard/crs/version/", CrsVersionListView.as_view(), name="crs_version"),
    path("crs/switch/", CrsSwitchVersionView.as_view(), name="switch_crs_version"),
    path(
        "dashboard/crs/settings/",
        ModSecuritySettingsView.as_view(),
        name="crs_settings",
    ),
    path(
        "crs/force-fetch/",
        ForceFetchCrsVersionsView.as_view(),
        name="force_fetch_crs_versions",
    ),
    # Custom rules AFTER-CRS
    path("dashboard/crs/custom-rules/", CustomRulesView.as_view(), name="custom_rules"),
    path(
        "dashboard/crs/custom-rules/add/",
        AddCustomRuleView.as_view(),
        name="add_custom_rule",
    ),
    path(
        "custom-rules/delete/<int:rule_id>/",
        DeleteCustomRuleView.as_view(),
        name="delete_custom_rule",
    ),
    path(
        "custom-rules/edit/<str:rule_id>/",
        EditCustomRuleView.as_view(),
        name="edit_custom_rule",
    ),
    # Managed policies
    path(
        "dashboard/policies/", PolicyManagementView.as_view(), name="policy_management"
    ),
    path(
        "dashboard/policies/address-lists/create/",
        AddressListCreateView.as_view(),
        name="address_list_create",
    ),
    path(
        "dashboard/policies/address-entries/create/",
        AddressEntryCreateView.as_view(),
        name="address_entry_create",
    ),
    path(
        "dashboard/policies/exclusions/create/",
        RuleExclusionCreateView.as_view(),
        name="rule_exclusion_create",
    ),
    path(
        "dashboard/policies/exclusions/<int:object_id>/update/",
        RuleExclusionUpdateView.as_view(),
        name="rule_exclusion_update",
    ),
    path(
        "dashboard/policies/revisions/create/",
        PolicyRevisionCreateView.as_view(),
        name="policy_revision_create",
    ),
    path(
        "dashboard/policies/revisions/<int:revision_id>/<str:operation>/",
        PolicyRevisionMutationView.as_view(),
        name="policy_revision_mutation",
    ),
    path(
        "dashboard/policies/deploy/", PolicyDeployView.as_view(), name="policy_deploy"
    ),
    path(
        "dashboard/policies/<str:object_type>/<int:object_id>/<str:operation>/",
        PolicyObjectMutationView.as_view(),
        name="policy_object_mutation",
    ),
    # App config + Admin profile
    path("dashboard/settings/", AppSettingsView.as_view(), name="app_settings"),
    path("dashboard/profile/", AdminProfileView.as_view(), name="admin_profile"),
]
