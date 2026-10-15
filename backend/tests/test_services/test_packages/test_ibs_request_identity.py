"""Unit tests for the package, codestream, and incident identity of IBS
request actions (backend/app/services/packages/ibs_request_identity.py).

Owning specifications:

- docs/features/packages/ibs-submission-tracking.md (Package and Codestream
  Identity: the physical and logical package of each action type, the
  origin separators `.SUSE_`, `.openSUSE_`, and `.RES_`, matching,
  unresolved, and non-matching actions, exact incident projects; Data
  Model > IBSRequestAction: the type-specific semantic identities; Scope
  Identity; Testing Requirements: package and codestream identity).
- docs/features/integrations/ibs-integration.md (Request Point Detail: the
  durable semantic identities, IBS names, and the `_redacted_` stored form
  of projects outside the `SUSE:` namespace).

Every function under test is pure; the actions are built directly in the
stored form that point detail returns. All names are fictional.
"""

from __future__ import annotations

from typing import Final

import pytest

from app.core.enums import IBSRequestActionType
from app.services.ibs_client import AcceptInfo, IBSRequestActionDetail
from app.services.packages.ibs_request_identity import (
    ActionIdentity,
    ActionMatch,
    action_identity,
    action_key,
    classify_action,
    detail_action_key,
    incident_number,
    is_valid_scope_identity,
    logical_package,
)

pytestmark = pytest.mark.unit

CODESTREAM: Final = "SUSE:SLE-15-SP6:Update"
OTHER_CODESTREAM: Final = "SUSE:SLE-15-SP7:Update"
PACKAGE: Final = "example"
INCIDENT: Final = 82001
REQUEST: Final = 970001
ORIGIN: Final = "SUSE_SLE-15-SP6_Update"
REDACTED: Final = "_redacted_"

MI: Final = IBSRequestActionType.MAINTENANCE_INCIDENT
MR: Final = IBSRequestActionType.MAINTENANCE_RELEASE


def incident_action(
    source_package: str = f"{PACKAGE}.{ORIGIN}",
    *,
    release_project: str | None = CODESTREAM,
    target_project: str | None = "SUSE:Maintenance",
    target_package: str | None = None,
    source_project: str = f"SUSE:Maintenance:REQUEST:{REQUEST}",
    number: int = REQUEST,
) -> IBSRequestActionDetail:
    """A `maintenance_incident` action in the stored form."""
    return IBSRequestActionDetail(
        request_number=number,
        action_type=MI,
        source_project=source_project,
        source_package=source_package,
        target_project=target_project,
        target_package=target_package,
        target_release_project=release_project,
    )


def release_action(
    target_package: str = f"{PACKAGE}.{INCIDENT}",
    *,
    source_project: str = f"SUSE:Maintenance:{INCIDENT}",
    source_package: str = f"{PACKAGE}.{ORIGIN}",
    target_project: str = CODESTREAM,
    number: int = REQUEST,
) -> IBSRequestActionDetail:
    """A `maintenance_release` action in the stored form."""
    return IBSRequestActionDetail(
        request_number=number,
        action_type=MR,
        source_project=source_project,
        source_package=source_package,
        target_project=target_project,
        target_package=target_package,
    )


def classify(
    action: IBSRequestActionDetail,
    *,
    package: str = PACKAGE,
    codestream: str = CODESTREAM,
    accepted: bool = False,
) -> ActionMatch:
    return classify_action(
        action,
        action_identity(action, accepted=accepted),
        package_name=package,
        codestream=codestream,
    )


class TestLogicalPackage:
    @pytest.mark.parametrize(
        ("physical", "expected"),
        [
            pytest.param(f"curl.{ORIGIN}", "curl", id="release-project-origin"),
            pytest.param(f"go1.27.{ORIGIN}", "go1.27", id="dotted-logical-package"),
            pytest.param("example.SUSE_SLFO_1.1", "example", id="dotted-origin"),
            pytest.param(
                f"example.SUSE_Maintenance_{INCIDENT}", "example", id="incident-origin"
            ),
            pytest.param("example.SUSE_Channels", "example", id="channels-origin"),
            pytest.param("example.SUSE_SLE-15-SP6_GA", "example", id="ga-origin"),
            pytest.param(
                "kguiaddons.openSUSE_Backports_SLE-15-SP4_Update.SUSE_SLE-15-SP4_Update",
                "kguiaddons",
                id="opensuse-origin-before-release-project",
            ),
            pytest.param("example.RES_8_Update", "example", id="res-origin"),
            pytest.param("example", "example", id="no-separator"),
            pytest.param("go1.27", "go1.27", id="dotted-without-separator"),
            pytest.param(
                "example.suse_sle-15-sp6_update",
                "example.suse_sle-15-sp6_update",
                id="separator-letter-case-differs",
            ),
        ],
    )
    def test_logical_package_physical_name_returns_part_before_first_separator(
        self, physical: str, expected: str
    ) -> None:
        assert logical_package(physical) == expected

    @pytest.mark.parametrize("separator", [".SUSE_", ".openSUSE_", ".RES_"])
    def test_logical_package_separator_at_end_returns_whole_name(
        self, separator: str
    ) -> None:
        assert logical_package(f"example{separator}") == f"example{separator}"

    def test_logical_package_trailing_separator_after_valid_one_splits_at_first(
        self,
    ) -> None:
        assert logical_package(f"example.{ORIGIN}.RES_") == "example"

    def test_logical_package_trailing_separator_does_not_hide_an_earlier_one(
        self,
    ) -> None:
        # `.SUSE_` occurs only at the end; `.RES_` earlier is followed by text.
        assert logical_package("example.RES_8.SUSE_") == "example"

    def test_logical_package_separator_at_index_zero_returns_empty_name(self) -> None:
        assert logical_package(f".{ORIGIN}") == ""

    def test_classify_action_empty_logical_package_matches_no_scope(self) -> None:
        action = incident_action(f".{ORIGIN}")

        assert action_identity(action, accepted=False).logical_package == ""
        assert classify(action) is ActionMatch.NON_MATCHING
        assert not is_valid_scope_identity("", CODESTREAM)


class TestIncidentNumber:
    def test_incident_number_exact_incident_project_returns_number(self) -> None:
        assert incident_number(f"SUSE:Maintenance:{INCIDENT}") == INCIDENT

    @pytest.mark.parametrize(
        "project",
        [
            pytest.param(None, id="absent"),
            pytest.param("SUSE:Maintenance", id="maintenance-root"),
            pytest.param(f"SUSE:Maintenance:0{INCIDENT}", id="leading-zero"),
            pytest.param("SUSE:Maintenance:0", id="zero"),
            pytest.param(f"SUSE:Maintenance:REQUEST:{REQUEST}", id="staging-project"),
            pytest.param(f"SUSE:Maintenance:{INCIDENT}:Sub", id="subproject"),
            pytest.param(f"suse:maintenance:{INCIDENT}", id="letter-case"),
            pytest.param(CODESTREAM, id="codestream"),
            pytest.param(REDACTED, id="redacted"),
        ],
    )
    def test_incident_number_other_project_returns_none(
        self, project: str | None
    ) -> None:
        assert incident_number(project) is None


class TestActionIdentity:
    def test_action_identity_open_submission_uses_source_package_and_no_incident(
        self,
    ) -> None:
        action = incident_action()

        assert action_identity(action, accepted=False) == ActionIdentity(
            logical_package=PACKAGE, codestream=CODESTREAM, incident_number=None
        )

    def test_action_identity_accepted_submission_uses_target_package_and_incident(
        self,
    ) -> None:
        action = incident_action(
            source_package=f"other.{ORIGIN}",
            target_project=f"SUSE:Maintenance:{INCIDENT}",
            target_package=f"{PACKAGE}.{ORIGIN}",
        )

        assert action_identity(action, accepted=True) == ActionIdentity(
            logical_package=PACKAGE, codestream=CODESTREAM, incident_number=INCIDENT
        )

    def test_action_identity_submission_of_request_not_accepted_has_no_incident(
        self,
    ) -> None:
        action = incident_action(
            target_project=f"SUSE:Maintenance:{INCIDENT}",
            target_package=f"{PACKAGE}.{ORIGIN}",
        )

        assert action_identity(action, accepted=False).incident_number is None

    def test_action_identity_accepted_submission_to_staging_project_has_no_incident(
        self,
    ) -> None:
        action = incident_action(target_project=f"SUSE:Maintenance:REQUEST:{REQUEST}")

        assert action_identity(action, accepted=True).incident_number is None

    def test_action_identity_submission_codestream_is_release_project(self) -> None:
        action = incident_action(release_project=REDACTED)

        assert action_identity(action, accepted=False).codestream == REDACTED

    @pytest.mark.parametrize(
        ("target_package", "expected"),
        [
            pytest.param(f"{PACKAGE}.{INCIDENT}", PACKAGE, id="plain"),
            pytest.param(f"go1.27.{INCIDENT}", "go1.27", id="dotted"),
        ],
    )
    def test_action_identity_release_strips_exact_incident_suffix(
        self, target_package: str, expected: str
    ) -> None:
        action = release_action(target_package)

        assert action_identity(action, accepted=True) == ActionIdentity(
            logical_package=expected, codestream=CODESTREAM, incident_number=INCIDENT
        )

    def test_action_identity_release_ignores_request_state(self) -> None:
        action = release_action()

        assert action_identity(action, accepted=False) == action_identity(
            action, accepted=True
        )

    @pytest.mark.parametrize(
        ("action", "incident"),
        [
            pytest.param(
                release_action(source_project=f"SUSE:Maintenance:REQUEST:{REQUEST}"),
                None,
                id="staging-source",
            ),
            pytest.param(
                release_action(source_project=REDACTED), None, id="redacted-source"
            ),
            pytest.param(
                release_action(f"{PACKAGE}.{INCIDENT + 1}"), INCIDENT, id="other-suffix"
            ),
            pytest.param(
                release_action(f"{PACKAGE}{INCIDENT}"), INCIDENT, id="suffix-not-dotted"
            ),
            pytest.param(release_action(f".{INCIDENT}"), INCIDENT, id="suffix-only"),
        ],
    )
    def test_action_identity_release_without_exact_incident_is_unresolved(
        self, action: IBSRequestActionDetail, incident: int | None
    ) -> None:
        assert action_identity(action, accepted=True) == ActionIdentity(
            logical_package=None, codestream=CODESTREAM, incident_number=incident
        )


class TestClassifyAction:
    @pytest.mark.parametrize(
        ("action", "accepted"),
        [
            pytest.param(incident_action(), False, id="open-submission"),
            pytest.param(
                incident_action(
                    target_project=f"SUSE:Maintenance:{INCIDENT}",
                    target_package=f"{PACKAGE}.{ORIGIN}",
                ),
                True,
                id="accepted-submission",
            ),
            pytest.param(
                incident_action(f"{PACKAGE}.SUSE_SLFO_1.1"),
                False,
                id="branch-origin-submission",
            ),
            pytest.param(
                incident_action(PACKAGE), False, id="submission-without-origin"
            ),
            pytest.param(release_action(), True, id="release"),
        ],
    )
    def test_classify_action_same_package_and_codestream_is_matching(
        self, action: IBSRequestActionDetail, accepted: bool
    ) -> None:
        assert classify(action, accepted=accepted) is ActionMatch.MATCHING

    @pytest.mark.parametrize(
        "action",
        [
            pytest.param(
                incident_action(release_project=OTHER_CODESTREAM),
                id="submission-other-codestream",
            ),
            pytest.param(
                incident_action(f"other.{ORIGIN}"), id="submission-other-package"
            ),
            pytest.param(
                incident_action(f"Example.{ORIGIN}"), id="submission-letter-case"
            ),
            pytest.param(
                incident_action(release_project=REDACTED),
                id="submission-redacted-release-project",
            ),
            pytest.param(
                incident_action(f"{PACKAGE}-devel.{ORIGIN}"),
                id="submission-longer-package",
            ),
            pytest.param(
                release_action(target_project=OTHER_CODESTREAM),
                id="release-other-codestream",
            ),
            pytest.param(
                release_action(f"Example.{INCIDENT}"), id="release-letter-case"
            ),
            pytest.param(
                release_action(f"patchinfo.{INCIDENT}", source_package="patchinfo"),
                id="patchinfo-release",
            ),
            pytest.param(
                release_action(
                    target_project="SUSE:Updates:SLE-Module-Basesystem:15-SP6:x86_64"
                ),
                id="updates-target",
            ),
            pytest.param(
                release_action(target_project="SUSE:Channels"), id="channels-target"
            ),
        ],
    )
    def test_classify_action_other_identity_is_non_matching(
        self, action: IBSRequestActionDetail
    ) -> None:
        assert classify(action, accepted=True) is ActionMatch.NON_MATCHING

    @pytest.mark.parametrize(
        "action",
        [
            pytest.param(
                release_action(source_project=f"SUSE:Maintenance:REQUEST:{REQUEST}"),
                id="non-incident-source",
            ),
            pytest.param(release_action(source_project=REDACTED), id="redacted-source"),
            pytest.param(
                release_action(f"{PACKAGE}.{INCIDENT + 1}"), id="wrong-suffix"
            ),
            pytest.param(release_action(f"{PACKAGE}.SUSE_Channels"), id="no-suffix"),
        ],
    )
    def test_classify_action_unresolvable_release_to_codestream_is_unresolved(
        self, action: IBSRequestActionDetail
    ) -> None:
        assert classify(action, accepted=True) is ActionMatch.UNRESOLVED

    @pytest.mark.parametrize(
        "action",
        [
            pytest.param(
                release_action(
                    f"{PACKAGE}.{INCIDENT + 1}", target_project=OTHER_CODESTREAM
                ),
                id="other-codestream",
            ),
            pytest.param(
                release_action(f"{PACKAGE}s.{INCIDENT + 1}"), id="other-package-prefix"
            ),
            pytest.param(
                release_action(f"Example.{INCIDENT + 1}"), id="prefix-letter-case"
            ),
        ],
    )
    def test_classify_action_unresolvable_release_outside_scope_is_non_matching(
        self, action: IBSRequestActionDetail
    ) -> None:
        assert classify(action, accepted=True) is ActionMatch.NON_MATCHING

    def test_classify_action_codestream_letter_case_differs_is_non_matching(
        self,
    ) -> None:
        assert (
            classify(incident_action(), codestream=CODESTREAM.lower())
            is ActionMatch.NON_MATCHING
        )


class TestActionKey:
    def test_detail_action_key_submission_excludes_target_fields(self) -> None:
        open_form = incident_action()
        accepted_form = IBSRequestActionDetail(
            request_number=REQUEST,
            action_type=MI,
            source_project=open_form.source_project,
            source_package=open_form.source_package,
            source_revision="0123456789abcdef0123456789abcdef",
            target_project=f"SUSE:Maintenance:{INCIDENT}",
            target_package=open_form.source_package,
            target_release_project=CODESTREAM,
            acceptinfo=AcceptInfo(rev="2", srcmd5="fedcba9876543210fedcba9876543210"),
        )

        assert (
            detail_action_key(open_form)
            == detail_action_key(accepted_form)
            == (
                REQUEST,
                MI,
                f"SUSE:Maintenance:REQUEST:{REQUEST}",
                f"{PACKAGE}.{ORIGIN}",
                CODESTREAM,
            )
        )

    @pytest.mark.parametrize(
        "other",
        [
            pytest.param(incident_action(number=REQUEST + 1), id="request-number"),
            pytest.param(
                incident_action(
                    source_project=f"SUSE:Maintenance:REQUEST:{REQUEST + 1}"
                ),
                id="source-project",
            ),
            pytest.param(incident_action(f"other.{ORIGIN}"), id="source-package"),
            pytest.param(
                incident_action(release_project=OTHER_CODESTREAM), id="release-project"
            ),
        ],
    )
    def test_detail_action_key_submission_identity_field_differs_is_distinct(
        self, other: IBSRequestActionDetail
    ) -> None:
        assert detail_action_key(incident_action()) != detail_action_key(other)

    def test_detail_action_key_release_is_target_project_and_package(self) -> None:
        action = release_action()
        moved_source = release_action(
            source_project=f"SUSE:Maintenance:{INCIDENT + 1}", source_package="other"
        )

        assert (
            detail_action_key(action)
            == detail_action_key(moved_source)
            == (
                REQUEST,
                MR,
                CODESTREAM,
                f"{PACKAGE}.{INCIDENT}",
            )
        )

    @pytest.mark.parametrize(
        "other",
        [
            pytest.param(release_action(number=REQUEST + 1), id="request-number"),
            pytest.param(release_action(target_project=OTHER_CODESTREAM), id="project"),
            pytest.param(release_action(f"{PACKAGE}.{INCIDENT + 1}"), id="package"),
        ],
    )
    def test_detail_action_key_release_identity_field_differs_is_distinct(
        self, other: IBSRequestActionDetail
    ) -> None:
        assert detail_action_key(release_action()) != detail_action_key(other)

    def test_action_key_types_never_collide(self) -> None:
        submission_key = action_key(
            REQUEST,
            MI,
            source_project=CODESTREAM,
            source_package=PACKAGE,
            target_project=CODESTREAM,
            target_package=PACKAGE,
            target_release_project=CODESTREAM,
        )
        release_key = action_key(
            REQUEST,
            MR,
            source_project=CODESTREAM,
            source_package=PACKAGE,
            target_project=CODESTREAM,
            target_package=PACKAGE,
            target_release_project=CODESTREAM,
        )

        assert submission_key != release_key

    @pytest.mark.parametrize(
        "action",
        [
            pytest.param(incident_action(), id="submission"),
            pytest.param(release_action(), id="release"),
        ],
    )
    def test_detail_action_key_equals_action_key_of_stored_fields(
        self, action: IBSRequestActionDetail
    ) -> None:
        assert detail_action_key(action) == action_key(
            action.request_number,
            action.action_type,
            source_project=action.source_project,
            source_package=action.source_package,
            target_project=action.target_project,
            target_package=action.target_package,
            target_release_project=action.target_release_project,
        )


class TestIsValidScopeIdentity:
    @pytest.mark.parametrize(
        ("package", "codestream"),
        [
            pytest.param(PACKAGE, CODESTREAM, id="usual"),
            pytest.param("go1.27", CODESTREAM, id="dotted-package"),
            pytest.param("libstdc++6", CODESTREAM, id="plus-sign"),
            pytest.param("p" * 254, CODESTREAM, id="longest-package"),
            pytest.param(PACKAGE, "openSUSE:Leap:15.6:Update", id="other-namespace"),
        ],
    )
    def test_is_valid_scope_identity_ibs_names_returns_true(
        self, package: str, codestream: str
    ) -> None:
        assert is_valid_scope_identity(package, codestream)

    @pytest.mark.parametrize(
        ("package", "codestream"),
        [
            pytest.param("", CODESTREAM, id="empty-package"),
            pytest.param("bad name", CODESTREAM, id="space-in-package"),
            pytest.param("example/sub", CODESTREAM, id="slash-in-package"),
            pytest.param(".", CODESTREAM, id="dot-package"),
            pytest.param("p" * 255, CODESTREAM, id="prefix-too-long"),
            pytest.param(PACKAGE, "", id="empty-codestream"),
            pytest.param(PACKAGE, "SUSE:SLE 15:Update", id="space-in-codestream"),
            pytest.param(PACKAGE, "S" * 256, id="codestream-too-long"),
        ],
    )
    def test_is_valid_scope_identity_invalid_name_returns_false(
        self, package: str, codestream: str
    ) -> None:
        assert not is_valid_scope_identity(package, codestream)
