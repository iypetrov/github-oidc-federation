import pytest

import github_oidc_federation.models as models


# --- PermissionLevel ---


def test_permission_level_ordering():
    assert models.PermissionLevel.READ < models.PermissionLevel.WRITE
    assert models.PermissionLevel.WRITE < models.PermissionLevel.ADMIN


def test_permission_level_string_value():
    assert models.PermissionLevel.READ == 'read'
    assert models.PermissionLevel.WRITE == 'write'
    assert models.PermissionLevel.ADMIN == 'admin'


# --- OidcFederationEntry ---


def test_oidc_federation_entry_valid_with_subject_only():
    entry = models.OidcFederationEntry(
        issuer='https://example.com',
        subject='repo:org/repo:ref:refs/heads/main',
        permissions={'contents': models.PermissionLevel.READ},
        repositories=None,
        principals=None,
    )
    assert entry.issuer == 'https://example.com'


def test_oidc_federation_entry_valid_with_principals_only():
    entry = models.OidcFederationEntry(
        issuer='https://example.com',
        subject=None,
        permissions={'contents': models.PermissionLevel.WRITE},
        repositories=['my-repo'],
        principals=[{'repository': 'org/repo'}],
    )
    assert entry.principals == [{'repository': 'org/repo'}]


def test_oidc_federation_entry_neither_subject_nor_principals_raises():
    with pytest.raises(ValueError, match='Either subject or principals must be specified'):
        models.OidcFederationEntry(
            issuer='https://example.com',
            subject=None,
            permissions={'contents': models.PermissionLevel.READ},
            repositories=None,
            principals=None,
        )


def test_oidc_federation_entry_none_permission_value_raises():
    with pytest.raises(ValueError, match='Permission levels must not be None'):
        models.OidcFederationEntry(
            issuer='https://example.com',
            subject='repo:org/repo:ref:refs/heads/main',
            permissions={'contents': None},
            repositories=None,
            principals=None,
        )


def test_oidc_federation_entry_empty_permissions_allowed():
    entry = models.OidcFederationEntry(
        issuer='https://example.com',
        subject='repo:org/repo:ref:refs/heads/main',
        permissions={},
        repositories=None,
        principals=None,
    )
    assert entry.permissions == {}


# --- GitHubAppCredentials.matches ---


def _make_credential(host: str, selectors=None) -> models.GitHubAppCredentials:
    return models.GitHubAppCredentials(
        private_key='dummy',
        app_id=1,
        host=host,
        selectors=selectors,
    )


def test_matches_without_selectors_same_host():
    cred = _make_credential('github.example.com')
    assert cred.matches('github.example.com/org/repo') is True


def test_matches_without_selectors_different_host():
    cred = _make_credential('github.example.com')
    assert cred.matches('other.example.com/org/repo') is False


def test_matches_with_selectors_correct_host_and_org():
    cred = _make_credential(
        'github.example.com',
        selectors=(models.GitHubAppSelector(org='my-org'),),
    )
    assert cred.matches('github.example.com/my-org/repo') is True


def test_matches_with_selectors_correct_host_wrong_org():
    cred = _make_credential(
        'github.example.com',
        selectors=(models.GitHubAppSelector(org='my-org'),),
    )
    assert cred.matches('github.example.com/other-org/repo') is False


def test_matches_with_selectors_wrong_host_matching_org():
    # This is the security-relevant case: same org name, different host must not match.
    cred = _make_credential(
        'victim.example.com',
        selectors=(models.GitHubAppSelector(org='shared-org'),),
    )
    assert cred.matches('attacker.example.com/shared-org/repo') is False


def test_matches_with_selectors_correct_host_and_repo():
    cred = _make_credential(
        'github.example.com',
        selectors=(models.GitHubAppSelector(org='my-org', repos=('allowed-repo',)),),
    )
    assert cred.matches('github.example.com/my-org/allowed-repo') is True


def test_matches_with_selectors_correct_host_wrong_repo():
    cred = _make_credential(
        'github.example.com',
        selectors=(models.GitHubAppSelector(org='my-org', repos=('allowed-repo',)),),
    )
    assert cred.matches('github.example.com/my-org/other-repo') is False
