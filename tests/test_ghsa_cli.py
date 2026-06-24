import os
import json
import sqlite3
import pytest
import unittest.mock

from ghsa_cli import main


@pytest.fixture(autouse=True)
def gh_token():
    token = os.environ["GH_TOKEN"] = "gh-token"
    yield token
    os.environ.pop("GH_TOKEN")


@pytest.fixture(autouse=True)
def cve_api():
    os.environ["CVE_CNA"] = "cve-cna"
    os.environ["CVE_USERNAME"] = "cve-username"
    os.environ["CVE_API_KEY"] = "cve-api-key"
    yield
    os.environ.pop("CVE_CNA")
    os.environ.pop("CVE_USERNAME")
    os.environ.pop("CVE_API_KEY")


def test_help(capsys):
    with pytest.raises(SystemExit) as e:
        main(["--help"])
    assert e.value.code == 0
    captured = capsys.readouterr()
    assert "usage: ghsa-cli" in captured.out
    assert captured.err == ""


def test_credit_me(mocker, gh_token: str):
    def mock_gh_request(method, url, *_, **__):
        resp = unittest.mock.Mock(status=200)
        if method == "GET" and url == "https://api.github.com/user":
            resp.json.return_value = {
                "login": "username",
            }
        else:
            resp.json.return_value = {"credits": []}
        return resp

    gh_request = mocker.patch(
        "ghsa_cli.gh_request", unittest.mock.Mock(wraps=mock_gh_request)
    )

    main(["--repo=owner/repo", "credit", "GHSA-xxxx-xxxx-xxxx", "--coordinator=me"])

    ghsa_url = "https://api.github.com/repos/owner/repo/security-advisories/GHSA-xxxx-xxxx-xxxx"
    me_url = "https://api.github.com/user"

    gh_request.assert_any_call("GET", ghsa_url, gh_token=gh_token)
    gh_request.assert_any_call("GET", me_url, gh_token=gh_token)
    gh_request.assert_any_call(
        "PATCH",
        ghsa_url,
        body={"credits": [{"type": "coordinator", "login": "username"}]},
        gh_token=gh_token,
    )


@pytest.mark.parametrize(
    ["command", "start_state", "end_state"],
    [
        ("close", "triage", "closed"),
        ("close", "draft", "closed"),
        ("close", "closed", "closed"),
        ("accept", "triage", "draft"),
        ("accept", "draft", "draft"),
    ],
)
def test_change_state(mocker, gh_token: str, command, start_state, end_state):
    def mock_gh_request(*_, **__):
        resp = unittest.mock.Mock(status=200)
        resp.json.return_value = {"state": start_state}
        return resp

    gh_request = mocker.patch(
        "ghsa_cli.gh_request", unittest.mock.Mock(wraps=mock_gh_request)
    )

    main(["--repo=owner/repo", command, "GHSA-xxxx-xxxx-xxxx"])

    ghsa_url = "https://api.github.com/repos/owner/repo/security-advisories/GHSA-xxxx-xxxx-xxxx"

    gh_request.assert_any_call("GET", ghsa_url, gh_token=gh_token)
    if start_state == end_state:  # No update needed.
        assert len(gh_request.mock_calls) == 1
        assert all(call.args[0] == "GET" for call in gh_request.mock_calls)
    else:
        gh_request.assert_any_call(
            "PATCH",
            ghsa_url,
            body={"state": end_state},
            gh_token=gh_token,
        )


@pytest.mark.parametrize(
    ["command", "start_state", "end_state"],
    [
        ("accept", "closed", "draft"),
        ("accept", "published", "draft"),
        ("close", "published", "closed"),
    ],
)
def test_change_state_errror(
    capsys, mocker, gh_token: str, command, start_state, end_state
):
    def mock_gh_request(*_, **__):
        resp = unittest.mock.Mock(status=200)
        resp.json.return_value = {"state": start_state}
        return resp

    gh_request = mocker.patch(
        "ghsa_cli.gh_request", unittest.mock.Mock(wraps=mock_gh_request)
    )

    with pytest.raises(SystemExit) as e:
        main(["--repo=owner/repo", command, "GHSA-xxxx-xxxx-xxxx"])

    assert e.value.code == 1
    captured = capsys.readouterr()
    assert captured.err == (
        f"ERROR: Could not move GHSA to state '{end_state}' from state '{start_state}'\n"
    )

    ghsa_url = "https://api.github.com/repos/owner/repo/security-advisories/GHSA-xxxx-xxxx-xxxx"
    gh_request.assert_any_call("GET", ghsa_url, gh_token=gh_token)


@pytest.mark.parametrize("start_state", ["closed", "draft", "triage"])
def test_move_to_issue(mocker, gh_token: str, start_state: str):
    def mock_gh_request(*_, **__):
        resp = unittest.mock.Mock(status=200)
        resp.json.return_value = {
            "state": start_state,
            "summary": "Report title",
            "description": ("x" * 3001),
        }
        return resp

    gh_request = mocker.patch(
        "ghsa_cli.gh_request", unittest.mock.Mock(wraps=mock_gh_request)
    )
    webbrowser_open = mocker.patch("webbrowser.open")

    main(["--repo=owner/repo", "move-to-issue", "GHSA-xxxx-xxxx-xxxx"])

    ghsa_url = "https://api.github.com/repos/owner/repo/security-advisories/GHSA-xxxx-xxxx-xxxx"
    gh_request.assert_any_call("GET", ghsa_url, gh_token=gh_token)

    if start_state != "closed":
        gh_request.assert_any_call(
            "PATCH", ghsa_url, gh_token=gh_token, body={"state": "closed"}
        )
    else:
        assert len(gh_request.mock_calls) == 1
        assert all(call.args[0] == "GET" for call in gh_request.mock_calls)

    webbrowser_open.assert_called_once_with(
        "https://github.com/owner/repo/issues/new"
        "?title=Report%20title&body=" + ("x" * 3000) + "..."
    )


@pytest.mark.parametrize("start_state", ["closed", "draft", "triage"])
def test_move_to_issue_no_close(mocker, gh_token: str, start_state):
    def mock_gh_request(*_, **__):
        resp = unittest.mock.Mock(status=200)
        resp.json.return_value = {
            "state": start_state,
            "summary": "Report title",
            "description": ("x" * 3001),
        }
        return resp

    gh_request = mocker.patch(
        "ghsa_cli.gh_request", unittest.mock.Mock(wraps=mock_gh_request)
    )
    webbrowser_open = mocker.patch("webbrowser.open")

    main(["--repo=owner/repo", "move-to-issue", "GHSA-xxxx-xxxx-xxxx", "--no-close"])

    ghsa_url = "https://api.github.com/repos/owner/repo/security-advisories/GHSA-xxxx-xxxx-xxxx"
    gh_request.assert_any_call("GET", ghsa_url, gh_token=gh_token)

    assert len(gh_request.mock_calls) == 1
    assert all(call.args[0] == "GET" for call in gh_request.mock_calls)

    webbrowser_open.assert_called_once_with(
        "https://github.com/owner/repo/issues/new"
        "?title=Report%20title&body=" + ("x" * 3000) + "..."
    )


def test_cve_record(mocker, capsys, gh_token):
    def mock_gh_request(_, url, **__):
        resp = unittest.mock.Mock(status=200)
        if (
            url
            == "https://api.github.com/repos/python/cpython/security-advisories/GHSA-xxxx-xxxx-xxxx"
        ):
            resp.json.return_value = {
                "summary": "Report title",
                "description": "Report description",
                "cve_id": "CVE-1234-5678",
                "cvss_severities": {
                    "cvss_v4": {
                        "score": 9.1,
                        "vector_string": "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
                    }
                },
                "cwe_ids": ["CWE-416", "CWE-787"],
                "cwes": [
                    {"cwe_id": "CWE-416", "name": "Use-after-free"},
                    {"cwe_id": "CWE-787", "name": "Out-of-bounds write"},
                ],
                "credits_detailed": [
                    {
                        "user": {
                            "login": "example",
                            "type": "User",
                        },
                        "type": "reporter",
                        "state": "accepted",
                    }
                ],
            }
        elif url == "https://api.github.com/users/example":
            resp.json.return_value = {
                "login": "example",
                "name": "Full Name",
            }
        else:
            raise ValueError(f"Unknown URL: {url}")
        return resp

    latest_python_version = mocker.patch(
        "ghsa_cli.latest_python_version", unittest.mock.Mock(wraps=lambda: "3.16")
    )
    gh_request = mocker.patch(
        "ghsa_cli.gh_request", unittest.mock.Mock(wraps=mock_gh_request)
    )

    main(["--repo=python/cpython", "cve-record", "GHSA-xxxx-xxxx-xxxx"])

    ghsa_url = "https://api.github.com/repos/python/cpython/security-advisories/GHSA-xxxx-xxxx-xxxx"
    gh_request.assert_any_call("GET", ghsa_url, gh_token=gh_token)

    assert gh_request.mock_calls == [
        unittest.mock.call("GET", ghsa_url, gh_token=gh_token),
        unittest.mock.call(
            "GET", "https://api.github.com/users/example", gh_token=gh_token
        ),
    ]
    assert latest_python_version.mock_calls == [unittest.mock.call()]

    captured = capsys.readouterr()
    assert json.loads(captured.out) == {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.2",
        "cveMetadata": {"cveId": "CVE-1234-5678", "state": "PUBLISHED"},
        "containers": {
            "cna": {
                "title": "Report title",
                "affected": [
                    {
                        "defaultStatus": "unaffected",
                        "modules": [],
                        "product": "CPython",
                        "repo": "https://github.com/python/cpython",
                        "vendor": "Python Software Foundation",
                        "versions": [
                            {
                                "version": "0",
                                "lessThan": "3.16.0",
                                "versionType": "python",
                            },
                        ],
                    }
                ],
                "descriptions": [
                    {"lang": "en", "value": "Report description", "supportingMedia": []}
                ],
                "problemTypes": [
                    {
                        "descriptions": [
                            {
                                "lang": "en",
                                "cweId": "CWE-416",
                                "type": "CWE",
                                "description": "CWE-416",
                            },
                            {
                                "lang": "en",
                                "cweId": "CWE-787",
                                "type": "CWE",
                                "description": "CWE-787",
                            },
                        ]
                    },
                ],
                "references": [],
                "metrics": [
                    {
                        "format": "CVSS",
                        "scenarios": [{"lang": "en", "value": "GENERAL"}],
                        "cvssV4_0": {
                            "exploitMaturity": "NOT_DEFINED",
                            "Safety": "NOT_DEFINED",
                            "Automatable": "NOT_DEFINED",
                            "Recovery": "NOT_DEFINED",
                            "valueDensity": "NOT_DEFINED",
                            "vulnerabilityResponseEffort": "NOT_DEFINED",
                            "providerUrgency": "NOT_DEFINED",
                            "version": "4.0",
                            "baseScore": 9.1,
                            "vectorString": "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
                        },
                    }
                ],
                "credits": [
                    {
                        "type": "reporter",
                        "value": "Full Name (https://github.com/example)",
                        "lang": "en",
                    }
                ],
                "source": {"discovery": "UNKNOWN"},
            }
        },
    }


def test_command_search(mocker, capsys):
    iter_security_advisories = mocker.patch("ghsa_cli.iter_security_advisories")
    iter_security_advisories.return_value = [
        {
            "ghsa_id": "GHSA-1111-1111-1111",
            "state": "closed",
            "summary": "Unrelated advisory",
            "description": "More unrelated text",
        },
        {
            "ghsa_id": "GHSA-2222-2222-2222",
            "state": "draft",
            "summary": "More related advisory",
            "description": "Text around baseb64.b64encode()",
        },
        {
            "ghsa_id": "GHSA-3333-3333-3333",
            "state": "triage",
            "summary": "Most related advisory b64encode.",
            "description": "Crash with baseb64.b64encode()",
        },
    ]

    main(["search", "base64.b64encode crash"])

    captured = capsys.readouterr()
    assert (
        captured.out.strip()
        == (
            """
┏━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ id                  ┃ state  ┃ title                            ┃
┡━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ GHSA-3333-3333-3333 │ triage │ Most related advisory b64encode. │
│ GHSA-2222-2222-2222 │ draft  │ More related advisory            │
└─────────────────────┴────────┴──────────────────────────────────┘
"""
        ).strip()
    )


def test_command_export(mocker, tmp_path):
    ghsa_id = "GHSA-abcd-efgh-ijkl"

    def mock_gh_request(_, url, **__):
        resp = unittest.mock.Mock(status=200)
        resp.headers = {"content-type": "application/json"}
        if (
            url
            == "https://api.github.com/repos/python/cpython/security-advisories?per_page=100"
        ):
            resp.json.return_value = [
                {
                    "ghsa_id": ghsa_id,
                    "summary": "Report title",
                    "description": "Report description",
                    "cve_id": "CVE-1234-5678",
                    "state": "closed",
                    "author": {
                        "login": "example1",
                    },
                    "severity": "CRITICAL",
                    "cvss_severities": {
                        "cvss_v4": {
                            "score": 9.1,
                            "vector_string": "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
                        }
                    },
                    "cwe_ids": ["CWE-416", "CWE-787"],
                    "cwes": [
                        {"cwe_id": "CWE-416", "name": "Use-after-free"},
                        {"cwe_id": "CWE-787", "name": "Out-of-bounds write"},
                    ],
                    "created_at": "2020-01-01T00:00:00Z",
                    "updated_at": "2020-01-02T00:00:00Z",
                    "published_at": "2020-01-03T00:00:00Z",
                    "credits_detailed": [
                        {
                            "user": {
                                "login": "example1",
                                "type": "User",
                            },
                            "type": "reporter",
                            "state": "accepted",
                        },
                        {
                            "user": {
                                "login": "example2",
                                "type": "User",
                            },
                            "type": "coordinator",
                            "state": "pending",
                        },
                    ],
                }
            ]
        else:
            raise ValueError(f"Unknown URL: {url}")
        return resp

    def mock_show_cve_record(cve_id):
        assert cve_id == "CVE-1234-5678"
        return {
            "cveMetadata": {
                "dateReserved": "2026-06-17T21:40:50Z",
                "datePublished": "2026-06-18T21:40:50Z",
                "dateUpdated": "2026-06-19T21:40:50Z",
                "state": "published",
            }
        }

    mock_cve_client = unittest.mock.Mock()
    mock_cve_client.show_cve_record = mock_show_cve_record

    mocker.patch("ghsa_cli.gh_request", unittest.mock.Mock(wraps=mock_gh_request))
    mock_cve_api = mocker.patch("ghsa_cli.CVE_API")
    mock_cve_api.return_value = mock_cve_client

    db_filepath = os.path.join(tmp_path, "ghsa.sqlite")
    main(["--repo=python/cpython", "export", f"--output={db_filepath}"])

    db = sqlite3.connect(db_filepath)
    advisory_records = db.execute("SELECT * FROM advisories;").fetchall()
    assert advisory_records == [
        (
            "GHSA-abcd-efgh-ijkl",
            "CVE-1234-5678",
            "published",
            "closed",
            "Report title",
            "Report description",
            "CRITICAL",
            9.1,
            "2020-01-01T00:00:00Z",
            "2020-01-02T00:00:00Z",
            "2026-06-17T21:40:50Z",
            "2026-06-18T21:40:50Z",
            "example1",
        )
    ]

    credits_records = sorted(db.execute("SELECT * FROM credits;").fetchall())
    assert credits_records == [
        ("GHSA-abcd-efgh-ijkl", "example1", "reporter", "accepted"),
        ("GHSA-abcd-efgh-ijkl", "example2", "coordinator", "pending"),
    ]
