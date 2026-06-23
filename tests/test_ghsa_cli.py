import os
import json
from textwrap import dedent

import pytest
import unittest.mock

from ghsa_cli import main


@pytest.fixture(autouse=True)
def gh_token():
    token = os.environ["GH_TOKEN"] = "gh-token"
    yield token
    os.environ.pop("GH_TOKEN")


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
