import os

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
