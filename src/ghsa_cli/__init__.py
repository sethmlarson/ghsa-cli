"""CLI for efficiently coordinating vulnerability reports and remediations with GitHub Security Advisories (GHSA)"""

import argparse
import datetime
import json
import os
import re
import sys
import typing
import urllib.parse
import subprocess
import webbrowser
import rich.console
import rich.table
from typing import NoReturn

import urllib3

__version__ = "2026.4.6.1"

HTTP = urllib3.PoolManager()
DEBUG = False


def command_list(args: argparse.Namespace) -> None:
    gh_token = args.gh_token
    fields = {"per_page": "100"}
    if args.state and len(args.state) == 1:
        fields["state"] = args.state[0]

    def iter_security_advisories():
        url = (
            f"https://api.github.com/repos/{args.repo_owner}/{args.repo_name}/security-advisories"
            f"?{urllib.parse.urlencode(fields)}"
        )
        while True:
            resp = gh_request("GET", url, gh_token=gh_token)
            if resp.status == 404:
                return
            elif resp.status >= 300:
                error(f"Could not fetch GHSAs: {resp.data[:300]}")

            if not resp.json():
                break
            yield from resp.json()

            link_re = re.compile(r"<([^>]+)>;\s+rel=\"([^\"]+)\"")
            for link_url, link_rel in link_re.findall(resp.headers.get("Link", "")):
                if link_rel == "next":
                    url = link_url
                    break
            else:
                break

    coordinator = None
    if args.coordinator:
        coordinator = resolve_default_gh_login(
            gh_login=args.coordinator,
            gh_token=gh_token,
        )

    # Apply filters on all security advisories.
    security_advisories = []
    for sec_adv in iter_security_advisories():
        if coordinator is not None and not any(
            credit["login"] == coordinator for credit in sec_adv["credits"]
        ):
            continue
        if sec_adv["state"] not in args.state:
            continue
        security_advisories.append(sec_adv)

    table = rich.table.Table()
    table.add_column("id")
    table.add_column("title")
    table.add_column("state")
    table.add_column("age")
    if coordinator is None:  # Only show coordinator if it's not filtered.
        table.add_column("coordinator")
    table.add_column("cvss")

    for sec_adv in security_advisories:
        sec_adv_coordinators = ", ".join(
            credit["login"]
            for credit in sec_adv["credits"]
            if credit["type"] == "coordinator"
        )

        # CVSSv4 is preferred, but multiple can be set.
        sec_adv_cvss = ""
        for cvss_v in ("cvss_v4", "cvss_v3"):
            if cvss_v in sec_adv["cvss_severities"]:
                cvss_score = sec_adv["cvss_severities"][cvss_v]["score"]
                if cvss_score is not None:
                    sec_adv_cvss = str(cvss_score)
                    break

        created_at = parse_rfc3339(sec_adv["created_at"])
        closed_at_or_now = parse_rfc3339(sec_adv["closed_at"])
        if closed_at_or_now is None:
            closed_at_or_now = datetime.datetime.now(tz=datetime.timezone.utc)
        age = duration_as_days(closed_at_or_now - created_at)

        table.add_row(
            sec_adv["ghsa_id"],
            sec_adv["summary"][:50],
            sec_adv["state"],
            age,
            *((sec_adv_coordinators,) if coordinator is None else ()),
            sec_adv_cvss,
        )

    console = rich.console.Console()
    console.print(table)


def command_credit(args: argparse.Namespace):
    gh_token = args.gh_token
    url = f"https://api.github.com/repos/{args.repo_owner}/{args.repo_name}/security-advisories/{args.ghsa_id}"

    resp = gh_request("GET", url, gh_token=gh_token)
    if resp.status >= 300:
        error("Could not fetch GHSA")
    credits = resp.json()["credits"][:]

    for credit_type in (
        "reporter",
        "coordinator",
        "remediation_developer",
        "remediation_reviewer",
    ):
        credit_gh_login = getattr(args, credit_type)
        if credit_gh_login is None:
            continue
        credit_gh_login = resolve_default_gh_login(
            gh_login=credit_gh_login,
            gh_token=gh_token,
        )
        add_credit = {
            "type": credit_type,
            "login": credit_gh_login,
        }
        if add_credit not in credits:
            credits.append(add_credit)

    resp = gh_request("PATCH", url, gh_token=gh_token, body={"credits": credits})
    if resp.status >= 300:
        error("Could not update credits for GHSA")


def _command_set_state(
    args: argparse.Namespace, state: str, from_states: list[str]
) -> None:
    gh_token = args.gh_token
    url = f"https://api.github.com/repos/{args.repo_owner}/{args.repo_name}/security-advisories/{args.ghsa_id}"

    resp = gh_request("GET", url, gh_token=gh_token)
    if resp.status >= 300:
        error("Could not fetch GHSA")

    from_state = resp.json()["state"]
    if from_state == state:
        return  # Exit if we're already in the desired state.
    if from_state not in from_states:
        error(f"Could not move GHSA to state '{state}' from state '{from_state}'")

    resp = gh_request("PATCH", url, gh_token=gh_token, body={"state": state})
    if resp.status >= 300:
        error("Could not update state for GHSA")


def command_accept(args: argparse.Namespace) -> None:
    _command_set_state(args, state="draft", from_states=["triage"])


def command_close(args: argparse.Namespace) -> None:
    _command_set_state(args, state="closed", from_states=["triage", "draft"])


def command_move_to_issue(args: argparse.Namespace) -> None:
    gh_token = args.gh_token
    ghsa_url = f"https://api.github.com/repos/{args.repo_owner}/{args.repo_name}/security-advisories/{args.ghsa_id}"

    resp = gh_request("GET", ghsa_url, gh_token=gh_token)
    if resp.status >= 300:
        error("Could not fetch GHSA")

    ghsa = resp.json()
    summary = ghsa["summary"]
    description = ghsa["description"]
    state = ghsa["state"]
    # Truncate the description to avoid 'URI Too Long' errors.
    max_description_len = 3000
    if len(description) > max_description_len:
        description = description[:max_description_len] + "..."

    query_str = urllib.parse.urlencode(
        (("title", summary), ("body", description)), quote_via=urllib.parse.quote
    )
    issue_url = (
        f"https://github.com/{args.repo_owner}/{args.repo_name}/issues/new?{query_str}"
    )

    webbrowser.open(issue_url)

    if state != "closed" and not args.no_close:
        _command_set_state(args, state="closed", from_states=[state])


def command_move_to_pr(args: argparse.Namespace) -> None:
    pass  # TODO


def command_collaborators(args: argparse.Namespace) -> None:
    pass  # TODO


def command_cve_record(args: argparse.Namespace) -> None:
    """
    Command which generates a CVE Record template which can be
    loaded into the 'Source' tab of Vulnogram from a GHSA
    to prepopulate many fields. Known values for 'affected'
    projects can be added.
    """
    gh_token = args.gh_token
    ghsa_url = f"https://api.github.com/repos/{args.repo_owner}/{args.repo_name}/security-advisories/{args.ghsa_id}"

    resp = gh_request("GET", ghsa_url, gh_token=gh_token)
    if resp.status >= 300:
        error("Could not fetch GHSA")
    ghsa_json = resp.json()

    summary = ghsa_json["summary"]
    description = ghsa_json["description"]
    cve_id = ghsa_json["cve_id"]
    credit_type_ghsa_to_cve = {
        "reporter": "reporter",
        "coordinator": "coordinator",
        "remediation_developer": "remediation developer",
        "remediation_reviewer": "remediation reviewer",
        "remediation_verifier": "remediation verifier",
        "analyst": "analyst",
        "finder": "finder",
    }
    affects_repo_to_cve = {
        "python/cpython": {
            "vendor": "Python Software Foundation",
            "product": "CPython",
            "repo": "https://github.com/python/cpython",
        },
        "pypa/pip": {
            "vendor": "Python Software Foundation",
            "product": "pip",
            "repo": "https://github.com/pypa/pip",
        },
    }
    cwes_cve = [
        {"descriptions": [{"lang": "en", "cweId": cwe_id, "type": "CWE"}]}
        for cwe_id in ghsa_json["cwe_ids"]
    ]
    credits_cve = []
    metrics_cve = []

    for credit in ghsa_json["credits_detailed"]:
        credit_type_cve = credit_type_ghsa_to_cve[credit["type"]]
        credit_login = credit["user"]["login"]
        resp = gh_request(
            "GET", f"https://api.github.com/users/{credit_login}", gh_token=gh_token
        )
        if resp.status >= 300:
            error(f"Could not fetch GitHub user: {credit_login}")
        credit_name = resp.json()["name"].strip()
        if not credit_name:
            credit_name = credit_login
        credits_cve.append(
            {
                "type": credit_type_cve,
                "value": credit_name,
                "lang": "en",
            }
        )

    if "cvss_v4" in ghsa_json["cvss_severities"]:
        ghsa_cvss_v4 = ghsa_json["cvss_severities"]["cvss_v4"]
        metrics_cve.append(
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
                    "baseScore": ghsa_cvss_v4["score"],
                    "vectorString": ghsa_cvss_v4["vector_string"],
                },
            }
        )

    cve_record = {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.2",
        "cveMetadata": {"cveId": cve_id, "state": "PUBLISHED"},
        "containers": {
            "cna": {
                "title": summary,
                "affected": [],
                "descriptions": [
                    {"lang": "en", "value": description, "supportingMedia": []}
                ],
                "problemTypes": cwes_cve,
                "references": [],
                "metrics": metrics_cve,
                "credits": credits_cve,
                "source": {"discovery": "UNKNOWN"},
            }
        },
    }

    if args.repo in affects_repo_to_cve:
        affects_cve = affects_repo_to_cve[args.repo].copy()
        affects_cve["defaultStatus"] = "unaffected"
        affects_cve["versions"] = [{"versionType": "python", "version": "0"}]
        cve_record["containers"]["cna"]["affected"] = [affects_cve]

    print(json.dumps(cve_record, indent=2))


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    try:
        gh_token = os.environ["GH_TOKEN"]
    except KeyError:
        error("Requires 'GH_TOKEN' environment variable to be set")

    parser = argparse.ArgumentParser("ghsa-cli", description=__doc__)
    parser.add_argument("--repo", help="GitHub repository owner and name", default=None)
    parser.add_argument(
        "--debug", help="Enable debug logging", action="store_true", default=False
    )
    subparsers = parser.add_subparsers(required=True, dest="command")

    # 'list'
    parser_list = subparsers.add_parser(
        "list", description="List GHSAs for a repository"
    )
    parser_list.add_argument(
        "--coordinator", help="Filter to GHSAs being coordinated by this login"
    )
    parser_list.add_argument(
        "--state",
        help="Filter to GHSAs in this state",
        nargs="+",
        choices=["draft", "triage", "closed", "published"],
        default=["triage", "draft"],
    )
    parser_list.add_argument(
        "--sort",
        help="Sort GHSAs by this field",
        default="created",
        choices=["created", "severity", "updated"],
    )

    # 'credit'
    parser_credit = subparsers.add_parser(
        "credit",
        description="Assign credit to a GitHub account. Use 'me' as an alias to assign your own account.",
    )
    parser_credit.add_argument("ghsa_id", help="GitHub Security Advisory ID")
    parser_credit.add_argument(
        "--reporter", help="GitHub login to assign to the 'Reporter' role"
    )
    parser_credit.add_argument(
        "--coordinator", help="GitHub login to assign the 'Coordinator' role"
    )
    parser_credit.add_argument(
        "--remediation-developer",
        help="GitHub login to assign the 'Remediation Developer' role",
    )
    parser_credit.add_argument(
        "--remediation-reviewer",
        help="GitHub login to assign the 'Remediation Reviewer' role",
    )

    # 'accept'
    parser_accept = subparsers.add_parser(
        "accept", description="Accept a report that is in 'Triage'"
    )
    parser_accept.add_argument("ghsa_id", help="GitHub Security Advisory ID")

    # 'close'
    parser_close = subparsers.add_parser(
        "close", description="Close a report from any state"
    )
    parser_close.add_argument("ghsa_id", help="GitHub Security Advisory ID")

    # 'move-to-issue'
    parser_move_to_issue = subparsers.add_parser(
        "move-to-issue",
        description="Open a new GitHub issue from a report and close the report",
    )
    parser_move_to_issue.add_argument("ghsa_id", help="GitHub Security Advisory ID")
    parser_move_to_issue.add_argument(
        "--no-close",
        action="store_true",
        help="Do not close the GHSA report after opening an issue",
    )

    # 'collaborators'
    parser_collaborators = subparsers.add_parser(
        "collaborators", description="Add collaborators to a GHSA"
    )
    parser_collaborators.add_argument(
        "--codeowners", nargs="+", help="Paths to gather collaborators from CODEOWNERS"
    )

    # 'cve-record'
    parser_cve_record = subparsers.add_parser(
        "cve-record", description="Generate a CVE record template from a GHSA"
    )
    parser_cve_record.add_argument("ghsa_id", help="GitHub Security Advisory ID")

    args = parser.parse_args(argv)
    args.gh_token = gh_token
    if args.debug:  # Enable debug logging early.
        global DEBUG
        DEBUG = True
    if args.repo is None:
        args.repo = resolve_default_repo()
    if args.repo is None:
        error(
            "No GitHub repository defined, use the 'GH_REPO' environment variable, "
            "'--repo' parameter, or set a git remote named 'upstream' or 'origin'",
        )
    elif not re.search(r"\A[^/]+/[^/]+\z", args.repo):
        error("GitHub repository must be in the form 'owner/repo'")
    args.repo_owner, args.repo_name = args.repo.split("/", 1)

    if getattr(args, "ghsa_id", None) and not re.search(
        r"\A(?:GHSA|ghsa)(?:-[a-z0-9]{4}){3}\z", args.ghsa_id
    ):  # GitHub API accepts both 'GHSA-' and 'ghsa-'
        error("GitHub Security Advisory ID must be in the form 'GHSA-xxxx-xxxx-xxxx'")

    command_funcs: dict[str, typing.Callable[[argparse.Namespace], None]] = {
        "list": command_list,
        "credit": command_credit,
        "accept": command_accept,
        "close": command_close,
        "move-to-issue": command_move_to_issue,
        "move-to-pr": command_move_to_pr,
        "collaborators": command_collaborators,
        "cve-record": command_cve_record,
    }
    command_func = command_funcs[args.command]
    command_func(args)
    return 0


def parse_rfc3339(value: str | None) -> datetime.datetime | None:
    """Parse a GitHub date according to RFC 3339"""
    if not isinstance(value, str):
        return value
    return datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%S%z")


def duration_as_days(value: datetime.timedelta) -> str:
    return f"{max(int(value.total_seconds() // 86400), 0)}d"


def resolve_default_gh_login(*, gh_login: str, gh_token: str) -> str:
    """Resolve 'me' option as a GitHub login to the actual identity."""
    if gh_login == "me":
        resp = gh_request("GET", "https://api.github.com/user", gh_token=gh_token)
        if resp.status >= 300:
            error("Could not resolve authenticated user")
        gh_login = resp.json()["login"]
    return gh_login


def resolve_default_repo() -> str | None:
    """Resolve a default for the '--repo' argument using current working directory"""
    if "GH_REPO" in os.environ:
        return os.environ["GH_REPO"]
    proc = subprocess.run(
        ["git", "remote", "-v"], cwd=os.getcwd(), stdout=subprocess.PIPE
    )
    if proc.returncode != 0:
        return None
    remotes = dict(
        re.findall(
            r"^(\w+)\s+((?:https?|ssh)://[^(\s]+)",
            proc.stdout.decode("utf-8"),
            re.MULTILINE,
        )
    )
    for remote in ("upstream", "origin"):
        if remote not in remotes:
            continue
        remote_url = remotes[remote]
        mat = re.search(r"[@/]github\.com/([^/]+)/([^/\s]+)", remote_url)
        if mat:
            return f"{mat.group(1)}/{mat.group(2)}"
    else:
        return None


def gh_request(
    method,
    url,
    *,
    gh_token,
    fields=None,
    body=None,
) -> urllib3.BaseHTTPResponse:
    """Make a GitHub API request with logging"""
    try:
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "Authorization": f"Bearer {gh_token}",
            "X-GitHub-Api-Version": "2026-03-10",
        }
        if isinstance(body, dict):
            body = json.dumps(body).encode("utf-8")
        resp = HTTP.request(method, url, fields=fields, body=body, headers=headers)
        if DEBUG:
            print(f"[{resp.status}] {method} {url}", file=sys.stderr)
    except Exception as e:
        if DEBUG:
            print(f"[---] {method} {url}", file=sys.stderr)
        raise e
    return resp


def error(message: str) -> NoReturn:
    """Print an error message and exit"""
    print("ERROR: " + message, file=sys.stderr)
    raise SystemExit(1)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
