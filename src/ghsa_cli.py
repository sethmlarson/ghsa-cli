import argparse
import datetime
import json
import os
import re
import sys
import typing
import subprocess

import urllib3

__version__ = "2026.04.02"

http = urllib3.PoolManager()


def command_credit(args: argparse.Namespace) -> int:
    gh_token = args.gh_token
    url = f"https://api.github.com/repos/{args.repo_owner}/{args.repo_name}/security-advisories/{args.ghsa_id}"

    resp = gh_request("GET", url, gh_token=gh_token)
    if resp.status >= 300:
        print("Could not fetch GHSA", file=sys.stderr)
        return 1
    credits = resp.json()["credits"][:]

    add_credits = []
    if args.reporter is not None:
        add_credits.append({"type": "reporter", "login": args.reporter})
    if args.coordinator is not None:
        add_credits.append({"type": "coordinator", "login": args.coordinator})
    if args.remediation_developer is not None:
        add_credits.append(
            {"type": "remediation_developer", "login": args.remediation_developer}
        )
    if args.remediation_reviewer is not None:
        add_credits.append(
            {"type": "remediation_reviewer", "login": args.remediation_reviewer}
        )

    for add_credit in add_credits:
        if add_credit not in credits:
            credits.append(add_credit)

    resp = gh_request("PATCH", url, gh_token=gh_token, body={"credits": credits})
    if resp.status >= 300:
        print("Could not update credits for GHSA", file=sys.stderr)
        return 1
    return 0


def _command_set_state(
    args: argparse.Namespace, state: str, from_states: list[str]
) -> int:
    gh_token = args.gh_token
    url = f"https://api.github.com/repos/{args.repo_owner}/{args.repo_name}/security-advisories/{args.ghsa_id}"

    resp = gh_request("GET", url, gh_token=gh_token)
    if resp.status >= 300:
        print("Could not fetch GHSA", file=sys.stderr)
        return 1

    from_state = resp.json()["state"]
    if from_state not in from_states:
        print(
            f"Could not move GHSA to state '{state}' from state '{from_state}'",
            file=sys.stderr,
        )
        return 1

    resp = gh_request("PATCH", url, gh_token=gh_token, body={"state": state})
    if resp.status >= 300:
        print("Could not update state for GHSA", file=sys.stderr)
        return 1
    return 0


def command_accept(args: argparse.Namespace) -> int:
    return _command_set_state(args, state="draft", from_states=["triage"])


def command_close(args: argparse.Namespace) -> int:
    return _command_set_state(args, state="close", from_states=["triage", "draft"])


def command_move_to_issue(args: argparse.Namespace) -> int:
    return 0  # TODO


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    try:
        gh_token = os.environ["GH_TOKEN"]
    except KeyError:
        print("Requires 'GH_TOKEN' environment variable to be set", file=sys.stderr)
        return 1
    try:
        cve_token = os.environ["CVE_TOKEN"] or None
    except KeyError:
        cve_token = None

    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", help="GitHub repository owner and name", default=None)
    subparsers = parser.add_subparsers(required=True, dest="command")

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

    args = parser.parse_args(argv)
    args.gh_token = gh_token
    args.cve_token = cve_token
    if args.repo is None:
        args.repo = default_repo()
    if args.repo is None:
        print(
            "No GitHub repository defined, use 'GH_REPO' environment variable, "
            "'--repo' parameter, or set a git remote named 'upstream' or 'origin'",
            file=sys.stderr,
        )
        return 1
    elif not re.search(r"\A[^/]+/[^/]+\z", args.repo):
        print("GitHub repository must be in the form 'owner/repo'", file=sys.stderr)
        return 1
    args.repo_owner, args.repo_name = args.repo.split("/", 1)

    if args.ghsa_id is not None and not re.search(
        r"\AGHSA(?:-[a-z0-9]{4}){3}\z", args.ghsa_id
    ):
        print(
            "GitHub Security Advisory ID must be in the form 'GHSA-xxxx-xxxx-xxxx'",
            file=sys.stderr,
        )
        return 1

    command_funcs: dict[str, typing.Callable[[argparse.Namespace], int]] = {
        "credit": command_credit,
        "accept": command_accept,
        "close": command_close,
        "move-to-issue": command_move_to_issue,
    }
    command_func = command_funcs[args.command]
    return command_func(args)


def parse_rfc3339(value: str | None) -> datetime.datetime | None:
    """Parse a GitHub date according to RFC 3339"""
    if not isinstance(value, str):
        return value
    return datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")


def default_repo() -> str | None:
    """Resolve a default for the '--repo' argument using current working directory"""
    if "GH_REPO" in os.environ:
        return os.environ["GH_REPO"]
    proc = subprocess.run(
        ["git", "remote", "-v"], cwd=os.getcwd(), stdout=subprocess.PIPE
    )
    if proc.returncode != 0:
        return None
    remotes = dict(
        re.findall(r"^([\w+])\s+((?:https?|ssh)://.+)$", proc.stdout.decode("utf-8"))
    )
    for remote in ("upstream", "origin"):
        if remote not in remotes:
            continue
        remote_url = remotes[remote]
        mat = re.search(r"/github\.com/([^/]+)/([^/\s]+)", remote_url)
        if mat:
            return f"{mat.group(1)}/{mat.group(2)}"
    else:
        return None


def gh_request(
    method, url, *, gh_token, fields=None, body=None
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
        resp = http.request(method, url, fields=fields, body=body, headers=headers)
        print(f"[{resp.status}] {method} {url}", file=sys.stderr)
    except Exception as e:
        print(f"[---] {method} {url}", file=sys.stderr)
        raise e
    return resp


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
