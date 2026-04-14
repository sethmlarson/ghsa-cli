# ghsa-cli

CLI for efficiently coordinating vulnerability reports
and remediations with GitHub Security Advisories (GHSA).

Install from PyPI (`python -m pip install ghsa-cli`) and
authenticate using a `GH_TOKEN` environment variable within the shell
session with a GitHub personal access token. Repository automatically
resolves to the `upstream`/`origin` remote of the current working directory
git repository or can be set manually via `GH_REPO` or `--repo`.

Below are some common workflows this tool is designed for:

**Assigning yourself as 'Coordinator' for a ticket**

Assign yourself as a coordinator. The alias `me` works for
options specified via the command line to mean the
currently authenticated user.

```
ghsa-cli credit GHSA-xxxx-xxxx-xxxx --coordinator me
```

**Adding collaborators by name**

Adds collaborators by name, either teams or individual users.

```
ghsa-cli collaborators GHSA-xxxx-xxxx-xxxx --login sethmlarson
ghsa-cli collaborators GHSA-xxxx-xxxx-xxxx --team python/fuzzers
```

**Moving a GHSA to a public GitHub issue**

Prompts the user with a new GitHub issue templated with
the same title and description as the current ticket.
By default, closes the GHSA if the GHSA isn't already closed.

```
ghsa-cli move-to-issue GHSA-xxxx-xxxx-xxxx
```

You can skip closing the GHSA after the issue templating page is
opened by passing `--no-close`.

**Listing open GHSAs where you are assigned 'Coordinator'**

Useful for prioritizing which ticket you should work on next
depending on their state, age, and whether a fix has been
developed and reviewed.

```
ghsa-cli list --coordinator me

┏━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━┳━━━━━━━━┳━━━━━━┳━━━━━━┓
┃ id                  ┃ title ┃ state  ┃ age  ┃ cvss ┃
┡━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━╇━━━━━━━━╇━━━━━━╇━━━━━━┩
│ GHSA-xxxx-xxxx-xxxx │ ...   │ triage │ 10d  │ 6.5  │
│ GHSA-xxxx-xxxx-xxxx │ ...   │ draft  │ 16d  │ 7.0  │
│ GHSA-xxxx-xxxx-xxxx │ ...   │ draft  │ 21d  │ 2.0  │
│ GHSA-xxxx-xxxx-xxxx │ ...   │ draft  │ 60d  │ 2.0  │
└─────────────────────┴───────┴────────┴──────┴──────┘
```

**Prioritizing reports based on CVSS or age**

```
ghsa-cli list --sort cvss age

┏━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━┳━━━━━━━━┳━━━━━━┳━━━━━━┓
┃ id                  ┃ title ┃ state  ┃ age  ┃ cvss ┃
┡━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━╇━━━━━━━━╇━━━━━━╇━━━━━━┩
│ GHSA-xxxx-xxxx-xxxx │ ...   │ draft  │ 16d  │ 7.0  │
│ GHSA-xxxx-xxxx-xxxx │ ...   │ triage │ 10d  │ 6.5  │
│ GHSA-xxxx-xxxx-xxxx │ ...   │ draft  │ 60d  │ 2.0  │
│ GHSA-xxxx-xxxx-xxxx │ ...   │ draft  │ 21d  │ 2.0  │
└─────────────────────┴───────┴────────┴──────┴──────┘
```

**Creating reports and integrating with CVE APIs**

CVE APIs require a CVE Services API key. Set
the `CVE_USERNAME`, `CVE_CNA`, and `CVE_API_KEY`
environment variables to access properties about CVE
IDs and records.

Use the `--columns` parameter with `list` to add
additional columns to the report.

```
ghsa-cli list --state triage draft closed --columns id state cve_id cve_state

┏━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┓
┃ id                  ┃ state  ┃ cve_id         ┃ cve_state ┃
┡━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━━━━━┩
│ GHSA-xxxx-xxxx-xxxx │ triage │                │           │
│ GHSA-xxxx-xxxx-xxxx │ closed │ CVE-YYY-YYYY   │ published │
│ GHSA-xxxx-xxxx-xxxx │ draft  │ CVE-YYY-YYYY   │ reserved  │
└─────────────────────┴────────┴────────────────┴───────────┘
```