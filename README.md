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

**Searching for reports based on text**

Use the `search` command and supply text to
search through advisory titles and descriptions.

```
ghsa-cli search crlf

┏━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ id                  ┃ state  ┃ title                                             ┃
┡━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ GHSA-xxxx-xxxx-xxxx │ closed │ IMAP Protocol Command Injection (CRLF) in imaplib │
│ GHSA-xxxx-xxxx-xxxx │ closed │ POP3 Protocol Command Injection (CRLF) in poplib  │
└─────────────────────┴────────┴───────────────────────────────────────────────────┘
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

**Creating a template CVE Record from a GHSA**

The command `cve-record` will create a template
CVE record from the information available in a GHSA
for use with a program like Vulnogram. This makes
creating a CVE record quick and transfers information
like credits and CVSS automatically.

```
ghsa-cli cve-record GHSA-xxxx-yyyy-zzzz

{
  "dataType": "CVE_RECORD",
  "dataVersion": "5.2",
  "cveMetadata": {
    "cveId": "CVE-YYYY-XXXX",
    "state": "PUBLISHED"
  },
  "containers": {
    "cna": {
      "title": "...",
      "affected": [
        {
          "vendor": "Python Software Foundation",
          "product": "CPython",
          "repo": "https://github.com/python/cpython",
          "defaultStatus": "unaffected",
          "versions": [
            {
              "versionType": "python",
              "version": "0"
            }
          ],
          "modules": []
        }
      ]
...
```