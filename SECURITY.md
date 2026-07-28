# Security policy

## Supported versions

OpsDoctor is currently pre-release. Security fixes are applied to the active
development branch and, after releases begin, to the latest tagged minor
series. Older pre-1.0 series may require upgrading.

| Version | Supported |
| --- | --- |
| `main` (unreleased) | Yes |
| Latest tagged minor series | Yes |
| Older series | No |

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability or include target
credentials, private hostnames, diagnostic reports, database files, or logs in
a public discussion.

Use GitHub's private vulnerability reporting form:

<https://github.com/Naenier/opsdoctor/security/advisories/new>

Include only the information needed to reproduce and assess the issue:

- affected version or commit;
- affected operating system;
- attack prerequisites and impact;
- minimal reproduction steps or a proof of concept;
- relevant code locations;
- whether the report may contain sensitive infrastructure data.

The maintainers aim to acknowledge a report within three business days,
provide an initial assessment within seven business days, and send an update
at least every fourteen days while remediation is active. Complex reports may
take longer to validate. A fix, advisory, and release will be coordinated
before public disclosure when the report is accepted.

If private vulnerability reporting is unavailable, open a public issue that
contains no vulnerability details and asks a maintainer to establish a private
channel.

## Security scope

Security-relevant behavior includes:

- leakage of URL, proxy, header, configuration, history, or log secrets;
- bypass of TLS verification without explicit user action;
- arbitrary command execution or shell interpolation;
- unbounded resource consumption from untrusted network data;
- unsafe file permissions or database migration behavior;
- diagnostic report injection that crosses a trust boundary;
- dependency or build-pipeline compromise.

OpsDoctor is a diagnostic client. A remote service returning an error,
certificate failure, or malformed response is not by itself a vulnerability
unless it causes unsafe local behavior.

## Disclosure credit

Reporters who follow this policy may be credited in the advisory and release
notes if they choose. Anonymous reporting and requests to omit credit are
respected.
