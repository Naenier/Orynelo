# Security policy

## Supported code

Security fixes are applied to the active `main` development branch. Older
commits are not maintained as separate supported series.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability or include target
credentials, private hostnames, diagnostic reports, database files, or logs in
a public discussion.

Use GitHub's private vulnerability reporting form:

<https://github.com/Naenier/orynelo/security/advisories/new>

Include only the information needed to reproduce and assess the issue:

- affected commit or build information;
- affected operating system;
- attack prerequisites and impact;
- minimal reproduction steps or a proof of concept;
- relevant code locations;
- whether the report may contain sensitive infrastructure data.

The maintainers aim to acknowledge a report within three business days,
provide an initial assessment within seven business days, and send an update
at least every fourteen days while remediation is active. Complex reports may
take longer to validate. A fix, advisory, and public disclosure will be
coordinated when the report is accepted.

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

Orynelo is a diagnostic client. A remote service returning an error,
certificate failure, or malformed response is not by itself a vulnerability
unless it causes unsafe local behavior.

## Disclosure credit

Reporters who follow this policy may be credited in the advisory if they
choose. Anonymous reporting and requests to omit credit are respected.
