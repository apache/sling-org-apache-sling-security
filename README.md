[![Apache Sling](https://sling.apache.org/res/logos/sling.png)](https://sling.apache.org)

&#32;[![Build Status](https://ci-builds.apache.org/job/Sling/job/modules/job/sling-org-apache-sling-security/job/master/badge/icon)](https://ci-builds.apache.org/job/Sling/job/modules/job/sling-org-apache-sling-security/job/master/)&#32;[![Test Status](https://img.shields.io/jenkins/tests.svg?jobUrl=https://ci-builds.apache.org/job/Sling/job/modules/job/sling-org-apache-sling-security/job/master/)](https://ci-builds.apache.org/job/Sling/job/modules/job/sling-org-apache-sling-security/job/master/test/?width=800&height=600)&#32;[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=apache_sling-org-apache-sling-security&metric=coverage)](https://sonarcloud.io/dashboard?id=apache_sling-org-apache-sling-security)&#32;[![Sonarcloud Status](https://sonarcloud.io/api/project_badges/measure?project=apache_sling-org-apache-sling-security&metric=alert_status)](https://sonarcloud.io/dashboard?id=apache_sling-org-apache-sling-security)&#32;[![JavaDoc](https://www.javadoc.io/badge/org.apache.sling/org.apache.sling.security.svg)](https://www.javadoc.io/doc/org.apache.sling/org.apache.sling.security)&#32;[![Maven Central](https://maven-badges.herokuapp.com/maven-central/org.apache.sling/org.apache.sling.security/badge.svg)](https://search.maven.org/#search%7Cga%7C1%7Cg%3A%22org.apache.sling%22%20a%3A%22org.apache.sling.security%22)&#32;[![Contrib](https://sling.apache.org/badges/status-contrib.svg)](https://github.com/apache/sling-aggregator/blob/master/docs/status/contrib.md) [![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

# Apache Sling Security

This module is part of the [Apache Sling](https://sling.apache.org) project.

The Apache Sling Security module provides:

- CSRF protection through the **Referrer Filter**
- download hardening through the **Content Disposition Filter**

This OSGi bundle can be used as a standalone bundle outside of Apache Sling. In that case, only the Referrer Filter functionality is available, as the Content Disposition Filter depends on the Apache Sling API.

## Requirements

- Java 11+
- Maven

The project inherits build plugins and checks from Sling parent POM `66`.

## Build and test

- Build: `mvn clean install`
- Build without tests: `mvn clean install -DskipTests`
- Run tests: `mvn test`
- Run Spotless check: `mvn spotless:check`
- Apply Spotless formatting: `mvn spotless:apply`
- Run RAT license checks: `mvn rat:check`
- Run OSGi baseline checks: `mvn baseline:check`

## Referrer Filter (CSRF protection)

The Referrer Filter is registered as an OSGi HTTP Whiteboard `Preprocessor` and checks browser-originated modification requests.
It validates the `referer` header and falls back to `origin` when `referer` is not present.

Configuration PID: `org.apache.sling.security.impl.ReferrerFilter`

Main configuration options:

- **Allow Empty** (`allow.empty`)
- **Allow Hosts** (`allow.hosts`)
- **Allow Regexp Host** (`allow.hosts.regexp`)
- **Filter Methods** (`filter.methods`)
- **Exclude Regexp User Agent** (`exclude.agents.regexp`)
- **Exclude Paths** (`exclude.paths`)

### Sample configuration

```json
{
  "allow.empty": false,
  "allow.hosts": ["mysite.com", "localhost"],
  "allow.hosts.regexp": [],
  "filter.methods": ["POST", "PUT", "DELETE", "COPY", "MOVE"],
  "exclude.agents.regexp": [],
  "exclude.paths": []
}
```

It is also possible to amend this configuration with factory configurations for:

- Factory PID: `org.apache.sling.security.impl.ReferrerFilterAmendmentImpl`

### Sample amendment configuration

```json
{
  "allow.hosts": ["mysite.com", "localhost"],
  "allow.hosts.regexp": [],
  "exclude.agents.regexp": [],
  "exclude.paths": []
}
```

## Content Disposition Filter

The Content Disposition Filter is a Sling request/forward filter that adds `Content-Disposition: attachment` for configured resource paths on `GET` and `HEAD` requests. It supports explicit path includes, prefix includes (`*` suffix), exclusions, and optional all-path mode.

The header is only added for resources that contain `jcr:data` directly or below `jcr:content/jcr:data`.

Configuration PID: `org.apache.sling.security.impl.ContentDispositionFilter`

Main configuration options:

- **Included Resource Paths & Content Types** (`sling.content.disposition.paths`)
- **Excluded Resource Paths** (`sling.content.disposition.excluded.paths`)
- **Enable For All Resource Paths** (`sling.content.disposition.all.paths`)

### Sample configuration

```json
{
  "sling.content.disposition.paths": [
    "/content/secure/*",
    "/content/files/report.pdf:text/html,text/plain"
  ],
  "sling.content.disposition.excluded.paths": [
    "/content/secure/preview"
  ],
  "sling.content.disposition.all.paths": false
}
```
