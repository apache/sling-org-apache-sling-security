[![Apache Sling](https://sling.apache.org/res/logos/sling.png)](https://sling.apache.org)

&#32;[![Build Status](https://ci-builds.apache.org/job/Sling/job/modules/job/sling-org-apache-sling-security/job/master/badge/icon)](https://ci-builds.apache.org/job/Sling/job/modules/job/sling-org-apache-sling-security/job/master/)&#32;[![Test Status](https://img.shields.io/jenkins/tests.svg?jobUrl=https://ci-builds.apache.org/job/Sling/job/modules/job/sling-org-apache-sling-security/job/master/)](https://ci-builds.apache.org/job/Sling/job/modules/job/sling-org-apache-sling-security/job/master/test/?width=800&height=600)&#32;[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=apache_sling-org-apache-sling-security&metric=coverage)](https://sonarcloud.io/dashboard?id=apache_sling-org-apache-sling-security)&#32;[![Sonarcloud Status](https://sonarcloud.io/api/project_badges/measure?project=apache_sling-org-apache-sling-security&metric=alert_status)](https://sonarcloud.io/dashboard?id=apache_sling-org-apache-sling-security)&#32;[![JavaDoc](https://www.javadoc.io/badge/org.apache.sling/org.apache.sling.security.svg)](https://www.javadoc.io/doc/org.apache.sling/org.apache.sling.security)&#32;[![Maven Central](https://maven-badges.herokuapp.com/maven-central/org.apache.sling/org.apache.sling.security/badge.svg)](https://search.maven.org/#search%7Cga%7C1%7Cg%3A%22org.apache.sling%22%20a%3A%22org.apache.sling.security%22)&#32;[![Contrib](https://sling.apache.org/badges/status-contrib.svg)](https://github.com/apache/sling-aggregator/blob/master/docs/status/contrib.md) [![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

# Apache Sling Security

This module is part of the [Apache Sling](https://sling.apache.org) project.

The Apache Sling Security module provides CSRF protection through a filter checking the referrer and a content disposition filter. This OSGi bundle can be used as a standalone bundle outside of Apache Sling - in that case only the referrer check functionality is available as the content disposition filter depends on the Apache Sling Framework

## Referrer Filter (CSRF Protection)

Configuring the Apache Sling Referrer Filter involves setting up an OSGi configuration to manage which referrers are allowed to access your application. Here are some of the options:

- **Allow Empty**: Determines if requests with empty or missing referrer headers are allowed. This should typically be set to `false` for security reasons.
- **Allow Hosts**: Specifies a list of allowed hosts for the referrer. These are matched against the full referrer URL.
- **Allow Regexp Hosts**: Allows using regular expressions to match referrer hosts.
- **Filter Methods**: Specifies which HTTP methods (e.g., POST, PUT, DELETE) are filtered by the Referrer Filter.
- **Exclude Regexp User Agents**: Allows excluding certain user agents from referrer checks.
- **Exclude Paths**: Specifies paths that should not be checked for referrers.

### Sample Configuration

The filter can be configured through an OSGi configuration for the PID `org.apache.sling.security.impl.ReferrerFilter`. This is a sample configuration in JSON format:

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

In addition it is possible to amend the configuration by additional OSGi factory configurations for the factory PID `org.apache.sling.security.impl.ReferrerFilterAmendmentImpl`. This is a sample configuration in JSON format:

```json
{
  "allow.hosts": ["mysite.com", "localhost"],
  "allow.hosts.regexp": [],
  "exclude.agents.regexp": [],
  "exclude.paths": []
}
```


