# Project Overview

Apache Sling Security is an OSGi bundle for Apache Sling that provides two servlet filters: `ReferrerFilter` (a `Preprocessor` that blocks requests with missing or untrusted `Referer` headers to prevent CSRF) and `ContentDispositionFilter` (a Sling request/forward filter that forces `Content-Disposition: attachment` on responses for configured paths/content types). Components use OSGi R6/R7 declarative services annotations (`org.osgi.service.component.annotations`) with metatype configuration. The bundle targets Java 11 and is built with Maven.

# Core Commands

- **Build:** `mvn clean install`
- **Build (skip tests):** `mvn clean install -DskipTests`
- **Run full test suite:** `mvn test`
- **Run a single test class:** `mvn test -Dtest=ReferrerFilterTest`
- **Run a single test method:** `mvn test -Dtest=ReferrerFilterTest#testMethodName`
- **Lint / format check (Spotless via parent POM):** `mvn spotless:check`
- **Apply formatting:** `mvn spotless:apply`
- **License header check:** `mvn rat:check`
- **OSGi baseline check:** `mvn baseline:check`
- **Release:** follow [Apache Sling release process](https://sling.apache.org/contributing.html)

No dev server — this is an OSGi bundle deployed to a running Sling/Felix instance.

# Project Layout

```
pom.xml                        Maven build descriptor
bnd.bnd                        OSGi bundle manifest overrides
src/
  main/java/org/apache/sling/security/impl/
    ReferrerFilter.java                  CSRF filter (OSGi Preprocessor)
    ReferrerFilterAmendment.java         Interface for referrer allowlist extensions
    ReferrerFilterAmendmentImpl.java     Default amendment implementation
    ContentDispositionFilter.java        Content-Disposition enforcement filter
    ContentDispositionFilterConfiguration.java  Metatype config interface
  test/java/org/apache/sling/security/impl/
    ReferrerFilterTest.java
    ContentDispositionFilterTest.java
target/                        Build output (generated, not committed)
```

All production code lives under `org.apache.sling.security.impl`. There are no public API packages exported — this bundle is purely internal implementation.

# Development Patterns & Constraints

- **Java version:** 11 (source and target)
- **OSGi components:** Use `org.osgi.service.component.annotations` (`@Component`, `@Reference`, `@Activate`). Do NOT use Felix SCR annotations.
- **Metatype config:** Define configuration interfaces with `@ObjectClassDefinition` / `@AttributeDefinition` in the same file as or alongside the component.
- **Indentation:** 4 spaces (no tabs). Follow existing code style.
- **License header:** Every `.java` file must carry the Apache 2.0 license header. Run `mvn rat:check` to verify.
- **No public API exports:** `bnd.bnd` sets `Import-Package` with `org.apache.sling.*` as optional. Do not add new exported packages without discussion.
- **Servlet API:** `javax.servlet` (not `jakarta.servlet`) — dependency is `javax.servlet-api`.
- **Logging:** SLF4J only (`org.slf4j`). No `java.util.logging` or Log4j direct usage.
- **Dependencies:** Minimize additions. All compile-time deps must be `provided` scope (OSGi container supplies them). Test deps use `test` scope.

# Git Workflow

- **Default branch:** `master`
- **Commit messages:** Reference JIRA issue when applicable (`SLING-XXXXX - description`). Use imperative mood.
- **Branching:** Feature branches are typical; branch names are free-form.
- **PRs:** Require passing CI (Jenkins). License and baseline checks run as part of CI.
- **No force pushes** to `master` (enforced by repo policy).
- **Tags:** Release tags follow `org.apache.sling.security-X.Y.Z` (set by `maven-release-plugin`).

# Testing Guidelines

- **Framework:** JUnit 4 (`junit:junit`), with Mockito 4 and JMock for mocking.
- **Test location:** `src/test/java/org/apache/sling/security/impl/`
- **Naming:** Test class name = production class name + `Test`. Test methods use descriptive names.
- **Coverage:** No enforced coverage threshold; aim to cover all filter logic branches (allow/deny decisions).
- **Run all tests:** `mvn test`
- **Run one class:** `mvn test -Dtest=ContentDispositionFilterTest`
- **Reports:** `target/surefire-reports/`

# Gotchas

- `ReferrerFilter` is registered as an OSGi `Preprocessor` (HTTP Whiteboard), not a standard Sling filter — it runs before Sling servlet resolution.
- The `bnd.bnd` sets `Require-Capability` for `osgi.http` version 1.x; updating the HTTP Whiteboard spec version requires updating this too.
- `org.apache.sling.*` imports are marked `resolution:=optional` so the bundle can load even when Sling API is absent — keep this in mind when adding Sling API usage.
- OSGi metatype XML descriptors are generated at compile time by annotation processing into `target/classes/OSGI-INF/`. Never edit them manually.
- The parent POM (`sling-bundle-parent`) controls Spotless, RAT, baseline, and other plugin versions. Do not override plugin versions locally unless necessary.
- `junit-addons:1.4` is a transitive test dependency with old Xerces — it is pulled in by JMock; avoid adding more dependencies on it.

# Security

<!-- sling-security-default:start -->
The threat model for this project is https://github.com/apache/sling/blob/master/docs/threat-model.md .
<!-- sling-security-default:end -->

