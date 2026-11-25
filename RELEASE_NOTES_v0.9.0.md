# SiteGuard Android v0.9.0

## UX and dashboard

- Refined the existing dark/red visual language with a branded gradient header, clearer local-first and activity states, stronger card hierarchy, higher contrast, and more consistent spacing.
- Improved bottom-navigation selection colors and added explicit accessibility descriptions to navigation and important dashboard icons.
- Replaced the separate web-only result view with a unified findings list sourced from website scans, source-file analysis, and ZIP project analysis.
- Added in-page search by title, ID, asset/path and CWE, plus severity filters. Sorted findings by severity (Critical → High → Medium → Low → Info) and corrected dashboard totals to count all current finding sources.
- Removed duplicated finding cards from nested project/source detail panels; findings now appear once in the unified results section.
- Collapsed the dense Website Security Specialist evidence, architecture, control, and test-plan details behind an explicit expand/collapse action. Summary indicators remain visible.
- Improved the empty state so it differentiates “no scan has run” from “checks ran without findings”; neither state is represented as proof of security.

## Reporting and versioning

- Bumped app version to `0.9.0` (`versionCode = 10`).
- Bumped JSON report schema to version 3 and made the top-level `findings` array include the deduplicated, unified results from web, source, and project analysis.
- Updated HTML report product version metadata.
- Added a 40-domain prompt execution matrix and honest coverage classifications. No complete domain or specification is marked fully tested based on the presence of a module or a smoke test.

## Preserved behavior and constraints

- Retained existing bottom navigation destinations and core tools.
- Retained the black/red theme, local-first operation, no AI API / hosted inference requirement, passive network scope controls, and preview-only remediation behavior.
- No production site, source project, database, order, payment, or inventory mutation was added.

## Validation limits

- Source preflight and project archive checks are run for this package.
- Android Gradle compilation, Compose compilation against the Android SDK, JUnit via Gradle, lint, APK assembly, signing, install/upgrade, and physical-device UX/accessibility checks require the Android SDK/Gradle environment and have not been claimed here.
