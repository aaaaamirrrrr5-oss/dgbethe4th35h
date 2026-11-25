# SiteGuard v0.14.0 — selected implementation matrix

| Selected capability | Included in source | What works now | Important boundary |
|---|---|---|---|
| Local AI and reasoning | Yes | Deterministic evidence weighting, source corroboration, action priority, explanation | No generative/on-device LLM or model training |
| Threat intelligence | Yes | CISA KEV HTTPS fetch/parser/cache, daily WorkManager refresh, OSV package-version query | No independent signed-feed verification; live feed was not fetched in this environment |
| WordPress/WooCommerce Runtime | Yes | Explicitly authorized HTTPS REST GET-only checks for user, settings, plugins, themes and WC system status | No writes, orders/payments mutation, deep role/capability matrix or DNS-pinned transport |
| Deep web and API analysis | Partial | Bounded six-path same-origin GET, security headers, CORS, standard OpenAPI path discovery | Not full DAST, authZ/business-logic testing, crawling or authenticated API workflow testing |
| AST and Taint | Partial | Lexical tokens, statement/scope structure, selected source-to-sink flows | Not compiler-grade AST; no full CFG, alias, type or interprocedural analysis |
| Cloud and Network Security | Partial | Static IaC checks for selected Kubernetes/Terraform/Docker/CI/IAM/TLS patterns; prior DNS/TLS/network features retained | No live Cloud provider, effective IAM, asset inventory or runtime API inspection in the new module |
| Binary Android Analysis | Partial | APK ZIP bounds, binary XML manifest metadata, permission/component checks, DEX URL string indicators | No cryptographic APK signature validation, decompilation, native disassembly or runtime sandbox; AAB coverage limited |
| Remediation and Rollback | Partial | Local exact-match patch preview, hash guard, backup and rollback in private workspace | No automatic remote WordPress/Cloud/production change |
| Independent professional dashboard | Yes | Advanced in-app center with ten capability tabs, status and report actions | It is an independent destination/composable inside the existing app, not a separate Android Activity |
| Multi-type automation and monitoring | Partial | Existing authorized passive web queue plus new daily CISA WorkManager job and fail-closed policy | WP credentials and selected document URIs are not persisted; other job types are interactive |
| Professional/comparative reporting | Yes | Encrypted snapshots, new/resolved/changed/stable summary, Markdown and Persian RTL PDF | Comparison quality depends on matching scan scope and finding identifiers |
| Complete testing and trusted APK/AAB build | CI configured; local JVM tests executed | 12/12 smoke cases and 15/15 advanced JUnit-source methods through a compatibility harness; source release gate 22 PASS / 1 WARN | Official Gradle/JUnit task, Android/Compose build, lint, APK/AAB, signing and device results remain unverified |

## Safety model

The new modules perform passive/read-only work by default. Any connection to a target site requires an in-app declaration of authorization. Private-network mode is explicit and disabled by default. New remediation writes are limited to the local application workspace. No brute force, exploit execution or unauthorised testing is introduced.
