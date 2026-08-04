# Changelog

All notable changes to Crossforge are documented here. Versions follow
[Semantic Versioning](https://semver.org/).

## [0.1.1] - 2026-08-03

### Fixed

- Report unsupported Python runtimes clearly before importing 3.11-only
  modules ([#28](https://github.com/Satscryption/Crossforge/issues/28)).
- Require independent reviewers to return a structured final report and permit
  one fixed recovery request when the first return is empty
  ([#30](https://github.com/Satscryption/Crossforge/issues/30)).
- Bound the normal skill's strict wildcard hook to the invoking prompt or an
  active durable run, with explicit and automatic release paths
  ([#31](https://github.com/Satscryption/Crossforge/issues/31)).
- Bump every release and runtime version source so Claude Code invalidates the
  cached 0.1.0 plugin ([#32](https://github.com/Satscryption/Crossforge/issues/32)).

## [0.1.0] - 2026-07-30

- Initial alpha release.
