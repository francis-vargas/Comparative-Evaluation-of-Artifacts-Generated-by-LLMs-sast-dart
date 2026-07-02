from dart_sast.engine.finding import Severity
from dart_sast.engine.registry import register_rule
from dart_sast.engine.rule import PubspecRule


@register_rule
class UnmaintainedComponentRule(PubspecRule):
    rule_id = "DART-SAST-CWE1104"
    cwe = "CWE-1104"
    title = "Use of Unmaintained Third Party Component"
    description = (
        "A dependency in pubspec.yaml is pinned to an unconstrained version "
        "('any'), sourced directly from git without a fixed ref/commit, or "
        "sourced from a local path. All three patterns make it impossible "
        "to know exactly which code is being shipped, and 'any'/no-ref git "
        "dependencies can silently pull in new, unreviewed, or abandoned "
        "code on every build."
    )
    severity = Severity.MEDIUM
    recommendation = (
        "Pin dependencies to a specific version range (e.g. '^1.2.3'). For "
        "git dependencies, always set a 'ref' to a fixed commit hash or "
        "tag. Periodically audit dependencies (dart pub outdated, "
        "pub.dev's 'popularity/maintenance' scores) and replace packages "
        "that have not been updated in a long time."
    )
    references = (
        "https://cwe.mitre.org/data/definitions/1104.html",
        "https://dart.dev/tools/pub/dependencies",
    )

    def analyze_pubspec(self, context):
        findings = []
        data = context.data or {}
        for section in ("dependencies", "dev_dependencies"):
            deps = data.get(section)
            if not isinstance(deps, dict):
                continue
            for name, spec in deps.items():
                reason = self._check_spec(spec)
                if reason:
                    line = self._find_line(context.raw_text, name)
                    findings.append(
                        self._make_finding(
                            file_path=context.relative_path,
                            line=line,
                            column=1,
                            snippet=f"{name}: {reason}",
                        )
                    )
        return findings

    @staticmethod
    def _check_spec(spec) -> str | None:
        if isinstance(spec, str):
            if spec.strip().lower() == "any" or spec.strip() == "":
                return "unconstrained version ('any') -- unpredictable upstream changes"
            return None
        if isinstance(spec, dict):
            if "git" in spec:
                git_spec = spec["git"]
                if isinstance(git_spec, dict) and not git_spec.get("ref"):
                    return "git dependency without a pinned 'ref' (commit/tag)"
                if isinstance(git_spec, str):
                    return "git dependency without a pinned 'ref' (commit/tag)"
            if "path" in spec:
                return "local path dependency -- not tracked/audited like a published package"
        return None

    @staticmethod
    def _find_line(raw_text: str, name: str) -> int:
        for idx, line in enumerate(raw_text.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith(f"{name}:") or stripped == name:
                return idx
        return 1
