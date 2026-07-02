import re

from dart_sast.engine.finding import Severity
from dart_sast.engine.registry import register_rule
from dart_sast.engine.rule import ManifestRule

_COMPONENT_TAGS = ("activity", "service", "receiver", "provider")


@register_rule
class ImproperAndroidComponentExportRule(ManifestRule):
    rule_id = "DART-SAST-CWE926"
    cwe = "CWE-926"
    title = "Improper Export of Android Application Component"
    description = (
        "An <activity>/<service>/<receiver>/<provider> in AndroidManifest.xml "
        "is explicitly exported (android:exported=\"true\") without any "
        "android:permission restricting who can invoke it. Any other app "
        "installed on the device can then launch this component, potentially "
        "bypassing the intended entry points of the application."
    )
    severity = Severity.HIGH
    recommendation = (
        "Set android:exported=\"false\" for components that are not meant to "
        "be reached by other applications. If a component must be exported "
        "(e.g. to handle deep links), protect it with android:permission or "
        "validate the calling package/intent extras defensively."
    )
    references = (
        "https://cwe.mitre.org/data/definitions/926.html",
        "https://developer.android.com/guide/topics/manifest/activity-element#exported",
    )

    _tag_re = re.compile(
        r"<(activity|service|receiver|provider)\b(?:(?!/?>).)*?/?>",
        re.IGNORECASE | re.DOTALL,
    )
    _exported_true_re = re.compile(r"android:exported\s*=\s*\"true\"", re.IGNORECASE)
    _permission_re = re.compile(r"android:permission\s*=", re.IGNORECASE)

    def analyze_manifest(self, context):
        findings = []
        for match in self._tag_re.finditer(context.text):
            tag_text = match.group(0)
            if not self._exported_true_re.search(tag_text):
                continue
            if self._permission_re.search(tag_text):
                continue
            line = context.text.count("\n", 0, match.start()) + 1
            snippet = tag_text.strip().split("\n")[0].strip()
            findings.append(
                self._make_finding(
                    file_path=context.relative_path,
                    line=line,
                    column=1,
                    snippet=snippet,
                )
            )
        return findings
