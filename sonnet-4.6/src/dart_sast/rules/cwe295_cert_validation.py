import re

from dart_sast.engine.finding import Severity
from dart_sast.engine.registry import register_rule
from dart_sast.engine.rule import RegexRule


@register_rule
class ImproperCertificateValidationRule(RegexRule):
    rule_id = "DART-SAST-CWE295"
    cwe = "CWE-295"
    title = "Improper Certificate Validation"
    description = (
        "TLS certificate validation is disabled or overridden to always "
        "succeed (badCertificateCallback returning true, "
        "SecurityContext(withTrustedRoots: false) combined with an "
        "always-accept callback, or an HttpClient with unconditional trust). "
        "This allows man-in-the-middle attacks against otherwise-HTTPS "
        "traffic."
    )
    severity = Severity.CRITICAL
    recommendation = (
        "Do not override badCertificateCallback in release builds. If "
        "certificate pinning is required, validate the certificate/public "
        "key fingerprint explicitly instead of returning true "
        "unconditionally."
    )
    references = (
        "https://cwe.mitre.org/data/definitions/295.html",
        "https://owasp.org/www-project-mobile-top-10/2023-risks/m5-insecure-communication",
    )
    patterns = (
        re.compile(r"badCertificateCallback\s*=.*(?:\(.*\)\s*=>\s*true|\{\s*return\s+true)"),
        re.compile(r"(?i)\.badCertificateCallback\s*=\s*\(.*\)\s*\{"),
    )
