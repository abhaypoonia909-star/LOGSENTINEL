from dataclasses import dataclass, asdict

@dataclass
class VulnerabilityFinding:
    line: int
    severity: str
    type: str
    description: str
    recommendation: str
    owasp: str
    cwe: str
    file: str
    snippet: str = ""

    def to_dict(self) -> dict:
        return asdict(self)