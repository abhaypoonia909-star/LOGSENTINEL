import re
import pandas as pd

class LogParser:
    def __init__(self):
        self.format_detected = "text"
        self.total_lines = 0
        self.parsed_lines = 0

    def parse(self, content):

        lines = content.splitlines()

        self.total_lines = len(lines)

        data = []

        for line in lines:

            line_lower = line.lower()

            ip_match = re.search(
                r"(?:\d{1,3}\.){3}\d{1,3}",
                line
            )

            ip = ip_match.group(0) if ip_match else None

            level = "INFO"

            if "critical" in line_lower:
                level = "CRITICAL"

            elif "error" in line_lower:
                level = "ERROR"

            elif "warning" in line_lower:
                level = "WARNING"

            print(line)
            print(ip)
            print(level)
            print("----------------")
            data.append({
                "message": line,
                "level": level,
                "ip_address": ip,

                "is_error":
                    level == "ERROR",

                "is_warning":
                    level == "WARNING",

                "is_critical":
                    level == "CRITICAL"
                    or "privilege escalation" in line_lower,

                "is_failed_login":
                    "failed password" in line_lower
                    or "failed login" in line_lower
            })

        self.parsed_lines = len(data)

        return pd.DataFrame(data)