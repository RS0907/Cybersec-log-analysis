
import json
import ollama
from pathlib import Path

BASE_DIR = Path(__file__).parent

SYSTEM_PROMPT = (BASE_DIR / "prompts/system_prompt.txt").read_text()
LOGS = (BASE_DIR / "logs/sample_logs.txt").read_text()

USER_PROMPT = f"""
Analyze the following cybersecurity logs and produce a structured JSON report.

JSON SCHEMA:
{{
  "overview": {{
    "total_attacks": number,
    "unique_attack_types": number
  }},
  "attack_summary": [
    {{
      "attack_type": string,
      "count": number,
      "owasp_category": string,
      "severity": string
    }}
  ],
  "events": [
    {{
      "timestamp": string,
      "source_ip": string,
      "destination_ip": string,
      "attack_type": string,
      "vulnerability": string,
      "affected_service": string,
      "severity": string,
      "recommended_action": string
    }}
  ]
}}

Logs:
<<<
{LOGS}
>>>
"""

response = ollama.chat(
    model="llama3:8b",
    messages=[
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": USER_PROMPT}
    ]
)

content = response["message"]["content"]

# Extract JSON safely
start = content.find("{")
end = content.rfind("}") + 1

json_text = content[start:end]
data = json.loads(json_text)


output_dir = BASE_DIR / "outputs"
output_dir.mkdir(exist_ok=True)

with open(output_dir / "report.json", "w") as f:
    json.dump(data, f, indent=2)

print("✅ Log analysis complete. JSON saved to outputs/report.json")
