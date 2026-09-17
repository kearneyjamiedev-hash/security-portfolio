import requests
import json
import pandas as pd

from zipfile import ZipFile
from io import BytesIO


def validate_logon_event(raw_event):
    required_fields = [
        "EventTime",
        "SourceName",
        "EventID",
        "Hostname",
        "TargetUserName",
        "TargetDomainName"
    ]

    for field in required_fields:
        value = raw_event.get(field)

        if value is None or str(value).strip() == "":
            return False
    
    return True


def normalize_logon_event(raw_event, dataset_name):
    normalized_event = {
        "event": {
            "timestamp": raw_event.get("EventTime"),
            "provider": raw_event.get("SourceName"),
            "code": raw_event.get("EventID")
        },
        "host": {
            "name": raw_event.get("Hostname")
        },
        "user": {
            "name": raw_event.get("TargetUserName"),
            "domain": raw_event.get("TargetDomainName")
        },
        "source": {
            "ip": raw_event.get("IpAddress")
        },
        "logon": {
            "id": raw_event.get("TargetLogonId"),
            "type": raw_event.get("LogonType"),
            "authentication_package": raw_event.get(
                "AuthenticationPackageName"
            )
        },
        "process": {
            "id": raw_event.get("ProcessId"),
            "name": raw_event.get("ProcessName")
        },
        "dataset": {
            "provider": "OTRF",
            "name": dataset_name,
            "type": "historical"
        },
        "raw": raw_event
    }

    return normalized_event


url = "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/lateral_movement/host/empire_smbexec_dcerpc_smb_svcctl.zip"

response = requests.get(url)
response.raise_for_status()

zip_file = ZipFile(BytesIO(response.content))
file_name = zip_file.namelist()[0]

print(f"Reading dataset: {file_name}")

events = []

with zip_file.open(file_name) as dataset_file:
    for line in dataset_file:
        event = json.loads(line)
        events.append(event)

df = pd.DataFrame(events)

print("\nDataset shape:")
print(df.shape)

print("\nEvent ID counts:")
print(df["EventID"].value_counts())

login_events = df[df["EventID"] == 4624]

print("\n4624 login events:")
print(
    login_events[
        [
            "EventTime",
            "Hostname",
            "TargetUserName",
            "IpAddress",
            "LogonType"
        ]
    ]
)

normalized_logins = []

for raw_event in events:
    if (
        raw_event.get("EventID") == 4624
        and validate_logon_event(raw_event)
    ):
        normalized_event = normalize_logon_event(
            raw_event,
            file_name
        )

        normalized_logins.append(normalized_event)

print("\nNormalized login count:")
print(len(normalized_logins))

print("\nFirst normalized login:")
print(
    json.dumps(
        normalized_logins[0],
        indent=4,
        default=str
    )
)