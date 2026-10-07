import re
import ipaddress


print("'Northmen' Security Operations Center")
print()
print("Processing log-in attempts...")
print()
print("All suspicious attempts:")
print()

log_file = "logs/auth.log"

with open(log_file, "r") as file:
    for line in file:
        if "Failed password" in line:
            print(line.strip())

print()
print()
log_file = "logs/auth.log"

failed_attempts = 0

with open(log_file, "r") as file:
    for line in file:
        if "Failed password" in line:
            failed_attempts += 1


print("Failed login attempts:", failed_attempts)


def parse_log(line):
    match = re.search(r"\bfrom\s+(\S+)\s+port\s+\d+", line)

    if match is None:
        return None

    try:
        source_ip = str(ipaddress.ip_address(match.group(1)))
    except ValueError:
        return None

    return {
        "hostname": "nm-files01",
        "source_ip": source_ip,
    }
