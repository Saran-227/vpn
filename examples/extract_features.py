from app.security_engine import SecurityAssessmentEngine
import pandas as pd


# ---------------------------------------------------------
# Configuration
# ---------------------------------------------------------

INPUT_FILE =  "./data/exp_003_packets.tsv"


# ---------------------------------------------------------
# Load TShark output
# ---------------------------------------------------------

df = pd.read_csv(
    INPUT_FILE,
    sep="\t",
    encoding="utf-16"
)


# ---------------------------------------------------------
# Clean numeric fields
# ---------------------------------------------------------

numeric_columns = [
    "frame.number",
    "frame.time_epoch",
    "frame.len"
]

for column in numeric_columns:
    df[column] = pd.to_numeric(
        df[column],
        errors="coerce"
    )


df = df.dropna(
    subset=["frame.time_epoch", "frame.len"]
)


# ---------------------------------------------------------
# Basic flow statistics
# ---------------------------------------------------------

packet_count = len(df)

total_bytes = df["frame.len"].sum()

start_time = df["frame.time_epoch"].min()
end_time = df["frame.time_epoch"].max()

flow_duration = end_time - start_time


if flow_duration > 0:

    packets_per_second = (
        packet_count / flow_duration
    )

    bytes_per_second = (
        total_bytes / flow_duration
    )

else:

    packets_per_second = 0
    bytes_per_second = 0


# ---------------------------------------------------------
# Determine the two endpoints
# ---------------------------------------------------------

src_ips = (
    df["ip.src"]
    .dropna()
    .astype(str)
)

dst_ips = (
    df["ip.dst"]
    .dropna()
    .astype(str)
)

all_ips = pd.concat(
    [src_ips, dst_ips]
).value_counts()


print("===== ENDPOINTS =====")

for ip, count in all_ips.items():
    print(f"{ip}: {count} occurrences")


# ---------------------------------------------------------
# Main source
# ---------------------------------------------------------

if len(src_ips) > 0:

    main_source = src_ips.value_counts().index[0]

else:

    main_source = None


# ---------------------------------------------------------
# Sent / received bytes
# ---------------------------------------------------------

if main_source is not None:

    bytes_sent = df.loc[
        df["ip.src"].astype(str) == main_source,
        "frame.len"
    ].sum()

    bytes_received = df.loc[
        df["ip.dst"].astype(str) == main_source,
        "frame.len"
    ].sum()

else:

    bytes_sent = 0
    bytes_received = 0


# ---------------------------------------------------------
# TCP / UDP connections
#
# Count unique endpoint pairs rather than packets.
# ---------------------------------------------------------

tcp_df = df[
    df["ip.proto"].astype(str).str.strip() == "6"
]

udp_df = df[
    df["ip.proto"].astype(str).str.strip() == "17"
]


def count_connections(protocol_df):

    if protocol_df.empty:
        return 0

    pairs = (
        protocol_df[
            ["ip.src", "ip.dst"]
        ]
        .dropna()
        .drop_duplicates()
    )

    return len(pairs)


tcp_connections = count_connections(
    tcp_df
)

udp_connections = count_connections(
    udp_df
)


# ---------------------------------------------------------
# Traffic imbalance
# ---------------------------------------------------------

if bytes_sent == 0 and bytes_received == 0:

    imbalance_ratio = 0

elif bytes_sent == 0 or bytes_received == 0:

    imbalance_ratio = float("inf")

else:

    imbalance_ratio = max(
        bytes_sent / bytes_received,
        bytes_received / bytes_sent
    )


# ---------------------------------------------------------
# EXACT FEATURE DICTIONARY FOR ENGINE
# ---------------------------------------------------------

features = {

    "packets_per_second":
        float(packets_per_second),

    "bytes_per_second":
        float(bytes_per_second),

    "tcp_connections":
        int(tcp_connections),

    "udp_connections":
        int(udp_connections),

    "flow_duration":
        float(flow_duration),

    "bytes_sent":
        int(bytes_sent),

    "bytes_received":
        int(bytes_received)
}

# ---------------------------------------------------------
# Run Security Assessment Engine
# ---------------------------------------------------------

engine = SecurityAssessmentEngine()

assessment = engine.assess(features)

print("\n===== SECURITY ASSESSMENT =====")

import json

print(
    json.dumps(
        assessment,
        indent=4
    )
)

# ---------------------------------------------------------
# Display
# ---------------------------------------------------------

print("\n===== ENGINE FEATURES =====")

for key, value in features.items():
    print(f"{key}: {value}")


print("\n===== TRAFFIC INFORMATION =====")

print(f"Packet count:       {packet_count}")
print(f"Total bytes:        {total_bytes:.0f}")
print(f"Flow duration:      {flow_duration:.6f} seconds")
print(f"Packets/second:     {packets_per_second:.6f}")
print(f"Bytes/second:       {bytes_per_second:.6f}")

print(f"TCP connections:    {tcp_connections}")
print(f"UDP connections:    {udp_connections}")

print(f"Main source:        {main_source}")

print(f"Bytes sent:         {bytes_sent:.0f}")
print(f"Bytes received:     {bytes_received:.0f}")

print(f"Traffic imbalance:  {imbalance_ratio:.6f}")