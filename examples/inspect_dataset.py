import pandas as pd

file_path = "data/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"

# Read only a small sample
df = pd.read_csv(file_path, nrows=10)

df.columns = df.columns.str.strip()

print("\n===== DATASET INFORMATION =====")
print(f"Rows inspected: {len(df)}")
print(f"Columns: {len(df.columns)}")

print("\n===== REQUIRED COLUMNS =====")

required_columns = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Average Packet Size",
    "Flow Packets/s",
    "Flow Bytes/s",
    "Label"
]

for column in required_columns:

    if column in df.columns:
        print(f"✓ {column}")
    else:
        print(f"✗ {column} — NOT FOUND")

print("\n===== SAMPLE VALUES =====")

sample_columns = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Average Packet Size",
    "Flow Packets/s",
    "Flow Bytes/s",
    "Label"
]

print(df[sample_columns].to_string(index=False))

print("\n===== LABEL DISTRIBUTION IN SAMPLE =====")
print(df["Label"].value_counts())