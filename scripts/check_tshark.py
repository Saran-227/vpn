import shutil
import subprocess
import sys


def main() -> int:
    tshark_path = shutil.which("tshark")

    if tshark_path is None:
        print("ERROR: TShark was not found in PATH.")
        return 1

    print(f"TShark found at: {tshark_path}")

    try:
        result = subprocess.run(
            [tshark_path, "--version"],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
    except subprocess.TimeoutExpired:
        print("ERROR: TShark did not respond within 10 seconds.")
        return 1
    except subprocess.CalledProcessError as exc:
        print("ERROR: TShark failed to execute.")
        if exc.stderr:
            print(exc.stderr.strip())
        return 1
    except OSError as exc:
        print(f"ERROR: Could not execute TShark: {exc}")
        return 1

    version_output = result.stdout.strip() or result.stderr.strip()

    if not version_output:
        print("ERROR: TShark executed but returned no version information.")
        return 1

    print("TShark verification successful.")
    print(version_output.splitlines()[0])

    return 0


if __name__ == "__main__":
    sys.exit(main())
