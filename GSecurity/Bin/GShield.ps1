function Remove-SuspiciousDLLs {
    	$drives = Get-PSDrive -PSProvider FileSystem | Where-Object { 
        $_.DriveType -in @('Fixed', 'Removable', 'Network') 
    }
	$dlls = Get-ChildItem -Recurse -Path $drives -Filter "*.dll"
    foreach ($dll in $dlls) {
        try {
            $cert = Get-AuthenticodeSignature $dll.FullName
            if ($cert.Status -ne "Valid") {
                Write-Log "Removing suspicious DLL: $($dll.FullName)"
                Remove-Item $dll.FullName -Force
            }
        } catch {
            Write-Log "Error checking DLL $($dll.FullName)"
        }
    }
}

function Kill-ProcessesOnPorts {
    $ports = @(80, 443, 8080, 8888)

    while ($true) {
        foreach ($port in $ports) {
            # Get process ID (PID) listening on the port
            $connections = netstat -ano | Select-String ":$port\s+.*LISTENING"

            foreach ($conn in $connections) {
                $pid = ($conn -split "\s+")[-1]  # Extract PID from netstat output
                
                if ($pid -match "^\d+$") {
                    # Kill the process
                    Write-Host "Killing process on port $port (PID: $pid)"
                    Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
                }
            }
        }
    }
}

# Continuously run the script in the background
Start-Job -ScriptBlock {
    while ($true) {
        Kill-ProcessesOnPorts
        Remove-SuspiciousDLLs
    }
}
