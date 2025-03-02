function Remove-SuspiciousDLLs {
    $drives = Get-PSDrive -PSProvider FileSystem | Where-Object { 
        $_.DriveType -in @('Fixed', 'Removable', 'Network') 
    }
    $dlls = Get-ChildItem -Recurse -Path $drives.Root -Filter "*.dll"
    foreach ($dll in $dlls) {
        $cert = Get-AuthenticodeSignature $dll.FullName
        if ($cert.Status -ne "Valid") {
            $processes = Get-WmiObject Win32_Process | Where-Object { 
                $_.CommandLine -like "*$($dll.FullName)*" 
            }
            foreach ($process in $processes) {
                Stop-Process -Id $process.ProcessId -Force
            }
            takeown /f $dll.FullName
            icacls $dll.FullName /inheritance:d
            icacls $dll.FullName /grant:r Administrators:F
            Remove-Item $dll.FullName -Force
        }
    }
}

function Kill-ProcessesOnPorts {
    $ports = @(80, 443, 8080, 8888)
    $connections = Get-NetTCPConnection -State Listen | Where-Object { $_.LocalPort -in $ports }
    foreach ($conn in $connections) {
        $pid = $conn.OwningProcess
        Stop-Process -Id $pid -Force
    }
}

Start-Job -ScriptBlock {
    while ($true) {
	Remove-SuspiciousDLLs
	Kill-ProcessesOnPorts
    }
}