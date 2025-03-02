# Function to monitor and remove suspicious DLLs (signed and unsigned)
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

# Continuously run the script in the background
Start-Job -ScriptBlock {
    while ($true) {
        Remove-SuspiciousDLLs
    }
}
