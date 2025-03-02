# CPU Benchmark
function Test-CPU {
    $start = Get-Date
    $maxIterations = 100000
    for ($i = 0; $i -lt $maxIterations; $i++) {
        $result = $i * 2 + 1 - $i
        Write-Progress -Activity "CPU Benchmark" -Status "Testing Integer Math..." -PercentComplete (($i / $maxIterations) * 100)
    }
    $intTime = (Get-Date) - $start

    $start = Get-Date
    $maxIterations = 100000
    for ($i = 0; $i -lt $maxIterations; $i++) {
        $result = [math]::sqrt($i) * [math]::PI
        Write-Progress -Activity "CPU Benchmark" -Status "Testing Floating Point Math..." -PercentComplete (($i / $maxIterations) * 100)
    }
    $floatTime = (Get-Date) - $start

    $cpuScore = 1 / ($intTime.TotalSeconds + $floatTime.TotalSeconds)
    return [math]::Round($cpuScore * 1000, 2)
}

# Memory Benchmark
function Test-Memory {
    $start = Get-Date
    $maxIterations = 10000
    $array = @()
    for ($i = 0; $i -lt $maxIterations; $i++) {
        $array += $i
        Write-Progress -Activity "Memory Benchmark" -Status "Allocating Memory..." -PercentComplete (($i / $maxIterations) * 100)
    }
    $fillTime = (Get-Date) - $start

    $start = Get-Date
    $sum = 0
    foreach ($item in $array) {
        $sum += $item
        Write-Progress -Activity "Memory Benchmark" -Status "Reading Memory..." -PercentComplete (($array.IndexOf($item) + 1) / $array.Count * 100)
    }
    $readTime = (Get-Date) - $start

    $memoryScore = 1 / ($fillTime.TotalSeconds + $readTime.TotalSeconds)
    return [math]::Round($memoryScore * 100, 2)
}

# Disk Benchmark
function Test-Disk {
    $directory = "C:\Temp"
    if (-not (Test-Path -Path $directory)) {
        New-Item -ItemType Directory -Path $directory
    }
    $filePath = "$directory\benchmark_testfile.txt"
    $content = "0" * 1024 * 1024 # 1 MB data

    $start = Get-Date
    Set-Content -Path $filePath -Value $content
    $writeTime = (Get-Date) - $start

    $start = Get-Date
    $data = Get-Content -Path $filePath
    $readTime = (Get-Date) - $start

    Remove-Item -Path $filePath -Force

    $diskScore = 1 / ($writeTime.TotalSeconds + $readTime.TotalSeconds)
    return [math]::Round($diskScore, 2)
}

# Graphics Benchmark
function Test-Graphics {
    $start = Get-Date
    $maxFrames = 1000
    for ($i = 0; $i -lt $maxFrames; $i++) {
        Start-Sleep -Milliseconds 1
        Write-Progress -Activity "Graphics Benchmark" -Status "Rendering Frames..." -PercentComplete (($i / $maxFrames) * 100)
    }
    $renderTime = (Get-Date) - $start

    $graphicsScore = 1 / $renderTime.TotalSeconds
    return [math]::Round($graphicsScore * 1000, 2)
}

# Main Function
function Run-Benchmark {

    # Run Benchmark
    $cpuScore = Test-CPU
    $memoryScore = Test-Memory
    $diskScore = Test-Disk
    $graphicsScore = Test-Graphics

    # Display Results
    $results = @(
        "CPU Score: $cpuScore"
        "Memory Score: $memoryScore"
        "Disk Score: $diskScore"
        "Graphics Score: $graphicsScore"
    )
    $results -join "`n" | Out-String
}

# Run the benchmark
Run-Benchmark
