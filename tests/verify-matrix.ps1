param([ValidateSet(3, 4)][int[]]$Branches = @(3, 4),
  [ValidateSet('bcc32', 'bcc32c', 'msc32', 'bcc64', 'msc64')][string[]]$Configurations = @(),
  [ValidateSet('win32', 'win64', 'all')][string]$Platform = 'all',
  [switch]$EurekaLog, [string]$EurekaLogRoot = 'D:\tools\EurekaLog7')
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot
$outRoot = Join-Path $env:LOCALAPPDATA 'DelphiLibOpenSSL-validation'
$failed = $false
New-Item -ItemType Directory $outRoot -Force | Out-Null
$configs = @(
  @('bcc32', 'dcc32', 'C_COMPILER_BORLAND_32'),
  @('bcc32c', 'dcc32', 'C_COMPILER_BCC32C'),
  @('msc32', 'dcc32', 'C_COMPILER_MSC_32'),
  @('bcc64', 'dcc64', 'C_COMPILER_BORLAND_64'),
  @('msc64', 'dcc64', 'C_COMPILER_MSC_64'))
foreach ($branch in $Branches) {
  foreach ($cfg in $configs) {
    $name, $compiler, $define = $cfg
    if ($Configurations.Count -and $name -notin $Configurations) { continue }
    if ($Platform -eq 'win32' -and $compiler -ne 'dcc32') { continue }
    if ($Platform -eq 'win64' -and $compiler -ne 'dcc64') { continue }
    $label = "b$branch-$name"
    $extraDefines = ''
    $extraUnits = ''
    if ($EurekaLog) {
      $label = "eureka-$label"
      $eurekaPlatform = if ($compiler -eq 'dcc64') { 'Win64' } else { 'Win32' }
      $extraDefines = ';EUREKALOG;EUREKALOG_VER7'
      $extraUnits = ";$EurekaLogRoot\Lib\$eurekaPlatform\Release\Studio29;$EurekaLogRoot\Lib\Common"
    }
    $out = Join-Path $outRoot $label
    New-Item -ItemType Directory $out -Force | Out-Null
    & python "$root\helpers\build_record_layout_probe.py" --branch $branch --compiler $name --output $out
    if ($LASTEXITCODE -ne 0) { throw "C record layout probe failed: $label" }
    $bat = Join-Path $out 'compile.bat'
    @"
@echo off
call "$root\build_config.bat" bcc32_classic >nul 2>&1
if errorlevel 1 exit /b 1
cd /d "$PSScriptRoot"
$compiler -B -GD -DOPENSSL_${branch}X;$define;CI;ABI_LAYOUT_PROBE$extraDefines OpenSSL3Tests.dpr -U"$root$extraUnits" -O"$out" -N0"$out" -E"$out" > "$out\build.log" 2>&1
exit /b %errorlevel%
"@ | Set-Content $bat -Encoding ascii
    & cmd /c $bat
    $buildExit = $LASTEXITCODE
    $warnings = @(Select-String "$out\build.log" -Pattern 'Warning:|Error:|Fatal:').Count
    if ($buildExit -ne 0) {
      Write-Output "b$branch-$name BUILD FAILED ($warnings diagnostics): $out"
      $failed = $true
      continue
    }
    if ($EurekaLog) {
      & "$EurekaLogRoot\Bin64\ecc32.exe" "--el_alter_exe=$PSScriptRoot\OpenSSL3Tests.dproj;$out\OpenSSL3Tests.exe" > "$out\eureka.log" 2>&1
      if ($LASTEXITCODE -ne 0) {
        Write-Output "$label EUREKALOG POSTPROCESS FAILED: $out"
        $failed = $true
        continue
      }
    }
    $start = New-Object System.Diagnostics.ProcessStartInfo
    $start.FileName = "$out\OpenSSL3Tests.exe"
    $start.WorkingDirectory = $out
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $p = [System.Diagnostics.Process]::Start($start)
    $stdout = $p.StandardOutput.ReadToEndAsync()
    $stderr = $p.StandardError.ReadToEndAsync()
    if (!$p.WaitForExit(30000)) {
      Write-Output "b$branch-$name HUNG PID=$($p.Id): $out"
      if ($compiler -eq 'dcc64') {
        & python "$root\helpers\stackdump_win64.py" $p.Id > "$out\stacks.log"
      }
      Stop-Process -Id $p.Id
      $p.WaitForExit()
      [IO.File]::WriteAllText("$out\run.log", $stdout.GetAwaiter().GetResult())
      [IO.File]::WriteAllText("$out\stderr.log", $stderr.GetAwaiter().GetResult())
      $failed = $true
    } else {
      $p.WaitForExit()
      [IO.File]::WriteAllText("$out\run.log", $stdout.GetAwaiter().GetResult())
      [IO.File]::WriteAllText("$out\stderr.log", $stderr.GetAwaiter().GetResult())
      Write-Output "b$branch-$name EXIT=$($p.ExitCode) DIAGNOSTICS=$warnings $out"
      Select-String "$out\run.log" -Pattern 'Results:|FAIL:|Runtime error' | ForEach-Object Line
      $runText = Get-Content -LiteralPath "$out\run.log" -Raw
      $discovered = [regex]::Match($runText, '=== OpenSSL3 Tests: (\d+) active of (\d+) total ===')
      $results = [regex]::Match($runText, '=== Results: (\d+) passed, 0 failed, 0 errors, 0 ignored ===')
      $minimumTests = if ($branch -eq 4) { 146 } else { 144 }
      $complete = $discovered.Success -and $results.Success -and
        ([int]$discovered.Groups[1].Value -eq [int]$discovered.Groups[2].Value) -and
        ([int]$results.Groups[1].Value -eq [int]$discovered.Groups[1].Value) -and
        ([int]$results.Groups[1].Value -ge $minimumTests)
      if ($p.ExitCode -ne 0 -or $warnings -ne 0 -or
          (Get-Content -LiteralPath "$out\stderr.log" -Raw) -or
          (Select-String -Path "$out\run.log" -Pattern 'Runtime error|Access violation|Unhandled exception') -or
          !$complete) {
        $failed = $true
      }
    }
  }
}
if ($failed) { exit 1 }
exit 0
