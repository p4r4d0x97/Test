<#
.SYNOPSIS
  Periodically OCRs your target app's window (using Windows' built-in offline OCR engine)
  and restarts the app if it sees a "bad" symbol (e.g. "!" where a "1" should be).

  Unlike a keyboard hook, this looks at what's actually drawn on screen — so it catches
  the problem whether it's the scanner sending the wrong character OR the app itself
  mis-rendering a correct keystroke.

.SETUP
  1. Edit the CONFIG block below.
  2. Requires Windows 10/11 with an OCR language pack installed (Settings > Time & Language >
     Language & Region > your language > Options > check "Optical character recognition").
     Most systems already have this.
  3. Test visibly first:
       powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\ScreenWatchdog.ps1
     Watch ScreenWatchdog.log to see what it's reading and confirm it's not misfiring.
  4. Once confirmed, run hidden via ScreenWatchdog_Launch.vbs (Startup folder / Task Scheduler).

.NOTES
  - Only scans while your target app is the FOREGROUND window, so text elsewhere on screen
    (browser tabs, chat apps, emails with "@" in them, etc.) is never read.
  - By default it captures the whole app window. If you get false positives from other text
    in the app (prices with "$", etc.), set $CaptureFullWindow = $false and fill in
    $RelativeRegion with just the input field's location (see instructions at the bottom).
  - OCR is not instant and occasionally misreads characters. If you need guaranteed accuracy,
    the keyboard-hook version is more precise; this version is better for figuring out
    whether the app or the scanner is at fault, and works either way.
#>

# ===================== CONFIG =====================
$TargetProcessName  = "YourApp"                       # process name WITHOUT .exe (Task Manager > Details)
$TargetExePath      = "C:\Path\To\YourApp.exe"        # full path used to relaunch it
$TargetExeArgs      = ""                              # launch arguments, or leave blank
$TriggerChars       = @('!','@','#','$','%','^','&','*','(',')')
$PollIntervalMs     = 700                              # how often to OCR-check, in milliseconds
$CooldownSeconds    = 5                                # minimum seconds between restarts
$CaptureFullWindow  = $true                            # $false = use $RelativeRegion instead
$RelativeRegion     = @{ X = 0; Y = 0; Width = 300; Height = 40 }  # pixels, relative to window top-left corner
$LogFile            = Join-Path $PSScriptRoot "ScreenWatchdog.log"
$EnableLogging      = $false                           # set $true to write ScreenWatchdog.log again
$UpscaleFactor      = 2                                # upsize captured image before OCR (improves small-text accuracy)
$DoubleCheckMs      = 300                               # 2nd capture this many ms after the 1st, to dodge a blinking cursor
$ContrastBoost      = $true                             # convert to high-contrast grayscale before OCR (helps with colored backgrounds)
# ====================================================

function Write-Log($msg) {
    if (-not $EnableLogging) { return }
    try { Add-Content -Path $LogFile -Value "$(Get-Date -Format o)  $msg" -ErrorAction SilentlyContinue } catch {}
}

# ---- Win32 interop: foreground window / rect / DPI ----
Add-Type -Language CSharp -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public struct RECT { public int Left; public int Top; public int Right; public int Bottom; }

public class Win32Screen
{
    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);
    [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
}
"@
[void][Win32Screen]::SetProcessDPIAware()

Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Windows.Forms

# ---- WinRT interop plumbing (needed to call the Windows OCR engine from PowerShell) ----
Add-Type -AssemblyName System.Runtime.WindowsRuntime
$asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {
    $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1'
})[0]

function Await($WinRtTask, [Type]$ResultType) {
    $asTask = $asTaskGeneric.MakeGenericMethod($ResultType)
    $netTask = $asTask.Invoke($null, @($WinRtTask))
    $netTask.Wait(-1) | Out-Null
    return $netTask.Result
}

[Windows.Storage.Streams.InMemoryRandomAccessStream, Windows.Storage.Streams, ContentType = WindowsRuntime] | Out-Null
[Windows.Storage.Streams.DataWriter, Windows.Storage.Streams, ContentType = WindowsRuntime] | Out-Null
[Windows.Graphics.Imaging.BitmapDecoder, Windows.Graphics.Imaging, ContentType = WindowsRuntime] | Out-Null
[Windows.Media.Ocr.OcrEngine, Windows.Media.Ocr, ContentType = WindowsRuntime] | Out-Null

$ocrEngine = [Windows.Media.Ocr.OcrEngine]::TryCreateFromUserProfileLanguages()
if ($null -eq $ocrEngine) {
    Write-Log "FATAL: No OCR language pack available. Install one under Settings > Time & Language > Language & Region."
    exit 1
}

function Get-TargetWindowRect {
    $fg = [Win32Screen]::GetForegroundWindow()
    if ($fg -eq [IntPtr]::Zero) { return $null }
    $procId = 0
    [void][Win32Screen]::GetWindowThreadProcessId($fg, [ref]$procId)
    try { $name = (Get-Process -Id $procId -ErrorAction Stop).ProcessName } catch { return $null }
    if ($name -ne $TargetProcessName) { return $null }

    $rect = New-Object RECT
    if (-not [Win32Screen]::GetWindowRect($fg, [ref]$rect)) { return $null }
    return $rect
}

function Get-ScreenText($rect) {
    if ($CaptureFullWindow) {
        $x = $rect.Left; $y = $rect.Top
        $w = $rect.Right - $rect.Left
        $h = $rect.Bottom - $rect.Top
    } else {
        $x = $rect.Left + $RelativeRegion.X
        $y = $rect.Top + $RelativeRegion.Y
        $w = $RelativeRegion.Width
        $h = $RelativeRegion.Height
    }
    if ($w -le 0 -or $h -le 0) { return "" }

    $bmp = New-Object System.Drawing.Bitmap $w, $h
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    try { $g.CopyFromScreen($x, $y, 0, 0, (New-Object System.Drawing.Size $w, $h)) } finally { $g.Dispose() }

    if ($UpscaleFactor -gt 1) {
        $bigW = $w * $UpscaleFactor
        $bigH = $h * $UpscaleFactor
        $bigBmp = New-Object System.Drawing.Bitmap $bigW, $bigH
        $bg = [System.Drawing.Graphics]::FromImage($bigBmp)
        $bg.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
        $bg.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
        try { $bg.DrawImage($bmp, 0, 0, $bigW, $bigH) } finally { $bg.Dispose() }
        $bmp.Dispose()
        $bmp = $bigBmp
    }

    if ($ContrastBoost) {
        # Grayscale + push contrast toward pure black/white so colored backgrounds (yellow, etc.)
        # stop competing with the text for OCR's attention.
        $cW = $bmp.Width; $cH = $bmp.Height
        $contrastBmp = New-Object System.Drawing.Bitmap $cW, $cH
        $cg = [System.Drawing.Graphics]::FromImage($contrastBmp)
        # Standard luminosity-preserving grayscale matrix, with extra weight pushed to widen contrast.
        $matrixElements = [float[][]]@(
            [float[]]@(0.6, 0.6, 0.6, 0, 0),
            [float[]]@(0.6, 0.6, 0.6, 0, 0),
            [float[]]@(0.6, 0.6, 0.6, 0, 0),
            [float[]]@(0, 0, 0, 1, 0),
            [float[]]@(-0.3, -0.3, -0.3, 0, 1)
        )
        $colorMatrix = New-Object System.Drawing.Imaging.ColorMatrix (,$matrixElements)
        $attrs = New-Object System.Drawing.Imaging.ImageAttributes
        $attrs.SetColorMatrix($colorMatrix)
        try {
            $cg.DrawImage($bmp, (New-Object System.Drawing.Rectangle(0, 0, $cW, $cH)), 0, 0, $cW, $cH, [System.Drawing.GraphicsUnit]::Pixel, $attrs)
        } finally {
            $cg.Dispose()
            $attrs.Dispose()
        }
        $bmp.Dispose()
        $bmp = $contrastBmp
    }

    $ms = New-Object System.IO.MemoryStream
    $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    $ms.Position = 0
    $bytes = $ms.ToArray()
    $ms.Dispose()

    $ras = New-Object Windows.Storage.Streams.InMemoryRandomAccessStream
    $outStream = $ras.GetOutputStreamAt(0)
    $writer = New-Object Windows.Storage.Streams.DataWriter $outStream
    $writer.WriteBytes($bytes)
    Await ($writer.StoreAsync()) ([uint32]) | Out-Null
    Await ($outStream.FlushAsync()) ([bool]) | Out-Null
    $writer.DetachStream() | Out-Null

    $decoder = Await ([Windows.Graphics.Imaging.BitmapDecoder]::CreateAsync($ras)) ([Windows.Graphics.Imaging.BitmapDecoder])
    $softwareBmp = Await ($decoder.GetSoftwareBitmapAsync()) ([Windows.Graphics.Imaging.SoftwareBitmap])
    $ocrResult = Await ($ocrEngine.RecognizeAsync($softwareBmp)) ([Windows.Media.Ocr.OcrResult])

    return $ocrResult.Text
}

$script:LastRestart = Get-Date "2000-01-01"

function Invoke-Restart($foundChar) {
    $now = Get-Date
    if (($now - $script:LastRestart).TotalSeconds -lt $CooldownSeconds) { return }
    $script:LastRestart = $now

    Write-Log "Detected '$foundChar' on screen -> restarting $TargetProcessName"
    try {
        Get-Process -Name $TargetProcessName -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 500
        if ($TargetExeArgs -ne "") { Start-Process -FilePath $TargetExePath -ArgumentList $TargetExeArgs }
        else { Start-Process -FilePath $TargetExePath }
        Write-Log "Restart complete."
    } catch {
        Write-Log "Restart FAILED: $_"
    }
}

Write-Log "Screen watchdog started. Watching for: $($TriggerChars -join ' ') in '$TargetProcessName'."

while ($true) {
    try {
        $rect = Get-TargetWindowRect
        if ($null -ne $rect) {
            $foundChar = $null

            $text1 = Get-ScreenText $rect
            if ($text1) { Write-Log "OCR read (pass 1): $text1" }
            foreach ($c in $TriggerChars) { if ($text1.Contains($c)) { $foundChar = $c; break } }

            if ($null -eq $foundChar -and $DoubleCheckMs -gt 0) {
                Start-Sleep -Milliseconds $DoubleCheckMs
                $rect2 = Get-TargetWindowRect   # re-fetch in case window moved/closed
                if ($null -ne $rect2) {
                    $text2 = Get-ScreenText $rect2
                    if ($text2) { Write-Log "OCR read (pass 2): $text2" }
                    foreach ($c in $TriggerChars) { if ($text2.Contains($c)) { $foundChar = $c; break } }
                }
            }

            if ($null -ne $foundChar) { Invoke-Restart $foundChar }
        }
    } catch {
        Write-Log "Loop error: $_"
    }
    Start-Sleep -Milliseconds $PollIntervalMs
}
