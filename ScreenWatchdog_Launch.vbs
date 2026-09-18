' Launches ScreenWatchdog.ps1 fully hidden (no console window flash).
' Put a shortcut to THIS file in your Startup folder (Win+R -> shell:startup)
' if you want it to start automatically at login.

Set objShell = CreateObject("WScript.Shell")
scriptDir = CreateObject("Scripting.FileSystemObject").GetParentFolderName(WScript.ScriptFullName)
psScript = scriptDir & "\ScreenWatchdog.ps1"

objShell.Run "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File """ & psScript & """", 0, False
