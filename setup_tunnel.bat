@echo off
set ADB=%LOCALAPPDATA%\Android\Sdk\platform-tools\adb.exe
for /f "skip=1 tokens=1,2" %%a in ('"%ADB%" devices') do (
  if "%%b"=="device" (
    echo Emulator: %%a
    "%ADB%" -s %%a reverse tcp:5000 tcp:5000
  )
)
echo Done. If you see 5000 above, the tunnel is ready.
pause