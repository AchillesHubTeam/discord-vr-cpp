# Discord VR Status (C++ native)

Open the exe once. Authorize in browser, paste the URL. It auto-registers Startup (current user, no admin) and keeps VR status in background. Delete `auth.json` to change account.

Build on Windows:
```
cl /std:c++17 /EHsc /O2 main.cpp /link winhttp.lib bcrypt.lib /SUBSYSTEM:WINDOWS /OUT:DiscordVRStatus.exe
```
Or use the GitHub Actions workflow in `.github/workflows/build.yml`.
