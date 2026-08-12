# VulnMicroScan local test fixture

This is an isolated Flask service for testing VulnMicroScan locally. It does
not import or modify the scanner.

## Run it

From this directory, create and activate a virtual environment, then install
the fixture dependency:

```powershell
cd C:\Users\USER\Desktop\microvulnscan\VulnMicroScan\test\fixture
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python app.py
```

The service listens on port `5055` on all local interfaces.

Because VulnMicroScan blocks scans targeting `127.0.0.1` to prevent
self-target deadlocks, find your computer's LAN IPv4 address with:

```powershell
ipconfig
```

Then use that address as the VulnMicroScan Base URL, for example
`http://192.168.100.148:5055`. Keep the fixture running while the scan is in
progress.

If PowerShell blocks activation, run the service with the virtual environment
interpreter directly instead:

```powershell
.\.venv\Scripts\python.exe app.py
```

## Test endpoints

Use these paths as VulnMicroScan endpoints with the base URL
`http://YOUR-LAN-IP:5055`:

| Endpoint | Expected result |
| --- | --- |
| `/ok` | `200 Available` |
| `/not-found` | `404 Not Found` |
| `/unauthorized` | `401 Authentication Required` |
| `/forbidden` | `403 Forbidden` |
| `/method-not-allowed` | `405 Method Not Allowed` for GET |
| `/server-error` | `500 Server Error` |
| `/timeout` | Delayed response; should trigger a scanner timeout |
| `/missing-security-headers` | `200`; deliberately omits the recommended security headers |

The `/method-not-allowed` route only accepts POST, while VulnMicroScan uses
GET requests, so Flask produces the intended 405 response.

The timeout route sleeps for 15 seconds. Stop the fixture with `Ctrl+C` when
finished testing.
