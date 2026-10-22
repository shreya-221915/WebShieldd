# WebShield — Python Web Security Scanner

A beginner-friendly educational web app that checks basic HTTP security headers, HTTPS use, and visible cookie security flags. It creates a downloadable JSON report.

## Safety scope

- Default demo target: `http://127.0.0.1:8000`
- Scanning is limited to localhost/loopback and exact hostnames in `WEBSHIELD_ALLOWED_HOSTS` that resolve only to private, loopback, or link-local addresses.
- Redirects are not followed.
- Only scan systems you own or have explicit permission to test.
- This is an educational checker, not a full vulnerability scanner.

## Windows setup

1. Install Python 3.11 or newer from https://www.python.org/downloads/windows/ and select **Add python.exe to PATH** during installation.
2. Extract this ZIP to a folder such as `C:\WebShield`.
3. Open Command Prompt in that folder.
4. Create a virtual environment:

   ```bat
   py -m venv .venv
   .venv\Scripts\activate
   ```

5. Install dependencies:

   ```bat
   python -m pip install --upgrade pip
   pip install -r requirements.txt
   ```

## Run the demo

Open **two** Command Prompt windows in the project folder. Activate the virtual environment in each one.

**Window 1 — local demo target:**

```bat
python demo_site.py
```

Keep this window open. The demo server listens only on `127.0.0.1`.

**Window 2 — WebShield dashboard:**

```bat
python -m streamlit run app.py
```

Your browser should open the dashboard. If it does not, visit http://localhost:8501.

Keep the target URL as `http://127.0.0.1:8000` and click **Run security checks**. Expand findings and use **Download JSON report** to save the results.

## Optional: allow a private host you own

In the same Command Prompt window used to launch Streamlit, set an exact hostname that you own and that resolves only to private/loopback/link-local IP addresses. Example:

```bat
set WEBSHIELD_ALLOWED_HOSTS=dev.example.internal
python -m streamlit run app.py
```

Use only an authorized host. Public IP destinations are blocked by this starter version. The allowlist is an additional guardrail, not a substitute for permission or network controls.

## Submission demonstration

1. Show the dashboard and the default local target.
2. Click **Run security checks**.
3. Explain that the demo server intentionally omits common security headers.
4. Show the detected findings and recommendations.
5. Download `webshield_report.json`.
6. Include screenshots of the dashboard and report in your project document.
7. Clearly label the findings as observations from the local demo, not proof that a real website is vulnerable.

## Project objectives

- Inspect basic HTTP response security headers.
- Identify missing or present browser security controls.
- Present findings in a readable dashboard.
- Export evidence in JSON format.

## Limitations

- Does not test exploitability or perform penetration testing.
- Does not follow redirects.
- Cookie parsing is a simplified demonstration and may not accurately separate multiple cookies.
- Does not independently audit TLS versions/ciphers or validate application logic.
- A missing header is a recommendation for review, not automatic proof of a vulnerability.
