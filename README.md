# SPECTRA — Deep APK Analyzer v4.0

**Offline, read-only Android APK static triage. English dashboard and report.**

## Windows installation

1. Install Python 3.10+ and select **Add Python to PATH**.
2. Extract the project and run `INSTALL_WINDOWS.bat` once (installs `cryptography` used for supported sharded loaders).
3. Run `START_WINDOWS.bat`.
4. Open `http://127.0.0.1:8765` and **upload an APK**. Analysis starts automatically.
5. View **Payload stages, Spyware commands, Code evidence, Embedded config, Findings, Permissions**. Export JSON or English HTML report.

## Scope

- Scans uploaded bytes; never installs/executes APK; no cloud submission or network lookups.
- Parses manifest permissions and components, DEX strings & method references, candidate network addresses and JSON configuration.
- Attempts to recover ordinary embedded APKs, GZIP embedded APKs, and **one supported authenticated AES-GCM sharded loader format**. This decryptor is not universal.
- Displays stage-specific SHA-256, decoded package, spyware command labels, selected method references, and HTML configuration snippets.
- Network indicators from static files are **not confirmed C2 connections**. Camera/keylogger method references are **not proof they were executed**.
- **Code evidence** contains DEX method references and strings (not Java/Kotlin decompilation). Use JADX or MobSF separately if decompiled source is needed.
- Encoded/packed code, reflective calls, and ELF native logic can remain undetected; lack of findings is NOT an indication the APK is safe.
- Maximum original APK upload: 120 MB; bounded ZIP/DEX/payload parsing. Analyze unknown samples only on a dedicated analyst computer/VM.

### Test

Run `python -m unittest discover -s tests -v` in the project folder to run tests. The uploaded APK is **not included** in this distribution.

All reporting labels and evidence are in English. No hard-coded case results.
