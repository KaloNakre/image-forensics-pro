# Contributing to Image Forensics Pro

Thank you for considering contributing to **Image Forensics Pro**! We welcome contributions from OSINT researchers, cybersecurity specialists, computer vision developers, and open-source enthusiasts.

---

## 🛠️ How to Contribute

### 1. Reporting Bugs
- Search existing issues to ensure the bug hasn't already been reported.
- Open a new issue with a clear title and description.
- Include reproduction steps, environment details (OS, Python version, ExifTool installation status), and error logs where applicable.

### 2. Requesting Features
- Open a feature request issue explaining the proposed functionality.
- Describe the use case and how it benefits OSINT image forensics workflows.

### 3. Submitting Pull Requests (PRs)
1. Fork the repository: `https://github.com/KaloNakre/image-forensics-pro`
2. Create a feature branch: `git checkout -b feature/amazing-forensic-engine`
3. Commit your changes: `git commit -m 'feat: Add C2PA metadata signature parser'`
4. Ensure pytest passes: `pytest test_app.py`
5. Push to your branch: `git push origin feature/amazing-forensic-engine`
6. Open a Pull Request on GitHub against the `main` branch.

---

## 💻 Code Style Guidelines

- Follow **PEP 8** standards for Python backend code (`main.py`, `test_app.py`).
- Keep async endpoints clean and non-blocking.
- Maintain responsive, dark-mode glassmorphic styling in `osint-vision-pro.html`.

---

## 🧪 Testing

Before submitting a PR, make sure all tests pass cleanly:

```bash
pytest test_app.py
```
