import os
import re
import zipfile
import tempfile
import shutil


ALLOWED_EXTENSIONS = {
    ".html", ".htm", ".css", ".js", ".jsx",
    ".ts", ".tsx", ".php", ".py", ".java",
    ".c", ".cpp", ".h", ".json", ".xml",
    ".sql", ".env", ".txt"
}


def is_safe_path(base_path, target_path):
    base_path = os.path.abspath(base_path)
    target_path = os.path.abspath(target_path)

    return os.path.commonpath(
        [base_path, target_path]
    ) == base_path


def extract_zip_safely(zip_path, extract_to):

    with zipfile.ZipFile(zip_path, "r") as zip_file:

        for member in zip_file.infolist():

            target_path = os.path.join(
                extract_to,
                member.filename
            )

            if not is_safe_path(
                extract_to,
                target_path
            ):
                raise ValueError(
                    "Unsafe file path detected inside ZIP."
                )

        zip_file.extractall(extract_to)


def add_finding(
    findings,
    finding_type,
    severity,
    file_path,
    message,
    recommendation
):

    findings.append({
        "type": finding_type,
        "severity": severity,
        "file": file_path,
        "message": message,
        "recommendation": recommendation
    })


def scan_file(file_path):

    findings = []

    try:

        with open(
            file_path,
            "r",
            encoding="utf-8",
            errors="ignore"
        ) as file:

            content = file.read()

    except Exception:

        return findings


    # ------------------------------------------------
    # 1. Hardcoded Password
    # ------------------------------------------------

    password_pattern = re.compile(
        r"(password|passwd|pwd)"
        r"\s*[:=]\s*[\"'][^\"']+[\"']",
        re.IGNORECASE
    )

    if password_pattern.search(content):

        add_finding(
            findings,
            "Hardcoded Password",
            "High",
            file_path,
            "A possible hardcoded password was detected.",
            "Store passwords securely using environment variables or a secret manager."
        )


    # ------------------------------------------------
    # 2. Possible API Key / Secret
    # ------------------------------------------------

    api_pattern = re.compile(
        r"(api[_-]?key|secret[_-]?key)"
        r"\s*[:=]\s*[\"'][^\"']+[\"']",
        re.IGNORECASE
    )

    if api_pattern.search(content):

        add_finding(
            findings,
            "Possible API Key",
            "High",
            file_path,
            "A possible API key or secret was detected in the source code.",
            "Move sensitive credentials outside the source code."
        )


    # ------------------------------------------------
    # 3. JavaScript eval()
    # ------------------------------------------------

    if re.search(
        r"\beval\s*\(",
        content,
        re.IGNORECASE
    ):

        add_finding(
            findings,
            "Dangerous JavaScript Function",
            "Medium",
            file_path,
            "The eval() function was detected.",
            "Avoid eval() when possible because it can execute dynamically supplied code."
        )


    # ------------------------------------------------
    # 4. innerHTML
    # ------------------------------------------------

    if re.search(
        r"\.innerHTML\s*=",
        content,
        re.IGNORECASE
    ):

        add_finding(
            findings,
            "Potential XSS Risk",
            "Medium",
            file_path,
            "Direct assignment to innerHTML was detected.",
            "Prefer safer DOM APIs such as textContent when inserting untrusted data."
        )


    # ------------------------------------------------
    # 5. Possible SQL Injection
    # ------------------------------------------------

    sql_pattern = re.compile(
        r"(SELECT|INSERT|UPDATE|DELETE)"
        r".*(\+|\$\{|%s)",
        re.IGNORECASE
    )

    if sql_pattern.search(content):

        add_finding(
            findings,
            "Possible SQL Injection Risk",
            "High",
            file_path,
            "Possible unsafe SQL query construction was detected.",
            "Use parameterized queries or prepared statements."
        )


    # ------------------------------------------------
    # 6. HTTP instead of HTTPS
    # ------------------------------------------------

    if re.search(
        r"http://",
        content,
        re.IGNORECASE
    ):

        add_finding(
            findings,
            "Insecure HTTP Reference",
            "Low",
            file_path,
            "An HTTP URL was detected instead of HTTPS.",
            "Use HTTPS for external resources and website communication."
        )


    # ------------------------------------------------
    # 7. Debug Mode
    # ------------------------------------------------

    if re.search(
        r"debug\s*=\s*True",
        content,
        re.IGNORECASE
    ):

        add_finding(
            findings,
            "Debug Mode Enabled",
            "Medium",
            file_path,
            "Debug mode appears to be enabled.",
            "Disable debug mode before deploying the website."
        )


    return findings


def scan_project(zip_path):

    temp_directory = tempfile.mkdtemp(
        prefix="codesecure_"
    )

    findings = []
    files_scanned = 0

    try:

        extract_zip_safely(
            zip_path,
            temp_directory
        )

        for root, directories, files in os.walk(
            temp_directory
        ):

            for filename in files:

                extension = os.path.splitext(
                    filename
                )[1].lower()

                if extension not in ALLOWED_EXTENSIONS:
                    continue

                file_path = os.path.join(
                    root,
                    filename
                )

                files_scanned += 1

                file_findings = scan_file(
                    file_path
                )

                findings.extend(
                    file_findings
                )


        return {
            "files_scanned": files_scanned,
            "findings": findings,
            "status": "success"
        }


    except Exception as error:

        return {
            "files_scanned": files_scanned,
            "findings": [],
            "status": "error",
            "error": str(error)
        }


    finally:

        shutil.rmtree(
            temp_directory,
            ignore_errors=True
        )