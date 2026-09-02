from flask import Flask, render_template, request, render_template_string
import os

from werkzeug.utils import secure_filename
from scanner import scan_project


app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"zip"}

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


def calculate_score(findings):
    score = 100

    for finding in findings:
        severity = finding.get("severity", "Low")

        if severity == "High":
            score -= 25
        elif severity == "Medium":
            score -= 15
        elif severity == "Low":
            score -= 5

    return max(score, 0)


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/upload", methods=["POST"])
def upload_file():

    if "project" not in request.files:
        return "No file selected."

    file = request.files["project"]

    if file.filename == "":
        return "No file selected."

    if not allowed_file(file.filename):
        return "Only ZIP files are allowed."

    filename = secure_filename(file.filename)

    filepath = os.path.join(
        app.config["UPLOAD_FOLDER"],
        filename
    )

    file.save(filepath)

    # Scan the uploaded project
    result = scan_project(filepath)

    if result["status"] != "success":
        return f"""
        <h2>Scan Error</h2>
        <p>{result.get("error", "Unknown error")}</p>
        <a href="/">Go Back</a>
        """

    findings = result["findings"]
    files_scanned = result["files_scanned"]

    score = calculate_score(findings)

    # Remove uploaded ZIP after scanning
    try:
        os.remove(filepath)
    except OSError:
        pass

    return render_template_string(
        RESULTS_PAGE,
        filename=filename,
        files_scanned=files_scanned,
        findings=findings,
        score=score
    )


RESULTS_PAGE = """
<!DOCTYPE html>
<html lang="en">

<head>

    <meta charset="UTF-8">

    <meta name="viewport"
          content="width=device-width, initial-scale=1.0">

    <title>CodeSecure - Security Report</title>

    <style>

        * {
            box-sizing: border-box;
        }

        body {
            margin: 0;
            font-family: Arial, sans-serif;
            background: #07111f;
            color: white;
        }

        .container {
            width: 90%;
            max-width: 1100px;
            margin: auto;
            padding: 40px 0;
        }

        .top {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 40px;
        }

        .logo {
            font-size: 24px;
            font-weight: bold;
        }

        .back {
            color: #9ca3af;
            text-decoration: none;
        }

        .hero {
            text-align: center;
            margin-bottom: 35px;
        }

        .hero h1 {
            font-size: 42px;
            margin-bottom: 10px;
        }

        .hero p {
            color: #9ca3af;
        }

        .score-card {
            background: #101d30;
            border: 1px solid #26364d;
            border-radius: 18px;
            padding: 35px;
            text-align: center;
            margin-bottom: 25px;
        }

        .score {
            font-size: 72px;
            font-weight: bold;
            margin: 10px;
        }

        .score-label {
            color: #9ca3af;
            font-size: 16px;
        }

        .stats {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 20px;
            margin-bottom: 25px;
        }

        .stat {
            background: #101d30;
            border: 1px solid #26364d;
            border-radius: 15px;
            padding: 25px;
        }

        .stat h3 {
            margin: 0 0 8px;
            font-size: 28px;
        }

        .stat p {
            margin: 0;
            color: #9ca3af;
        }

        .report {
            background: #101d30;
            border: 1px solid #26364d;
            border-radius: 18px;
            padding: 30px;
        }

        .report h2 {
            margin-top: 0;
        }

        .safe {
            padding: 25px;
            border-radius: 12px;
            background: #10251d;
            border: 1px solid #1d6b4a;
        }

        .finding {
            background: #0b1627;
            border: 1px solid #26364d;
            border-radius: 12px;
            padding: 20px;
            margin-top: 15px;
        }

        .finding-title {
            font-size: 19px;
            font-weight: bold;
        }

        .severity {
            display: inline-block;
            margin-top: 10px;
            padding: 5px 10px;
            border-radius: 6px;
            background: #402020;
            color: #ffb4b4;
            font-size: 13px;
        }

        .file {
            color: #8ab4f8;
            margin-top: 10px;
            word-break: break-all;
        }

        .message {
            color: #cbd5e1;
            margin-top: 10px;
        }

        @media(max-width: 700px) {

            .stats {
                grid-template-columns: 1fr;
            }

            .hero h1 {
                font-size: 32px;
            }

        }

    </style>

</head>


<body>

<div class="container">

    <div class="top">

        <div class="logo">
            🛡️ CodeSecure
        </div>

        <a class="back" href="/">
            ← Scan another project
        </a>

    </div>


    <div class="hero">

        <h1>Security Analysis Complete</h1>

        <p>
            Analysis report for <strong>{{ filename }}</strong>
        </p>

    </div>


    <div class="score-card">

        <div class="score">
            {{ score }}/100
        </div>

        <div class="score-label">
            Security Score
        </div>

    </div>


    <div class="stats">

        <div class="stat">

            <h3>
                {{ files_scanned }}
            </h3>

            <p>
                Files Scanned
            </p>

        </div>


        <div class="stat">

            <h3>
                {{ findings|length }}
            </h3>

            <p>
                Security Findings
            </p>

        </div>

    </div>


    <div class="report">

        <h2>
            🔍 Security Findings
        </h2>


        {% if findings %}

            {% for finding in findings %}

                <div class="finding">

                    <div class="finding-title">
                        {{ finding["type"] }}
                    </div>

                    <span class="severity">
                        {{ finding["severity"] }}
                    </span>

                    <div class="file">
                        📄 {{ finding["file"] }}
                    </div>

                    <div class="message">
                        {{ finding["message"] }}
                    </div>

                </div>

            {% endfor %}

        {% else %}

            <div class="safe">

                <h3>
                    ✅ No Critical Vulnerabilities Detected
                </h3>

                <p>
                    CodeSecure did not detect any of the
                    currently configured security patterns
                    in the analyzed files.
                </p>

            </div>

        {% endif %}

    </div>

</div>

</body>

</html>
"""


if __name__ == "__main__":
    app.run(debug=True)