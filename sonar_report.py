#!/usr/bin/env python3
"""Scan a project with a local SonarQube server and write the findings to Markdown.

Usage:
    python sonar_report.py [project_dir] --token squ_xxx
    python sonar_report.py . --start-server --min-severity MEDIUM
    python sonar_report.py . --skip-scan            # just re-export the last analysis
"""

import argparse
import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

GRADLE_PLUGIN_VERSION = "6.0.1.5171"
CONTAINER_NAME = "sonarqube-local"

# Covers both the legacy (MAJOR/MINOR/CRITICAL) and the newer impact-based (HIGH/MEDIUM/LOW) scales.
SEVERITY_RANK = {
    "BLOCKER": 5,
    "CRITICAL": 4, "HIGH": 4,
    "MAJOR": 3, "MEDIUM": 3,
    "MINOR": 2, "LOW": 2,
    "INFO": 1,
}
SEVERITY_ICON = {5: "🟥", 4: "🟧", 3: "🟨", 2: "🟦", 1: "⬜"}

METRICS = [
    ("ncloc", "Lines of code"),
    ("bugs", "Bugs"),
    ("vulnerabilities", "Vulnerabilities"),
    ("code_smells", "Code smells"),
    ("security_hotspots", "Security hotspots"),
    ("coverage", "Coverage %"),
    ("duplicated_lines_density", "Duplication %"),
]


class Sonar:
    def __init__(self, host, token):
        self.host = host.rstrip("/")
        self.auth = "Basic " + base64.b64encode(f"{token}:".encode()).decode() if token else None

    def get(self, path, **params):
        url = path if path.startswith("http") else f"{self.host}{path}"
        if params:
            url += "?" + urllib.parse.urlencode(params)
        req = urllib.request.Request(url)
        if self.auth:
            req.add_header("Authorization", self.auth)
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.load(resp)

    def is_up(self):
        try:
            return self.get("/api/system/status").get("status") == "UP"
        except (urllib.error.URLError, OSError, ValueError):
            return False


def run(cmd, cwd):
    print("$", " ".join(str(c) for c in cmd), flush=True)
    subprocess.run([str(c) for c in cmd], cwd=cwd, check=True)


def start_server(sonar):
    if sonar.is_up():
        return
    if not shutil.which("docker"):
        sys.exit("SonarQube isn't reachable and docker isn't on PATH.")
    if subprocess.run(["docker", "info"], capture_output=True).returncode != 0:
        sys.exit("Docker is installed but its engine isn't running. Start Docker Desktop, "
                 "wait for it to say 'Engine running', then try again.")
    existing = subprocess.run(["docker", "ps", "-aq", "-f", f"name=^{CONTAINER_NAME}$"],
                              capture_output=True, text=True).stdout.strip()
    if existing:
        subprocess.run(["docker", "start", CONTAINER_NAME], check=True)
    else:
        subprocess.run(["docker", "run", "-d", "--name", CONTAINER_NAME, "-p", "9000:9000",
                        "sonarqube:community"], check=True)
    print("Waiting for SonarQube to come up", end="", flush=True)
    for _ in range(180):
        if sonar.is_up():
            print(" ready.")
            return
        print(".", end="", flush=True)
        time.sleep(2)
    sys.exit("\nSonarQube didn't start within 6 minutes; check `docker logs sonarqube-local`.")


def scan(project, key, host, token):
    props = {"sonar.projectKey": key, "sonar.host.url": host, "sonar.token": token}

    gradle_files = [project / f for f in ("build.gradle", "build.gradle.kts")]
    if any(f.exists() for f in gradle_files):
        wrapper = project / ("gradlew.bat" if os.name == "nt" else "gradlew")
        gradle = str(wrapper) if wrapper.exists() else shutil.which("gradle")
        if not gradle:
            sys.exit("Gradle project but no gradlew or gradle on PATH.")
        cmd = [gradle, "classes", "sonar", *(f"-D{k}={v}" for k, v in props.items())]
        already_applied = any(f.exists() and "org.sonarqube" in f.read_text(errors="ignore")
                              for f in gradle_files)
        if already_applied:
            run(cmd, project)
            return
        # Apply the plugin via an init script so the build files stay untouched.
        init = tempfile.NamedTemporaryFile("w", suffix=".gradle", delete=False)
        init.write(
            "initscript {\n"
            "    repositories { gradlePluginPortal() }\n"
            f'    dependencies {{ classpath "org.sonarsource.scanner.gradle:sonarqube-gradle-plugin:{GRADLE_PLUGIN_VERSION}" }}\n'
            "}\n"
            "rootProject { apply plugin: org.sonarqube.gradle.SonarQubePlugin }\n"
        )
        init.close()
        try:
            run([*cmd, "--init-script", init.name], project)
        finally:
            os.unlink(init.name)
        return

    if (project / "pom.xml").exists():
        wrapper = project / ("mvnw.cmd" if os.name == "nt" else "mvnw")
        mvn = str(wrapper) if wrapper.exists() else shutil.which("mvn")
        if not mvn:
            sys.exit("Maven project but no mvnw or mvn on PATH.")
        run([mvn, "-B", "compile", "org.sonarsource.scanner.maven:sonar-maven-plugin:sonar",
             *(f"-D{k}={v}" for k, v in props.items())], project)
        return

    solutions = sorted(project.glob("*.sln")) + sorted(project.glob("*.slnx"))
    if solutions:
        scanner = [shutil.which("dotnet-sonarscanner")] if shutil.which("dotnet-sonarscanner") \
            else ["dotnet", "sonarscanner"]
        run([*scanner, "begin", f"/k:{key}", f"/d:sonar.host.url={host}", f"/d:sonar.token={token}"], project)
        run(["dotnet", "build", solutions[0], "--no-incremental"], project)
        run([*scanner, "end", f"/d:sonar.token={token}"], project)
        return

    flags = [*(f"-D{k}={v}" for k, v in props.items()), "-Dsonar.sources=."]
    if shutil.which("sonar-scanner"):
        run(["sonar-scanner", *flags], project)
    elif shutil.which("docker"):
        # From inside a container, "localhost" is the container itself.
        docker_host = host.replace("localhost", "host.docker.internal").replace("127.0.0.1", "host.docker.internal")
        flags = [f.replace(host, docker_host) for f in flags]
        run(["docker", "run", "--rm", "--add-host=host.docker.internal:host-gateway",
             "-v", f"{project}:/usr/src", "sonarsource/sonar-scanner-cli", *flags], project)
    else:
        sys.exit("No Gradle/Maven/.sln found and neither sonar-scanner nor docker is available.")


def find_report_task(project, since):
    candidates = [
        project / "build/sonar/report-task.txt",
        project / "target/sonar/report-task.txt",
        project / ".sonarqube/out/.sonar/report-task.txt",
        project / ".scannerwork/report-task.txt",
    ]
    found = [p for p in candidates if p.exists()] or list(project.rglob("report-task.txt"))
    found = [p for p in found if p.stat().st_mtime >= since - 5]
    return max(found, key=lambda p: p.stat().st_mtime) if found else None


def wait_for_processing(sonar, report_task):
    props = dict(line.split("=", 1) for line in report_task.read_text().splitlines() if "=" in line)
    url = props.get("ceTaskUrl")
    if not url:
        return
    print("Waiting for the server to process the analysis", end="", flush=True)
    for _ in range(300):
        status = sonar.get(url)["task"]["status"]
        if status == "SUCCESS":
            print(" done.")
            return
        if status in ("FAILED", "CANCELED"):
            sys.exit(f"\nServer-side processing {status.lower()}; see {url}")
        print(".", end="", flush=True)
        time.sleep(2)
    sys.exit("\nTimed out waiting for the analysis to be processed.")


def paged(sonar, path, list_key, **params):
    items, extra, page = [], defaultdict(list), 1
    while True:
        data = sonar.get(path, p=page, ps=500, **params)
        items += data.get(list_key, [])
        for k in ("rules", "components"):
            extra[k] += data.get(k, [])
        total = data.get("paging", {}).get("total", data.get("total", 0))
        # The API refuses to page past 10k results.
        if page * 500 >= min(total, 10_000):
            return items, extra
        page += 1


def classify(issue):
    impacts = issue.get("impacts")
    if impacts:
        worst = max(impacts, key=lambda i: SEVERITY_RANK.get(i["severity"], 0))
        qualities = ", ".join(i["softwareQuality"].title() for i in impacts)
        return worst["severity"], qualities
    return issue.get("severity", "INFO"), issue.get("type", "").replace("_", " ").title()


def file_of(component, key):
    return component.split(":", 1)[1] if component.startswith(key + ":") else component


def md_escape(text):
    return text.replace("|", "\\|").replace("\n", " ")


def build_report(sonar, key, min_rank):
    issues, extra = paged(sonar, "/api/issues/search", "issues",
                          componentKeys=key, resolved="false", additionalFields="rules")
    rule_names = {r["key"]: r["name"] for r in extra["rules"]}
    try:
        hotspots, _ = paged(sonar, "/api/hotspots/search", "hotspots", projectKey=key, status="TO_REVIEW")
    except urllib.error.HTTPError:
        hotspots = []
    try:
        gate = sonar.get("/api/qualitygates/project_status", projectKey=key)["projectStatus"]["status"]
    except urllib.error.HTTPError:
        gate = "UNKNOWN"
    try:
        measures = {m["metric"]: m.get("value", "–") for m in sonar.get(
            "/api/measures/component", component=key,
            metricKeys=",".join(m for m, _ in METRICS))["component"]["measures"]}
    except urllib.error.HTTPError:
        measures = {}

    rows = []
    for issue in issues:
        severity, quality = classify(issue)
        rank = SEVERITY_RANK.get(severity, 0)
        if rank < min_rank:
            continue
        rows.append({
            "file": file_of(issue["component"], key),
            "line": issue.get("line") or issue.get("textRange", {}).get("startLine") or 0,
            "severity": severity,
            "rank": rank,
            "quality": quality,
            "rule": issue["rule"],
            "message": issue.get("message", ""),
            "effort": issue.get("effort", ""),
        })

    out = [f"# SonarQube report: `{key}`", "",
           f"Generated {datetime.now():%Y-%m-%d %H:%M} from {sonar.host}  ",
           f"Quality gate: **{gate}**", ""]

    if measures:
        out += ["| Metric | Value |", "|---|---|"]
        out += [f"| {label} | {measures[m]} |" for m, label in METRICS if m in measures]
        out.append("")

    out += [f"## Summary: {len(rows)} open issues", ""]
    if rows:
        by_sev = Counter(r["severity"] for r in rows)
        out += ["| Severity | Count |", "|---|---|"]
        for sev, n in sorted(by_sev.items(), key=lambda kv: -SEVERITY_RANK.get(kv[0], 0)):
            out.append(f"| {SEVERITY_ICON.get(SEVERITY_RANK.get(sev, 1), '')} {sev} | {n} |")
        out.append("")

        out += ["### Most frequent rules", "", "| Rule | Name | Count |", "|---|---|---|"]
        for rule, n in Counter(r["rule"] for r in rows).most_common(15):
            out.append(f"| [`{rule}`]({sonar.host}/coding_rules?open={urllib.parse.quote(rule)}) "
                       f"| {md_escape(rule_names.get(rule, ''))} | {n} |")
        out.append("")

        out += ["## Issues by file", ""]
        by_file = defaultdict(list)
        for r in rows:
            by_file[r["file"]].append(r)
        ordered = sorted(by_file.items(), key=lambda kv: (-max(r["rank"] for r in kv[1]), kv[0]))
        for path, file_rows in ordered:
            out += [f"### `{path}` ({len(file_rows)})", ""]
            for r in sorted(file_rows, key=lambda r: (r["line"], -r["rank"])):
                effort = f" · {r['effort']}" if r["effort"] else ""
                out.append(f"- [ ] L{r['line']} {SEVERITY_ICON.get(r['rank'], '')} **{r['severity']}** "
                           f"{r['quality']}: {md_escape(r['message'])} (`{r['rule']}`{effort})")
            out.append("")

    if hotspots:
        out += [f"## Security hotspots to review ({len(hotspots)})", ""]
        for h in sorted(hotspots, key=lambda h: (h.get("component", ""), h.get("line", 0))):
            out.append(f"- [ ] `{file_of(h['component'], key)}` L{h.get('line', 0)} "
                       f"**{h.get('vulnerabilityProbability', '?')}** {h.get('securityCategory', '')}: "
                       f"{md_escape(h.get('message', ''))} (`{h.get('ruleKey', '')}`)")
        out.append("")

    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description="Run a SonarQube scan and write the results as Markdown.")
    ap.add_argument("project", nargs="?", default=".", help="project directory (default: current)")
    ap.add_argument("--key", help="SonarQube project key (default: directory name)")
    ap.add_argument("--host", default=os.environ.get("SONAR_HOST_URL", "http://localhost:9000"))
    ap.add_argument("--token", default=os.environ.get("SONAR_TOKEN"), help="user token (or SONAR_TOKEN env)")
    ap.add_argument("--out", default="sonar-report.md")
    ap.add_argument("--min-severity", default="INFO", type=str.upper, choices=sorted(SEVERITY_RANK))
    ap.add_argument("--skip-scan", action="store_true", help="only export the latest analysis")
    ap.add_argument("--start-server", action="store_true", help="start a local SonarQube container if needed")
    args = ap.parse_args()

    project = Path(args.project).resolve()
    key = args.key or "".join(c if c.isalnum() or c in "-_.:" else "-" for c in project.name)
    sonar = Sonar(args.host, args.token)

    if args.start_server:
        start_server(sonar)
    elif not sonar.is_up():
        sys.exit(f"SonarQube isn't reachable at {args.host} (use --start-server to launch it in Docker).")

    if not args.token:
        sys.exit("No token. Log in at the server (admin/admin on first run), create one under "
                 "My Account > Security, then pass --token or set SONAR_TOKEN.")

    if not args.skip_scan:
        started = time.time()
        scan(project, key, args.host, args.token)
        report_task = find_report_task(project, started)
        if report_task:
            wait_for_processing(sonar, report_task)
        else:
            print("Couldn't find report-task.txt; waiting 15s and hoping processing is done.")
            time.sleep(15)

    try:
        report = build_report(sonar, key, SEVERITY_RANK[args.min_severity])
    except urllib.error.HTTPError as e:
        sys.exit(f"API error {e.code} from {e.url}: {e.read().decode(errors='ignore')[:300]}")

    out = Path(args.out)
    if not out.is_absolute():
        out = project / out
    out.write_text(report, encoding="utf-8")
    print(f"Wrote {out}")


if __name__ == "__main__":
    main()