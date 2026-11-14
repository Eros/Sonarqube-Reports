# SonarQube Report

Runs a SonarQube analysis on a project and writes the results to `sonar-report.md`.

## Requirements

- Python 3.9+
- A SonarQube server, either:
  - [Docker Desktop](https://www.docker.com/products/docker-desktop/) (the script runs `sonarqube:community` for you), or
  - the [SonarQube Community Build](https://www.sonarsource.com/products/sonarqube/downloads/) zip, unzipped, plus Java 17 or 21
- A scanner for your project type:
  - Gradle / Maven: nothing extra (uses the project's wrapper or `gradle`/`mvn` on PATH)
  - .NET / Unity: `dotnet tool install -g dotnet-sonarscanner`
  - Anything else: [sonar-scanner](https://docs.sonarsource.com/sonarqube-server/analyzing-source-code/scanners/sonarscanner/) on PATH, or Docker

## First run

1. Start the server: `python sonar_report.py <project> --start-server`

   This uses a local SonarQube install if it finds one, otherwise Docker. It looks for a `sonarqube*` folder
   next to the script, in your home, Downloads or Tools folder, or in `<drive>:\`, `<drive>:\Tools`,
   `<drive>:\Dev` and `<drive>:\Dev\Tools`. If yours is elsewhere, pass `--sonar-home`.
2. Open http://localhost:9000, log in with `admin` / `admin` and set a new password.
3. Create a token under **My Account → Security**.

## Usage

```
set SONAR_TOKEN=squ_...
python sonar_report.py <project>
```

| Option | Description |
|---|---|
| `--start-server` | Start SonarQube if it isn't running |
| `--sonar-home <dir>` | Local install to use (or set `SONAR_HOME`); auto-detected if omitted |
| `--build-args "<args>"` | Extra arguments for `dotnet build` |
| `--ignore-build-errors` | .NET only: finish the analysis even if a post-compile build step fails |
| `--docker` | Use Docker even if a local install is found |
| `--key <key>` | Project key (default: folder name) |
| `--min-severity <level>` | Hide issues below this level, e.g. `MEDIUM` |
| `--skip-scan` | Re-export the last analysis without scanning |
| `--out <file>` | Output file (default: `sonar-report.md` in the project folder) |
| `--host <url>` | Server URL (default: `http://localhost:9000`) |