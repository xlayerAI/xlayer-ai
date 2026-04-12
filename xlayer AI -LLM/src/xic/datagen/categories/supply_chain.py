"""
Supply Chain Security generator.
Produces dependency analysis, SBOM review, CI/CD security, and container image entries.
"""

import random
from typing import List, Dict, Any
from ..templates import CategoryGenerator, pick_complexity, pick_severity, format_entry, rand_ip, rand_domain, rand_port, rand_var_name, rand_func_name, rand_table_name, rand_path
from ..knowledge_base import CWE_DB, OWASP_TOP10, MITRE_ATTACK, APP_CONTEXTS, PRODUCTS, CLOUD_SERVICES, FRAMEWORKS, PROTOCOLS


# ── Instruction pools ──────────────────────────────────────────────────────────

DEPENDENCY_INSTRUCTIONS = [
    "Analyze the following dependency manifest for supply chain security risks. Identify vulnerable, outdated, or suspicious packages.",
    "Review this project's dependency file for potential supply chain attack vectors including typosquatting, dependency confusion, and known vulnerabilities.",
    "Perform a software composition analysis (SCA) on the following dependency list. Flag any packages with known CVEs, abandoned maintenance, or suspicious characteristics.",
    "Evaluate the supply chain risk of the packages in this manifest. Consider maintainer trust, download statistics, and version pinning practices.",
    "As a security engineer, audit the following dependency configuration. Identify risks related to unpinned versions, transitive dependencies, and package integrity.",
]

SBOM_INSTRUCTIONS = [
    "Generate a security assessment based on the following Software Bill of Materials (SBOM). Identify components with known vulnerabilities and license risks.",
    "Review this SBOM for compliance with supply chain security best practices. Check for outdated components, missing integrity hashes, and license conflicts.",
    "Analyze the following SBOM in CycloneDX format. Identify high-risk components and recommend a remediation plan.",
    "Evaluate this software inventory for supply chain security posture. Flag components that require updates, have reached end-of-life, or lack provenance information.",
]

CICD_INSTRUCTIONS = [
    "Review the following CI/CD pipeline configuration for security weaknesses. Identify risks in build steps, secret handling, and artifact integrity.",
    "Audit this GitHub Actions / GitLab CI workflow for supply chain security issues. Check for untrusted actions, secret exposure, and missing verification steps.",
    "Analyze this CI/CD pipeline definition for build system integrity risks. Look for injection points, privilege escalation, and missing artifact signing.",
    "Evaluate the security of this continuous integration configuration. Identify where an attacker could inject malicious code or compromise build artifacts.",
    "Perform a security review of this deployment pipeline. Check for insecure practices in dependency installation, testing, and artifact publishing.",
]

CONTAINER_INSTRUCTIONS = [
    "Analyze the following Dockerfile for supply chain and security risks. Check base image provenance, layer optimization, and secret handling.",
    "Review this container image configuration for supply chain security concerns. Evaluate base image trust, package installation practices, and runtime security.",
    "Audit this Dockerfile for security best practices. Identify issues with user privileges, exposed ports, and dependency management.",
    "Perform a container security assessment on this Dockerfile. Check for image provenance, vulnerability scanning integration, and least-privilege compliance.",
]

LOCKFILE_INSTRUCTIONS = [
    "Analyze the following lock file for integrity and supply chain security. Check for unexpected changes, hash mismatches, and suspicious registry sources.",
    "Review this lock file diff for signs of supply chain compromise. Look for new or modified packages that could indicate dependency confusion or hijacking.",
]

CODE_SIGNING_INSTRUCTIONS = [
    "Evaluate the code signing and artifact verification practices described in this configuration. Identify gaps in the software supply chain trust model.",
    "Review the following release and signing configuration for weaknesses. Check key management, signature verification, and distribution integrity.",
]

ALL_INSTRUCTIONS = (
    DEPENDENCY_INSTRUCTIONS + SBOM_INSTRUCTIONS + CICD_INSTRUCTIONS +
    CONTAINER_INSTRUCTIONS + LOCKFILE_INSTRUCTIONS + CODE_SIGNING_INSTRUCTIONS
)

# ── Package templates ──────────────────────────────────────────────────────────

NPM_PACKAGES_LEGIT = [
    ("express", "4.18.2"), ("lodash", "4.17.21"), ("axios", "1.4.0"),
    ("react", "18.2.0"), ("mongoose", "7.3.1"), ("jsonwebtoken", "9.0.1"),
    ("bcrypt", "5.1.0"), ("cors", "2.8.5"), ("dotenv", "16.3.1"),
    ("helmet", "7.0.0"), ("morgan", "1.10.0"), ("multer", "1.4.5-lts.1"),
    ("winston", "3.10.0"), ("uuid", "9.0.0"), ("validator", "13.11.0"),
    ("sequelize", "6.32.1"), ("pg", "8.11.1"), ("redis", "4.6.7"),
    ("socket.io", "4.7.1"), ("passport", "0.6.0"),
]

NPM_PACKAGES_SUSPICIOUS = [
    ("expresss", "4.18.2", "Typosquatting of 'express' - extra 's'"),
    ("lodassh", "4.17.21", "Typosquatting of 'lodash' - extra 's'"),
    ("axois", "1.4.0", "Typosquatting of 'axios' - transposed letters"),
    ("react-dev-utils-2", "12.0.0", "Suspicious fork of legitimate react-dev-utils"),
    ("colors-js", "1.4.1", "Namespace confusion with legitimate 'colors' package"),
    ("event-stream-4", "4.0.1", "Suspicious fork referencing compromised event-stream"),
    ("crossenv", "7.0.3", "Typosquatting of 'cross-env' - missing hyphen"),
    ("babelcli", "6.26.0", "Typosquatting of 'babel-cli' - missing hyphen"),
    ("node-fabric", "1.0.0", "Name confusion with legitimate fabric package"),
    ("http-proxy-agnt", "5.0.0", "Typosquatting of 'http-proxy-agent' - truncated"),
]

PIP_PACKAGES_LEGIT = [
    ("django", "4.2.3"), ("flask", "2.3.2"), ("requests", "2.31.0"),
    ("sqlalchemy", "2.0.19"), ("celery", "5.3.1"), ("boto3", "1.28.9"),
    ("cryptography", "41.0.2"), ("pyjwt", "2.8.0"), ("pillow", "10.0.0"),
    ("gunicorn", "21.2.0"), ("psycopg2-binary", "2.9.6"), ("redis", "4.6.0"),
    ("fastapi", "0.100.0"), ("uvicorn", "0.23.1"), ("pydantic", "2.1.1"),
    ("httpx", "0.24.1"), ("python-dotenv", "1.0.0"), ("pytest", "7.4.0"),
]

PIP_PACKAGES_SUSPICIOUS = [
    ("djnago", "4.2.3", "Typosquatting of 'django' - transposed letters"),
    ("python-requests", "2.31.0", "Namespace confusion with 'requests'"),
    ("python3-dateutil", "2.8.2", "Typosquatting of 'python-dateutil' - added '3'"),
    ("flassk", "2.3.2", "Typosquatting of 'flask' - extra 's'"),
    ("crypt0graphy", "41.0.0", "Typosquatting of 'cryptography' - zero substitution"),
    ("boto4", "1.0.0", "Dependency confusion targeting internal 'boto4' package"),
    ("colourama", "0.4.6", "Typosquatting of 'colorama' - British spelling variant"),
    ("reqeusts", "2.31.0", "Typosquatting of 'requests' - transposed letters"),
]

# ── Scenario generators ────────────────────────────────────────────────────────

def _gen_package_json(rng, include_suspicious=False):
    """Generate a realistic package.json snippet."""
    num_deps = rng.randint(6, 12)
    deps = rng.sample(NPM_PACKAGES_LEGIT, min(num_deps, len(NPM_PACKAGES_LEGIT)))

    suspicious_items = []
    if include_suspicious:
        num_sus = rng.randint(1, 3)
        suspicious_items = rng.sample(NPM_PACKAGES_SUSPICIOUS, num_sus)

    lines = ['{\n  "name": "' + rng.choice(["my-app", "web-service", "api-server", "backend", "platform"]) + '",']
    lines.append('  "version": "1.0.0",')
    lines.append('  "dependencies": {')

    all_deps = [(n, v) for n, v in deps]
    for name, ver, _ in suspicious_items:
        all_deps.append((name, ver))
    rng.shuffle(all_deps)

    dep_lines = []
    for name, ver in all_deps:
        pin = rng.choice(["^", "~", ">=", ""])
        dep_lines.append(f'    "{name}": "{pin}{ver}"')
    lines.append(",\n".join(dep_lines))

    lines.append("  },")
    lines.append('  "devDependencies": {')
    dev_deps = [
        ('"jest"', '"29.6.1"'), ('"eslint"', '"8.45.0"'),
        ('"nodemon"', '"3.0.1"'), ('"typescript"', '"5.1.6"'),
    ]
    dev_lines = [f'    {n}: {v}' for n, v in rng.sample(dev_deps, rng.randint(2, 4))]
    lines.append(",\n".join(dev_lines))
    lines.append("  }")
    lines.append("}")

    return "\n".join(lines), suspicious_items


def _gen_requirements_txt(rng, include_suspicious=False):
    """Generate a realistic requirements.txt snippet."""
    num_deps = rng.randint(6, 12)
    deps = rng.sample(PIP_PACKAGES_LEGIT, min(num_deps, len(PIP_PACKAGES_LEGIT)))

    suspicious_items = []
    if include_suspicious:
        num_sus = rng.randint(1, 3)
        suspicious_items = rng.sample(PIP_PACKAGES_SUSPICIOUS, num_sus)

    lines = []
    all_deps = list(deps)
    for name, ver, _ in suspicious_items:
        all_deps.append((name, ver))
    rng.shuffle(all_deps)

    for name, ver in all_deps:
        pin_style = rng.choice(["==", ">=", "~=", ""])
        if pin_style:
            lines.append(f"{name}{pin_style}{ver}")
        else:
            lines.append(name)

    return "\n".join(lines), suspicious_items


def _gen_dockerfile(rng, risky=False):
    """Generate a realistic Dockerfile snippet."""
    base_images_safe = [
        "python:3.11-slim", "node:20-alpine", "golang:1.21-alpine",
        "ruby:3.2-slim", "openjdk:17-slim", "rust:1.71-slim",
    ]
    base_images_risky = [
        "python:latest", "node:latest", "ubuntu:latest",
        "centos:7", "php:7.4", "nginx:latest",
    ]

    base = rng.choice(base_images_risky if risky else base_images_safe)
    app_name = rng.choice(["app", "service", "api", "backend", "worker"])

    lines = [f"FROM {base}"]

    issues = []

    if risky and rng.random() < 0.5:
        lines.append("")
        lines.append("# Install dependencies as root")
        issues.append("Running as root - no USER instruction to drop privileges")
    else:
        lines.append("")
        lines.append("RUN addgroup --system appgroup && adduser --system --ingroup appgroup appuser")

    lines.append(f"WORKDIR /{app_name}")
    lines.append("")

    if "python" in base:
        lines.append("COPY requirements.txt .")
        if risky and rng.random() < 0.6:
            lines.append("RUN pip install -r requirements.txt")
            issues.append("pip install without --no-cache-dir wastes image space and may cache sensitive data")
        else:
            lines.append("RUN pip install --no-cache-dir -r requirements.txt")
        lines.append("COPY . .")
    elif "node" in base:
        lines.append("COPY package*.json ./")
        if risky and rng.random() < 0.6:
            lines.append("RUN npm install")
            issues.append("Using 'npm install' instead of 'npm ci' - does not guarantee reproducible builds")
        else:
            lines.append("RUN npm ci --only=production")
        lines.append("COPY . .")
    else:
        lines.append("COPY . .")
        lines.append("RUN make build")

    if risky and rng.random() < 0.5:
        secret_val = rng.choice(["DB_PASSWORD", "API_KEY", "SECRET_KEY", "AWS_SECRET_ACCESS_KEY"])
        lines.append(f'ENV {secret_val}="placeholder_change_me"')
        issues.append(f"Secret ({secret_val}) embedded as ENV in Dockerfile - visible in image history")

    if risky and rng.random() < 0.4:
        lines.append("COPY .env /app/.env")
        issues.append(".env file copied into container image - may contain production secrets")

    ports = rng.sample([80, 443, 3000, 5000, 8000, 8080], rng.randint(1, 2))
    for p in ports:
        lines.append(f"EXPOSE {p}")

    if risky and rng.random() < 0.4:
        lines.append(f'CMD ["{app_name}"]')
    else:
        if "python" in base:
            lines.append('CMD ["gunicorn", "--bind", "0.0.0.0:8000", "app:app"]')
        elif "node" in base:
            lines.append('CMD ["node", "server.js"]')
        else:
            lines.append(f'CMD ["./{app_name}"]')

    if not risky or rng.random() < 0.3:
        lines.append("USER appuser")
    else:
        if "Running as root" not in str(issues):
            issues.append("No USER instruction - container runs as root by default")

    return "\n".join(lines), issues


def _gen_cicd_config(rng, risky=False):
    """Generate a CI/CD pipeline configuration snippet."""
    platform = rng.choice(["github_actions", "gitlab_ci"])
    issues = []

    if platform == "github_actions":
        lines = ["name: CI/CD Pipeline", "on:", "  push:", '    branches: ["main"]', "  pull_request:", "", "jobs:", "  build:", '    runs-on: ubuntu-latest', "    steps:"]

        lines.append("      - uses: actions/checkout@v3")

        if risky and rng.random() < 0.5:
            untrusted_action = rng.choice([
                "random-user/deploy-action@main",
                "some-org/build-tool@master",
                "community-tools/cache-helper@latest",
            ])
            lines.append(f"      - uses: {untrusted_action}")
            issues.append(f"Untrusted third-party action '{untrusted_action}' pinned to branch instead of SHA - vulnerable to tag/branch hijacking")

        lang = rng.choice(["node", "python", "go"])
        if lang == "node":
            lines.append("      - uses: actions/setup-node@v3")
            lines.append("        with:")
            lines.append("          node-version: '20'")
            if risky and rng.random() < 0.5:
                lines.append("      - run: npm install")
                issues.append("Using 'npm install' instead of 'npm ci' in CI - non-reproducible builds")
            else:
                lines.append("      - run: npm ci")
            lines.append("      - run: npm test")
            lines.append("      - run: npm run build")
        elif lang == "python":
            lines.append("      - uses: actions/setup-python@v4")
            lines.append("        with:")
            lines.append("          python-version: '3.11'")
            lines.append("      - run: pip install -r requirements.txt")
            lines.append("      - run: pytest")

        if risky and rng.random() < 0.5:
            lines.append("      - run: echo ${{ github.event.pull_request.title }}")
            issues.append("PR title injected directly into shell command - vulnerable to command injection via crafted PR title")

        if risky and rng.random() < 0.5:
            lines.append("      - name: Deploy")
            lines.append("        run: |")
            lines.append("          curl -X POST https://deploy.example.com/trigger \\")
            lines.append(f"            -H 'Authorization: Bearer ${{{{ secrets.DEPLOY_TOKEN }}}}' \\")
            lines.append("            -d '{\"ref\": \"main\"}'")
            lines.append("        env:")
            lines.append("          DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}")
        elif risky and rng.random() < 0.5:
            lines.append("      - name: Deploy")
            lines.append('        run: echo "deploying..." && ./deploy.sh')
            lines.append("        env:")
            secret_name = rng.choice(["AWS_ACCESS_KEY_ID", "DOCKER_PASSWORD", "NPM_TOKEN"])
            lines.append(f"          {secret_name}: ${{{{ secrets.{secret_name} }}}}")

        if risky and rng.random() < 0.4:
            lines.append("")
            lines.append("  publish:")
            lines.append("    runs-on: ubuntu-latest")
            lines.append("    needs: build")
            lines.append("    permissions:")
            lines.append("      contents: write")
            lines.append("      packages: write")
            lines.append("      id-token: write")
            issues.append("Overly broad permissions granted - packages:write and id-token:write may not be needed")

        config_text = "\n".join(lines)
    else:
        lines = ["stages:", "  - build", "  - test", "  - deploy", ""]
        lines.append("build:")
        lines.append("  stage: build")
        lines.append(f"  image: {rng.choice(['node:20', 'python:3.11', 'golang:1.21'])}")
        lines.append("  script:")
        lines.append("    - echo 'Building...'")

        if risky and rng.random() < 0.5:
            lines.append(f"    - echo $CI_REGISTRY_PASSWORD | docker login -u $CI_REGISTRY_USER --password-stdin $CI_REGISTRY")
            issues.append("Registry credentials passed via environment variable in script - may appear in job logs")

        lines.append("    - make build")
        lines.append("")
        lines.append("test:")
        lines.append("  stage: test")
        lines.append("  script:")
        lines.append("    - make test")
        lines.append("")
        lines.append("deploy:")
        lines.append("  stage: deploy")
        lines.append("  script:")
        lines.append("    - make deploy")

        if risky and rng.random() < 0.5:
            lines.append("  only:")
            lines.append("    - main")
        else:
            lines.append("  rules:")
            lines.append('    - if: $CI_COMMIT_BRANCH == "main"')

        if risky and rng.random() < 0.4:
            lines.append("  environment:")
            lines.append("    name: production")
            issues.append("No manual approval gate for production deployment - any merge to main auto-deploys")

        config_text = "\n".join(lines)

    return config_text, issues, platform


# ── Entry generators ────────────────────────────────────────────────────────────

def _generate_dependency_entry(rng, complexity, idx, prefix):
    """Generate a dependency analysis entry."""
    severity = pick_severity(rng, complexity)
    is_npm = rng.random() < 0.5
    include_sus = complexity in ("intermediate", "advanced", "expert")

    if is_npm:
        manifest, suspicious = _gen_package_json(rng, include_suspicious=include_sus)
        ecosystem = "npm"
        manifest_name = "package.json"
    else:
        manifest, suspicious = _gen_requirements_txt(rng, include_suspicious=include_sus)
        ecosystem = "PyPI"
        manifest_name = "requirements.txt"

    app_context = rng.choice(APP_CONTEXTS)
    input_text = f"**Project:** {app_context.title()}\n"
    input_text += f"**Ecosystem:** {ecosystem}\n"
    input_text += f"**File:** {manifest_name}\n\n"
    input_text += f"```\n{manifest}\n```"

    output = f"## Supply Chain Security Analysis: {manifest_name}\n\n"
    output += f"**Ecosystem:** {ecosystem}\n"
    output += f"**Project Context:** {app_context}\n\n"

    # Suspicious packages
    if suspicious:
        output += "### CRITICAL: Suspicious Packages Detected\n\n"
        for name, ver, reason in suspicious:
            output += f"**{name}@{ver}**\n"
            output += f"- **Risk:** {reason}\n"
            output += f"- **Action:** Remove immediately and investigate how it was introduced\n"
            output += f"- **CWE:** CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)\n\n"

    # Version pinning analysis
    output += "### Version Pinning Analysis\n\n"
    pinning_issues = [
        "Packages using '^' or '~' prefix allow automatic minor/patch updates that could introduce vulnerabilities",
        "Packages without version pins will resolve to latest, making builds non-reproducible",
        "Consider using exact version pins (==) or a lock file for reproducible builds",
    ]
    for issue in rng.sample(pinning_issues, rng.randint(1, 2)):
        output += f"- {issue}\n"
    output += "\n"

    # General recommendations
    output += "### Supply Chain Security Recommendations\n\n"
    recommendations = [
        "Enable dependency lock files (package-lock.json / requirements.txt with hashes) and commit them to version control",
        "Configure automated vulnerability scanning (Dependabot, Snyk, or Renovate) for all dependencies",
        "Implement a private registry or proxy (Artifactory, Nexus) to control package sources",
        "Enable Subresource Integrity (SRI) checks for CDN-loaded scripts",
        "Pin dependencies to exact versions and use hash verification where supported",
        "Review new dependencies before adoption: check maintainer reputation, download counts, and age",
        "Set up namespace reservation in private registries to prevent dependency confusion",
        f"Run {'npm audit' if ecosystem == 'npm' else 'pip-audit / safety check'} in CI/CD pipeline before deployment",
        "Generate and maintain SBOM (Software Bill of Materials) for compliance and audit",
        "Monitor package registries for typosquatting variants of your internal package names",
    ]
    for j, rec in enumerate(rng.sample(recommendations, rng.randint(5, 8)), 1):
        output += f"{j}. {rec}\n"

    cwe_id = rng.choice(["CWE-829", "CWE-345", "CWE-426", "CWE-502"])
    return format_entry(
        entry_id=f"{prefix}-{idx:05d}",
        title=f"Dependency Analysis: {ecosystem} - {app_context.title()}",
        severity=severity,
        cwe=cwe_id,
        instruction=rng.choice(DEPENDENCY_INSTRUCTIONS),
        input_text=input_text,
        output_text=output,
    )


def _generate_cicd_entry(rng, complexity, idx, prefix):
    """Generate a CI/CD pipeline security entry."""
    severity = pick_severity(rng, complexity)
    risky = complexity in ("intermediate", "advanced", "expert")
    config, issues, platform = _gen_cicd_config(rng, risky=risky)

    platform_name = "GitHub Actions" if platform == "github_actions" else "GitLab CI"
    app_context = rng.choice(APP_CONTEXTS)

    input_text = f"**Project:** {app_context.title()}\n"
    input_text += f"**CI/CD Platform:** {platform_name}\n\n"
    input_text += f"```yaml\n{config}\n```"

    output = f"## CI/CD Pipeline Security Review: {platform_name}\n\n"
    output += f"**Project:** {app_context}\n\n"

    if issues:
        output += "### Security Issues Found\n\n"
        for i, issue in enumerate(issues, 1):
            issue_severity = rng.choice(["High", "Critical"]) if "injection" in issue.lower() or "secret" in issue.lower() else rng.choice(["Medium", "High"])
            output += f"**Issue {i} [{issue_severity}]:** {issue}\n\n"

            # Generate remediation per issue
            if "untrusted" in issue.lower() or "action" in issue.lower():
                output += "**Remediation:** Pin actions to a specific commit SHA instead of a mutable tag/branch. "
                output += "Example: `uses: actions/checkout@abc123def456` instead of `@v3`.\n\n"
            elif "npm install" in issue.lower():
                output += "**Remediation:** Replace `npm install` with `npm ci` to ensure the build uses the exact versions from package-lock.json.\n\n"
            elif "injection" in issue.lower():
                output += "**Remediation:** Never interpolate untrusted data directly into shell commands. "
                output += "Use an intermediate environment variable or a dedicated action for input sanitization.\n\n"
            elif "permission" in issue.lower():
                output += "**Remediation:** Follow the principle of least privilege. Only grant the permissions each job actually needs.\n\n"
            elif "secret" in issue.lower() or "credential" in issue.lower():
                output += "**Remediation:** Use native secret management features. Avoid echoing or logging secrets. Consider using OIDC for cloud authentication.\n\n"
            elif "approval" in issue.lower() or "manual" in issue.lower():
                output += "**Remediation:** Add a manual approval step or environment protection rules before production deployments.\n\n"
            else:
                output += "**Remediation:** Review and apply security hardening per the CI/CD platform security documentation.\n\n"
    else:
        output += "### Analysis\n\nNo critical security issues detected in the pipeline configuration. "
        output += "The following general recommendations still apply.\n\n"

    output += "### CI/CD Security Best Practices\n\n"
    best_practices = [
        "Pin all third-party actions/images to immutable references (commit SHA or digest)",
        "Use short-lived, scoped credentials (OIDC) instead of long-lived secrets",
        "Implement branch protection rules requiring reviews before merge to main",
        "Enable build artifact signing and verification (Sigstore/cosign)",
        "Run SAST, DAST, and dependency scanning as mandatory pipeline steps",
        "Isolate CI/CD runners from production networks",
        "Implement audit logging for all pipeline executions and configuration changes",
        "Use ephemeral build environments that are destroyed after each run",
        "Verify integrity of build tools and dependencies before use",
        "Implement pipeline-as-code with mandatory code review for CI/CD changes",
    ]
    for j, bp in enumerate(rng.sample(best_practices, rng.randint(5, 8)), 1):
        output += f"{j}. {bp}\n"

    cwe_id = rng.choice(["CWE-829", "CWE-78", "CWE-200", "CWE-345", "CWE-798"])
    return format_entry(
        entry_id=f"{prefix}-{idx:05d}",
        title=f"CI/CD Security Review: {platform_name} - {app_context.title()}",
        severity=severity,
        cwe=cwe_id,
        instruction=rng.choice(CICD_INSTRUCTIONS),
        input_text=input_text,
        output_text=output,
    )


def _generate_container_entry(rng, complexity, idx, prefix):
    """Generate a container image security entry."""
    severity = pick_severity(rng, complexity)
    risky = complexity in ("intermediate", "advanced", "expert")
    dockerfile, issues = _gen_dockerfile(rng, risky=risky)

    app_context = rng.choice(APP_CONTEXTS)
    input_text = f"**Project:** {app_context.title()}\n"
    input_text += "**File:** Dockerfile\n\n"
    input_text += f"```dockerfile\n{dockerfile}\n```"

    output = f"## Container Security Assessment\n\n"
    output += f"**Project:** {app_context}\n\n"

    if issues:
        output += "### Security Issues Found\n\n"
        for i, issue in enumerate(issues, 1):
            issue_severity = "Critical" if "secret" in issue.lower() or "root" in issue.lower() else rng.choice(["Medium", "High"])
            output += f"**Issue {i} [{issue_severity}]:** {issue}\n\n"
    else:
        output += "### Analysis\n\nThe Dockerfile follows most security best practices.\n\n"

    output += "### Container Security Recommendations\n\n"
    recs = [
        "Use specific image tags with SHA256 digest pinning instead of 'latest' or mutable tags",
        "Run containers as non-root user with a dedicated application user",
        "Use multi-stage builds to minimize the final image attack surface",
        "Never embed secrets in Dockerfile ENV or COPY instructions - use runtime secret injection",
        "Scan images for vulnerabilities using Trivy, Grype, or Snyk Container",
        "Use distroless or minimal base images (Alpine, slim variants) to reduce attack surface",
        "Implement a .dockerignore file to prevent sensitive files from being included",
        "Sign container images using cosign or Docker Content Trust (DCT)",
        "Enable read-only filesystem at runtime where possible",
        "Set appropriate resource limits (CPU, memory) to prevent resource abuse",
        "Use HEALTHCHECK instruction for container orchestrator integration",
        "Avoid running SSH or debugging tools in production containers",
    ]
    for j, rec in enumerate(rng.sample(recs, rng.randint(5, 8)), 1):
        output += f"{j}. {rec}\n"

    cwe_id = rng.choice(["CWE-269", "CWE-798", "CWE-200", "CWE-250", "CWE-276"])
    return format_entry(
        entry_id=f"{prefix}-{idx:05d}",
        title=f"Container Security: {app_context.title()}",
        severity=severity,
        cwe=cwe_id,
        instruction=rng.choice(CONTAINER_INSTRUCTIONS),
        input_text=input_text,
        output_text=output,
    )


def _generate_sbom_entry(rng, complexity, idx, prefix):
    """Generate an SBOM analysis entry."""
    severity = pick_severity(rng, complexity)
    app_context = rng.choice(APP_CONTEXTS)

    # Build SBOM component list
    ecosystem = rng.choice(["npm", "pypi"])
    if ecosystem == "npm":
        deps = rng.sample(NPM_PACKAGES_LEGIT, rng.randint(6, 12))
    else:
        deps = rng.sample(PIP_PACKAGES_LEGIT, rng.randint(6, 12))

    input_text = f"**Project:** {app_context.title()}\n"
    input_text += f"**SBOM Format:** CycloneDX 1.4\n"
    input_text += f"**Ecosystem:** {ecosystem}\n\n"
    input_text += "**Components:**\n\n"
    input_text += "| Component | Version | License | Type |\n"
    input_text += "|-----------|---------|---------|------|\n"

    licenses = ["MIT", "Apache-2.0", "BSD-3-Clause", "ISC", "GPL-3.0", "LGPL-2.1", "MPL-2.0", "Unlicense", "AGPL-3.0"]
    sbom_components = []
    for name, ver in deps:
        lic = rng.choice(licenses)
        comp_type = rng.choice(["library", "framework"])
        input_text += f"| {name} | {ver} | {lic} | {comp_type} |\n"
        sbom_components.append((name, ver, lic, comp_type))

    output = f"## SBOM Security Assessment\n\n"
    output += f"**Project:** {app_context}\n"
    output += f"**Total Components:** {len(sbom_components)}\n\n"

    # License analysis
    output += "### License Compliance\n\n"
    copyleft = [c for c in sbom_components if c[2] in ("GPL-3.0", "AGPL-3.0", "LGPL-2.1")]
    if copyleft:
        output += "**WARNING:** The following components use copyleft licenses that may have viral implications:\n\n"
        for name, ver, lic, _ in copyleft:
            output += f"- **{name}@{ver}** ({lic}) - Review compatibility with your project license\n"
        output += "\n"
    else:
        output += "All components use permissive licenses compatible with commercial use.\n\n"

    # Vulnerability summary (simulated)
    output += "### Vulnerability Summary\n\n"
    num_vulns = rng.randint(0, 4)
    if num_vulns > 0:
        output += f"**{num_vulns} known vulnerabilities found:**\n\n"
        for v in range(num_vulns):
            comp = rng.choice(sbom_components)
            cve = f"CVE-{rng.randint(2022,2025)}-{rng.randint(10000,99999)}"
            vsev = rng.choice(["Low", "Medium", "High", "Critical"])
            output += f"- **{cve}** in {comp[0]}@{comp[1]} [{vsev}] - Update to latest patched version\n"
        output += "\n"
    else:
        output += "No known vulnerabilities found in current component versions.\n\n"

    output += "### Recommendations\n\n"
    output += "1. Integrate SBOM generation into the CI/CD pipeline (e.g., syft, cyclonedx-cli)\n"
    output += "2. Set up continuous vulnerability monitoring for all SBOM components\n"
    output += "3. Establish a dependency update policy with maximum allowed age\n"
    output += "4. Review copyleft license obligations before distribution\n"
    output += "5. Maintain an approved component list and enforce it via policy\n"

    cwe_id = rng.choice(["CWE-829", "CWE-345", "CWE-1104"])
    return format_entry(
        entry_id=f"{prefix}-{idx:05d}",
        title=f"SBOM Analysis: {app_context.title()}",
        severity=severity,
        cwe=cwe_id,
        instruction=rng.choice(SBOM_INSTRUCTIONS),
        input_text=input_text,
        output_text=output,
    )


class SupplyChainGenerator(CategoryGenerator):
    category = "supply_chain"
    id_prefix = "xld-supply"

    def generate_entries(self, rng: random.Random, count: int, start_id: int,
                         complexity_weights) -> List[Dict[str, Any]]:
        entries = []
        # Distribute: 30% dependency, 25% CI/CD, 25% container, 20% SBOM
        dep_count = int(count * 0.30)
        cicd_count = int(count * 0.25)
        container_count = int(count * 0.25)
        sbom_count = count - dep_count - cicd_count - container_count

        idx = start_id
        for _ in range(dep_count):
            complexity = pick_complexity(rng, complexity_weights)
            entries.append(_generate_dependency_entry(rng, complexity, idx, self.id_prefix))
            idx += 1

        for _ in range(cicd_count):
            complexity = pick_complexity(rng, complexity_weights)
            entries.append(_generate_cicd_entry(rng, complexity, idx, self.id_prefix))
            idx += 1

        for _ in range(container_count):
            complexity = pick_complexity(rng, complexity_weights)
            entries.append(_generate_container_entry(rng, complexity, idx, self.id_prefix))
            idx += 1

        for _ in range(sbom_count):
            complexity = pick_complexity(rng, complexity_weights)
            entries.append(_generate_sbom_entry(rng, complexity, idx, self.id_prefix))
            idx += 1

        return entries
