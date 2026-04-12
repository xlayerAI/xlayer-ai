"""
Cloud Security generator.
Produces AWS/Azure/GCP security misconfiguration assessments including
S3/Blob public access, IAM over-permissions, unencrypted storage, public endpoints,
missing logging, container security, serverless security, and network isolation.
Target: 7000 entries.
"""

import random
from typing import List, Dict, Any
from ..templates import (
    CategoryGenerator, pick_complexity, pick_severity, format_entry,
    rand_ip, rand_domain, rand_port, rand_var_name, rand_func_name,
    rand_table_name, rand_path,
)
from ..knowledge_base import (
    CWE_DB, OWASP_TOP10, MITRE_ATTACK, APP_CONTEXTS, PRODUCTS,
    CLOUD_SERVICES, FRAMEWORKS, PROTOCOLS,
)


# ── Instruction pools ──────────────────────────────────────────────────────

CLOUD_INSTRUCTIONS = [
    "Analyze the following cloud configuration for security misconfigurations. Identify risks and provide remediation guidance aligned with CIS benchmarks.",
    "Review this cloud infrastructure setup and identify security weaknesses. Explain the potential impact and recommend secure configuration changes.",
    "As a cloud security engineer, assess the following cloud resource configuration. Identify violations of security best practices and provide fixes.",
    "Evaluate this cloud deployment for security compliance. Map findings to CIS benchmarks and provide remediation steps with infrastructure-as-code examples.",
    "Perform a cloud security posture assessment on the following configuration. Identify misconfigurations, explain the risk, and provide remediation.",
    "Review this cloud environment configuration for security anti-patterns. Classify each finding by severity and provide actionable remediation steps.",
    "As a cloud security architect, analyze the following infrastructure configuration. Identify gaps in defense-in-depth and recommend improvements.",
    "Assess this cloud resource for compliance with the shared responsibility model. Identify customer-side security obligations that are not being met.",
    "Evaluate the following cloud configuration against the principle of least privilege. Identify over-permissive settings and recommend restrictions.",
    "Conduct a cloud security review of this configuration. Identify data protection gaps, access control issues, and monitoring deficiencies.",
    "Review this cloud deployment for network security, data encryption, and identity management best practices. Provide a prioritized remediation plan.",
    "Analyze this cloud infrastructure for potential attack vectors. Map findings to MITRE ATT&CK for Cloud and provide detection and prevention strategies.",
    "As a cloud penetration tester, evaluate this configuration for exploitable misconfigurations. Provide findings with risk ratings and remediation guidance.",
    "Assess this multi-cloud configuration for security inconsistencies. Identify gaps that could lead to data exposure or unauthorized access.",
    "Review the following cloud-native application security posture. Identify container, serverless, and orchestration security issues.",
    "Evaluate this cloud IAM configuration for privilege escalation paths. Identify excessive permissions and recommend least-privilege policies.",
]

# ── Scenario types ─────────────────────────────────────────────────────────

SCENARIO_TYPES = [
    "storage_public", "iam_overpermission", "unencrypted_storage",
    "public_endpoint", "missing_logging", "container_security",
    "serverless_security", "network_isolation",
]

# ── Cloud provider selection helpers ──────────────────────────────────────

PROVIDER_NAMES = {"aws": "AWS", "azure": "Azure", "gcp": "GCP"}

# ── Storage public access templates ───────────────────────────────────────

STORAGE_CONFIGS = {
    "aws": [
        {
            "config": '{\n  "Bucket": "prod-customer-data-2024",\n  "ACL": "public-read",\n  "Policy": {\n    "Statement": [{\n      "Sid": "PublicRead",\n      "Effect": "Allow",\n      "Principal": "*",\n      "Action": "s3:GetObject",\n      "Resource": "arn:aws:s3:::prod-customer-data-2024/*"\n    }]\n  },\n  "PublicAccessBlockConfiguration": {\n    "BlockPublicAcls": false,\n    "BlockPublicPolicy": false,\n    "IgnorePublicAcls": false,\n    "RestrictPublicBuckets": false\n  },\n  "ServerSideEncryptionConfiguration": null,\n  "VersioningConfiguration": {"Status": "Suspended"},\n  "LoggingConfiguration": null\n}',
            "service": "S3",
            "issues": ["Public bucket ACL", "Public bucket policy", "No encryption", "No versioning", "No access logging"],
        },
        {
            "config": '{\n  "Bucket": "app-backups-storage",\n  "ACL": "private",\n  "Policy": {\n    "Statement": [{\n      "Effect": "Allow",\n      "Principal": {"AWS": "*"},\n      "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],\n      "Resource": "arn:aws:s3:::app-backups-storage/*"\n    }]\n  },\n  "PublicAccessBlockConfiguration": {\n    "BlockPublicAcls": true,\n    "BlockPublicPolicy": false,\n    "IgnorePublicAcls": true,\n    "RestrictPublicBuckets": false\n  }\n}',
            "service": "S3",
            "issues": ["Bucket policy allows any AWS principal", "Incomplete public access block", "Write/Delete access to any principal"],
        },
    ],
    "azure": [
        {
            "config": '{\n  "name": "prodcustomerdata",\n  "type": "Microsoft.Storage/storageAccounts",\n  "properties": {\n    "allowBlobPublicAccess": true,\n    "minimumTlsVersion": "TLS1_0",\n    "supportsHttpsTrafficOnly": false,\n    "encryption": {\n      "services": {\n        "blob": {"enabled": false}\n      }\n    },\n    "networkAcls": {\n      "defaultAction": "Allow"\n    }\n  }\n}',
            "service": "Blob Storage",
            "issues": ["Public blob access enabled", "TLS 1.0 allowed", "HTTP allowed", "No encryption", "No network restrictions"],
        },
    ],
    "gcp": [
        {
            "config": '{\n  "name": "prod-data-export",\n  "storageClass": "STANDARD",\n  "iamConfiguration": {\n    "uniformBucketLevelAccess": {"enabled": false}\n  },\n  "acl": [\n    {"entity": "allUsers", "role": "READER"},\n    {"entity": "allAuthenticatedUsers", "role": "WRITER"}\n  ],\n  "defaultObjectAcl": [\n    {"entity": "allUsers", "role": "READER"}\n  ],\n  "encryption": null,\n  "retentionPolicy": null\n}',
            "service": "Cloud Storage",
            "issues": ["allUsers read access", "allAuthenticatedUsers write access", "No uniform bucket-level access", "No encryption", "No retention policy"],
        },
    ],
}

# ── IAM over-permission templates ─────────────────────────────────────────

IAM_CONFIGS = {
    "aws": [
        {
            "config": '{\n  "PolicyName": "DeveloperAccess",\n  "PolicyDocument": {\n    "Version": "2012-10-17",\n    "Statement": [{\n      "Effect": "Allow",\n      "Action": "*",\n      "Resource": "*"\n    }]\n  },\n  "AttachedTo": ["group/developers"],\n  "MFAEnforced": false,\n  "MaxSessionDuration": 43200\n}',
            "service": "IAM",
            "issues": ["Wildcard actions (Admin access)", "Wildcard resources", "No MFA enforcement", "12-hour session duration"],
        },
        {
            "config": '{\n  "RoleName": "LambdaExecutionRole",\n  "AssumeRolePolicyDocument": {\n    "Statement": [{\n      "Effect": "Allow",\n      "Principal": {"Service": "lambda.amazonaws.com"},\n      "Action": "sts:AssumeRole"\n    }]\n  },\n  "Policies": [{\n    "PolicyName": "LambdaFullAccess",\n    "PolicyDocument": {\n      "Statement": [\n        {"Effect": "Allow", "Action": "s3:*", "Resource": "*"},\n        {"Effect": "Allow", "Action": "dynamodb:*", "Resource": "*"},\n        {"Effect": "Allow", "Action": "logs:*", "Resource": "*"},\n        {"Effect": "Allow", "Action": "iam:*", "Resource": "*"}\n      ]\n    }\n  }]\n}',
            "service": "IAM",
            "issues": ["Lambda role with iam:* (privilege escalation)", "Wildcard S3 access", "Wildcard DynamoDB access", "Overly broad permissions for a single function"],
        },
    ],
    "azure": [
        {
            "config": '{\n  "roleDefinitionId": "Owner",\n  "principalType": "User",\n  "scope": "/subscriptions/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",\n  "principalName": "developer@company.com",\n  "conditionalAccess": "none",\n  "mfaRequired": false\n}',
            "service": "Active Directory",
            "issues": ["Owner role at subscription scope", "No conditional access policy", "MFA not required", "Individual user assignment (should use groups)"],
        },
    ],
    "gcp": [
        {
            "config": '{\n  "bindings": [\n    {\n      "role": "roles/owner",\n      "members": ["user:developer@company.com", "serviceAccount:app-sa@project.iam.gserviceaccount.com"]\n    },\n    {\n      "role": "roles/editor",\n      "members": ["group:all-devs@company.com"]\n    }\n  ],\n  "serviceAccountKeys": [\n    {"keyType": "USER_MANAGED", "keyAlgorithm": "KEY_ALG_RSA_2048", "validAfterTime": "2023-01-15"}\n  ]\n}',
            "service": "IAM",
            "issues": ["Owner role assigned to service account", "Editor role to broad group", "User-managed service account key (should use workload identity)", "Key over 90 days old"],
        },
    ],
}

# ── Unencrypted storage templates ─────────────────────────────────────────

ENCRYPTION_CONFIGS = {
    "aws": [
        {
            "config": '{\n  "DBInstanceIdentifier": "prod-database",\n  "Engine": "mysql",\n  "EngineVersion": "8.0.28",\n  "StorageEncrypted": false,\n  "PubliclyAccessible": true,\n  "MultiAZ": false,\n  "BackupRetentionPeriod": 1,\n  "DeletionProtection": false,\n  "AutoMinorVersionUpgrade": false,\n  "IAMDatabaseAuthenticationEnabled": false,\n  "MonitoringInterval": 0\n}',
            "service": "RDS",
            "issues": ["No encryption at rest", "Publicly accessible", "No Multi-AZ", "Minimal backup retention", "No deletion protection", "No enhanced monitoring"],
        },
    ],
    "azure": [
        {
            "config": '{\n  "name": "prod-vm-01",\n  "type": "Microsoft.Compute/virtualMachines",\n  "properties": {\n    "storageProfile": {\n      "osDisk": {\n        "encryptionSettings": {"enabled": false}\n      },\n      "dataDisks": [\n        {"diskEncryptionSet": null, "name": "data-disk-01"}\n      ]\n    },\n    "osProfile": {\n      "adminUsername": "azureuser",\n      "disablePasswordAuthentication": false\n    },\n    "diagnosticsProfile": {\n      "bootDiagnostics": {"enabled": false}\n    }\n  }\n}',
            "service": "Virtual Machines",
            "issues": ["OS disk not encrypted", "Data disk not encrypted", "Password authentication enabled", "Boot diagnostics disabled"],
        },
    ],
    "gcp": [
        {
            "config": '{\n  "name": "prod-instance-01",\n  "machineType": "e2-standard-4",\n  "disks": [{\n    "diskEncryptionKey": null,\n    "autoDelete": true\n  }],\n  "serviceAccounts": [{\n    "email": "123456-compute@developer.gserviceaccount.com",\n    "scopes": ["https://www.googleapis.com/auth/cloud-platform"]\n  }],\n  "shieldedInstanceConfig": {\n    "enableSecureBoot": false,\n    "enableVtpm": false\n  },\n  "metadata": {\n    "items": [{"key": "serial-port-enable", "value": "true"}]\n  }\n}',
            "service": "Compute Engine",
            "issues": ["No customer-managed encryption key", "Default service account with full scope", "Shielded VM disabled", "Serial port enabled"],
        },
    ],
}

# ── Public endpoint templates ─────────────────────────────────────────────

PUBLIC_ENDPOINT_CONFIGS = {
    "aws": [
        {
            "config": '{\n  "SecurityGroups": [{\n    "GroupId": "sg-0123456789abcdef0",\n    "GroupName": "web-server-sg",\n    "IpPermissions": [\n      {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},\n      {"IpProtocol": "tcp", "FromPort": 3306, "ToPort": 3306, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},\n      {"IpProtocol": "tcp", "FromPort": 0, "ToPort": 65535, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},\n      {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}\n    ]\n  }],\n  "IMDSv1": true,\n  "PublicIpAddress": "54.x.x.x"\n}',
            "service": "EC2",
            "issues": ["SSH open to world", "MySQL open to world", "All TCP ports open", "All protocols open", "IMDSv1 enabled (SSRF risk)"],
        },
    ],
    "azure": [
        {
            "config": '{\n  "name": "prod-nsg",\n  "securityRules": [\n    {\n      "name": "AllowAll",\n      "properties": {\n        "protocol": "*",\n        "sourceAddressPrefix": "*",\n        "destinationPortRange": "*",\n        "access": "Allow",\n        "direction": "Inbound",\n        "priority": 100\n      }\n    }\n  ]\n}',
            "service": "Virtual Machines",
            "issues": ["NSG allows all inbound traffic", "No port restrictions", "No source IP restrictions", "Low priority rule overrides all others"],
        },
    ],
    "gcp": [
        {
            "config": '{\n  "name": "allow-all-ingress",\n  "network": "default",\n  "direction": "INGRESS",\n  "priority": 100,\n  "sourceRanges": ["0.0.0.0/0"],\n  "allowed": [\n    {"IPProtocol": "tcp", "ports": ["0-65535"]},\n    {"IPProtocol": "udp", "ports": ["0-65535"]}\n  ],\n  "targetTags": []\n}',
            "service": "Compute Engine",
            "issues": ["All TCP/UDP ports open to internet", "Using default network", "No target tags (applies to all instances)", "Low priority overrides specific rules"],
        },
    ],
}

# ── Missing logging templates ─────────────────────────────────────────────

LOGGING_CONFIGS = {
    "aws": [
        {
            "config": '{\n  "CloudTrail": {"IsLogging": false},\n  "GuardDuty": {"Status": "DISABLED"},\n  "VPCFlowLogs": [],\n  "S3AccessLogging": {"TargetBucket": null},\n  "ConfigService": {"RecorderStatus": "STOPPED"},\n  "SecurityHub": {"Status": "DISABLED"}\n}',
            "service": "CloudTrail",
            "issues": ["CloudTrail disabled", "GuardDuty disabled", "No VPC Flow Logs", "No S3 access logging", "Config recorder stopped", "SecurityHub disabled"],
        },
    ],
    "azure": [
        {
            "config": '{\n  "diagnosticSettings": [],\n  "activityLogAlerts": [],\n  "securityCenter": {\n    "pricingTier": "Free",\n    "autoProvisioningSettings": "Off"\n  },\n  "networkWatcher": {"provisioningState": "NotRegistered"}\n}',
            "service": "Monitor",
            "issues": ["No diagnostic settings configured", "No activity log alerts", "Security Center on free tier", "Auto-provisioning disabled", "Network Watcher not registered"],
        },
    ],
    "gcp": [
        {
            "config": '{\n  "auditConfigs": [],\n  "securityCommandCenter": {"tier": "STANDARD"},\n  "vpcFlowLogs": {"enabled": false},\n  "dataCatalog": {"policyTagManager": "disabled"},\n  "accessTransparency": {"status": "DISABLED"}\n}',
            "service": "Cloud Logging",
            "issues": ["No audit log configuration", "VPC Flow Logs disabled", "Data catalog policy tags disabled", "Access Transparency disabled"],
        },
    ],
}

# ── Container security templates ──────────────────────────────────────────

CONTAINER_CONFIGS = {
    "aws": [
        {
            "config": '{\n  "cluster": "prod-eks",\n  "endpointAccess": {"publicAccess": true, "privateAccess": false},\n  "logging": {"clusterLogging": [{"types": [], "enabled": false}]},\n  "encryptionConfig": [],\n  "podSecurityPolicy": "disabled",\n  "networkPolicy": "none",\n  "serviceAccountTokens": {"automountServiceAccountToken": true},\n  "samplePodSpec": {\n    "securityContext": {"runAsRoot": true, "privileged": true},\n    "hostNetwork": true,\n    "hostPID": true\n  }\n}',
            "service": "EKS",
            "issues": ["Public API endpoint", "No private access", "Cluster logging disabled", "No encryption", "No pod security", "Privileged containers", "Host networking", "Host PID"],
        },
    ],
    "azure": [
        {
            "config": '{\n  "name": "prod-aks",\n  "properties": {\n    "apiServerAccessProfile": {\n      "authorizedIPRanges": null,\n      "enablePrivateCluster": false\n    },\n    "networkProfile": {\n      "networkPolicy": "none",\n      "networkPlugin": "kubenet"\n    },\n    "addonProfiles": {\n      "azurepolicy": {"enabled": false},\n      "omsagent": {"enabled": false}\n    },\n    "enableRBAC": false\n  }\n}',
            "service": "AKS",
            "issues": ["Public API with no IP restrictions", "No network policy", "Azure Policy disabled", "Monitoring disabled", "RBAC disabled"],
        },
    ],
    "gcp": [
        {
            "config": '{\n  "name": "prod-gke",\n  "masterAuthorizedNetworksConfig": {"enabled": false},\n  "privateClusterConfig": null,\n  "legacyAbac": {"enabled": true},\n  "networkPolicy": {"enabled": false},\n  "workloadIdentityConfig": null,\n  "nodePools": [{\n    "config": {\n      "serviceAccount": "default",\n      "oauthScopes": ["https://www.googleapis.com/auth/cloud-platform"]\n    }\n  }],\n  "shieldedNodes": {"enabled": false}\n}',
            "service": "GKE",
            "issues": ["No master authorized networks", "No private cluster", "Legacy ABAC enabled", "No network policy", "No workload identity", "Default service account with full scope", "Shielded nodes disabled"],
        },
    ],
}

# ── Serverless security templates ─────────────────────────────────────────

SERVERLESS_CONFIGS = {
    "aws": [
        {
            "config": '{\n  "FunctionName": "process-payments",\n  "Runtime": "nodejs16.x",\n  "Role": "arn:aws:iam::123456789012:role/lambda-admin-role",\n  "Environment": {\n    "Variables": {\n      "DB_PASSWORD": "SuperSecret123!",\n      "API_KEY": "sk-live-xxxxxxxxxxxxxxxx",\n      "STRIPE_SECRET": "sk_live_xxxxxxxxxxxxx"\n    }\n  },\n  "VpcConfig": {},\n  "Timeout": 900,\n  "ReservedConcurrentExecutions": null,\n  "TracingConfig": {"Mode": "PassThrough"},\n  "FunctionUrlConfig": {\n    "AuthType": "NONE",\n    "Cors": {"AllowOrigins": ["*"]}\n  }\n}',
            "service": "Lambda",
            "issues": ["Secrets in environment variables", "Admin execution role", "No VPC", "No concurrency limit", "Tracing disabled", "Public function URL with no auth", "CORS wildcard"],
        },
    ],
    "azure": [
        {
            "config": '{\n  "name": "process-orders",\n  "properties": {\n    "runtime": "dotnet6",\n    "siteConfig": {\n      "appSettings": [\n        {"name": "DatabasePassword", "value": "P@ssw0rd123"},\n        {"name": "ConnectionString", "value": "Server=prod-db;User=sa;Password=admin123"}\n      ],\n      "ftpsState": "AllAllowed",\n      "http20Enabled": false,\n      "minTlsVersion": "1.0"\n    },\n    "httpsOnly": false,\n    "identity": {"type": "None"}\n  }\n}',
            "service": "Azure Functions",
            "issues": ["Plaintext credentials in settings", "FTP allowed", "HTTP/2 disabled", "TLS 1.0 allowed", "HTTPS not enforced", "No managed identity"],
        },
    ],
    "gcp": [
        {
            "config": '{\n  "name": "process-data",\n  "runtime": "python39",\n  "entryPoint": "handler",\n  "serviceAccountEmail": "123456-compute@developer.gserviceaccount.com",\n  "environmentVariables": {\n    "DB_PASS": "admin123",\n    "GCP_KEY": "{\\\"type\\\": \\\"service_account\\\", ...}"\n  },\n  "ingressSettings": "ALLOW_ALL",\n  "vpcConnector": null,\n  "invoker": "allUsers"\n}',
            "service": "Cloud Functions",
            "issues": ["Default service account", "Secrets in env vars including service account key", "Allows all ingress", "No VPC connector", "allUsers can invoke"],
        },
    ],
}

# ── Network isolation templates ───────────────────────────────────────────

NETWORK_CONFIGS = {
    "aws": [
        {
            "config": '{\n  "VPC": {\n    "VpcId": "vpc-default",\n    "CidrBlock": "172.31.0.0/16",\n    "IsDefault": true\n  },\n  "Subnets": [\n    {"SubnetId": "subnet-pub-1", "MapPublicIpOnLaunch": true, "AvailabilityZone": "us-east-1a"},\n    {"SubnetId": "subnet-pub-2", "MapPublicIpOnLaunch": true, "AvailabilityZone": "us-east-1b"}\n  ],\n  "InternetGateway": "igw-attached",\n  "NATGateway": null,\n  "RouteTables": [{\n    "Routes": [\n      {"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-xxxx"}\n    ]\n  }],\n  "VPCEndpoints": [],\n  "FlowLogs": []\n}',
            "service": "VPC",
            "issues": ["Using default VPC", "All subnets are public", "No private subnets", "No NAT Gateway", "No VPC endpoints for AWS services", "No flow logs"],
        },
    ],
    "azure": [
        {
            "config": '{\n  "name": "prod-vnet",\n  "addressSpace": {"addressPrefixes": ["10.0.0.0/8"]},\n  "subnets": [\n    {"name": "default", "addressPrefix": "10.0.0.0/8", "networkSecurityGroup": null, "serviceEndpoints": []}\n  ],\n  "ddosProtectionPlan": null,\n  "privateDnsZones": [],\n  "virtualNetworkPeerings": []\n}',
            "service": "Virtual Network",
            "issues": ["Single /8 subnet (no segmentation)", "No NSG attached", "No service endpoints", "No DDoS protection", "No private DNS", "No network peering isolation"],
        },
    ],
    "gcp": [
        {
            "config": '{\n  "name": "default",\n  "autoCreateSubnetworks": true,\n  "firewallRules": [\n    {"name": "default-allow-ssh", "sourceRanges": ["0.0.0.0/0"], "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}]},\n    {"name": "default-allow-rdp", "sourceRanges": ["0.0.0.0/0"], "allowed": [{"IPProtocol": "tcp", "ports": ["3389"]}]},\n    {"name": "default-allow-icmp", "sourceRanges": ["0.0.0.0/0"], "allowed": [{"IPProtocol": "icmp"}]}\n  ],\n  "privateGoogleAccess": false,\n  "flowLogs": false\n}',
            "service": "VPC Network",
            "issues": ["Using default auto-mode network", "SSH open to world", "RDP open to world", "ICMP open to world", "No Private Google Access", "No flow logs"],
        },
    ],
}

# Map scenario types to config dictionaries
SCENARIO_CONFIGS = {
    "storage_public": STORAGE_CONFIGS,
    "iam_overpermission": IAM_CONFIGS,
    "unencrypted_storage": ENCRYPTION_CONFIGS,
    "public_endpoint": PUBLIC_ENDPOINT_CONFIGS,
    "missing_logging": LOGGING_CONFIGS,
    "container_security": CONTAINER_CONFIGS,
    "serverless_security": SERVERLESS_CONFIGS,
    "network_isolation": NETWORK_CONFIGS,
}

SCENARIO_LABELS = {
    "storage_public": "Public Storage Exposure",
    "iam_overpermission": "IAM Over-Permission",
    "unencrypted_storage": "Unencrypted Data Storage",
    "public_endpoint": "Public Endpoint Exposure",
    "missing_logging": "Missing Security Logging",
    "container_security": "Container/Kubernetes Security",
    "serverless_security": "Serverless Security",
    "network_isolation": "Network Isolation",
}

SCENARIO_CWE = {
    "storage_public": "CWE-284",
    "iam_overpermission": "CWE-269",
    "unencrypted_storage": "CWE-311",
    "public_endpoint": "CWE-668",
    "missing_logging": "CWE-778",
    "container_security": "CWE-269",
    "serverless_security": "CWE-798",
    "network_isolation": "CWE-668",
}

CIS_REFERENCES = {
    "storage_public": {
        "aws": ["CIS AWS 2.1.1 - Ensure S3 bucket policy does not grant public access",
                "CIS AWS 2.1.2 - Ensure S3 Bucket Policy is set to deny HTTP requests",
                "CIS AWS 2.1.5 - Ensure S3 bucket access logging is enabled"],
        "azure": ["CIS Azure 3.1 - Ensure storage account has public access disabled",
                  "CIS Azure 3.7 - Ensure default network access rule is set to deny"],
        "gcp": ["CIS GCP 5.1 - Ensure Cloud Storage buckets are not anonymously accessible",
                "CIS GCP 5.2 - Ensure Cloud Storage buckets have uniform access enabled"],
    },
    "iam_overpermission": {
        "aws": ["CIS AWS 1.4 - Ensure no root account access key exists",
                "CIS AWS 1.16 - Ensure IAM policies are attached to groups/roles only",
                "CIS AWS 1.17 - Ensure MFA is enabled for all IAM users"],
        "azure": ["CIS Azure 1.1 - Ensure MFA is enabled for all privileged users",
                  "CIS Azure 1.3 - Ensure guest users are reviewed regularly"],
        "gcp": ["CIS GCP 1.1 - Ensure corporate credentials are used",
                "CIS GCP 1.4 - Ensure service account keys are rotated within 90 days"],
    },
    "unencrypted_storage": {
        "aws": ["CIS AWS 2.3.1 - Ensure RDS instances have encryption enabled",
                "CIS AWS 2.2.1 - Ensure EBS volume encryption is enabled"],
        "azure": ["CIS Azure 7.1 - Ensure VM disks are encrypted",
                  "CIS Azure 4.1.1 - Ensure SQL databases have encryption enabled"],
        "gcp": ["CIS GCP 4.1 - Ensure compute instances use customer-managed encryption keys",
                "CIS GCP 6.1 - Ensure Cloud SQL database instances require SSL"],
    },
    "public_endpoint": {
        "aws": ["CIS AWS 5.1 - Ensure no security groups allow ingress from 0.0.0.0/0 to port 22",
                "CIS AWS 5.2 - Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389"],
        "azure": ["CIS Azure 6.1 - Ensure that RDP access is restricted from the internet",
                  "CIS Azure 6.2 - Ensure that SSH access is restricted from the internet"],
        "gcp": ["CIS GCP 3.6 - Ensure SSH access is restricted from the internet",
                "CIS GCP 3.7 - Ensure RDP access is restricted from the internet"],
    },
    "missing_logging": {
        "aws": ["CIS AWS 3.1 - Ensure CloudTrail is enabled in all regions",
                "CIS AWS 3.4 - Ensure CloudTrail log file validation is enabled",
                "CIS AWS 4.1 - Ensure a log metric filter and alarm exist for unauthorized API calls"],
        "azure": ["CIS Azure 5.1.1 - Ensure diagnostic setting captures all categories",
                  "CIS Azure 5.2.1 - Ensure activity log alerts are configured"],
        "gcp": ["CIS GCP 2.1 - Ensure Cloud Audit Logging is configured",
                "CIS GCP 2.2 - Ensure log metric filters and alerts exist"],
    },
    "container_security": {
        "aws": ["CIS EKS 1.1 - Ensure cluster endpoint is not publicly accessible",
                "CIS EKS 3.1 - Ensure Kubernetes Secrets are encrypted"],
        "azure": ["CIS AKS 1.1 - Ensure RBAC is enabled",
                  "CIS AKS 3.1 - Ensure network policy is configured"],
        "gcp": ["CIS GKE 6.1 - Ensure legacy ABAC is disabled",
                "CIS GKE 6.2 - Ensure network policy is enabled"],
    },
    "serverless_security": {
        "aws": ["AWS Well-Architected - Use least privilege IAM roles for Lambda",
                "AWS Best Practice - Store secrets in Secrets Manager, not environment variables"],
        "azure": ["Azure Best Practice - Use Managed Identity for Functions",
                  "Azure Best Practice - Store secrets in Key Vault"],
        "gcp": ["GCP Best Practice - Use dedicated service accounts for Cloud Functions",
                "GCP Best Practice - Store secrets in Secret Manager"],
    },
    "network_isolation": {
        "aws": ["CIS AWS 5.3 - Ensure default VPC is not used",
                "CIS AWS 3.9 - Ensure VPC flow logging is enabled in all VPCs"],
        "azure": ["CIS Azure 6.4 - Ensure NSG flow logs are enabled",
                  "CIS Azure 6.6 - Ensure DDoS Protection Standard is enabled"],
        "gcp": ["CIS GCP 3.1 - Ensure default network is not used",
                "CIS GCP 3.8 - Ensure VPC Flow Logs are enabled"],
    },
}


def _build_output(rng, scenario_type, provider, config_entry, complexity, app):
    """Build a detailed cloud security assessment output."""
    label = SCENARIO_LABELS[scenario_type]
    provider_name = PROVIDER_NAMES[provider]
    service = config_entry["service"]
    issues = config_entry["issues"]
    cwe = SCENARIO_CWE[scenario_type]
    cwe_info = CWE_DB.get(cwe, {"name": "Security Misconfiguration", "severity": ["medium"], "owasp": "A05:2021"})
    severity = pick_severity(rng, complexity)
    cis_refs = CIS_REFERENCES.get(scenario_type, {}).get(provider, [])

    output = f"## Cloud Security Assessment: {label}\n\n"
    output += f"**Cloud Provider:** {provider_name}\n"
    output += f"**Service:** {service}\n"
    output += f"**Application:** {app}\n"
    output += f"**Severity:** {severity.upper()}\n"
    output += f"**CWE:** {cwe} ({cwe_info['name']})\n\n"

    output += "### Findings Summary\n\n"
    output += f"| # | Finding | Severity | CIS Reference |\n"
    output += f"|---|---------|----------|---------------|\n"
    for i, issue in enumerate(issues, 1):
        sev = rng.choice(["High", "Critical"]) if "public" in issue.lower() or "wildcard" in issue.lower() or "admin" in issue.lower() or "secret" in issue.lower() else rng.choice(["Medium", "High"])
        ref = cis_refs[i % len(cis_refs)] if cis_refs else "N/A"
        output += f"| {i} | {issue} | {sev} | {ref} |\n"
    output += "\n"

    output += "### Detailed Analysis\n\n"
    for i, issue in enumerate(issues, 1):
        output += f"**Finding {i}: {issue}**\n"
        output += f"- **Risk:** {_issue_risk(issue, scenario_type)}\n"
        output += f"- **Impact:** {_issue_impact(issue, scenario_type)}\n\n"

    output += "### Remediation\n\n"
    output += _remediation(rng, scenario_type, provider, config_entry)

    if complexity in ("advanced", "expert"):
        output += "### Infrastructure-as-Code Fix\n\n"
        output += _iac_fix(rng, scenario_type, provider, config_entry)

        output += "### Detection & Monitoring\n\n"
        output += _detection_monitoring(scenario_type, provider)

    output += "### Compliance Mapping\n\n"
    if cis_refs:
        for ref in cis_refs:
            output += f"- {ref}\n"
    output += f"- OWASP: {cwe_info.get('owasp', 'A05:2021')} - {OWASP_TOP10.get(cwe_info.get('owasp', ''), 'Security Misconfiguration')}\n"
    output += f"- {provider_name} Well-Architected Framework: Security Pillar\n"

    return output, severity


def _issue_risk(issue, scenario_type):
    if "public" in issue.lower() or "alluser" in issue.lower() or "world" in issue.lower():
        return "Direct exposure to the internet allows any unauthenticated actor to access or exploit this resource"
    if "wildcard" in issue.lower() or "admin" in issue.lower() or "owner" in issue.lower():
        return "Excessive permissions enable privilege escalation and lateral movement if the identity is compromised"
    if "encrypt" in issue.lower() or "tls" in issue.lower() or "http " in issue.lower():
        return "Data at rest or in transit is unprotected, risking exposure in case of unauthorized access or interception"
    if "log" in issue.lower() or "monitor" in issue.lower() or "audit" in issue.lower():
        return "Lack of visibility prevents detection of unauthorized access, making incident response significantly harder"
    if "secret" in issue.lower() or "password" in issue.lower() or "credential" in issue.lower():
        return "Hardcoded secrets in configuration can be extracted from logs, environment dumps, or source control"
    if "privileged" in issue.lower() or "root" in issue.lower() or "host" in issue.lower():
        return "Container breakout risk allows attackers to compromise the underlying host and other workloads"
    return "Security misconfiguration increases the attack surface and may enable unauthorized access"


def _issue_impact(issue, scenario_type):
    if scenario_type == "storage_public":
        return "Data exfiltration, unauthorized data modification, regulatory violations (GDPR, HIPAA, PCI-DSS)"
    if scenario_type == "iam_overpermission":
        return "Full account compromise, data exfiltration, resource destruction, cryptomining abuse"
    if scenario_type == "unencrypted_storage":
        return "Data exposure in case of unauthorized access, non-compliance with data protection regulations"
    if scenario_type == "public_endpoint":
        return "Unauthorized access, brute force attacks, exploitation of known vulnerabilities"
    if scenario_type == "missing_logging":
        return "Inability to detect, investigate, or respond to security incidents"
    if scenario_type == "container_security":
        return "Container escape, node compromise, lateral movement within the cluster"
    if scenario_type == "serverless_security":
        return "Credential theft, unauthorized API access, data exfiltration via function abuse"
    if scenario_type == "network_isolation":
        return "Lateral movement, unauthorized access between security zones, data exfiltration"
    return "Security compromise with potential data loss and operational impact"


def _remediation(rng, scenario_type, provider, config_entry):
    remediations = {
        "storage_public": {
            "aws": (
                "1. Enable S3 Block Public Access at account level:\n"
                "   ```\n   aws s3api put-public-access-block --bucket BUCKET --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true\n   ```\n"
                "2. Enable default encryption (AES-256 or KMS):\n"
                "   ```\n   aws s3api put-bucket-encryption --bucket BUCKET --server-side-encryption-configuration '{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"aws:kms\"}}]}'\n   ```\n"
                "3. Enable versioning and access logging\n"
                "4. Review and restrict bucket policies to specific IAM principals\n"
                "5. Use VPC endpoints for S3 access from internal workloads\n\n"
            ),
            "azure": (
                "1. Disable public blob access on the storage account\n"
                "2. Set minimum TLS version to 1.2\n"
                "3. Enforce HTTPS-only traffic\n"
                "4. Enable storage encryption with customer-managed keys\n"
                "5. Configure network rules to deny by default and allow specific VNets\n\n"
            ),
            "gcp": (
                "1. Remove allUsers and allAuthenticatedUsers bindings\n"
                "2. Enable uniform bucket-level access\n"
                "3. Configure customer-managed encryption keys (CMEK)\n"
                "4. Set a retention policy for data protection\n"
                "5. Enable audit logging for data access\n\n"
            ),
        },
        "iam_overpermission": {
            "aws": (
                "1. Replace wildcard (*) actions with specific required permissions\n"
                "2. Scope resource ARNs to specific resources, not *\n"
                "3. Enforce MFA for all IAM users:\n"
                "   ```json\n   {\"Effect\": \"Deny\", \"NotAction\": \"iam:*\", \"Resource\": \"*\", \"Condition\": {\"BoolIfExists\": {\"aws:MultiFactorAuthPresent\": \"false\"}}}\n   ```\n"
                "4. Reduce session duration to 1 hour for sensitive roles\n"
                "5. Implement permission boundaries to cap maximum permissions\n"
                "6. Use IAM Access Analyzer to identify unused permissions\n\n"
            ),
            "azure": (
                "1. Replace Owner role with specific role assignments\n"
                "2. Use custom roles with least-privilege permissions\n"
                "3. Enable Conditional Access policies with MFA requirement\n"
                "4. Assign roles to groups, not individual users\n"
                "5. Implement Privileged Identity Management (PIM) for just-in-time access\n\n"
            ),
            "gcp": (
                "1. Replace primitive roles (Owner/Editor) with predefined or custom roles\n"
                "2. Remove user-managed service account keys; use workload identity\n"
                "3. Use IAM Recommender to identify excess permissions\n"
                "4. Implement organization-level IAM policies\n"
                "5. Enable audit logging for IAM changes\n\n"
            ),
        },
    }
    # Get specific remediation or generic
    specific = remediations.get(scenario_type, {}).get(provider, "")
    if specific:
        return specific

    # Generic remediation
    return (
        f"1. Apply least-privilege configuration to the {config_entry['service']} resource\n"
        f"2. Enable encryption at rest and in transit\n"
        f"3. Restrict network access to known, trusted sources\n"
        f"4. Enable comprehensive logging and monitoring\n"
        f"5. Implement automated compliance scanning\n"
        f"6. Review configuration against CIS benchmarks for {PROVIDER_NAMES[provider]}\n\n"
    )


def _iac_fix(rng, scenario_type, provider, config_entry):
    if provider == "aws" and scenario_type == "storage_public":
        return (
            "```hcl\n# Terraform - Secure S3 Bucket\n"
            "resource \"aws_s3_bucket\" \"secure\" {\n"
            "  bucket = \"prod-customer-data-2024\"\n"
            "}\n\n"
            "resource \"aws_s3_bucket_public_access_block\" \"secure\" {\n"
            "  bucket = aws_s3_bucket.secure.id\n"
            "  block_public_acls       = true\n"
            "  block_public_policy     = true\n"
            "  ignore_public_acls      = true\n"
            "  restrict_public_buckets = true\n"
            "}\n\n"
            "resource \"aws_s3_bucket_server_side_encryption_configuration\" \"secure\" {\n"
            "  bucket = aws_s3_bucket.secure.id\n"
            "  rule {\n"
            "    apply_server_side_encryption_by_default {\n"
            "      sse_algorithm = \"aws:kms\"\n"
            "    }\n"
            "  }\n"
            "}\n\n"
            "resource \"aws_s3_bucket_versioning\" \"secure\" {\n"
            "  bucket = aws_s3_bucket.secure.id\n"
            "  versioning_configuration {\n"
            "    status = \"Enabled\"\n"
            "  }\n"
            "}\n```\n\n"
        )
    if provider == "aws" and scenario_type == "iam_overpermission":
        return (
            "```hcl\n# Terraform - Least Privilege IAM Policy\n"
            "resource \"aws_iam_policy\" \"developer\" {\n"
            "  name   = \"DeveloperAccess\"\n"
            "  policy = jsonencode({\n"
            "    Version = \"2012-10-17\"\n"
            "    Statement = [\n"
            "      {\n"
            "        Effect = \"Allow\"\n"
            "        Action = [\n"
            "          \"s3:GetObject\", \"s3:PutObject\", \"s3:ListBucket\",\n"
            "          \"dynamodb:GetItem\", \"dynamodb:PutItem\", \"dynamodb:Query\",\n"
            "          \"logs:CreateLogGroup\", \"logs:CreateLogStream\", \"logs:PutLogEvents\"\n"
            "        ]\n"
            "        Resource = [\n"
            "          \"arn:aws:s3:::app-data-*\",\n"
            "          \"arn:aws:dynamodb:*:*:table/app-*\",\n"
            "          \"arn:aws:logs:*:*:log-group:/app/*\"\n"
            "        ]\n"
            "      }\n"
            "    ]\n"
            "  })\n"
            "}\n```\n\n"
        )
    # Generic Terraform placeholder
    return (
        f"```hcl\n# Terraform - Secure {config_entry['service']} Configuration\n"
        f"# Apply the remediation steps above using your IaC tool\n"
        f"# Key principles:\n"
        f"#   - Explicit deny by default\n"
        f"#   - Least privilege access\n"
        f"#   - Encryption enabled\n"
        f"#   - Logging and monitoring active\n"
        f"```\n\n"
    )


def _detection_monitoring(scenario_type, provider):
    output = ""
    if scenario_type == "storage_public":
        output += "- Enable AWS Config / Azure Policy / GCP Organization Policies to detect public storage\n"
        output += "- Set up alerts for S3 bucket policy changes that grant public access\n"
        output += "- Use CSPM tools (Prowler, ScoutSuite, Checkov) for continuous assessment\n"
        output += "- Monitor CloudTrail / Activity Logs for storage configuration changes\n\n"
    elif scenario_type == "iam_overpermission":
        output += "- Use IAM Access Analyzer / Azure AD Access Reviews / GCP IAM Recommender\n"
        output += "- Alert on IAM policy changes that add wildcard permissions\n"
        output += "- Monitor for unused permissions and service accounts\n"
        output += "- Implement automated permission right-sizing\n\n"
    elif scenario_type == "container_security":
        output += "- Deploy runtime security (Falco, Sysdig, Aqua) for container monitoring\n"
        output += "- Implement admission controllers to prevent insecure pod configurations\n"
        output += "- Scan container images in CI/CD for vulnerabilities and misconfigurations\n"
        output += "- Monitor for privileged container creation and host namespace usage\n\n"
    else:
        output += "- Enable cloud-native security monitoring services\n"
        output += "- Deploy CSPM tools for continuous configuration assessment\n"
        output += "- Set up alerts for configuration changes that reduce security posture\n"
        output += "- Conduct regular cloud security assessments and penetration tests\n\n"
    return output


# ── Main generator ────────────────────────────────────────────────────────

class CloudSecurityGenerator(CategoryGenerator):
    category = "cloud_security"
    id_prefix = "xld-cloud"

    def generate_entries(self, rng: random.Random, count: int, start_id: int,
                         complexity_weights: Dict[str, float]) -> List[Dict[str, Any]]:
        entries = []
        idx = start_id

        # Weight distribution across scenario types
        weights = {
            "storage_public": 0.15,
            "iam_overpermission": 0.15,
            "unencrypted_storage": 0.12,
            "public_endpoint": 0.12,
            "missing_logging": 0.10,
            "container_security": 0.12,
            "serverless_security": 0.12,
            "network_isolation": 0.12,
        }

        for scenario_type, pct in weights.items():
            n = int(count * pct)
            configs = SCENARIO_CONFIGS[scenario_type]
            providers = list(configs.keys())

            for _ in range(n):
                complexity = pick_complexity(rng, complexity_weights)
                provider = rng.choice(providers)
                config_entry = rng.choice(configs[provider])
                app = rng.choice(APP_CONTEXTS)
                label = SCENARIO_LABELS[scenario_type]
                cwe = SCENARIO_CWE[scenario_type]

                input_text = f"**Cloud Provider:** {PROVIDER_NAMES[provider]}\n"
                input_text += f"**Service:** {config_entry['service']}\n"
                input_text += f"**Application:** {app}\n"
                input_text += f"**Assessment Type:** {label}\n\n"
                input_text += f"Resource Configuration:\n```json\n{config_entry['config']}\n```"

                output_text, severity = _build_output(
                    rng, scenario_type, provider, config_entry, complexity, app
                )

                entries.append(format_entry(
                    entry_id=f"{self.id_prefix}-{idx:05d}",
                    title=f"Cloud Security: {label} - {PROVIDER_NAMES[provider]} {config_entry['service']}",
                    severity=severity,
                    cwe=cwe,
                    instruction=rng.choice(CLOUD_INSTRUCTIONS),
                    input_text=input_text,
                    output_text=output_text,
                ))
                idx += 1

        # Fill remaining entries
        while len(entries) < count:
            scenario_type = rng.choice(SCENARIO_TYPES)
            configs = SCENARIO_CONFIGS[scenario_type]
            provider = rng.choice(list(configs.keys()))
            config_entry = rng.choice(configs[provider])
            complexity = pick_complexity(rng, complexity_weights)
            app = rng.choice(APP_CONTEXTS)
            label = SCENARIO_LABELS[scenario_type]
            cwe = SCENARIO_CWE[scenario_type]

            input_text = f"**Cloud Provider:** {PROVIDER_NAMES[provider]}\n"
            input_text += f"**Service:** {config_entry['service']}\n"
            input_text += f"**Application:** {app}\n"
            input_text += f"**Assessment Type:** {label}\n\n"
            input_text += f"Resource Configuration:\n```json\n{config_entry['config']}\n```"

            output_text, severity = _build_output(
                rng, scenario_type, provider, config_entry, complexity, app
            )

            entries.append(format_entry(
                entry_id=f"{self.id_prefix}-{idx:05d}",
                title=f"Cloud Security: {label} - {PROVIDER_NAMES[provider]} {config_entry['service']}",
                severity=severity,
                cwe=cwe,
                instruction=rng.choice(CLOUD_INSTRUCTIONS),
                input_text=input_text,
                output_text=output_text,
            ))
            idx += 1

        return entries
