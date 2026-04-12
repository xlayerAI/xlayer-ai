"""
Cryptography generator.
Produces entries about cryptographic weaknesses, secure crypto practices,
and protocol-level crypto analysis.
"""

import random
from typing import List, Dict, Any
from ..templates import CategoryGenerator, pick_complexity, pick_severity, format_entry, rand_ip, rand_domain, rand_port, rand_var_name, rand_func_name, rand_table_name, rand_path
from ..knowledge_base import CWE_DB, OWASP_TOP10, MITRE_ATTACK, APP_CONTEXTS, PRODUCTS, CLOUD_SERVICES, FRAMEWORKS, PROTOCOLS


# ── Instruction pools ──────────────────────────────────────────────────────────

WEAK_CRYPTO_INSTRUCTIONS = [
    "Analyze the following code for cryptographic weaknesses. Identify insecure algorithms, improper usage, and recommend secure alternatives.",
    "Review this code for cryptographic vulnerabilities. Check for weak hashing, broken encryption, and insecure key management practices.",
    "Perform a cryptographic security audit on the following code. Identify any use of deprecated or weak cryptographic primitives.",
    "As a cryptography expert, evaluate this code for security issues. Focus on algorithm strength, mode of operation, key handling, and IV/nonce management.",
    "Assess the cryptographic implementation in this code. Identify deviations from best practices and explain the security implications.",
]

KEY_MGMT_INSTRUCTIONS = [
    "Review the following code for key management issues. Analyze how cryptographic keys are generated, stored, rotated, and destroyed.",
    "Evaluate the key management practices in this code. Identify hardcoded keys, weak key derivation, and missing key rotation.",
    "Audit this code for cryptographic key handling vulnerabilities. Check for secure key storage, proper key lengths, and key lifecycle management.",
    "Analyze the key management approach in this implementation. Identify risks related to key exposure, derivation strength, and storage security.",
]

CERT_INSTRUCTIONS = [
    "Review the following code for certificate validation issues. Check for hostname verification, chain validation, and trust store configuration.",
    "Analyze this TLS/SSL configuration for security weaknesses. Identify issues with certificate pinning, protocol versions, and cipher suite selection.",
    "Audit the certificate handling in this code. Check for proper validation, revocation checking, and secure trust anchor management.",
    "Evaluate the TLS implementation in this code for security issues. Focus on certificate verification, protocol negotiation, and cipher preferences.",
]

PROTOCOL_INSTRUCTIONS = [
    "Analyze this cryptographic protocol implementation for security flaws. Check for replay attacks, downgrade attacks, and nonce reuse.",
    "Review the following protocol configuration for cryptographic weaknesses. Evaluate cipher suite ordering, protocol versions, and key exchange methods.",
    "Assess this security protocol implementation for known attack vectors including padding oracle, timing attacks, and protocol downgrade.",
]

HASH_INSTRUCTIONS = [
    "Evaluate the hashing implementation in this code. Identify weak hash algorithms and recommend secure alternatives for the given use case.",
    "Review this password hashing code for security issues. Check algorithm choice, salt generation, iteration count, and timing safety.",
]

RANDOM_INSTRUCTIONS = [
    "Analyze the random number generation in this code for cryptographic security. Identify use of insecure PRNGs and recommend secure alternatives.",
    "Review this code for weak randomness issues. Check if security-sensitive operations use cryptographically secure random number generators.",
]

ALL_INSTRUCTIONS = (
    WEAK_CRYPTO_INSTRUCTIONS + KEY_MGMT_INSTRUCTIONS + CERT_INSTRUCTIONS +
    PROTOCOL_INSTRUCTIONS + HASH_INSTRUCTIONS + RANDOM_INSTRUCTIONS
)

# ── Code snippet templates ─────────────────────────────────────────────────────

PYTHON_WEAK_CRYPTO = [
    {
        "name": "MD5 password hashing",
        "code": '''import hashlib

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

def verify_password(password, stored_hash):
    return hashlib.md5(password.encode()).hexdigest() == stored_hash''',
        "issues": [
            "MD5 is cryptographically broken - vulnerable to collision attacks and extremely fast to brute-force",
            "No salt used - identical passwords produce identical hashes, enabling rainbow table attacks",
            "No key stretching/iteration - single hash is computationally trivial to reverse",
            "String comparison may be vulnerable to timing attacks",
        ],
        "fix": '''import bcrypt

def hash_password(password: str) -> bytes:
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode('utf-8'), salt)

def verify_password(password: str, stored_hash: bytes) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), stored_hash)''',
        "cwe": "CWE-327",
    },
    {
        "name": "DES encryption",
        "code": '''from Crypto.Cipher import DES
import base64

KEY = b"secretky"  # 8 bytes for DES

def encrypt(plaintext):
    cipher = DES.new(KEY, DES.MODE_ECB)
    padded = plaintext.ljust(8 * ((len(plaintext) + 7) // 8))
    return base64.b64encode(cipher.encrypt(padded.encode())).decode()

def decrypt(ciphertext):
    cipher = DES.new(KEY, DES.MODE_ECB)
    decrypted = cipher.decrypt(base64.b64decode(ciphertext))
    return decrypted.decode().rstrip()''',
        "issues": [
            "DES uses a 56-bit key - can be brute-forced in hours on modern hardware",
            "ECB mode is deterministic - identical plaintext blocks produce identical ciphertext, revealing patterns",
            "Hardcoded encryption key in source code",
            "No integrity protection (no HMAC or authenticated encryption)",
            "Naive padding scheme - use PKCS7 standard padding",
        ],
        "fix": '''from cryptography.fernet import Fernet
# Or for more control:
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

def encrypt_aesgcm(plaintext: bytes, key: bytes) -> bytes:
    """Encrypt using AES-256-GCM (authenticated encryption)."""
    nonce = os.urandom(12)  # 96-bit nonce for GCM
    aesgcm = AESGCM(key)  # key must be 32 bytes for AES-256
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ciphertext  # Prepend nonce for decryption

def decrypt_aesgcm(data: bytes, key: bytes) -> bytes:
    nonce = data[:12]
    ciphertext = data[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)''',
        "cwe": "CWE-327",
    },
    {
        "name": "Weak PRNG for tokens",
        "code": '''import random
import string

def generate_session_token():
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(32))

def generate_password_reset_token():
    return str(random.randint(100000, 999999))''',
        "issues": [
            "random.choice() uses Mersenne Twister PRNG - not cryptographically secure, state can be recovered from 624 outputs",
            "Password reset token has only ~20 bits of entropy (6 digits) - trivially brute-forceable",
            "Session tokens generated with predictable PRNG can be predicted by an attacker",
        ],
        "fix": '''import secrets
import string

def generate_session_token() -> str:
    return secrets.token_urlsafe(32)  # 256 bits of entropy

def generate_password_reset_token() -> str:
    return secrets.token_urlsafe(32)  # Use high-entropy token, not numeric code''',
        "cwe": "CWE-330",
    },
    {
        "name": "SHA1 for integrity verification",
        "code": '''import hashlib

def compute_file_checksum(filepath):
    sha1 = hashlib.sha1()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            sha1.update(chunk)
    return sha1.hexdigest()

def verify_download(filepath, expected_hash):
    return compute_file_checksum(filepath) == expected_hash''',
        "issues": [
            "SHA-1 is vulnerable to collision attacks (SHAttered) - an attacker can create two files with the same hash",
            "For file integrity verification, SHA-256 or SHA-3 should be used",
            "String comparison of hashes may be vulnerable to timing side-channel attacks",
        ],
        "fix": '''import hashlib
import hmac

def compute_file_checksum(filepath: str) -> str:
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            sha256.update(chunk)
    return sha256.hexdigest()

def verify_download(filepath: str, expected_hash: str) -> bool:
    actual = compute_file_checksum(filepath)
    return hmac.compare_digest(actual, expected_hash)  # Constant-time comparison''',
        "cwe": "CWE-327",
    },
]

NODE_WEAK_CRYPTO = [
    {
        "name": "ECB mode AES encryption",
        "code": '''const crypto = require('crypto');

const KEY = 'my-secret-key-12'; // 16 bytes for AES-128

function encrypt(text) {
    const cipher = crypto.createCipheriv('aes-128-ecb', KEY, null);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
}

function decrypt(encryptedText) {
    const decipher = crypto.createDecipheriv('aes-128-ecb', KEY, null);
    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}''',
        "issues": [
            "ECB mode encrypts identical blocks to identical ciphertext - leaks plaintext patterns",
            "AES-128 provides lower security margin than AES-256",
            "Hardcoded encryption key in source code",
            "No authentication tag - ciphertext can be tampered with without detection",
            "No IV/nonce used - deterministic encryption",
        ],
        "fix": '''const crypto = require('crypto');

function encrypt(text, key) {
    // key should be 32 bytes for AES-256, loaded from secure key store
    const iv = crypto.randomBytes(12); // 96-bit IV for GCM
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag();
    // Return IV + authTag + ciphertext
    return iv.toString('hex') + authTag.toString('hex') + encrypted;
}''',
        "cwe": "CWE-327",
    },
    {
        "name": "IV reuse in CBC mode",
        "code": '''const crypto = require('crypto');

const KEY = Buffer.from('0123456789abcdef0123456789abcdef', 'hex');
const IV = Buffer.from('abcdef0123456789abcdef0123456789', 'hex'); // Static IV

function encryptMessage(message) {
    const cipher = crypto.createCipheriv('aes-128-cbc', KEY, IV);
    let encrypted = cipher.update(message, 'utf8', 'base64');
    encrypted += cipher.final('base64');
    return encrypted;
}''',
        "issues": [
            "Static IV reuse in CBC mode allows an attacker to detect repeated plaintext blocks",
            "With a known plaintext, IV reuse in CBC enables plaintext recovery of other messages",
            "Hardcoded key material in source code",
            "CBC mode without HMAC is vulnerable to padding oracle attacks",
        ],
        "fix": '''const crypto = require('crypto');

function encryptMessage(message, key) {
    const iv = crypto.randomBytes(16); // Fresh random IV for each encryption
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    let encrypted = cipher.update(message, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const tag = cipher.getAuthTag();
    return Buffer.concat([iv, tag, Buffer.from(encrypted, 'hex')]);
}''',
        "cwe": "CWE-329",
    },
    {
        "name": "Insecure JWT signing",
        "code": '''const jwt = require('jsonwebtoken');

const SECRET = 'mysecretkey';

function createToken(user) {
    return jwt.sign(
        { userId: user.id, role: user.role },
        SECRET,
        { algorithm: 'HS256' }
    );
}

function verifyToken(token) {
    return jwt.verify(token, SECRET);
}''',
        "issues": [
            "Weak HMAC secret - short, dictionary-word secret can be brute-forced offline",
            "jwt.verify() without specifying algorithms accepts 'none' algorithm in some library versions",
            "No token expiration set - tokens are valid indefinitely",
            "Hardcoded secret in source code",
        ],
        "fix": '''const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// Load from environment/secret manager, minimum 256 bits
const SECRET = process.env.JWT_SECRET;

function createToken(user) {
    return jwt.sign(
        { userId: user.id, role: user.role },
        SECRET,
        {
            algorithm: 'HS256',
            expiresIn: '1h',
            issuer: 'my-app',
            audience: 'my-app-users'
        }
    );
}

function verifyToken(token) {
    return jwt.verify(token, SECRET, {
        algorithms: ['HS256'],  // Explicitly restrict allowed algorithms
        issuer: 'my-app',
        audience: 'my-app-users'
    });
}''',
        "cwe": "CWE-347",
    },
]

JAVA_WEAK_CRYPTO = [
    {
        "name": "Insecure TLS configuration",
        "code": '''import javax.net.ssl.*;
import java.security.cert.X509Certificate;

public class ApiClient {
    private static SSLContext createInsecureContext() throws Exception {
        TrustManager[] trustAll = new TrustManager[]{
            new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() { return null; }
                public void checkClientTrusted(X509Certificate[] certs, String type) {}
                public void checkServerTrusted(X509Certificate[] certs, String type) {}
            }
        };
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, trustAll, new java.security.SecureRandom());
        return ctx;
    }

    public void connect(String url) throws Exception {
        HttpsURLConnection conn = (HttpsURLConnection) new java.net.URL(url).openConnection();
        conn.setSSLSocketFactory(createInsecureContext().getSocketFactory());
        conn.setHostnameVerifier((hostname, session) -> true);
        // ... use connection
    }
}''',
        "issues": [
            "Custom TrustManager accepts ALL certificates without validation - completely disables TLS certificate verification",
            "HostnameVerifier always returns true - disables hostname checking, allowing MITM with any valid certificate",
            "Generic 'TLS' protocol string may negotiate outdated TLS versions (1.0, 1.1)",
            "This effectively makes the HTTPS connection equivalent to plaintext HTTP against active attackers",
        ],
        "fix": '''import javax.net.ssl.*;

public class ApiClient {
    public void connect(String url) throws Exception {
        // Use the default SSLContext which validates certificates properly
        SSLContext ctx = SSLContext.getInstance("TLSv1.3");
        ctx.init(null, null, new java.security.SecureRandom());

        HttpsURLConnection conn = (HttpsURLConnection) new java.net.URL(url).openConnection();
        conn.setSSLSocketFactory(ctx.getSocketFactory());
        // Use default HostnameVerifier - do NOT override it
        // For certificate pinning, use OkHttp CertificatePinner or custom TrustManager
        // that validates against known certificate fingerprints
    }
}''',
        "cwe": "CWE-295",
    },
    {
        "name": "Weak key derivation",
        "code": '''import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class Encryptor {
    public static byte[] deriveKey(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(password.getBytes("UTF-8"));
    }

    public static byte[] encrypt(String data, String password) throws Exception {
        byte[] key = deriveKey(password);
        SecretKeySpec spec = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES");  // Defaults to ECB
        cipher.init(Cipher.ENCRYPT_MODE, spec);
        return cipher.doFinal(data.getBytes("UTF-8"));
    }
}''',
        "issues": [
            "MD5 used for key derivation - not a key derivation function, no salt, no iteration",
            "MD5 produces 128-bit output used as AES-128 key - reduced security margin",
            "Cipher.getInstance('AES') defaults to AES/ECB/PKCS5Padding in most JVMs - ECB mode leaks patterns",
            "No IV generation - deterministic encryption",
            "Password-based key derivation should use PBKDF2, bcrypt, scrypt, or Argon2",
        ],
        "fix": '''import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;

public class Encryptor {
    private static final int ITERATIONS = 310000;
    private static final int KEY_LENGTH = 256;

    public static SecretKey deriveKey(String password, byte[] salt) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_LENGTH);
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
    }

    public static byte[] encrypt(String data, String password) throws Exception {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        SecretKey key = deriveKey(password, salt);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
        byte[] ciphertext = cipher.doFinal(data.getBytes("UTF-8"));
        // Return salt + iv + ciphertext
        byte[] result = new byte[salt.length + iv.length + ciphertext.length];
        System.arraycopy(salt, 0, result, 0, salt.length);
        System.arraycopy(iv, 0, result, salt.length, iv.length);
        System.arraycopy(ciphertext, 0, result, salt.length + iv.length, ciphertext.length);
        return result;
    }
}''',
        "cwe": "CWE-916",
    },
]

TLS_CONFIGS = [
    {
        "name": "nginx TLS misconfiguration",
        "config": '''server {
    listen 443 ssl;
    server_name app.example.com;

    ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;
    ssl_ciphers ALL:!aNULL:!eNULL;
    ssl_prefer_server_ciphers off;
    ssl_certificate /etc/ssl/certs/server.crt;
    ssl_certificate_key /etc/ssl/private/server.key;

    # No HSTS header
    # No OCSP stapling
}''',
        "issues": [
            "TLSv1 and TLSv1.1 are deprecated and vulnerable to BEAST, POODLE, and other attacks",
            "Cipher string 'ALL' includes weak ciphers (RC4, DES, export-grade)",
            "ssl_prefer_server_ciphers off allows client to choose weaker ciphers",
            "Missing HSTS header - users can be downgraded to HTTP",
            "No OCSP stapling - certificate revocation checks are slower and less reliable",
        ],
        "cwe": "CWE-326",
    },
    {
        "name": "Apache TLS misconfiguration",
        "config": '''<VirtualHost *:443>
    ServerName secure.example.com
    SSLEngine on
    SSLProtocol all -SSLv3
    SSLCipherSuite HIGH:MEDIUM:!aNULL
    SSLCertificateFile /etc/ssl/certs/server.crt
    SSLCertificateKeyFile /etc/ssl/private/server.key
    SSLCompression on
</VirtualHost>''',
        "issues": [
            "'SSLProtocol all -SSLv3' still allows TLSv1.0 and TLSv1.1 which are deprecated",
            "MEDIUM cipher suites include 128-bit ciphers that may not meet compliance requirements",
            "SSLCompression on enables the CRIME/BREACH attack against TLS",
            "Missing HSTS, missing OCSP stapling configuration",
        ],
        "cwe": "CWE-326",
    },
]


def _generate_weak_crypto_entry(rng, complexity, idx, prefix):
    """Generate a weak cryptography analysis entry."""
    severity = pick_severity(rng, complexity)

    lang_pool = rng.choice(["python", "node", "java"])
    if lang_pool == "python":
        snippet = rng.choice(PYTHON_WEAK_CRYPTO)
        lang_name = "Python"
    elif lang_pool == "node":
        snippet = rng.choice(NODE_WEAK_CRYPTO)
        lang_name = "JavaScript (Node.js)"
    else:
        snippet = rng.choice(JAVA_WEAK_CRYPTO)
        lang_name = "Java"

    app_context = rng.choice(APP_CONTEXTS)
    input_text = f"**Application:** {app_context.title()}\n"
    input_text += f"**Language:** {lang_name}\n"
    input_text += f"**Component:** {snippet['name']}\n\n"
    input_text += f"```\n{snippet['code']}\n```"

    output = f"## Cryptographic Security Analysis\n\n"
    output += f"**Component:** {snippet['name']}\n"
    output += f"**Language:** {lang_name}\n"
    output += f"**CWE:** {snippet['cwe']} ({CWE_DB.get(snippet['cwe'], {}).get('name', 'Cryptographic Issue')})\n\n"

    output += "### Vulnerabilities Identified\n\n"
    for i, issue in enumerate(snippet["issues"], 1):
        output += f"**{i}.** {issue}\n\n"

    output += "### Security Impact\n\n"
    impact_map = {
        "CWE-327": "Use of broken or weak cryptographic algorithms can lead to data exposure, authentication bypass, and compliance violations. "
                    "An attacker can recover plaintext data, forge authentication tokens, or break encrypted communications.",
        "CWE-330": "Predictable random values used for security-sensitive operations (tokens, keys, nonces) allow attackers to "
                    "predict future values and compromise authentication, session management, or encryption.",
        "CWE-329": "IV/nonce reuse in symmetric encryption destroys confidentiality guarantees. In CBC mode, it enables "
                    "plaintext recovery; in CTR/GCM modes, it completely breaks the encryption scheme.",
        "CWE-295": "Disabled certificate validation allows man-in-the-middle attacks. An attacker on the network path can "
                    "intercept, read, and modify all 'encrypted' communications.",
        "CWE-347": "Improper cryptographic signature verification allows forged tokens, tampered messages, and bypassed "
                    "authentication controls.",
        "CWE-916": "Weak password hashing allows offline brute-force attacks. Modern GPUs can test billions of MD5/SHA hashes per second.",
    }
    output += impact_map.get(snippet["cwe"], "This cryptographic weakness exposes the system to potential data compromise.") + "\n\n"

    output += "### Secure Implementation\n\n"
    output += f"```\n{snippet['fix']}\n```\n\n"

    output += "### Recommendations\n\n"
    general_recs = [
        "Use well-vetted cryptographic libraries (e.g., libsodium, cryptography.io) instead of rolling your own crypto",
        "Follow NIST guidelines for algorithm selection: AES-256-GCM for encryption, SHA-256+ for hashing, ECDSA/Ed25519 for signatures",
        "Store all cryptographic keys in a dedicated secrets manager (HashiCorp Vault, AWS KMS, Azure Key Vault)",
        "Implement key rotation policies with automated rotation where possible",
        "Use constant-time comparison functions for all cryptographic value comparisons to prevent timing attacks",
        "Generate all IVs, nonces, and salts using cryptographically secure random number generators",
        "Prefer authenticated encryption (AES-GCM, ChaCha20-Poly1305) over unauthenticated modes (CBC, CTR)",
        "Enforce TLS 1.2+ for all network communications and disable legacy protocols",
    ]
    for j, rec in enumerate(rng.sample(general_recs, rng.randint(4, 6)), 1):
        output += f"{j}. {rec}\n"

    return format_entry(
        entry_id=f"{prefix}-{idx:05d}",
        title=f"Crypto Analysis: {snippet['name']} in {lang_name}",
        severity=severity,
        cwe=snippet["cwe"],
        instruction=rng.choice(WEAK_CRYPTO_INSTRUCTIONS),
        input_text=input_text,
        output_text=output,
    )


def _generate_key_mgmt_entry(rng, complexity, idx, prefix):
    """Generate a key management analysis entry."""
    severity = pick_severity(rng, complexity)
    app_context = rng.choice(APP_CONTEXTS)

    key_scenarios = [
        {
            "name": "Hardcoded API keys in configuration",
            "code": '''# config.py
DATABASE_URL = "postgresql://admin:P@ssw0rd123@db.internal:5432/production"
STRIPE_SECRET_KEY = "sk_live_abc123def456ghi789"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
JWT_SECRET = "my-jwt-secret-key"
ENCRYPTION_KEY = "0123456789abcdef"''',
            "issues": [
                "Production credentials hardcoded in source code - exposed in version control history",
                "Database password in connection string - visible to anyone with code access",
                "Live API keys (Stripe) in configuration file - financial system compromise risk",
                "AWS credentials hardcoded - full cloud account compromise possible",
                "JWT secret too short and predictable - tokens can be forged",
                "Encryption key in plaintext - defeats the purpose of encryption",
            ],
            "cwe": "CWE-798",
        },
        {
            "name": "Weak key derivation for encryption",
            "code": '''import hashlib

def get_encryption_key(user_password):
    # Derive encryption key from user password
    return hashlib.sha256(user_password.encode()).digest()

def get_api_signing_key():
    # Use application name as signing key
    return b"my-application-name-v2"''',
            "issues": [
                "Single SHA-256 hash is not a proper key derivation function - no salt, no iteration",
                "API signing key is a static string - not randomly generated",
                "No key stretching makes brute-force attacks against password-derived keys feasible",
                "Key derivation should use PBKDF2, scrypt, or Argon2 with sufficient iterations",
            ],
            "cwe": "CWE-916",
        },
        {
            "name": "Symmetric key stored alongside encrypted data",
            "code": '''import json
from cryptography.fernet import Fernet

class DataStore:
    def __init__(self):
        self.key = Fernet.generate_key()
        self.cipher = Fernet(self.key)

    def save_encrypted(self, data, filepath):
        encrypted = self.cipher.encrypt(json.dumps(data).encode())
        # Save key and encrypted data together
        with open(filepath, 'wb') as f:
            f.write(self.key + b'\\n' + encrypted)

    def load_encrypted(self, filepath):
        with open(filepath, 'rb') as f:
            content = f.read()
        key, encrypted = content.split(b'\\n', 1)
        cipher = Fernet(key)
        return json.loads(cipher.decrypt(encrypted))''',
            "issues": [
                "Encryption key stored alongside encrypted data - anyone with file access can decrypt",
                "Key is regenerated on each DataStore instantiation - previously encrypted data becomes inaccessible",
                "No key rotation mechanism - key compromise has unlimited blast radius",
                "Key should be stored in a separate, access-controlled location (KMS, Vault, HSM)",
            ],
            "cwe": "CWE-321",
        },
    ]

    scenario = rng.choice(key_scenarios)

    input_text = f"**Application:** {app_context.title()}\n"
    input_text += f"**Component:** {scenario['name']}\n\n"
    input_text += f"```\n{scenario['code']}\n```"

    output = f"## Key Management Security Analysis\n\n"
    output += f"**Component:** {scenario['name']}\n"
    output += f"**CWE:** {scenario['cwe']} ({CWE_DB.get(scenario['cwe'], {}).get('name', 'Key Management Issue')})\n\n"

    output += "### Issues Identified\n\n"
    for i, issue in enumerate(scenario["issues"], 1):
        output += f"**{i}.** {issue}\n\n"

    output += "### Key Management Best Practices\n\n"
    practices = [
        "Store all secrets in a dedicated secrets manager (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault)",
        "Use environment variables or mounted secret files for runtime configuration - never hardcode",
        "Implement automated key rotation with defined rotation periods (90 days for symmetric keys)",
        "Use Hardware Security Modules (HSMs) for high-value key operations",
        "Implement key hierarchy: master keys protect data encryption keys (envelope encryption)",
        "Maintain a complete key inventory with ownership, purpose, and expiration tracking",
        "Use separate keys for separate purposes (encryption, signing, key wrapping)",
        "Implement secure key destruction procedures when keys are rotated or decommissioned",
        "Enable secret scanning in CI/CD pipelines to prevent credential commits (git-secrets, truffleHog)",
        "Use short-lived credentials and temporary security tokens where possible (STS, OIDC)",
    ]
    for j, practice in enumerate(rng.sample(practices, rng.randint(5, 8)), 1):
        output += f"{j}. {practice}\n"

    return format_entry(
        entry_id=f"{prefix}-{idx:05d}",
        title=f"Key Management: {scenario['name']}",
        severity=severity,
        cwe=scenario["cwe"],
        instruction=rng.choice(KEY_MGMT_INSTRUCTIONS),
        input_text=input_text,
        output_text=output,
    )


def _generate_cert_entry(rng, complexity, idx, prefix):
    """Generate a certificate/TLS analysis entry."""
    severity = pick_severity(rng, complexity)
    app_context = rng.choice(APP_CONTEXTS)
    config_item = rng.choice(TLS_CONFIGS)

    input_text = f"**Application:** {app_context.title()}\n"
    input_text += f"**Component:** {config_item['name']}\n\n"
    input_text += f"```\n{config_item['config']}\n```"

    output = f"## TLS/Certificate Security Analysis\n\n"
    output += f"**Component:** {config_item['name']}\n"
    output += f"**CWE:** {config_item['cwe']} ({CWE_DB.get(config_item['cwe'], {}).get('name', 'TLS Issue')})\n\n"

    output += "### Issues Identified\n\n"
    for i, issue in enumerate(config_item["issues"], 1):
        output += f"**{i}.** {issue}\n\n"

    output += "### Recommended TLS Configuration\n\n"
    output += "```\n"
    output += "# Secure TLS settings\n"
    output += "ssl_protocols TLSv1.2 TLSv1.3;\n"
    output += "ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
    output += "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;\n"
    output += "ssl_prefer_server_ciphers on;\n"
    output += "ssl_session_timeout 1d;\n"
    output += "ssl_session_cache shared:SSL:10m;\n"
    output += "ssl_stapling on;\n"
    output += "ssl_stapling_verify on;\n"
    output += 'add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";\n'
    output += "```\n\n"

    output += "### TLS Security Checklist\n\n"
    checklist = [
        "Disable TLSv1.0 and TLSv1.1 - use TLSv1.2 minimum, prefer TLSv1.3",
        "Use only AEAD cipher suites (GCM, ChaCha20-Poly1305)",
        "Enable HSTS with a long max-age and includeSubDomains",
        "Configure OCSP stapling for efficient revocation checking",
        "Disable TLS compression to prevent CRIME/BREACH attacks",
        "Use 2048-bit RSA or 256-bit ECDSA certificates minimum",
        "Implement certificate transparency (CT) logging",
        "Set up automated certificate renewal (Let's Encrypt / ACME)",
        "Prefer ECDHE key exchange for forward secrecy",
        "Test configuration with SSL Labs (aim for A+ rating)",
    ]
    for j, item in enumerate(rng.sample(checklist, rng.randint(5, 8)), 1):
        output += f"{j}. {item}\n"

    return format_entry(
        entry_id=f"{prefix}-{idx:05d}",
        title=f"TLS Analysis: {config_item['name']}",
        severity=severity,
        cwe=config_item["cwe"],
        instruction=rng.choice(CERT_INSTRUCTIONS),
        input_text=input_text,
        output_text=output,
    )


def _generate_protocol_entry(rng, complexity, idx, prefix):
    """Generate a protocol-level crypto analysis entry."""
    severity = pick_severity(rng, complexity)
    app_context = rng.choice(APP_CONTEXTS)

    protocol_scenarios = [
        {
            "name": "Protocol downgrade vulnerability",
            "scenario": f"A {app_context} communicates with backend services. The client-server handshake supports "
                       f"fallback to older protocol versions when the initial negotiation fails.",
            "issues": [
                "Protocol version fallback allows an active MITM attacker to force downgrade to a weaker version",
                "No mechanism (SCSV) to detect and prevent downgrade attacks",
                "Fallback to deprecated versions exposes known vulnerabilities in older protocols",
            ],
            "mitigations": [
                "Implement TLS_FALLBACK_SCSV to prevent protocol downgrade",
                "Set minimum acceptable protocol version and reject connections below it",
                "Monitor for downgrade attempts as a potential indicator of active attack",
            ],
            "cwe": "CWE-757",
        },
        {
            "name": "Timing side-channel in authentication",
            "scenario": f"A {app_context} verifies HMAC signatures on incoming API requests using standard "
                       f"string comparison to check the computed signature against the provided signature.",
            "issues": [
                "Standard string comparison (== operator) short-circuits on first mismatch - response time leaks information about correct bytes",
                "An attacker can iteratively guess the correct HMAC signature one byte at a time",
                "Over thousands of requests, statistical analysis of timing differences reveals the full signature",
            ],
            "mitigations": [
                "Use constant-time comparison functions (hmac.compare_digest in Python, crypto.timingSafeEqual in Node.js)",
                "Implement rate limiting to reduce the number of attempts an attacker can make",
                "Add random delay jitter to response times (defense-in-depth, not a primary mitigation)",
            ],
            "cwe": "CWE-208",
        },
        {
            "name": "Replay attack vulnerability",
            "scenario": f"A {app_context} uses signed tokens for API authentication. The tokens contain a user ID "
                       f"and permissions but no timestamp, nonce, or sequence number.",
            "issues": [
                "Tokens without expiration or nonce can be captured and replayed indefinitely",
                "A network-level attacker can record and replay valid authentication tokens",
                "Revoked tokens remain valid since there is no mechanism to check freshness",
            ],
            "mitigations": [
                "Include a short expiration time (exp) and issued-at timestamp (iat) in all tokens",
                "Add a unique nonce/jti claim to each token and maintain a server-side revocation list",
                "Implement token binding to the client TLS session or IP address",
                "Use refresh token rotation to detect token theft",
            ],
            "cwe": "CWE-294",
        },
    ]

    scenario = rng.choice(protocol_scenarios)

    input_text = f"**Application:** {app_context.title()}\n"
    input_text += f"**Issue:** {scenario['name']}\n\n"
    input_text += f"{scenario['scenario']}\n"

    output = f"## Protocol Security Analysis: {scenario['name']}\n\n"
    output += f"**CWE:** {scenario['cwe']}\n\n"

    output += "### Vulnerabilities\n\n"
    for i, issue in enumerate(scenario["issues"], 1):
        output += f"**{i}.** {issue}\n\n"

    output += "### Mitigations\n\n"
    for i, mit in enumerate(scenario["mitigations"], 1):
        output += f"{i}. {mit}\n"
    output += "\n"

    output += "### Additional Protocol Security Recommendations\n\n"
    output += "- Implement defense in depth: combine multiple controls rather than relying on a single mechanism\n"
    output += "- Use established protocol libraries rather than implementing crypto protocols from scratch\n"
    output += "- Conduct protocol-level fuzzing to discover edge cases in the implementation\n"
    output += "- Monitor for anomalous protocol behavior as an indicator of active attacks\n"

    return format_entry(
        entry_id=f"{prefix}-{idx:05d}",
        title=f"Protocol Analysis: {scenario['name']}",
        severity=severity,
        cwe=scenario["cwe"],
        instruction=rng.choice(PROTOCOL_INSTRUCTIONS),
        input_text=input_text,
        output_text=output,
    )


class CryptographyGenerator(CategoryGenerator):
    category = "cryptography"
    id_prefix = "xld-crypto"

    def generate_entries(self, rng: random.Random, count: int, start_id: int,
                         complexity_weights) -> List[Dict[str, Any]]:
        entries = []
        # Distribute: 35% weak crypto, 25% key mgmt, 20% cert/TLS, 20% protocol
        weak_count = int(count * 0.35)
        key_count = int(count * 0.25)
        cert_count = int(count * 0.20)
        proto_count = count - weak_count - key_count - cert_count

        idx = start_id
        for _ in range(weak_count):
            complexity = pick_complexity(rng, complexity_weights)
            entries.append(_generate_weak_crypto_entry(rng, complexity, idx, self.id_prefix))
            idx += 1

        for _ in range(key_count):
            complexity = pick_complexity(rng, complexity_weights)
            entries.append(_generate_key_mgmt_entry(rng, complexity, idx, self.id_prefix))
            idx += 1

        for _ in range(cert_count):
            complexity = pick_complexity(rng, complexity_weights)
            entries.append(_generate_cert_entry(rng, complexity, idx, self.id_prefix))
            idx += 1

        for _ in range(proto_count):
            complexity = pick_complexity(rng, complexity_weights)
            entries.append(_generate_protocol_entry(rng, complexity, idx, self.id_prefix))
            idx += 1

        return entries
