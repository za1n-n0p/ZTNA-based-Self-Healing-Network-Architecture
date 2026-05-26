from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import ipaddress, pathlib

key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, u"ZeroTrust-NS-Project"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"NS Project"),
])
cert = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.now(timezone.utc))
    .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
    .add_extension(x509.SubjectAlternativeName([
        x509.IPAddress(ipaddress.IPv4Address("192.168.50.1")),
        x509.IPAddress(ipaddress.IPv4Address("192.168.50.135")),
        x509.DNSName(u"localhost"),
    ]), critical=False)
    .sign(key, hashes.SHA256())
)
base = pathlib.Path(__file__).parent
(base / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
(base / "key.pem").write_bytes(key.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.TraditionalOpenSSL,
    serialization.NoEncryption(),
))
print("cert.pem and key.pem generated successfully.")
