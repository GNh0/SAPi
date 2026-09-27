"""Local operator PKI bootstrap and certificate enrollment, never bundled keys."""
import datetime
import hashlib
import ipaddress
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from .files import private_directory, write_private
from sapi.constants import NAME


def fingerprint(certificate):
    return certificate.fingerprint(hashes.SHA256()).hex()


def _save(directory, name, key, certificate):
    write_private(directory / (name + ".key"), key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    write_private(directory / (name + ".pem"), certificate.public_bytes(serialization.Encoding.PEM))


def create_ca(directory):
    directory = private_directory(directory)
    key = ec.generate_private_key(ec.SECP256R1()); now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SAPI operator CA")])
    certificate = x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=1)).not_valid_after(now + datetime.timedelta(days=1095)).add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True).add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True).sign(key, hashes.SHA256())
    _save(directory, "ca", key, certificate)


def enroll(directory, name, *, host=None, output_directory=None):
    if not isinstance(name,str) or not NAME.fullmatch(name):raise ValueError("valid certificate name required")
    directory = Path(directory)
    ca = x509.load_pem_x509_certificate((directory / "ca.pem").read_bytes())
    ca_key = serialization.load_pem_private_key((directory / "ca.key").read_bytes(), password=None)
    key = ec.generate_private_key(ec.SECP256R1()); now = datetime.datetime.now(datetime.timezone.utc)
    builder = x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])).issuer_name(ca.subject).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=1)).not_valid_after(now + datetime.timedelta(days=30)).add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True).add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True).add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH if host else ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
    if host:
        try: entry = x509.IPAddress(ipaddress.ip_address(host))
        except ValueError: entry = x509.DNSName(host)
        builder = builder.add_extension(x509.SubjectAlternativeName([entry]), critical=False)
    certificate = builder.sign(ca_key, hashes.SHA256()); _save(private_directory(output_directory) if output_directory else directory, name, key, certificate)
    return fingerprint(certificate)
