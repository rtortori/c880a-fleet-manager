"""Validated HTTPS deployment material kept in the private data directory."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import ssl
import tempfile
import uuid
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID


MAX_PEM = 128 * 1024


def host_name(value: str) -> str:
    """A bare DNS name or IP; URL syntax and IPv6 brackets are not stored."""
    value = value.strip().strip("[]")
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        if (len(value) > 253 or not value or not all(
                re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
                for label in value.split("."))):
            raise ValueError("Enter a DNS name or IP address") from None
        return value.lower()
    if address.is_link_local:
        raise ValueError("Link-local addresses cannot be used for deployment")
    return str(address)


def url_host(value: str) -> str:
    return f"[{value}]" if ":" in value else value


def local_addresses() -> list[str]:
    """Only actual interface addresses are offered; wildcard binds are excluded."""
    return [entry["address"] for entry in local_interface_options()]


def listener_address(value: str) -> str:
    """A concrete local address; link-local addresses cannot be deployment listeners."""
    address = ipaddress.ip_address(value)
    if address.is_link_local:
        raise ValueError("Link-local addresses cannot be used for deployment")
    normalized = str(address)
    if normalized not in local_addresses():
        raise ValueError("Listener must use an address on a current local interface")
    return normalized


def local_interface_options() -> list[dict[str, str]]:
    """Show interface identity separately from the address stored for binding."""
    addresses = {"127.0.0.1": "Loopback", "::1": "Loopback"}
    try:
        import psutil
        for interface, entries in psutil.net_if_addrs().items():
            for entry in entries:
                if entry.family in (socket.AF_INET, socket.AF_INET6):
                    candidate = entry.address.split("%", 1)[0]
                    try:
                        address = ipaddress.ip_address(candidate)
                    except ValueError:
                        continue
                    if not (address.is_unspecified or address.is_multicast or address.is_link_local):
                        addresses[str(address)] = interface
    except ImportError:
        pass
    return [{"address": address, "interface": addresses[address]}
            for address in sorted(addresses, key=lambda item: (
                not ipaddress.ip_address(item).is_loopback, item))]


def validate_certificate(cert_pem: bytes, key_pem: bytes, chain_pem: bytes,
                         hosts: list[str]) -> dict[str, str]:
    if any(len(item) > MAX_PEM for item in (cert_pem, key_pem, chain_pem)):
        raise ValueError("Certificate material is too large")
    try:
        certificate = x509.load_pem_x509_certificate(cert_pem)
        leaf = certificate
        key = serialization.load_pem_private_key(key_pem, password=None)
        if key.public_key().public_bytes(serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo) != certificate.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo):
            raise ValueError("Certificate and private key do not match")
        if not isinstance(key, (ec.EllipticCurvePrivateKey, rsa.RSAPrivateKey)) or (
                isinstance(key, rsa.RSAPrivateKey) and key.key_size < 2048) or (
                isinstance(key, ec.EllipticCurvePrivateKey) and key.key_size < 256):
            raise ValueError("Certificate private key is too weak")
        now = datetime.now(timezone.utc)
        if not certificate.not_valid_before_utc <= now < certificate.not_valid_after_utc:
            raise ValueError("Certificate is outside its validity period")
        if certificate.signature_hash_algorithm and certificate.signature_hash_algorithm.name.lower() in ("sha1", "md5"):
            raise ValueError("Certificate uses a weak signature")
        names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        dns = {name.lower() for name in names.get_values_for_type(x509.DNSName)}
        ips = set(names.get_values_for_type(x509.IPAddress))
        for host in hosts:
            host = host_name(host)
            try:
                covered = ipaddress.ip_address(host) in ips
            except ValueError:
                covered = host in dns or any(host.endswith(name[1:]) and host.count(".") == name.count(".") for name in dns if name.startswith("*."))
            if not covered:
                raise ValueError(f"Certificate SAN does not cover {host}")
        # Let OpenSSL parse the complete chain and reject malformed PEM blocks.
        for part in chain_pem.split(b"-----END CERTIFICATE-----"):
            if part.strip():
                issuer = x509.load_pem_x509_certificate(part.strip() + b"\n-----END CERTIFICATE-----\n")
                if not issuer.not_valid_before_utc <= now < issuer.not_valid_after_utc:
                    raise ValueError("Certificate chain contains a certificate outside its validity period")
                if not issuer.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
                    raise ValueError("Certificate chain contains a non-CA certificate")
                if issuer.subject != certificate.issuer:
                    raise ValueError("Certificate chain is not ordered from the leaf issuer")
                try:
                    certificate.verify_directly_issued_by(issuer)
                except (InvalidSignature, ValueError) as exc:
                    raise ValueError("Certificate chain signature is invalid") from exc
                certificate = issuer
        with tempfile.TemporaryDirectory() as temporary:
            cert_path, key_path = Path(temporary) / "cert.pem", Path(temporary) / "key.pem"
            cert_path.write_bytes(cert_pem + b"\n" + chain_pem)
            key_path.write_bytes(key_pem)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert_path, key_path)
        return {"expires_at": leaf.not_valid_after_utc.isoformat(),
                "fingerprint": leaf.fingerprint(hashes.SHA256()).hex()}
    except (TypeError, AttributeError, ValueError, ssl.SSLError,
            UnsupportedAlgorithm, x509.ExtensionNotFound) as exc:
        raise ValueError(str(exc) or "Invalid certificate material") from None


def generate_certificate(hosts: list[str]) -> tuple[bytes, bytes]:
    hosts = list(dict.fromkeys(host_name(host) for host in hosts))
    key = ec.generate_private_key(ec.SECP256R1())
    names = []
    for host in hosts:
        try:
            names.append(x509.IPAddress(ipaddress.ip_address(host)))
        except ValueError:
            names.append(x509.DNSName(host))
    now = datetime.now(timezone.utc)
    try:
        expires = now.replace(year=now.year + 10)
    except ValueError:  # Leap-day issuance expires on February 28 ten years later.
        expires = now.replace(year=now.year + 10, day=28)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hosts[0])])
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5)).not_valid_after(expires)
            .add_extension(x509.SubjectAlternativeName(names), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    return (cert.public_bytes(serialization.Encoding.PEM),
            key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption()))


def write_private(path: Path, value: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(value)
        output.flush()
        os.fsync(output.fileno())


def stage_certificate(data_dir: Path, cert: bytes, key: bytes, chain: bytes,
                      hosts: list[str], source: str) -> dict[str, str]:
    details = validate_certificate(cert, key, chain, hosts)
    directory = data_dir / "certificates" / uuid.uuid4().hex
    directory.mkdir(parents=True, mode=0o700)
    try:
        write_private(directory / "server.pem", cert + b"\n" + chain)
        write_private(directory / "server.key", key)
        write_private(directory / "source.json", json.dumps({"source": source, **details}).encode())
        return {"cert": str(directory / "server.pem"), "key": str(directory / "server.key"),
                "source": source, **details}
    except BaseException:
        for child in directory.iterdir():
            child.unlink()
        directory.rmdir()
        raise


def validate_ca_bundle(pem: bytes) -> None:
    if not pem or len(pem) > MAX_PEM:
        raise ValueError("CA bundle is empty or too large")
    parts = pem.split(b"-----END CERTIFICATE-----")
    if parts[-1].strip() or len(parts) < 2:
        raise ValueError("Expected PEM CA certificates")
    for part in parts[:-1]:
        try:
            certificate = x509.load_pem_x509_certificate(part.strip() + b"\n-----END CERTIFICATE-----\n")
            now = datetime.now(timezone.utc)
            if not certificate.not_valid_before_utc <= now < certificate.not_valid_after_utc:
                raise ValueError("CA certificate is outside its validity period")
            if not certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
                raise ValueError("Bundle contains a non-CA certificate")
        except (ValueError, x509.ExtensionNotFound) as exc:
            raise ValueError(str(exc) or "Invalid CA certificate") from None


def read_config(data_dir: Path, *, pending: bool = False, name: str | None = None) -> dict:
    path = data_dir / (name or ("deployment.pending.json" if pending else "deployment.json"))
    return json.loads(path.read_text()) if path.exists() else {}


def atomic_config(data_dir: Path, name: str, values: dict) -> None:
    path = data_dir / name
    temporary = data_dir / (name + "." + uuid.uuid4().hex + ".tmp")
    write_private(temporary, json.dumps(values, sort_keys=True).encode())
    os.replace(temporary, path)
    descriptor = os.open(data_dir, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def validate_network(values: dict, *, occupied_ports: set[int] | None = None) -> dict:
    """Validate one complete deployment proposal before it reaches a listener."""
    values = values.copy()
    for field in ("manager_bind", "exporter_bind", "console_bind"):
        try:
            values[field] = listener_address(values[field])
        except ValueError as exc:
            raise ValueError(f"{field}: {exc}") from None
    for field in ("manager_host", "exporter_host", "console_host"):
        values[field] = host_name(values[field])
    if values["manager_host"] != values["console_host"]:
        raise ValueError("Manager and console must advertise the same host for session cookies")
    start, end = values["port_start"], values["port_end"]
    manager_port, offset = values["manager_port"], values["console_port_offset"]
    if not all(isinstance(number, int) and not isinstance(number, bool) for number in
               (start, end, manager_port, offset)):
        raise ValueError("Ports must be integers")
    if not (1 <= start <= end <= 65535 and 1 <= manager_port <= 65535
            and 1 <= start + offset <= end + offset <= 65535):
        raise ValueError("Invalid exporter or console port range")
    exporter_ports = set(range(start, end + 1))
    console_ports = {port + offset for port in exporter_ports}
    if exporter_ports & console_ports or manager_port in exporter_ports | console_ports:
        raise ValueError("Manager, exporter, and console ports overlap")
    if occupied_ports and not occupied_ports <= exporter_ports:
        raise ValueError("Existing exporter ports would leave the selected range")
    expected = f"https://{url_host(values['manager_host'])}:{manager_port}"
    origin = values.get("manager_origin", expected)
    parsed = urlsplit(origin)
    if (origin != expected or parsed.scheme != "https" or parsed.hostname != values["manager_host"]):
        raise ValueError("Manager origin must be the derived HTTPS URL")
    values["manager_origin"] = expected
    return values
