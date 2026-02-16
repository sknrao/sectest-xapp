"""
Certificate utility functions for xApp certificate validation

Validates O-RAN compliance:
- SEC-CTL-NEAR-RT-12: xApp ID embedded in X.509 certificate
- SEC-CTL-NEAR-RT-13: UUID v4 format for xApp ID
- SEC-CTL-NEAR-RT-14: subjectAltName URI-ID with UUID
"""

import uuid
import logging
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger(__name__)


def load_certificate(cert_path):
    """
    Load X.509 certificate from PEM file
    
    Args:
        cert_path: Path to PEM certificate file
        
    Returns:
        x509.Certificate object
        
    Raises:
        FileNotFoundError: If certificate file doesn't exist
        ValueError: If certificate format is invalid
    """
    try:
        with open(cert_path, 'rb') as f:
            cert_data = f.read()
        
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())
        return cert
    except FileNotFoundError:
        logger.error(f"Certificate file not found: {cert_path}")
        raise
    except Exception as e:
        logger.error(f"Failed to load certificate: {e}")
        raise ValueError(f"Invalid certificate format: {e}")


def validate_xapp_cert(cert_path):
    """
    Validate xApp certificate structure per O-RAN requirements
    
    Tests:
    - SEC-CTL-NEAR-RT-12: xApp ID in certificate
    - SEC-CTL-NEAR-RT-13: UUID v4 format
    - SEC-CTL-NEAR-RT-14: subjectAltName URI-ID
    
    Args:
        cert_path: Path to xApp certificate file
        
    Returns:
        Tuple of (is_valid: bool, message: str, xapp_id: str or None)
    """
    try:
        cert = load_certificate(cert_path)
        
        # Check for subjectAltName extension
        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        except x509.ExtensionNotFound:
            return False, "No subjectAltName extension found", None
        
        # Look for URI-ID in subjectAltName
        xapp_id = None
        uri_found = False
        
        for name in san_ext.value:
            if isinstance(name, x509.UniformResourceIdentifier):
                uri = name.value
                uri_found = True
                
                # Check if it's a URN with UUID format (SEC-CTL-NEAR-RT-14)
                if uri.startswith('urn:uuid:'):
                    uuid_str = uri.replace('urn:uuid:', '')
                    
                    try:
                        # Validate UUID v4 (SEC-CTL-NEAR-RT-13)
                        parsed_uuid = uuid.UUID(uuid_str, version=4)
                        xapp_id = uuid_str
                        
                        logger.info(f"Valid xApp certificate: UUID={xapp_id}")
                        return True, "Valid xApp certificate with UUID v4", xapp_id
                        
                    except ValueError as e:
                        logger.warning(f"Invalid UUID format in certificate: {uuid_str}")
                        return False, f"Invalid UUID format: {e}", None
                else:
                    logger.warning(f"URI found but not in urn:uuid: format: {uri}")
        
        if uri_found:
            return False, "URI found in SAN but not in correct urn:uuid: format", None
        else:
            return False, "No URI found in subjectAltName", None
            
    except Exception as e:
        logger.error(f"Certificate validation error: {e}")
        return False, f"Validation error: {e}", None


def extract_xapp_id(cert_path):
    """
    Extract xApp ID (UUID) from certificate
    
    Args:
        cert_path: Path to certificate file
        
    Returns:
        xApp ID (UUID string) or None if not found
    """
    is_valid, message, xapp_id = validate_xapp_cert(cert_path)
    
    if is_valid:
        return xapp_id
    else:
        logger.warning(f"Could not extract xApp ID: {message}")
        return None


def get_cert_expiry(cert_path):
    """
    Get certificate expiration date
    
    Args:
        cert_path: Path to certificate file
        
    Returns:
        datetime object with expiration date
    """
    cert = load_certificate(cert_path)
    return cert.not_valid_after_utc


def get_cert_validity_period(cert_path):
    """
    Get certificate validity period
    
    Args:
        cert_path: Path to certificate file
        
    Returns:
        Tuple of (not_before: datetime, not_after: datetime)
    """
    cert = load_certificate(cert_path)
    return cert.not_valid_before_utc, cert.not_valid_after_utc


def check_cert_expiry(cert_path, warn_days=30):
    """
    Check if certificate is expired or expiring soon
    
    Args:
        cert_path: Path to certificate file
        warn_days: Number of days before expiry to warn
        
    Returns:
        Dict with status information:
        {
            'expired': bool,
            'expiring_soon': bool,
            'days_until_expiry': int,
            'expiry_date': datetime
        }
    """
    cert = load_certificate(cert_path)
    now = datetime.now(timezone.utc)
    expiry = cert.not_valid_after_utc
    
    days_until_expiry = (expiry - now).days
    
    result = {
        'expired': days_until_expiry < 0,
        'expiring_soon': 0 <= days_until_expiry <= warn_days,
        'days_until_expiry': days_until_expiry,
        'expiry_date': expiry,
        'valid_from': cert.not_valid_before_utc
    }
    
    if result['expired']:
        logger.error(f"Certificate expired {abs(days_until_expiry)} days ago")
    elif result['expiring_soon']:
        logger.warning(f"Certificate expiring in {days_until_expiry} days")
    else:
        logger.info(f"Certificate valid for {days_until_expiry} more days")
    
    return result


def get_cert_subject(cert_path):
    """
    Get certificate subject information
    
    Args:
        cert_path: Path to certificate file
        
    Returns:
        Dict with subject fields
    """
    cert = load_certificate(cert_path)
    
    subject_dict = {}
    for attribute in cert.subject:
        subject_dict[attribute.oid._name] = attribute.value
    
    return subject_dict


def get_cert_issuer(cert_path):
    """
    Get certificate issuer information
    
    Args:
        cert_path: Path to certificate file
        
    Returns:
        Dict with issuer fields
    """
    cert = load_certificate(cert_path)
    
    issuer_dict = {}
    for attribute in cert.issuer:
        issuer_dict[attribute.oid._name] = attribute.value
    
    return issuer_dict


def get_cert_serial_number(cert_path):
    """
    Get certificate serial number
    
    Args:
        cert_path: Path to certificate file
        
    Returns:
        Serial number as hex string
    """
    cert = load_certificate(cert_path)
    return hex(cert.serial_number)


def get_cert_info(cert_path):
    """
    Get comprehensive certificate information
    
    Args:
        cert_path: Path to certificate file
        
    Returns:
        Dict with all certificate details
    """
    cert = load_certificate(cert_path)
    
    # Validate xApp compliance
    is_valid, validation_msg, xapp_id = validate_xapp_cert(cert_path)
    
    # Get expiry info
    expiry_info = check_cert_expiry(cert_path)
    
    info = {
        'subject': get_cert_subject(cert_path),
        'issuer': get_cert_issuer(cert_path),
        'serial_number': get_cert_serial_number(cert_path),
        'valid_from': cert.not_valid_before_utc.isoformat(),
        'valid_until': cert.not_valid_after_utc.isoformat(),
        'days_until_expiry': expiry_info['days_until_expiry'],
        'expired': expiry_info['expired'],
        'expiring_soon': expiry_info['expiring_soon'],
        'xapp_compliant': is_valid,
        'xapp_id': xapp_id,
        'validation_message': validation_msg,
        'signature_algorithm': cert.signature_algorithm_oid._name,
        'version': cert.version.name
    }
    
    return info


def verify_cert_chain(cert_path, ca_cert_path):
    """
    Verify certificate is signed by CA
    
    Args:
        cert_path: Path to certificate to verify
        ca_cert_path: Path to CA certificate
        
    Returns:
        Tuple of (is_valid: bool, message: str)
    """
    try:
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives import hashes
        
        cert = load_certificate(cert_path)
        ca_cert = load_certificate(ca_cert_path)
        
        # Verify issuer matches
        if cert.issuer != ca_cert.subject:
            return False, "Certificate issuer does not match CA subject"
        
        # Verify signature
        try:
            ca_public_key = ca_cert.public_key()
            ca_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm
            )
            return True, "Certificate chain valid"
        except Exception as e:
            return False, f"Signature verification failed: {e}"
            
    except Exception as e:
        logger.error(f"Certificate chain verification error: {e}")
        return False, f"Verification error: {e}"


if __name__ == "__main__":
    # Test certificate utilities
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python cert_utils.py <certificate_path>")
        sys.exit(1)
    
    cert_path = sys.argv[1]
    
    print(f"Analyzing certificate: {cert_path}")
    print("=" * 60)
    
    info = get_cert_info(cert_path)
    
    for key, value in info.items():
        print(f"{key}: {value}")