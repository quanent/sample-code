import base64
from cryptography import x509
from cryptography.hazmat.primitives import serialization

# Sample JWKS x5c entry
jwks = {
    "keys": [
        {
            "kty": "RSA",
            "use": "sig",
            "kid": "1b94c",
            "x5t": "1b94c",
            "x5c": [
                "MIIDQzCCAqygAwIBAgIGANiDqDRzMA0GCSqGSIb3DQEBBQUAMGIxCzAJBgNVBAYTAlVTMRYwFAYD
                 VQQKEw1FeGFtcGxlIEluYy4xEDAOBgNVBAsTB0V4YW1wbGUxEDAOBgNVBAMTB0V4YW1wbGUxHTAb
                 BgkqhkiG9w0BCQEWDmV4YW1wbGUuY29tMB4XDTExMDEwMTAwMDAwMFoXDTIxMDEwMTAwMDAwMFow
                 YjELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUV4YW1wbGUgSW5jLjEQMA4GA1UECxMHRXhhbXBsZTEQ
                 MA4GA1UEAxMHZXhhbXBsZTEdMBsGCSqGSIb3DQEJARYOZXhhbXBsZUBleGFtcGxlLmNvbTCCASIw
                 DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK8AP6o6LzW68FZXF4c3gU1q4szU2NyZf2fsBF2x
                 7L8Hi7vh5PS3LVC1b9nkg4QQoVROv4iHCJPC6vQL1Pjk7Xb48tcdiR8H5E0pHpZZy7yRQU5R4ZSy
                 hmXP8KszV39um7ROnPEA0iE7okFOqhFKaBFPQ8x4+8bRbLNRvT+Ajc8Vq0XZJHJs4H0kCkgvB3T1
                 VLk0t3ZXMyZ7RHZ8o5JZmjdsKEzxv5kjFWzQXoX66Kq3KUD44C5tNqIl4HN6mygrm0P2HFz3txa6
                 Oq65LqJYVJ+Gdi5q9NVJggJlD2lD7q3BGN45SGH56uB7g6t5sUdL0z4MeTmOhJX7PqBaTyPYMCOU
                 RIECAwEAAaMjMCEwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQIwDQYJKoZIhvcN
                 AQEFBQADggEBABRmaQoea2f32wGxdm/S4JN7r2nV0Dk54RCeyyptc6FZp4U9gKm3aIDR4/XHWH/k
                 +X9G4BgqOqaDOP1g6Txz+1WlKHeaN1x6fUpxvtwutVJW0GgM4K6g/7p9cq7YFDmaXlDXD5w1Un5x
                 k1lw20h3f2RVOJ9vDafhe2l7r4+a1Q+YYPOFhA2N0L5nBWVndppkOnUKu+EXr3nJpxzTNWs3mB4c
                 ES7Cke+IOJJ8/x4hy9RRMZf7zBB9F3vWeKBlQpAapStn6w3xqPi3PjFq5uJ3/p0YEekEVC6E3l5z
                 +f9AubS1Zz7TzL2P+8KFPwxg2SvF0V9hHD+XllXU5P8Cd6ShnwqKpjQ=",
                # Add additional certificates if needed
            ]
        }
    ]
}

def convert_x5c_to_pem(jwks):
    # Get the first x5c entry
    x5c_base64 = jwks["keys"][0]["x5c"][0]

    # Decode the base64-encoded certificate
    x5c_der = base64.b64decode(x5c_base64)

    # Load the certificate using cryptography
    certificate = x509.load_der_x509_certificate(x5c_der)

    # Convert the certificate to PEM format
    pem_certificate = certificate.public_bytes(serialization.Encoding.PEM)

    return pem_certificate.decode("utf-8")

# Convert and print the PEM format certificate
pem_certificate = convert_x5c_to_pem(jwks)
print(pem_certificate)

