"""Module which convert a R&S ECDSA signature into asn1 format."""

# Victor Näslund <vinas003@gmail.com> 2022

def convert_ecdsa_signature_format(signature: bytes, key_type: str) -> bytes:
    """Convert a R&S format ECDSA signature into asn1 format.

    For context look here:
    https://stackoverflow.com/questions/66101825/asn-1-structure-of-ecdsa-signature-in-x-509-certificate

    Paramters:
    signature (bytes): The signature.
    key_type (str): Key type. Currently one of ["secp256r1", "secp384r1", "secp521r1"]

    Returns:
    bytes
    """

    asn1_integer_code = 2
    asn1_init = bytearray([48])

    if key_type in ["secp521r1"]:
        asn1_init.append(129)

    r_length = int(len(signature) / 2)
    s_length = int(len(signature) / 2)

    r_data = signature[:r_length]
    s_data = signature[r_length:]

    # Remove leading zeros, since integers cant start with a 0
    if len(signature) % 8 != 0:
        while r_data[0] == 0:
            r_data = r_data[1:]
            r_length -= 1
        while s_data[0] == 0:
            s_data = s_data[1:]
            s_length -= 1

    # Ensure the integers are postive numbers
    if not r_data[0] < 128:
        r_data = bytearray([0]) + r_data[:]
        r_length += 1

    if not s_data[0] < 128:
        s_data = bytearray([0]) + s_data[:]
        s_length += 1

    return bytes(
        asn1_init
        + bytearray([r_length + s_length + 4])
        + bytearray([asn1_integer_code, r_length])
        + r_data
        + bytearray([asn1_integer_code, s_length])
        + s_data
    )
