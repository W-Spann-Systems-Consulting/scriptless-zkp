"""
Test examples for the KMAC-based eXtendable Output Functions (XOF) `KMACXOF128` and `KMACXOF256`.
"""
from scriptless_zkp.mac.kmac_xof import KMACXOF128, KMAC_XOF
from secrets import token_bytes


kmac_key: bytes = token_bytes(32)
print(f"Randomly generated KMAC key (32 bytes): {kmac_key.hex()}")

data_to_mac: str = "I don't like Spam!"
domain_sep_utf8: bytes = "separator-of-domains".encode('utf-8')
kmac_xof: KMAC_XOF = KMACXOF128.new(kmac_key, data=data_to_mac.encode('utf-8'), custom=domain_sep_utf8)
print(
    f"Initialized KMACXOF128 with random ({len(kmac_key)} B) secret key, test data: '{data_to_mac}', and domain"
    f" separator (custom) string: '{domain_sep_utf8.decode('utf-8')}': {type(kmac_xof).__qualname__}."
)

sub_key1: bytes = kmac_xof.read(32)
print(f"Derived sub-key #1 (32 bytes) from KMACXOF128: {sub_key1.hex()}")

sub_key2: bytes = kmac_xof.read(64)
print(f"Derived sub-key #2 (64 bytes) from KMACXOF128: {sub_key2.hex()}")
