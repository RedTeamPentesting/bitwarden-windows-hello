#!/usr/bin/env python3

########################################
#                                      #
#  RedTeam Pentesting GmbH             #
#  kontakt@redteam-pentesting.de       #
#  https://www.redteam-pentesting.de/  #
#                                      #
########################################


import dataclasses
import json
import sys
import typing
import uuid
from base64 import b64decode

import click
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.padding import MGF1, OAEP
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.padding import PKCS7


@dataclasses.dataclass
class BitwardenCipher:
    enc_type: int
    data: bytes
    iv: bytes | None = None
    mac: bytes | None = None

    def decrypt(self, key: bytes) -> bytes:
        # validate HMAC
        if self.mac and self.enc_type in [1, 2]:
            assert self.iv is not None
            hmac = HMAC(key[32:], algorithm=hashes.SHA256())
            hmac.update(self.iv)
            hmac.update(self.data)

            if hmac.finalize() != self.mac:
                raise Exception("hmac mismatch")

        # decrypt
        if self.enc_type in [0, 1, 2]:
            assert self.iv is not None
            aes = Cipher(algorithms.AES(key[:32]), modes.CBC(self.iv)).decryptor()
            plain_with_padding = aes.update(self.data) + aes.finalize()
            unpadder = PKCS7(128).unpadder()
            return unpadder.update(plain_with_padding) + unpadder.finalize()
        elif self.enc_type in [3, 5]:
            private_key = serialization.load_der_private_key(key, password=None)
            assert isinstance(private_key, RSAPrivateKey)
            return private_key.decrypt(
                self.data,
                OAEP(
                    mgf=MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        elif self.enc_type in [4, 6]:
            private_key = serialization.load_der_private_key(key, password=None)
            assert isinstance(private_key, RSAPrivateKey)
            return private_key.decrypt(
                self.data,
                OAEP(
                    mgf=MGF1(algorithm=hashes.SHA1()),
                    algorithm=hashes.SHA1(),
                    label=None,
                ),
            )
        else:
            raise ValueError(f"unsupported encryption type {self.enc_type}")


def cipher_from_str(cipher_string: str) -> BitwardenCipher:
    enc_type, rest = cipher_string.split(".", 1)
    enc_type = int(enc_type)
    splitted = rest.split("|")

    if enc_type == 0:
        return BitwardenCipher(
            enc_type=enc_type, iv=b64decode(splitted[0]), data=b64decode(splitted[1])
        )
    elif enc_type == 1 or enc_type == 2:
        return BitwardenCipher(
            enc_type=enc_type,
            iv=b64decode(splitted[0]),
            data=b64decode(splitted[1]),
            mac=b64decode(splitted[2]),
        )
    elif enc_type == 3 or enc_type == 4:
        return BitwardenCipher(enc_type=enc_type, data=b64decode(splitted[0]))
    elif enc_type == 5 or enc_type == 6:
        return BitwardenCipher(
            enc_type=enc_type, data=b64decode(splitted[0]), mac=b64decode(splitted[1])
        )
    else:
        raise ValueError(f"unsupported encryption type {enc_type}")


def is_valid_uuid(uuid_to_test, version=4) -> bool:
    try:
        uuid_obj = uuid.UUID(uuid_to_test, version=version)
    except ValueError:
        return False
    return str(uuid_obj) == uuid_to_test


def read_bitwarden_data_file(filename: str) -> typing.Dict:
    with open(filename, "r") as f:
        raw = f.read()
    return json.loads(raw)


def get_first_user(data: typing.Dict) -> typing.Dict:
    for key in data.keys():
        if is_valid_uuid(key):
            return data[key]
    raise RuntimeError("could not retrieve first user")


def decrypt_encryption_key(user_section: typing.Dict, key: bytes) -> bytes:
    cipher = cipher_from_str(user_section["keys"]["cryptoSymmetricKey"]["encrypted"])

    # if cryptoSymmetricKey uses encryption with HMAC, the derived key is stretched using HKDF
    if cipher.mac:
        key = stretch_key(key)

    return cipher.decrypt(key)


def decrypt_rsa_key(user_section: typing.Dict, enc_key: bytes):
    cipher = cipher_from_str(user_section["keys"]["privateKey"]["encrypted"])
    return cipher.decrypt(enc_key)


def organization_keys(user_section: typing.Dict, rsa_key: bytes) -> typing.Dict:
    orgs = {}
    org_key_section: typing.Dict = user_section["keys"]["organizationKeys"]["encrypted"]

    for org_key in org_key_section.keys():
        if is_valid_uuid(org_key):
            cipher = cipher_from_str(org_key_section[org_key]["key"])
            orgs[org_key] = cipher.decrypt(rsa_key)

    return orgs


def decrypt_cipher_block(
    block: typing.Dict, enc_key: bytes, orgs: typing.Dict
) -> typing.Dict:
    decrypted = {}

    key = enc_key

    if block.get("organizationId") and len(block["organizationId"]) > 0:
        key = orgs[block["organizationId"]]
        decrypted["organizationId"] = block["organizationId"]

    if block.get("name"):
        decrypted["name"] = cipher_from_str(block["name"]).decrypt(key).decode("utf-8")

    if block.get("notes"):
        decrypted["notes"] = (
            cipher_from_str(block["notes"]).decrypt(key).decode("utf-8")
        )

    if block.get("login"):
        login = {}

        if block["login"].get("username"):
            login["username"] = (
                cipher_from_str(block["login"]["username"]).decrypt(key).decode("utf-8")
            )

        if block["login"].get("password"):
            login["password"] = (
                cipher_from_str(block["login"]["password"]).decrypt(key).decode("utf-8")
            )

        if block["login"].get("uris"):
            decrypted_uris = []
            for uriblock in block["login"]["uris"]:
                if uriblock.get("uri"):
                    decrypted_uris.append(
                        cipher_from_str(uriblock["uri"]).decrypt(key).decode("utf-8")
                    )

            login["uris"] = decrypted_uris

        decrypted["login"] = login

    return decrypted


def decrypt_user_passwords(user_section: typing.Dict, enc_key: bytes) -> list[dict]:
    rsa = decrypt_rsa_key(user_section, enc_key)
    orgs = organization_keys(user_section, rsa)
    cipher_sections: typing.Dict = user_section["data"]["ciphers"]["encrypted"]

    decrypted_blocks = []
    for _, section in cipher_sections.items():
        decrypted_blocks.append(decrypt_cipher_block(section, enc_key, orgs))

    return decrypted_blocks


def derive_key(email: str, password: str, iterations: int) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=email.encode("utf-8"),
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))


def stretch_key(key: bytes) -> bytes:
    hkdfKey = HKDFExpand(algorithm=hashes.SHA256(), length=32, info=b"enc")
    hkdfMacKey = HKDFExpand(algorithm=hashes.SHA256(), length=32, info=b"mac")
    return hkdfKey.derive(key) + hkdfMacKey.derive(key)


@click.command()
@click.option("--password", default=None)
@click.option("--biometric", default=None)
@click.argument("filename")
def main(
    password: str,
    biometric: str,
    filename: str,
):
    if not password and not biometric:
        print("Specifiy either password or biometric key")
        sys.exit(1)

    if password and biometric:
        print("Password and Biometrics can not be supplied at the same time")
        sys.exit(1)

    data = read_bitwarden_data_file(filename)
    userSection = get_first_user(data)

    derived_key: bytes | None = None

    if password:
        email = userSection["profile"]["email"]
        iterations = int(userSection["profile"]["kdfIterations"])
        derived_key = derive_key(email, password, iterations)
    else:
        derived_key = b64decode(biometric)

    encKey = decrypt_encryption_key(userSection, derived_key)
    passwords = decrypt_user_passwords(userSection, encKey)
    print(json.dumps(passwords, indent=2))


if __name__ == "__main__":
    main()
