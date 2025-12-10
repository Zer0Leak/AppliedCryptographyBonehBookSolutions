import hmac
from typing import Optional, Tuple

from util import dict_to_json_str, json_str_to_dict, time_safe_compare
from util import str_to_bytes, bytes_to_str, encode_bytes, decode_bytes

from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import HMAC, SHA256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

import threading

# number of iterations for PBKDF2 algorithm
PBKDF2_ITERATIONS = 100000
# we can assume no password is longer than this many characters
MAX_PASSWORD_LENGTH = 64

########## START CODE HERE ##########
# Add any extra constants you may need
HMAC_MODE = SHA256
SALT_LENGTH = 16  # 128 bits
DERIVED_KEY_LENGTH = 32
MAX_PASSWORD_LENGTH = 64
MAX_DOMAIN_LENGTH = 2048
PADDING_BYTE = "."
LENGTH_SIZE = 1
ENDIANNESS = "little"
SIGN_MSG = b"CIn Crypto"
########### END CODE HERE ###########


class Keychain:
    def __init__(
        self,
        ########## START CODE HERE ##########
        password: str,
        ########### END CODE HERE ###########
    ):
        """
                Initializes the keychain using the provided information. Note that external users should
                likely never invoke the constructor directly and instead use either Key    tests = test_password_manager.TestFunctionality()
            tests.test_init_without_error()
            tests.test_set_and_retrieve_password()
            tests.test_set_and_retrieve_multiple_passwords()
            tests.test_get_returns_none_for_non_existent_password()
            tests.test_can_remove_password()
            tests.test_remove_returns_false_if_no_password_for_name()
            tests.test_dump_and_restore_database()
            tests.test_fails_to_restore_database_with_incorrect_checksum()
            tests.test_fails_to_restore_database_with_incorrect_password()
        chain.new or
                Keychain.load.

                Args:
                    You may design the constructor with any additional arguments you would like.
                Returns:
                    None
        """
        ########## START CODE HERE ##########
        self._lock = threading.Lock()
        self.data = {
            # Store member variables that you intend to be public here
            # (i.e. information that will not compromise security if an adversary sees).
            # This data should be dumped by the Keychain.dump function.
            # You should store the key-value store (KVS) in the "kvs" item in this dictionary.
            "pbkdf2_salt": None,
            "sign": None,
            "kvs": {},
        }
        self.secrets = {
            # Store member variables that you intend to be private here
            # (information that an adversary should NOT see).
            "keychain_password": password,
            "derived_keys": None,
            "kvs_dict": {},
            "kvs_dirty_dict": {},
            "marked_for_removal_set": set(),
        }
        # raise NotImplementedError(
        #     "Delete this line once you've implemented the Keychain constructor (__init__)"
        # )
        ########### END CODE HERE ###########

    ########## START CODE HERE ##########
    # Add any helper functions you may want to add here
    @classmethod
    def _salt(cls) -> bytes:
        salt = get_random_bytes(SALT_LENGTH)
        return salt

    def _set_salt_and_keys(self, salt: bytes, sign: bytes, derived_keys: Tuple[bytes, bytes, bytes]) -> None:
        if self.secrets["derived_keys"] is not None:
            raise Exception("Derived keys are already set. I'm a bad programmer.")

        encoded_salt = encode_bytes(salt)
        encoded_sign = encode_bytes(sign)
        self.data["pbkdf2_salt"] = encoded_salt
        self.data["sign"] = encoded_sign
        self.secrets["derived_keys"] = derived_keys

    def _initialize_keys_with_load_data(self):
        if self.data["pbkdf2_salt"] is None:
            raise ValueError("No salt found in data to load keys.")

        encoded_salt = self.data["pbkdf2_salt"]
        encoded_sign = self.data["sign"]

        salt = decode_bytes(encoded_salt)
        sign = decode_bytes(encoded_sign)
        derived_keys = __class__._generate_derived_keys(password=self.secrets["keychain_password"], salt=salt)

        key_sign = derived_keys[3]
        calculated_sign = HMAC.new(key=key_sign, msg=SIGN_MSG, digestmod=HMAC_MODE).digest()
        if not time_safe_compare(calculated_sign, sign):
            raise ValueError("Keychain password is incorrect.")

        self._set_salt_and_keys(salt=salt, sign=sign, derived_keys=derived_keys)

    def _initialize_salt_and_keys(self):
        salt = get_random_bytes(SALT_LENGTH)
        derived_keys = __class__._generate_derived_keys(password=self.secrets["keychain_password"], salt=salt)
        key_sign = derived_keys[3]
        sign = HMAC.new(key=key_sign, msg=SIGN_MSG, digestmod=HMAC_MODE).digest()
        self._set_salt_and_keys(salt=salt, sign=sign, derived_keys=derived_keys)

    @classmethod
    def _generate_derived_keys(cls, password: str, salt: bytes) -> Tuple[bytes, bytes, bytes]:
        password_bytes = str_to_bytes(password)

        extended_key = PBKDF2(
            password=password_bytes,
            salt=salt,
            dkLen=DERIVED_KEY_LENGTH,
            count=PBKDF2_ITERATIONS,
        )

        key_domain = HMAC.new(key=extended_key, msg=str_to_bytes("MAC Domain"), digestmod=HMAC_MODE).digest()
        key_passwd = HMAC.new(key=extended_key, msg=str_to_bytes("AES Password"), digestmod=HMAC_MODE).digest()
        key_row = HMAC.new(key=extended_key, msg=str_to_bytes("HMAC Row"), digestmod=HMAC_MODE).digest()
        key_sign = HMAC.new(key=extended_key, msg=str_to_bytes("HMAC Sign"), digestmod=HMAC_MODE).digest()

        return (key_domain, key_passwd, key_row, key_sign)

    def _save(self) -> None:
        key_domain, key_passwd, key_row, _ = self.secrets["derived_keys"]

        for domain in self.secrets["marked_for_removal_set"]:
            domain_hmac = HMAC.new(key=key_domain, msg=str_to_bytes(domain), digestmod=HMAC_MODE).digest()
            encoded_domain_hmac = encode_bytes(domain_hmac)
            if encoded_domain_hmac in self.data["kvs"]:
                del self.data["kvs"][encoded_domain_hmac]

        for domain, password in self.secrets["kvs_dirty_dict"].items():
            length_bytes = len(password).to_bytes(LENGTH_SIZE, byteorder=ENDIANNESS)
            padded_passwd = password.ljust(MAX_PASSWORD_LENGTH, PADDING_BYTE)
            padded_passwd_bytes = str_to_bytes(padded_passwd)

            len_passwd_pad_bytes = length_bytes + padded_passwd_bytes
            iv = get_random_bytes(SALT_LENGTH)

            packet = iv + AES.new(key=key_passwd, mode=AES.MODE_GCM, nonce=iv).encrypt(len_passwd_pad_bytes)

            domain_hmac = HMAC.new(key=key_domain, msg=str_to_bytes(domain), digestmod=HMAC_MODE).digest()
            row_hmac = HMAC.new(key=key_row, msg=domain_hmac + packet, digestmod=HMAC_MODE).digest()

            kvs_key = encode_bytes(domain_hmac)
            kvs_value = encode_bytes(row_hmac + packet)
            self.data["kvs"][kvs_key] = kvs_value

        for domain in self.secrets["marked_for_removal_set"]:
            if domain in self.secrets["kvs_dict"]:
                del self.secrets["kvs_dict"][domain]
                if domain in self.secrets["kvs_dirty_dict"]:
                    del self.secrets["kvs_dirty_dict"][domain]

        self.secrets["kvs_dict"].update(self.secrets["kvs_dirty_dict"])
        self.secrets["kvs_dirty_dict"] = {}
        self.secrets["marked_for_removal_set"] = set()

    def _load_domain_from_data_kvs(self, domain: str) -> Optional[str]:
        if domain in self.secrets["kvs_dict"]:
            raise Exception("Domain is already loaded. I'm a bad programmer.")

        key_domain, key_passwd, key_row, _ = self.secrets["derived_keys"]

        domain_hmac = HMAC.new(key=key_domain, msg=str_to_bytes(domain), digestmod=HMAC_MODE).digest()
        encoded_domain_hmac = encode_bytes(domain_hmac)

        encoded_value = self.data["kvs"].get(encoded_domain_hmac)
        if encoded_value is None:
            return None
        value = decode_bytes(encoded_value)

        row_hmac = value[: HMAC_MODE.digest_size]
        packet = value[HMAC_MODE.digest_size :]

        calculated_row_hmac = HMAC.new(key=key_row, msg=domain_hmac + packet, digestmod=HMAC_MODE).digest()

        if not time_safe_compare(calculated_row_hmac, row_hmac):
            raise ValueError("HMAC verification failed for domain.")

        iv = packet[:SALT_LENGTH]
        encrypted_len_passwd_pad = packet[SALT_LENGTH:]

        len_passwd_pad = AES.new(key=key_passwd, mode=AES.MODE_GCM, nonce=iv).decrypt(encrypted_len_passwd_pad)

        length_bytes = len_passwd_pad[:LENGTH_SIZE]
        length = int.from_bytes(length_bytes, byteorder=ENDIANNESS)
        password_bytes = len_passwd_pad[LENGTH_SIZE : LENGTH_SIZE + length]
        password = bytes_to_str(password_bytes)

        self.secrets["kvs_dict"][domain] = password

        return domain

    ########### END CODE HERE ###########

    @staticmethod
    def new(keychain_password: str) -> "Keychain":
        """
        Creates an empty keychain with the given keychain password.

        Args:
            keychain_password: the password to unlock the keychain
        Returns:
            A Keychain instance
        """
        ########## START CODE HERE ##########
        keychain = Keychain(password=keychain_password)
        keychain._initialize_salt_and_keys()
        return keychain
        ########### END CODE HERE ###########

    @staticmethod
    def load(keychain_password: str, repr: str, trusted_data_check: Optional[bytes] = None) -> "Keychain":
        """
        Creates a new keychain from an existing key-value store.

        Loads the keychain state from the provided representation (repr). You can assume that
        the representation passed to load is well-formed (i.e., it will be a valid JSON object)
        and was generated from the Keychain.dump function.

        Use the provided `json_str_to_dict` function to convert a JSON string into a nested dictionary.

        Args:
            keychain_password: the password to unlock the keychain
            repr: a JSON-encoded serialization of the contents of the key-value store (string)
            trusted_data_check: an optional SHA-256 checksum of the KVS (bytes or None)
        Returns:
            A Keychain instance containing the data from repr
        Throws:
            ValueError: if the checksum is provided in trusted_data_check and the checksum check fails
            ValueError: if the provided keychain password is not correct for the repr (hint: this is
                thrown for you by HMAC.verify)
        """
        ########## START CODE HERE ##########
        if trusted_data_check is not None:
            h = SHA256.new()
            h.update(str_to_bytes(repr))
            computed_checksum = h.digest()
            if not time_safe_compare(computed_checksum, trusted_data_check):
                raise ValueError("Checksum verification failed.")

        keychain = Keychain(password=keychain_password)
        keychain.data = json_str_to_dict(repr)
        keychain._initialize_keys_with_load_data()  # this will raise ValueError if password is incorrect
        return keychain
        # raise NotImplementedError("Delete this line once you've implemented Keychain.load")
        ########### END CODE HERE ###########

    def dump(self) -> Tuple[str, bytes]:
        """
        Returns a JSON serialization and a checksum of the contents of the keychain that can be
        loaded back using the Keychain.load function.

        For testing purposes, please ensure that the JSON string you return contains the key
        'kvs' with your KVS dict as its value. The KVS should have one key per domain.

        Use the provided `dict_to_json_str` function to convert a nested dictionary into
        its JSON representation.

        Returns:
            A tuple consisting of (1) the JSON serialization of the contents, and (2) the SHA256
            checksum of the JSON serialization
        """
        ########## START CODE HERE ##########
        with self._lock:
            self._save()
            repr = dict_to_json_str(self.data)
            h = SHA256.new()
            h.update(str_to_bytes(repr))
            checksum = h.digest()
            return (repr, checksum)
        ########### END CODE HERE ###########

    def get(self, domain: str) -> Optional[str]:
        """
        Fetches the password corresponding to a given domain from the key-value store.

        Args:
            domain: the domain for which the password is requested
        Returns:
            The password for the domain if it exists in the KVS, or None if it does not exist
        """
        ########## START CODE HERE ##########
        with self._lock:
            if domain is None:
                raise ValueError("Domain is None.")
            if len(domain) > MAX_DOMAIN_LENGTH:
                raise ValueError("Domain is too long.")

            if domain in self.secrets["marked_for_removal_set"]:
                return None

            password = self.secrets["kvs_dirty_dict"].get(domain)
            if password:
                return password

            if domain not in self.secrets["kvs_dict"]:
                # try to load if not load before
                self._load_domain_from_data_kvs(domain)

            password = self.secrets["kvs_dict"].get(domain, None)
            return password
        ########### END CODE HERE ###########

    def set(self, domain: str, password: str):
        """
        Inserts the domain and password into the KVS. If the domain is already
        in the password manager, this will update the password for that domain.
        If it is not, a new entry in the password manager is created.

        Args:
            domain: the domain for the provided password. This domain may already exist in the KVS
            password: the password for the provided domain
        """
        # ########## START CODE HERE ##########
        with self._lock:
            if domain is None:
                raise ValueError("Domain is None.")
            if len(domain) > MAX_DOMAIN_LENGTH:
                raise ValueError("Domain is too long.")
            if password is None:
                raise ValueError("Password is None.")
            if len(password) > MAX_PASSWORD_LENGTH:
                raise ValueError("Password is too long.")

            if domain in self.secrets["marked_for_removal_set"]:
                self.secrets["marked_for_removal_set"].remove(domain)

            if domain not in self.secrets["kvs_dict"]:
                # try to load if not load before
                self._load_domain_from_data_kvs(domain)

            if domain in self.secrets["kvs_dict"]:
                if time_safe_compare(self.secrets["kvs_dict"][domain], password):
                    if domain in self.secrets["kvs_dirty_dict"]:
                        # Remove from dirty dict if it exists
                        # del self.secrets["kvs_dirty_dict"][domain]

                        # WARNING: THIS WOULD BE A UNSECURE OPTIMIZATION!
                        # If we do not change the encryption (with randon) the adversary wins CPA game
                        # he sends (pass0, pass1), then he sends (pass0, pass0), if not changed it is Experiment 0
                        # otherwise Experiment 1, trivially 1.0 win chance.
                        pass
                    # No need to mark for data update
                    return
                else:
                    # domain exists but password is different, so we need to update
                    pass

            # mark to update in data.kvs
            self.secrets["kvs_dirty_dict"][domain] = password
        ########### END CODE HERE ###########

    def remove(self, domain: str) -> bool:
        """
        Removes the domain-password pair for the provided domain from the password manager.
        If the domain does not exist in the password manager, this method deos nothing.

        Args:
            domain: the domain which should be removed from the KVS, along with its password
        Returns:
            True if the domain existed in the KVS and was removed, False otherwise
        """
        ########## START CODE HERE ##########
        with self._lock:
            removed = False
            if domain in self.secrets["marked_for_removal_set"]:
                # already marked for removal
                return False

            if domain in self.secrets["kvs_dirty_dict"]:
                # Remove from dirty dict if it exists
                # We still not add to marked_for_removal_set here. Just if it exists in data.kvs (we check just bellow)
                del self.secrets["kvs_dirty_dict"][domain]
                removed = True

            if domain not in self.secrets["kvs_dict"]:
                # try to load if not load before
                self._load_domain_from_data_kvs(domain)

            if domain in self.secrets["kvs_dict"]:
                self.secrets["marked_for_removal_set"].add(domain)
                removed = True
            else:
                # May be it was removed from kvs_dirty_dict. i.e. removed before ever serialized.
                pass

            return removed
        ########### END CODE HERE ###########
