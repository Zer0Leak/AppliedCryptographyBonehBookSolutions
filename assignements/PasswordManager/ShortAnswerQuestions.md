# Project #1 (password manager) Short-answer Questions

## How we generate the keys

```
                                                            +----------------------+                  
                                                      +---> |  HMAC("MAC Domain")  |--> key_domain
                        +------------------------+    |     +----------------------+
get_random_bytes(16) -> |                        |    |     +----------------------+
                        | PBKDF2(derived_len=32) | -------> | HMAC("AES Password") |--> key_passwd
user_key -------------> |                        |    |     +----------------------+
                        +------------------------+    |     +----------------------+
                                                      +---> |   HMAC("HMAC Row")   |--> key_row
                                                      |     + ---------------------+
                                                      |     +----------------------+
                                                      +---> |   HMAC("HMAC Sign")  |--> key_sign
                                                            + ---------------------+


```

### How we sign the keychain dumped file

```
self.data["sign"] = HMAC(key_sign, "CIn Crypto")
```

### How Domain/Value is stored in kvs

```
domain_hmac = HMAC(key_domain, domain)

              +------- AES_GCM(key_passwd, IV) -------+
packet = IV + | 1_byte_length + password + pad64('.') |
              +---------------------------------------+

row_hmac = HMAC(key_row, domain_hmac + packet)

kvs_key = domain_hmac
kvs_value = row_hmac + packet
```

## Briefly describe your method for preventing the adversary from learning information about the lengths of the passwords stored in your password manager.

1. The password string is padded with "." up to max length of 64
2. The orinal length if prepended to the password (1 byte)
3. Then we prepend the HMAC of Domain (it doesn't matter for this question. See next question)
4. Then we encrypt them all together.
5. And finnaly we append to it a plain fresh random IV. (it doesn't matter for this question)
5. When loading back, we truncate decrypted password do length

## Briefly describe your method for preventing swap attacks (Section 2.2). Provide an argument for why the attack is prevented in your scheme

1. The HMAC(k_hmac, domains) is prepended to the password. And then it is all encrypted together. See previous question for details.
2. When we load a domain, and its value from data.kvs, we decrypt the value, and compare this HMAC with the key i.e. the HMAC of the domain.
3. It is not possible to put in serialized file a valid encrypted chunck for another domain.
4. It is possible to row-back though but it is handled in another next question.

## In our proposed defense against the rollback attack (Section 2.2), we assume that we can store the SHA-256 hash in a trusted location beyond the reach of an adversary. Is it necessary to assume that such a trusted location exists, in order to defend against rollback attacks? Briefly justify your answer.

Yes. It is necessary. Without that the adversary and replace the latest with any previous one.

## Because HMAC is a deterministic MAC (that is, its output is the same if it is run multiple times with the same input), we were able to look up domain names using their HMAC values. There are also randomized MACs, which can output different tags on multiple runs with the same input. Explain how you would do the look up if you had to use a randomized MAC instead of HMAC. Is there a performance penalty involved, and if so, what?

If that was the case, I see two options:

1. Store the random nonce together with the HMAC, and do O(n) search in a list instead of O(1) in dictionary, so yes, performance penality.
2. Store an encrypted dictionary of domain to nonce and pay the time for encrypt/decrypt it when loading or saving.

## In our specification, we leak the number of records in the password manager. Describe an approach to reduce the information leaked about the number of records. Specifically, if there are k records, your scheme should only leak ⌊log2(k)⌋ (that is, if k1 and k2 are such that ⌊log2(k1)⌋ = ⌊log2(k2)⌋, the attacker should not be able to distinguish between a case where the true number of records is k1 and another case where the true number of records is k2).

No. I don´t see how. We could use dummy records to fill up to 2^⌊log2(k)⌋ records, but, entually our dumped file will grow-up from 2^⌊log2(k)⌋ to 2^(⌊log2(k)⌋+1), at this point the adversary (that is setting one new domain and dupping immediatelly) know that the number of keys is exactly k + 1, and now k is a power of 2. From now, he can follow each add (or delete).

## What is a way we can add multi-user support for specific sites to our password manager system without compromising security for other sites that these users may wish to store passwords of? That is, if Alice and Bob wish to access one stored password (say for nytimes) that either of them can get and update, without allowing the other to access their passwords for other websites.

Create a shared keychain. This keychain is created with a random key. That key in unknown to Bob and Alice, and any other user sharing these domain/passwords. This keychain also stores its own key encrypted with Alice's key and bob's key. So, when they want read from this database, they use their key to get shared key for the shared domain. If Alice's key is compromised, the shared database is compromised too, but the Bob's private domains are safe.
