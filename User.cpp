//
// Created by gustavo on 2/10/23.
//

#include "User.hpp"
#include "UserKeys.hpp"
#include <iostream>
#include <libcryptosec/Signer.h>
#include <libcryptosec/ByteArray.h>
#include <libcryptosec/certificate/CertificateBuilder.h>
#include <libcryptosec/certificate/Certificate.h>
#include <libcryptosec/certificate/RDNSequence.h>

std::string issuer_private_key = "-----BEGIN RSA PRIVATE KEY-----\n"
"MIIEowIBAAKCAQEAtwNR60/El70dZDu7FQJ7Q+LKyt0dmofPdOJUUXr8GbucINNs\n"
"lyYRvqPCRwOG74DhPwP6nclfeyrzyXok0JbTt+LZCWDZTtKTxMy1MmlIf8sjR64c\n"
"TYm4EROGOlznA2JRf39u28ts2Ivp/eVnOshkleKrsl2yr5WWwlBR/DHMLRrhpZ85\n"
"ck3MBubNOqN8OY+FmYxk2XXxWaZ4qC41ikno5/FbfIzYcuHK1/RoJzyVl5mc0BEz\n"
"rP+4D5gQJSsa5AXA5SvVtQjL5U7BpDCuW04BYkdTkhn9tfHi8qiCmhyC4PP6oYdG\n"
"y5pJU5eDezkfFuad+CsRvvrEYf8DgS+N8jwr1QIDAQABAoIBABqI0rHJaPmPI9nK\n"
"hz9ukqyvDzQGhypGkp+hyRPfPvoEJ4ji3pWzoVMAr0RYkJHdH8thKk8CSWO0QJBv\n"
"szLDC4NX0pv3fMpe4ang/EyI00gkDcNwzQ248AUZzZZcrenhsWtI8KvRfMCQ2KZF\n"
"QohVUbAhoz9DMosepzMZLinglnfbdQnZFsqpGRR9IXOkLra/jzj2W13Fq3+cOW14\n"
"/EQ+yWM1Uck3Mtikz6Zat/IOvh8is7pbQsyTQtAZ6/cmFU8PsYKAb/ncKMubRgrV\n"
"kLZ72RYrQtl5JOhTN7/KaYjZ+arYVt6WExGhm7owGYrTpUszG9R8H42LzcF+DUpo\n"
"ECUgYqkCgYEA5RnJrczGAIDNGDo/Afyr0BNDb7HZLPdu0dltDnY1Tt/lMmltzKFU\n"
"G4B9T4t9ynchnzNN878wXQN3X2GgBanLxI1wDnatehzhaTIdtG2RF4VR1fOekttx\n"
"EO+UaNKYUVXlmElTM/6EpSId8VKCme+JbMJ91eGpwD+EabpOZbNKd3sCgYEAzIA+\n"
"7JbuV5PxWZgxHfbjOZQk9GWar3FCIYIfBkjAA8Azrx9Fu5cnMNiPVegiJk0CEg88\n"
"/rwFJdPoU5/fBVraU8pKgKX4iJaw3u+Gdem8R0vlPo5DbBtt58D1kSaiPxmGER4J\n"
"rS9Zf3NFa0i92FOzAC/N/nJEeumjGZNwM+gR4O8CgYEAwwRnnA2CwqzhaO0z81IN\n"
"QwsSzYJ71v4tFG7bmYLgL+sA5B/Aun7d5KdEhDC+fFlagnUetw0ZcyPfOo8Us51s\n"
"+jxXlchKNXdeHbjudkcKShZPqis94c7weTUnhO83f4z56t8H92uBqDvZdzIAQF8a\n"
"AT2x9h2o7SBka8eOsp2jFv8CgYAl10lNgDREUmTjnkzgbZHoUqhv7Okts7h3+NsC\n"
"z61wRD2MFy5RIwwmdrw3OkgvbCqI6vbvcB1HvamM59Vd6UzjGlik65FMvQ2ngw0P\n"
"fpvPWZTm+W4yb/TrYIJQRKTbJj7vpe5GdK+L7OmYi5JNmFdUHoRwo/ZWBCuhDO5D\n"
"PJsqUwKBgBOh9+rkdqQV9fTOfBEC9KAwnoHpX81ODWs+UC9DMCEqW7jStNc8MHSP\n"
"z5LhiBUcAxVT+rCjLtKNG9zEkK8cCbhZ7rcd1mCyU6Bz8iAOnLByIyhKWM2E5Z9k\n"
"3PZSy2WXu8GAGsCSRLZNIXW0/Fs8zKsx0C3GcYlf651jKz09FqUT\n"
"-----END RSA PRIVATE KEY-----";

User::User(std::string name) : name(name), keys(UserKeys(name, 2048)) { }

std::string User::get_name() {
    return name;
}

void User::set_id(int id_r) {
    id = id_r;
}

int User::get_id() {
    return id;
}

UserKeys User::get_keys() {
    return keys;
}

// Assina utilizando a chave que vem da Database
ByteArray User::sign(ByteArray hash, std::string p_key) {
    RSAPrivateKey rsa = RSAPrivateKey(p_key);
    ByteArray signed_hash = Signer::sign(rsa, hash, MessageDigest::SHA256);
    return signed_hash;
}

User::~User() {}

std::string User::get_digital_certificate_str() {
    CertificateBuilder builder = CertificateBuilder();
    RDNSequence subject = RDNSequence();
    subject.addEntry(RDNSequence::GIVEN_NAME, name);
    subject.addEntry(RDNSequence::COUNTRY, "Brazil");
    builder.setSubject(subject);

    RSAPrivateKey private_key = RSAPrivateKey(issuer_private_key);
    std::string public_key_str = keys.get_public_key_str();
    RSAPublicKey public_key = RSAPublicKey(public_key_str);

    builder.setPublicKey(public_key);
    Certificate *cert = builder.sign(private_key, MessageDigest::SHA256);
    return cert->getPemEncoded();
}
