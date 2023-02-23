//
// Created by gustavo on 2/10/23.
//

#include <libcryptosec/RSAKeyPair.h>
#include "UserKeys.hpp"
#include <string>

// Essa classe serve principalmente para organizacao e apresentaria maior utilidade em uma aplicacao maior
UserKeys::UserKeys(string &username, int size)
        : generated_keys(RSAKeyPair(size)), name(username) { }

std::string UserKeys::get_name() {
    return name;
}

std::string UserKeys::get_private_key_str() {
    return generated_keys.getPrivateKey()->getPemEncoded();
}

std::string UserKeys::get_public_key_str() {
    return generated_keys.getPublicKey()->getPemEncoded();
}

UserKeys::~UserKeys() { };
