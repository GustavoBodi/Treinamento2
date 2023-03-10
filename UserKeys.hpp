//
// Created by gustavo on 2/10/23.
//

#pragma once

#include <string>
#include <libcryptosec/RSAKeyPair.h>

// Classe para vincular o Usuario com as chaves, um pequeno wrapper
class UserKeys {
public:
    UserKeys(std::string &username, int size);

    std::string get_name();

    std::string get_private_key_str();

    std::string get_public_key_str();

    ~UserKeys();

private:
    RSAKeyPair generated_keys;
    std::string name;
};
