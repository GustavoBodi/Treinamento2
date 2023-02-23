//
// Created by gustavo on 2/10/23.
//

#pragma once

#include "UserKeys.hpp"
#include <string>
#include <vector>


class User {
public:
    User(std::string name);

    std::string get_name();

    std::string get_digital_certificate_str();

    void set_id(int id_r);

    int get_id();

    UserKeys get_keys();

    static ByteArray sign(ByteArray hash, std::string p_key);

    virtual ~User();

private:
    int id;
    std::string name;
    UserKeys keys;
};
