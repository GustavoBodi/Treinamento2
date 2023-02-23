//
// Created by gustavo on 2/10/23.
//

#pragma once

#include "User.hpp"
#include "UserKeys.hpp"
#include <map>
#include <string>
#include <fstream>
#include <memory>

class Pdf {
public:
    Pdf(std::string path_r);

    void set_needed(std::vector<int> needed);

    bool load_pdf(std::string pdf_path);

    std::string get_path();

    ByteArray get_hash();

    std::string get_value();

    std::vector<int> get_needed();

    ~Pdf() {}

private:
    void gen_hash();

    // Os vetores sao de uso temporario para que se insira os pdf na database
    std::string pdf;
    ByteArray hash;
    std::vector<int> needed_users;
    std::vector<int> user_signed;
    std::string path;
};
