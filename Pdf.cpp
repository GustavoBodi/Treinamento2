//
// Created by gustavo on 2/10/23.
//

#include "Pdf.hpp"
#include <fstream>
#include <streambuf>
#include <sstream>
#include <libcryptosec/MessageDigest.h>

bool Pdf::load_pdf(std::string pdf_path) {
    std::ifstream ifs(pdf_path.c_str());
    if (ifs.good()) {
        std::string content((std::istreambuf_iterator<char>(ifs)), (std::istreambuf_iterator<char>()));
        pdf = content;
        return true;
    } else {
        return false;
    }
}

void Pdf::gen_hash() {
    MessageDigest digest = MessageDigest(MessageDigest::SHA256);
    std::string pdf_str = get_value();
    hash = digest.doFinal(pdf_str);
}

Pdf::Pdf(std::string path_r) {
    path = path_r;
    load_pdf(path_r);
    gen_hash();
}

std::string Pdf::get_path() {
    return path;
}

std::vector<int> Pdf::get_needed() {
    return needed_users;
}

std::string Pdf::get_value() {
    return pdf;
}

ByteArray Pdf::get_hash() {
    return hash;
}

void Pdf::set_needed(std::vector<int> needed) {
    needed_users = needed;
}
