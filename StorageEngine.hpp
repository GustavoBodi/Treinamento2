//
// Created by gustavo on 2/10/23.
//

#pragma once

#include <vector>
#include "User.hpp"
#include "Pdf.hpp"
#include <pqxx/pqxx>

class StorageEngine {
public:
    StorageEngine(std::string &path);

    std::vector<int> get_users(int pdf_id);

    ByteArray get_hash(int pdf_id);

    bool insert_user(User user);

    bool delete_user(int id);

    void show_users();

    bool insert_pdf(Pdf pdf);

    bool delete_pdf(int pdf);

    void show_pdfs();

    int get_pdf(Pdf pdf_hash);

    bool check_user(int id);

    int get_last_id();

    bool exist_pdf(int id);

    bool check_pdf(int id);

    bool check_sign_ready(int pdf_id, int user_id);

    bool insert_signed(int pdf_id, int user_id);

    std::string get_private_key(int user_id);

    std::string get_public_key(int user_id);

    ByteArray get_signature(int pdf_id, int user_id);

    virtual ~StorageEngine() {delete db;};

private:
    void prepare_statements();
    pqxx::connection *db;
};
