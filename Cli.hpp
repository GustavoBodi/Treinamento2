//
// Created by gustavo on 2/12/23.
//

#pragma once

#include "Pdf.hpp"
#include "StorageEngine.hpp"
#include <vector>

// A Classe de interface do usuario
class Cli {
public:
    Cli(StorageEngine *db) : db(db) { show_options(); };

    void show_options();

    void check_is_ready_reactor();

    void check_signatures();

    void open_pdf();

    void show_pdf();

    void sign_pdf();

    void delete_pdf();

    void create_user();

    void delete_user();

    void show_users();

    void check_signature();

    ~Cli() {delete db;};


private:
    StorageEngine *db;
    void check(int user_id, int pdf_id);
    vector<int> get_ids();
};
