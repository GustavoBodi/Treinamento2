//
// Created by gustavo on 2/10/23.
//

#include "StorageEngine.hpp"
#include "User.hpp"
#include "Pdf.hpp"
#include "sqlite3.h"
#include <libcryptosec/Base64.h>
#include <libcryptosec/certificate/Certificate.h>

// Funcao normalmente utilizada com o sqlite
static int callback(void *NotUsed, int argc, char **argv, char **azColName) {
    int i;
    for (i = 0; i < argc; i++) {
        printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
    }
    std::cout << std::endl;
    return 0;
}

StorageEngine::StorageEngine(std::string &path) {
    int rc = sqlite3_open(path.c_str(), &db);
    if (rc) {
        std::cout << "Error Opening Database" << std::endl;
        std::exit(-1);
    } else {
        std::cout << "Database openned succesfully" << std::endl;
    }

    // Tabelas para os Pdfs e Usuarios, os hashes e assinaturas nao foram colocados como blobs, justamente por um problema
    // de conversao, assim o mais simples foi-se utilizar de texto e codificar via Base64
    std::string sql = "PRAGMA foreign_keys = on;CREATE TABLE if not exists USERS (" \
    " user_id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE NOT NULL, " \
    "         name TEXT UNIQUE NOT NULL, " \
    "         private_key TEXT UNIQUE NOT NULL, " \
    "         public_key TEXT UNIQUE NOT NULL " \
    " ); " \
    " CREATE TABLE if not exists PDF ( " \
    " pdf_id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE NOT NULL, " \
    "         path TEXT UNIQUE NOT NULL, " \
    "         hash TEXT UNIQUE NOT NULL " \
    " ); " \
    " CREATE TABLE if not exists SIGNED ( " \
    " pdf_id INTEGER NOT NULL, " \
    " user_id INTEGER NOT NULL, " \
    " signature TEXT UNIQUE NOT NULL, " \
    "         FOREIGN KEY (pdf_id) " \
    " REFERENCES PDF (pdf_id) " \
    " ON DELETE CASCADE " \
    " ON UPDATE NO ACTION, " \
    " FOREIGN KEY(user_id) " \
    " REFERENCES USERS (user_id) " \
    " ON DELETE CASCADE " \
    " ON UPDATE NO ACTION " \
    " ); " \
    " CREATE TABLE if not exists NEEDED ( " \
    "         pdf_id INTEGER NOT NULL, " \
    "         user_id INTEGER NOT NULL, " \
    "         FOREIGN KEY (pdf_id) " \
    " REFERENCES PDF (pdf_id) " \
    " ON DELETE CASCADE " \
    " ON UPDATE NO ACTION, " \
    " FOREIGN KEY(user_id) " \
    " REFERENCES USERS (user_id) " \
    " ON DELETE CASCADE " \
    " ON UPDATE NO ACTION " \
    " ); ";
    char *err;
    rc = sqlite3_exec(db, sql.c_str(), callback, 0, &err);
    if (rc != SQLITE_OK) {
        std::cerr << "Error with sql " << std::endl;
        std::cerr << sqlite3_errmsg(db);
        std::exit(0);
    }
}

bool StorageEngine::insert_user(User user) {
    sqlite3_stmt *stmt;
    std::string sql = "INSERT INTO USERS (name, private_key, public_key) VALUES (?, ?, ?)";
    sqlite3_prepare(db, sql.c_str(), -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, user.get_name().c_str(), user.get_name().length(), SQLITE_TRANSIENT);

    std::string private_key = user.get_keys().get_private_key_str();
    std::string digital_certificate = user.get_digital_certificate_str();

    sqlite3_bind_text(stmt, 2, private_key.c_str(), private_key.length(), SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, digital_certificate.c_str(), digital_certificate.length(), SQLITE_TRANSIENT);

    sqlite3_step(stmt);
    int result = sqlite3_finalize(stmt);

    if (SQLITE_OK != result) {
        std::cout << sqlite3_errmsg(db) << std::endl;
        return false;
    }
    return true;
}

// Ao se inserir o pdf o caminho dele sera colocado na database, no entanto vale notar que esse valor nao e necessario
// para o funcionamente do programa, existe para lembrar o usuario sobre qual seira o arquivo em questao
bool StorageEngine::insert_pdf(Pdf pdf) {
    sqlite3_stmt *stmt;
    std::string sql = "INSERT INTO PDF (path, hash) VALUES(?, ?)";
    sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, pdf.get_path().c_str(), pdf.get_path().length(), SQLITE_TRANSIENT);
    ByteArray buffer = pdf.get_hash();
    std::string hash = Base64::encode(buffer);
    sqlite3_bind_text(stmt, 2, hash.c_str() , hash.length(), SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    int result = sqlite3_finalize(stmt);
    if (SQLITE_OK != result) {
        std::cout << sqlite3_errmsg(db) << std::endl;
        return false;
    }

    int pdf_id = get_last_id();

    for (int i = 0; i < pdf.get_needed().size(); ++i) {
        int needed = pdf.get_needed()[i];
        std::string sql1 = "INSERT INTO NEEDED (pdf_id, user_id) VALUES ((SELECT pdf_id from PDF WHERE pdf_id=?), (SELECT user_id FROM USERS WHERE user_id=?))";
        sqlite3_prepare_v2(db, sql1.c_str(), -1, &stmt, NULL);
        sqlite3_bind_int64(stmt, 1, pdf_id);
        sqlite3_bind_int64(stmt, 2, needed);
        sqlite3_step(stmt);
        int result1 = sqlite3_finalize(stmt);
        if (SQLITE_OK != result1) {
            std::cout << sqlite3_errmsg(db) << std::endl;
            return false;
        }
    }
    return true;
}

void StorageEngine::show_users() {
    std::string sql = "SELECT * from USERS";

    std::cout << "Printing Users in the database: " << std::endl;

    sqlite3_exec(db, sql.c_str(), callback, NULL, NULL);

    std::cout << "End of Users" << std::endl;
}

void StorageEngine::show_pdfs() {
    std::string sql = " SELECT " \
    " n.pdf_id, " \
    "         path, " \
    "         user_id " \
    " FROM PDF p " \
    " INNER JOIN NEEDED n ON N.pdf_id = p.pdf_id ";

    std::cout << "Printing PDFs in the database: " << std::endl;

    sqlite3_exec(db, sql.c_str(), callback, NULL, NULL);

    std::cout << "End of PDF" << std::endl;
}


bool StorageEngine::delete_pdf(int pdf_id) {
    sqlite3_stmt *stmt;
    std::string sql = "DELETE FROM PDF WHERE pdf_id=?";
    sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, NULL);
    sqlite3_bind_int64(stmt, 1, pdf_id);
    sqlite3_step(stmt);
    int result1 = sqlite3_finalize(stmt);
    std::cout << sqlite3_errmsg(db) << std::endl;
    if (SQLITE_OK != result1) {
        std::cout << sqlite3_errmsg(db) << std::endl;
        return false;
    }
    return true;
}

bool StorageEngine::delete_user(int id) {
    sqlite3_stmt *stmt;
    std::string sql = "DELETE FROM USERS WHERE user_id=?";
    sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, NULL);
    sqlite3_bind_int64(stmt, 1, id);
    sqlite3_step(stmt);
    int result = sqlite3_finalize(stmt);
    if (SQLITE_OK != result) {
        std::cout << sqlite3_errmsg(db) << std::endl;
        return false;
    }
    return true;
}

// Devido a API primitiva para o uso do sqlite, essa e a maneira mais simples para obter os ids
long long StorageEngine::get_last_id() {
    long long id = sqlite3_last_insert_rowid(db);
    return id;
}

// Valida a existencia do usuario
bool StorageEngine::check_user(int id) {
    sqlite3_stmt *stmt;
    std::string sql = "SELECT * FROM USERS WHERE user_id = ?";
    sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, NULL);
    sqlite3_bind_int64(stmt, 1, id);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        return true;
    }
    sqlite3_finalize(stmt);
    return false;
}

// Checa a existencia do pdf
bool StorageEngine::exist_pdf(int id) {
    sqlite3_stmt *stmt;
    std::string sql = "SELECT * FROM PDF WHERE pdf_id = ?";
    sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, NULL);
    sqlite3_bind_int64(stmt, 1, id);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        return true;
    }
    sqlite3_finalize(stmt);
    return false;
}

// Valida se a quantidade de entradas assinadas e necessarias e igual,
// a funcao da classe Cli::check_signatures(), checa essas assinaturas e corresponde a outra funcao
bool StorageEngine::check_pdf(int id) {
    sqlite3_stmt *stmt;
    std::string sql = "SELECT COUNT(*) FROM NEEDED WHERE pdf_id = ?";
    sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, NULL);
    sqlite3_bind_int64(stmt, 1, id);
    sqlite3_step(stmt);
    int result0 = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);

    std::string sql1 = "SELECT COUNT(*) FROM SIGNED WHERE pdf_id = ?";
    sqlite3_prepare_v2(db, sql1.c_str(), -1, &stmt, NULL);
    sqlite3_bind_int64(stmt, 1, id);
    sqlite3_step(stmt);
    int result1 = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);

    if (!StorageEngine::exist_pdf(id)) {
        std::cout << "The pdf specified doesn't exist" << std::endl;
    } else if (result0 == result1) {
        return true;
    }
    return false;
}

// Checa se esse pdf ja for assinado por esse usuario
bool StorageEngine::check_sign_ready(int pdf_id, int user_id) {
    sqlite3_stmt *stmt;
    std::string sql = "SELECT * FROM NEEDED WHERE pdf_id = ? AND user_id = ?";
    sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, NULL);
    sqlite3_bind_int64(stmt, 1, pdf_id);
    sqlite3_bind_int64(stmt, 2, user_id);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        return true;
    }
    sqlite3_finalize(stmt);
    return false;
}

// Insere a assinatura
bool StorageEngine::insert_signed(int pdf_id, int user_id) {
    sqlite3_stmt *stmt;
    std::string sql = "INSERT INTO SIGNED (pdf_id, user_id, signature) VALUES ((SELECT pdf_id from PDF WHERE pdf_id=?), (SELECT user_id FROM USERS WHERE user_id=?), ?)";
    if ((!check_user(user_id)) || (!exist_pdf(pdf_id))) {
        return false;
    }
    ByteArray hash = get_hash(pdf_id);

    std::string private_key = get_private_key(user_id);

    // Codificou-se em Base64 para evitar problemas com leituras de strings para valores nulos
    ByteArray buffer = User::sign(hash, private_key);
    std::string signature = Base64::encode(buffer);

    sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, NULL);
    sqlite3_bind_int64(stmt, 1, pdf_id);
    sqlite3_bind_int64(stmt, 2, user_id);
    sqlite3_bind_text(stmt, 3, signature.c_str(), signature.length(), SQLITE_TRANSIENT);

    sqlite3_step(stmt);
    int result = sqlite3_finalize(stmt);
    if (SQLITE_OK != result) {
        std::cout << sqlite3_errmsg(db) << std::endl;
        return false;
    }
    return true;
}

// As chaves privadas e publicas estao na mesmas databse, naturalmente que em uma aplicacao real, isso nao seria
// aplicado
std::string StorageEngine::get_private_key(int user_id) {
    sqlite3_stmt *stmt;
    std::string sql = "SELECT * FROM USERS WHERE user_id=?";
    sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, NULL);
    sqlite3_bind_int64(stmt, 1, user_id);
    sqlite3_step(stmt);

    std::string name = std::string((const char*)sqlite3_column_text(stmt, 1));
    std::string private_key = std::string((const char*)sqlite3_column_text(stmt, 2));
    std::string public_key = std::string((const char*)sqlite3_column_text(stmt, 3));

    sqlite3_finalize(stmt);

    return private_key;
}

std::string StorageEngine::get_public_key(int user_id) {
    sqlite3_stmt *stmt;
    std::string sql = "SELECT * FROM USERS WHERE user_id=?";
    sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, NULL);
    sqlite3_bind_int64(stmt, 1, user_id);
    sqlite3_step(stmt);

    std::string name = std::string((const char*)sqlite3_column_text(stmt, 1));
    std::string private_key = std::string((const char*)sqlite3_column_text(stmt, 2));
    std::string digital_certificate = std::string((const char*)sqlite3_column_text(stmt, 3));

    Certificate pb = Certificate(digital_certificate);
    Certificate public_key = Certificate(pb);

    sqlite3_finalize(stmt);

    return public_key.getPublicKey()->getPemEncoded();
}

// Obtem o hash do pdf por id, vale notar que existe outra funcao para o carregamento e comparacao do hash,
// esta funcao existe para criar uma facilidade no Cli para utilizar-se os ids
ByteArray StorageEngine::get_hash(int pdf_id) {
    sqlite3_stmt *stmt = 0;
    std::string sql = "SELECT hash FROM PDF WHERE pdf_id = ?";
    sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, NULL);
    sqlite3_bind_int64(stmt, 1, pdf_id);
    sqlite3_step(stmt);

    std::string hash = (const char *)sqlite3_column_text(stmt, 0);

    int result = sqlite3_finalize(stmt);
    if (SQLITE_OK != result) {
        std::cout << sqlite3_errmsg(db) << std::endl;
    }
    return Base64::decode(hash);
}

ByteArray StorageEngine::get_signature(int pdf_id, int user_id) {
    sqlite3_stmt *stmt = 0;
    std::string sql = "SELECT signature FROM SIGNED WHERE pdf_id = ? AND user_id=?";
    sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, NULL);
    sqlite3_bind_int64(stmt, 1, pdf_id);
    sqlite3_bind_int64(stmt, 2, user_id);
    int rc = sqlite3_step(stmt);

    if (rc != SQLITE_ROW) {
        return ByteArray("");
    }
    std::string signature = (const char *)sqlite3_column_text(stmt, 0);

    int result = sqlite3_finalize(stmt);
    if (SQLITE_OK != result) {
        std::cout << sqlite3_errmsg(db) << std::endl;
    }
    return Base64::decode(signature);
}

vector<int> StorageEngine::get_users(int pdf_id) {
    vector<int> list = vector<int>();
    sqlite3_stmt *stmt;
    std::string sql = "SELECT user_id FROM NEEDED WHERE pdf_id = ?";
    sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, NULL);
    sqlite3_bind_int64(stmt, 1, pdf_id);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        int user_id = sqlite3_column_int(stmt, 0);
        list.push_back(user_id);
    }

    sqlite3_finalize(stmt);
    return list;
}

int StorageEngine::get_pdf(Pdf pdf) {
    sqlite3_stmt *stmt;
    std::string sql = "SELECT pdf_id FROM PDF WHERE hash = ?";
    sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, NULL);
    ByteArray buffer = pdf.get_hash();
    std::string hash = Base64::encode(buffer);
    sqlite3_bind_text(stmt, 1, hash.c_str(), hash.length(), NULL);

    int result = sqlite3_step(stmt);
    int id = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);

    if (result == SQLITE_ROW) {
        return id;
    }
    return -1;
}
