//
// Created by gustavo on 2/10/23.
//

#include "StorageEngine.hpp"
#include "User.hpp"
#include "Pdf.hpp"
#include <iostream>
#include <libcryptosec/Base64.h>
#include <libcryptosec/certificate/Certificate.h>
#include <pqxx/pqxx>

StorageEngine::StorageEngine(std::string &path) {
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

    try {
      pqxx::connection *db = new pqxx::connection("dbname=postgres user=postgres password=password hostaddr=127.0.0.1 port=5433");
      if (db->is_open()) {
        std::cout << "Succesfull Database Connection" << std::endl;
      } else {
        std::cout << "Failed Databases Connection" << std::endl;
      }
      prepare_statements();
    } catch (std::exception const &e) {
      std::cout << e.what() << std::endl;
    }
}

void StorageEngine::prepare_statements() {
  std::string sql = "INSERT INTO USERS (name, private_key, public_key) VALUES ($1, $2, $3)";
  db->prepare("insert_user", sql);

  sql = "INSERT INTO PDF (path, hash) VALUES($1, $2)";
  db->prepare("insert_pdf", sql);

  sql = "SELECT * from USERS";
  db->prepare("show_users", sql);

  sql = " SELECT " \
  " n.pdf_id, " \
  "         path, " \
  "         user_id " \
  " FROM PDF p " \
  " INNER JOIN NEEDED n ON N.pdf_id = p.pdf_id ";
  db->prepare("show_pdfs", sql);

  sql = "DELETE FROM PDF WHERE pdf_id=$1";
  db->prepare("delete_pdf", sql);

  sql = "DELETE FROM USERS WHERE user_id=$1";
  db->prepare("delete_user", sql);

  sql = "SELECT * FROM USERS WHERE user_id = $1";
  db->prepare("check_user", sql);

  sql = "SELECT * FROM PDF WHERE pdf_id = $1";
  db->prepare("exist_pdf", sql);

  sql = "INSERT INTO NEEDED (pdf_id, user_id) VALUES ((SELECT pdf_id from PDF WHERE pdf_id=?), (SELECT user_id FROM USERS WHERE user_id=?))";
  db->prepare("insert_needed", sql);

  sql = "SELECT COUNT(*) FROM NEEDED WHERE pdf_id = $1";
  db->prepare("check_pdf", sql);

  sql = "SELECT COUNT(*) FROM SIGNED WHERE pdf_id = $1";
  db->prepare("check_signed", sql);

  sql = "SELECT * FROM NEEDED WHERE pdf_id = $1 AND user_id = $2";
  db->prepare("check_sign_ready", sql);

  sql = "INSERT INTO SIGNED (pdf_id, user_id, signature) VALUES ((SELECT pdf_id from PDF WHERE pdf_id=$1), (SELECT user_id FROM USERS WHERE user_id=$2), $3)";
  db->prepare("insert_signed", sql);

  sql = "SELECT * FROM USERS WHERE user_id=$1";
  db->prepare("get_private_key", sql);

  sql = "SELECT * FROM USERS WHERE user_id=$1";
  db->prepare("get_public_key", sql);

  sql = "SELECT hash FROM PDF WHERE pdf_id = $1";
  db->prepare("get_hash", sql);

  sql = "SELECT signature FROM SIGNED WHERE pdf_id = $1 AND user_id=$2";
  db->prepare("get_signature", sql);

  sql = "SELECT user_id FROM NEEDED WHERE pdf_id = $1";
  db->prepare("get_users", sql);

  sql = "SELECT pdf_id FROM PDF WHERE hash = $1";
  db->prepare("get_pdf", sql);
}

bool StorageEngine::insert_user(User user) {
  pqxx::work w (*db);

  std::string private_key = user.get_keys().get_private_key_str();
  std::string digital_certificate = user.get_digital_certificate_str();

  pqxx::result result = w.prepared("insert_user")(user.get_name())(private_key)(digital_certificate).exec();
}

// Ao se inserir o pdf o caminho dele sera colocado na database, no entanto vale notar que esse valor nao e necessario
// para o funcionamente do programa, existe para lembrar o usuario sobre qual seira o arquivo em questao
bool StorageEngine::insert_pdf(Pdf pdf) {
  ByteArray buffer = pdf.get_hash();
  std::string hash = Base64::encode(buffer);
  pqxx::work w (*db);
  pqxx::result result = w.prepared("insert_pdf")(pdf.get_path())(hash).exec();

  int pdf_id = get_last_id();

  for (int i = 0; i < pdf.get_needed().size(); ++i) {
      int needed = pdf.get_needed()[i];
      pqxx::work w (*db);
      pqxx::result result = w.prepared("insert_needed")(pdf_id)(needed).exec();
  }

}

void StorageEngine::show_users() {
  pqxx::work w (*db);
  pqxx::result result = w.prepared("show_users").exec();
}

void StorageEngine::show_pdfs() {
  pqxx::work w (*db);
  pqxx::result result = w.prepared("show_pdfs").exec();
}

bool StorageEngine::delete_pdf(int pdf_id) {
  pqxx::work w (*db);
  pqxx::result result = w.prepared("delete_pdf").exec();
}

bool StorageEngine::delete_user(int id) {
  pqxx::work w (*db);
  pqxx::result result = w.prepared("delete_user")(id).exec();
}

// Valida a existencia do usuario
bool StorageEngine::check_user(int id) {
  pqxx::work w (*db);
  pqxx::result result = w.prepared("check_users")(id).exec();
}

int StorageEngine::get_last_id()
{
  return 0;
}

// Checa a existencia do pdf
bool StorageEngine::exist_pdf(int id) {
  pqxx::work w (*db);
  pqxx::result result = w.prepared("exist_pdf")(id).exec();
}

// Valida se a quantidade de entradas assinadas e necessarias e igual,
// a funcao da classe Cli::check_signatures(), checa essas assinaturas e corresponde a outra funcao
bool StorageEngine::check_pdf(int id) {
  pqxx::work w (*db);
  pqxx::result result_check = w.prepared("check_pdf")(id).exec();

  pqxx::result result_signed = w.prepared("check_signed")(id).exec();
}

//// Checa se esse pdf ja for assinado por esse usuario
bool StorageEngine::check_sign_ready(int pdf_id, int user_id) {
  pqxx::work w (*db);
  pqxx::result result = w.prepared("check_sign_ready").exec();
}

//// Insere a assinatura
bool StorageEngine::insert_signed(int pdf_id, int user_id) {
  if ((!check_user(user_id)) || (!exist_pdf(pdf_id))) {
      return false;
  }
  ByteArray hash = get_hash(pdf_id);
  std::string private_key = get_private_key(user_id);
  // Codificou-se em Base64 para evitar problemas com leituras de strings para valores nulos
  ByteArray buffer = User::sign(hash, private_key);

  std::string signature = Base64::encode(buffer);
  pqxx::work w (*db);
  pqxx::result result = w.prepared("insert_signed")(pdf_id)(user_id)(signature).exec();
}

  // As chaves privadas e publicas estao na mesmas databse, naturalmente que em uma aplicacao real, isso nao seria
  // aplicado
std::string StorageEngine::get_private_key(int user_id) {
  pqxx::work w (*db);
  pqxx::result result = w.prepared("get_private_key")(user_id).exec();
}

std::string StorageEngine::get_public_key(int user_id) {
  pqxx::work w (*db);
  pqxx::result result = w.prepared("get_public_key")(user_id).exec();

}

// Obtem o hash do pdf por id, vale notar que existe outra funcao para o carregamento e comparacao do hash,
// esta funcao existe para criar uma facilidade no Cli para utilizar-se os ids
ByteArray StorageEngine::get_hash(int pdf_id) {
  pqxx::work w (*db);
  pqxx::result result = w.prepared("get_hash")(pdf_id).exec();
}

ByteArray StorageEngine::get_signature(int pdf_id, int user_id) {
  pqxx::work w (*db);
  pqxx::result result = w.prepared("get_signature")(pdf_id)(user_id).exec();
}

vector<int> StorageEngine::get_users(int pdf_id) {
  pqxx::work w (*db);
  pqxx::result result = w.prepared("get_users")(pdf_id).exec();
}

int StorageEngine::get_pdf(Pdf pdf) {
  ByteArray buffer = pdf.get_hash();
  std::string hash = Base64::encode(buffer);

  pqxx::work w (*db);
  pqxx::result result = w.prepared("get_pdf")(hash).exec();
}
