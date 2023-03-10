//
// Created by gustavo on 2/12/23.
//

#include "Cli.hpp"
#include "StorageEngine.hpp"
#include "User.hpp"
#include "libcryptosec/Signer.h"
#include "libcryptosec/KeyPair.h"
#include "libcryptosec/MessageDigest.h"

void Cli::create_user() {
    std::cout << "Creating the User: " << std::endl;
    std::cout << "Insert a name: " << std::endl;
    std::string name;
    std::cin >> name;
    User new_user = User(name);
    if (db->insert_user(new_user)) {
        std::cout << "Succesfull User creation" << std::endl;
        new_user.set_id((int) db->get_last_id());
    } else {
        std::cout << "Failed to create user" << std::endl;
    }
}

void Cli::show_users() {
    db->show_users();
}

void Cli::delete_user() {
    std::cout << "Input the id of the User to be deleted" << std::endl;
    int id;
    std::cin >> id;
    db->delete_user(id);
}

void Cli::show_options() {
    while (true) {
        std::cout << "What do you want to do? \n(1) Add User\n(2) Remove User\n(3) Show User\n(4) Add Pdf\n"\
        "(5) Remove Pdf\n(6) Show Pdfs\n(7) Check Pdf\n(8) Sign Pdf\n(9) Verify Signature\n"\
        "(10) Check all Signatures\n(11)Exit" << std::endl;
        int answer;
        std::cin >> answer;
        switch (answer) {
            case (1):
                create_user();
                break;
            case (2):
                delete_user();
                break;
            case (3):
                show_users();
                break;
            case (4):
                open_pdf();
                break;
            case (5):
                delete_pdf();
                break;
            case (6):
                show_pdf();
                break;
            case (7):
                check_is_ready_reactor();
                break;
            case (8):
                sign_pdf();
                break;
            case (9):
                check_signature();
                break;
            case (10):
                check_signatures();
                break;
            case (11):
                exit(0);
                break;
            default:
                continue;
        }
    }
}

void Cli::open_pdf() {
    std::cout << "Insert the path to the pdf: " << std::endl;
    std::string path;
    std::cin >> path;

    Pdf pdf = Pdf(path);
    int i = db->get_pdf(pdf);
    if (i != -1) {
        std::cout << "Your pdf_id is: " << i << std::endl;
    } else {
        vector<int> ids = get_ids();
        pdf.set_needed(ids);
        db->insert_pdf(pdf);
    }

}

vector<int> Cli::get_ids() {
    vector<int> ids;
    int id_needed = 0;
    cout << "Insert the id of the User, for stopping(0): " << endl;
    cin >> id_needed;
    while (id_needed != 0) {
        if (db->check_user(id_needed)) {
            ids.push_back(id_needed);
        } else {
            cout << "No user with such id" << endl;
        }
        cout << "Insert the id of the User, for stopping(0): " << endl;
        cin >> id_needed;
    }
    return ids;
}

// Nesta parte testa-se se o reator esta pronto, aferindo a quantidade de rows na Database, esta funcao
// nao serve para validacao
void Cli::check_is_ready_reactor() {
    std::cout << "Insert the id of the Pdf" << std::endl;
    int id;
    std::cin >> id;
    if (db->check_pdf(id)) {
        std::cout << "The reactor is ready for this document" << std::endl;
    } else {
        std::cout << "The reactor is not ready for this document" << std::endl;
    }
}

// Checa todas as assinaturas
void Cli::check_signatures() {
    std::cout << "Put the pdf id" << std::endl;
    int pdf_id;
    std::cin >> pdf_id;
    vector<int> list = db->get_users(pdf_id);
    for (int i = 0; i < list.size(); ++i) {
        check(list[i], pdf_id);
    }
}

// A assinatura e armazenada na database, nao sendo portanto colocada diretamente no Pdf, como seria o padrao
void Cli::sign_pdf() {
    std::cout << "Which is the Pdf (id) you want to sign: " << std::endl;
    int pdf_id;
    std::cin >> pdf_id;

    std::cout << "Which is the User (id) you want to sign as: " << std::endl;
    int user_id;
    std::cin >> user_id;

    if (db->exist_pdf(pdf_id) && db->check_user(user_id) && db->check_sign_ready(pdf_id, user_id) ) {
        db->insert_signed(pdf_id, user_id);
    } else {
        std::cout << "Failed to sign the pdf" << std::endl;
    }
}

void Cli::show_pdf() {
    db->show_pdfs();
}

void Cli::delete_pdf() {
    std::cout << "Insert the id of the Pdf to delete: " << std::endl;
    int id;
    std::cin >> id;
    db->delete_pdf(id);
}

void Cli::check_signature() {
    std::cout << "Insert the id of the Pdf to check: " << std::endl;
    int pdf_id;
    std::cin >> pdf_id;
    std::cout << "Insert the id of the User to check: " << std::endl;
    int user_id;
    std::cin >> user_id;
    if (db->check_user(user_id) && db->check_pdf(pdf_id)) {
        check(user_id, pdf_id);
    } else {
        std::cout << "Error while checking" << std::endl;
    }
}

void Cli::check(int user_id, int pdf_id) {
    ByteArray hash = db->get_hash(pdf_id);
    std::string key_buffer = db->get_public_key(user_id);
    RSAPublicKey public_key = RSAPublicKey(key_buffer);
    ByteArray signature = db->get_signature(pdf_id, user_id);

    bool result = Signer::verify(public_key, signature, hash, MessageDigest::SHA256);

    if (result) {
        std::cout << "The Signature of the user (" << user_id << ") is valid" << std::endl;
    } else {
        std::cout << "The Signature is invalid" << std::endl;
    }
}
