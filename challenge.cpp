#include <string>

#include "Cli.hpp"
#include "StorageEngine.hpp"

// Cli representa a interface com o usuario; O caminho para a database esta diretamente no codigo,
// mas antes de rodar precisa-se criar o arquivo apesar de ser uma instancia de sqlite (touch db.db)
int main(int argc, char **argv) {
    std::string path = "db.db";
    StorageEngine db = StorageEngine(path);
    Cli app_it = Cli(db);

    return 0;
}
