# Desafio Labsec 2023 C++
## Introdução
O desafio consiste em criar uma aplicação que permita que diversos usuários assinem um Pdf, para que quando atingido o consenso o reator ligue.
Para criá-lo utilisou-se além do Wrapper de OpenSSL uma Database SqLite
As seguintes funções foram implementadas:
- Registro de Usuário
- Registro de Pdf
- Comparação de Hashes
- Geração de chaves RSA e Certificados
- Verificação

## Instalação
Para rodar o programa, é necessário ter o Docker, e preferencialmente um Pdf para teste (disponível na versão em Zip).
```
$ git clone https://github.com/GustavoRibeiroB/Labsec.git
$ cd Labsec 
$ docker build -t labsec-challenge .
$ docker run -ti --name labsec-challenge labsec-challenge bash
# cd /home/labsec/challenge
# make all
# ./challenge.out
```

## Utilização
O programa têm 10 opções diferentes e deve ser rodado de forma iterativa:

| Número | Descrição | Input | Output |
| -- | -- | -- | -- |
| 1 | Adicionar Usuário |Nome(sem espaços) | Erro ou Sucesso |
| 2 | Deletar Usuário | Id(checar função 3) | Erro ou Sucesso | 
| 3 | Mostrar Usuários || Usuários |
| 4 | Adiciona Pdf | Caminho para o Pdf e Ids dos Usuários | Erro ou Sucesso |
| 5 | Remove Pdf | Id(checar função 6) | Pdfs |
| 6 | Mostrat Pdf || Pdfs
| 7 | Checar Reator | Id(pdf) | Erro ou Sucesso(não checa assinaturas) |
| 8 | Assinar Pdf | Id(pdf) e Id(usuário) | Erro ou Sucesso |
| 9 | Checa Assinatura(uma) | Id(pdf) e Id(usuário) | Erro ou Sucesso |
| 10 | Checa Assinatura(todas) | Id(pdf) | Erro ou Sucesso |
| 11 | Sair do Programa |||

## Exemplo
Um exemplo do funcionamento pode ser visto abaixo:






