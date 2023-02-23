# Desafio Labsec 2023 C++
## Introdução
O desafio consiste em criar uma aplicação que permita que diversos usuários assinem um Pdf, para que quando atingido o consenso o reator ligue.
Para criá-lo utilisou-se além do Wrapper de OpenSSL e uma Database SqLite
As seguintes funções foram implementadas:
- Registro de Usuário
- Registro de Pdf
- Comparação de Hashes
- Geração de chaves RSA e Certificados
- Verificação

## Instalação
Para rodar o programa, é necessário ter o Docker, e preferencialmente um Pdf para teste disponível (disponível na versão em Zip).
```
git clone https://github.com/GustavoRibeiroB/Labsec.git
cd Labsec 
docker build -t labsec-challenge .
docker run -ti --name labsec-challenge labsec-challenge bash
cd /home/labsec/challenge
make all
./challenge.out
```

## Utilização






