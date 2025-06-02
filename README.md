# Ferramenta de Cifragem e Decifragem ADFGVX em C

## Introdução: Um Programa para Cifragem ADFGVX

Este projeto apresenta uma implementação em C da cifra clássica ADFGVX, um algoritmo histórico de criptografia. O foco principal é fornecer uma ferramenta capaz de **cifrar** mensagens de texto, transformando-as em um formato codificado para proteger sua confidencialidade.

Embora a cifragem seja a funcionalidade central, o programa também oferece a capacidade de **decifrar** mensagens previamente codificadas (assumindo que a mesma chave e lógica de algoritmo sejam usadas) e realizar uma série de **testes** para validar a correção e o desempenho do algoritmo implementado.

## O Algoritmo ADFGVX

A cifra ADFGVX, utilizada durante a Primeira Guerra Mundial, é uma cifra de substituição fracionada combinada com uma transposição colunar. Seu funcionamento pode ser resumido nas seguintes etapas:

### Cifragem:

1.  **Matriz de Polybius Modificada**: Utiliza-se uma matriz quadrada (neste caso, 6x6, definida pelas constantes `square` e `symbols` no código) preenchida com caracteres (letras, números, símbolos). As linhas e colunas desta matriz são nomeadas com os símbolos 'A', 'D', 'F', 'G', 'V', 'X'.
2.  **Substituição**: Cada caractere da mensagem original é localizado na matriz Polybius. Ele é então substituído por um par de símbolos ADFGVX, onde o primeiro símbolo corresponde à linha e o segundo à coluna do caractere na matriz. Caracteres não presentes na matriz são geralmente ignorados (conforme implementado em `get_adfgvx_symbols`).
    * Exemplo: Se 'M' está na linha 'F' e coluna 'A' da matriz, ele é substituído por "FA".
3.  **Formação da Mensagem Intermediária**: Todos os pares de símbolos ADFGVX resultantes da substituição são concatenados para formar uma longa string de símbolos.
4.  **Transposição Colunar com Chave**:
    * Uma palavra-chave secreta é escolhida.
    * Os símbolos da mensagem intermediária são escritos linha por linha sob as letras da palavra-chave, formando colunas. (Função `polybius_encode_to_columns`).
    * As colunas são então reordenadas de acordo com a ordem alfabética das letras da palavra-chave. (Função `transpose_columns_by_key_order`).
    * O texto cifrado final é obtido lendo os símbolos de cada coluna reordenada, de cima para baixo, da esquerda para a direita. (Este processo de leitura para formar a string linear é feito ao salvar no arquivo ou ao preparar para a decifragem).

### Decifragem:

A decifragem é o processo inverso, utilizando a lógica implementada em `adfgvx_decipher.c`:

1.  **Reverter a Transposição Colunar (`reverse_transposition`)**:
    * O texto cifrado linearizado é recebido como entrada.
    * Calcula-se o número de linhas (`rows`) e símbolos extras (`extra`) com base no comprimento do texto cifrado e no `key_length`.
    * Um array `order` é criado e ordenado para refletir a ordem alfabética dos caracteres da chave. `order[i]` passa a conter o índice original da coluna que é a i-ésima na ordem alfabética da chave.
    * O número de símbolos em cada coluna *original* (`col_counts[orig_index]`) é determinado. A lógica (`col_counts[orig_index] = rows + (orig_index < extra ? 1 : 0);`) implica que as primeiras `extra` colunas *na ordem original da chave* são as que recebem um símbolo a mais.
    * A matriz `columns[][]` (representando as colunas na ordem original da chave) é preenchida. Para cada coluna na ordem alfabética da chave (identificada por `order[i]`), o número correspondente de símbolos (dado por `col_counts[order[i]]` na sua lógica, ou `rows + (i < extra ? 1 : 0)` se interpretarmos como o comprimento da i-ésima coluna alfabética) é lido do texto cifrado linearizado e colocado em `columns[order[i]]`.
2.  **Reconstruir a Sequência Intermediária (`reverse_polybius`)**:
    * Os símbolos da matriz `columns` (agora com as colunas na ordem original da chave e com os `col_counts` corretos) são lidos linha por linha, da esquerda para a direita, para reconstruir a string linear `rearranged_symbols` que existia antes da transposição na cifragem.
3.  **Reverter a Substituição de Polybius (`decode_symbols`)**:
    * A string `rearranged_symbols` é lida em pares.
    * Cada par de símbolos ADFGVX é convertido de volta para seus índices numéricos (usando `symbol_index`).
    * Esses índices (linha, coluna) são usados para localizar o caractere correspondente na matriz `square` original.
    * Esses caracteres formam a mensagem decifrada.

## Estrutura de Arquivos e Módulos

O projeto está organizado com os arquivos de código fonte (`.c`) na pasta `src/` e os arquivos de cabeçalho (`.h`) na pasta `headers/`.

* `projeto_adfgvx/`
    * `headers/`
        * `cipher_config.h`
        * `file_operations.h`
        * `adfgvx_core.h`
        * `adfgvx_decipher.h`
    * `src/`
        * `file_operations.c`
        * `adfgvx_core.c`
        * `adfgvx_decipher.c`
        * `main_decipher_and_test.c`
        * `(opcionalmente main.c ou main_cipher_only.c)`
    * `key.txt`
    * `message.txt`
    * `encrypted.txt`
    * `cipher_adfgvx_v4.cbp`
    * `(outros arquivos gerados)`

* **`headers/cipher_config.h`**: Contém definições de macros globais (ex: `MAX_MESSAGE_LENGTH`, `MAX_KEY_LENGTH`) e nomes de arquivos padrão.
* **`headers/file_operations.h`** e **`src/file_operations.c`**: Módulo responsável pelas operações de leitura e escrita de arquivos.
* **`headers/adfgvx_core.h`** e **`src/adfgvx_core.c`**: Módulo contendo a lógica principal para o processo de **cifragem** ADFGVX.
* **`headers/adfgvx_decipher.h`** e **`src/adfgvx_decipher.c`**: Módulo contendo a lógica principal para o processo de **decifragem** ADFGVX.
* **`src/main_decipher_and_test.c`**: Programa principal que foca na decifragem de um arquivo e na execução de testes de validação.
* **`src/main.c`**: Poderia ser um programa principal focado apenas na cifragem.
* **`cipher_adfgvx_v4.cbp`**: Projeto do codeblocks com dois targets (cifragem-Release e Decifragem/Teste)

## Principais Métodos (Funções Chave e sua Lógica)

### Em `src/adfgvx_core.c` (Cifragem):

* **`void cipher_adfgvx(...)`**:
    * Orquestra todo o processo de cifragem ADFGVX.
    * Chama internamente (funções `static`):
        * `get_adfgvx_symbols()`: Localiza um caractere na matriz Polybius (`square`) e retorna seus símbolos ADFGVX correspondentes (`symbols`) para linha e coluna.
        * `insert_symbol_to_column()`: Adiciona um símbolo ADFGVX à próxima posição disponível na coluna correta da `encoded_symbol_matrix`, baseando-se no `symbol_count` e `key_length`. Atualiza `symbols_per_column`.
        * `polybius_encode_to_columns()`: Itera sobre a mensagem original. Para cada caractere, obtém seus dois símbolos ADFGVX e os insere sequencialmente nas colunas da `encoded_symbol_matrix`.
        * `transpose_columns_by_key_order()`: Cria uma cópia da chave (`sorted_key`). Ordena `sorted_key` alfabeticamente. Sempre que dois caracteres em `sorted_key` são trocados durante a ordenação, as colunas correspondentes inteiras na `encoded_symbol_matrix` e seus contadores em `symbols_per_column` também são trocados.

### Em `src/adfgvx_decipher.c` (Decifragem):

* **`void decipher_adfgvx(char *encrypted_text, char *key, int key_length, char *output)`**:
    * Orquestra o processo de decifragem.
    * Chama internamente (funções `static`):
        * `symbol_index()`: Dado um caractere 'A', 'D', 'F', 'G', 'V', ou 'X', retorna seu índice numérico (0-5).
        * `reverse_transposition()`: Desfaz a transposição colunar.
        * `reverse_polybius()`: Pega a matriz `columns[][]` (com as colunas já na ordem original da chave) e lê os símbolos linha por linha para reconstruir a string linear `rearranged_symbols`.
        * `decode_symbols()`: Pega a string `rearranged_symbols`, lê os símbolos ADFGVX em pares, e reconstrói os caracteres da mensagem original.

### Em `src/file_operations.c`:

* **`int read_file(...)`**: Lê a primeira linha de um arquivo para um buffer, removendo o `\n` ou `\r\n`.
* **`int write_encrypted_data_to_file(...)`**: Escreve a `encoded_symbol_matrix` (saída da cifragem) de forma linearizada para um arquivo.
* **`int write_plaintext_to_file(...)`**: Escreve uma string de texto simples (como a mensagem decifrada) para um arquivo.

## Como Compilar (Estrutura com Pastas `src` e `headers`)

Assumindo que você está na **pasta raiz do seu projeto** ao executar estes comandos:

**Requisitos:** Compilador GCC (ou compatível), padrão C99 ou superior (para VLAs).

1.  **Para compilar a Ferramenta de Decifragem e Testes (`adfgvx_decipher_tester`):**
    ```bash
    gcc -Wall -Wextra -pedantic -std=c99 -Iheaders src/main_decipher_and_test.c src/adfgvx_core.c src/adfgvx_decipher.c src/file_operations.c -o adfgvx_decipher_tester
    ```

2.  **Para compilar uma Ferramenta de Cifragem (ex: se você criar `src/main.c`):**
    ```bash
    gcc -Wall -Wextra -pedantic -std=c99 -Iheaders src/main.c src/adfgvx_core.c src/file_operations.c -o adfgvx_cipher_tool
    ```

### Explicação das Diretivas (Flags) de Compilação GCC:

* **`gcc`**: O comando para invocar o compilador GNU C.
* **`-Wall`**: Ativa "todos" os avisos comuns do compilador. Ajuda a identificar potenciais problemas no código que não são erros de sintaxe, mas podem levar a comportamento inesperado.
* **`-Wextra`**: Ativa um conjunto adicional de avisos do compilador, ainda mais rigorosos que `-Wall`.
* **`-pedantic`**: Emite todos os avisos exigidos pelo padrão C estrito; rejeita programas que usam extensões GNU proibidas. Ajuda a escrever código mais portável.
* **`-std=c99`**: Especifica que o código deve ser compilado de acordo com o padrão ISO C99. Isso é importante se o seu código utiliza funcionalidades introduzidas no C99, como VLAs (Variable Length Arrays) ou declarações de variáveis no meio de blocos. Você pode usar `c11` ou `c17` para padrões mais recentes.
* **`-Iheaders`**: Esta é uma diretiva crucial para a estrutura de pastas.
    * `-I` (maiúsculo) é a flag para adicionar um diretório à lista de caminhos onde o compilador procura por arquivos de cabeçalho (`.h`) que são incluídos com `#include "nome_do_arquivo.h"`.
    * `headers` (sem espaço após `-I`) é o nome da pasta que você criou para armazenar seus arquivos de cabeçalho.
    * Com esta flag, quando o compilador encontra `#include "cipher_config.h"`, ele procurará por `cipher_config.h` na pasta `headers` (relativa ao diretório onde o comando de compilação é executado).
* **`src/nome_do_arquivo.c`**: Especifica o caminho e o nome de cada arquivo fonte (`.c`) que precisa ser compilado e linkado. Como os arquivos `.c` estão na pasta `src/`, você precisa prefixá-los com `src/`.
* **`-o nome_do_executavel`**:
    * `-o` é a flag para especificar o nome do arquivo de saída (o programa executável).
    * `nome_do_executavel` é o nome que você quer dar ao seu programa compilado (ex: `adfgvx_decipher_tester`).

## Como Usar

1.  **Prepare os Arquivos de Entrada (na raiz do projeto ou conforme configurado):**
    * **`key.txt`**: Contém a chave (ex: `SEGREDO`).
    * **`message.txt`**: Contém a mensagem original (ex: `ATAQUE AO AMANHECER.`).
    * **`encrypted.txt`**: (Para decifrar) Deve conter o texto cifrado gerado anteriormente.

2.  **Executando (Exemplo com `adfgvx_decipher_tester`):**
    * Primeiro, gere um `encrypted.txt` usando uma ferramenta de cifragem (como a `adfgvx_cipher_tool` compilada a partir de um `main` focado em cifragem).
    * Execute a ferramenta de decifragem e testes:
        ```bash
        ./adfgvx_decipher_tester
        ```
    * O programa tentará decifrar `encrypted.txt` usando `key.txt`, salvará o resultado em `decrypted_test_output.txt` (ou o nome em `cipher_config.h`), comparará com `message.txt`, e executará testes internos.

## Testes para Validação (em `src/main_decipher_and_test.c`)

A parte de teste no `main_decipher_and_test.c` serve para **validar a correção e a robustez** da nossa implementação da cifra ADFGVX. Eles não são parte do processo de cifragem/decifragem para o usuário final, mas sim ferramentas de desenvolvimento para garantir que o algoritmo funciona como esperado.

* **Teste de Decifragem Principal (Fluxo do `main` em `main_decipher_and_test.c`)**:
    * **O que faz**: Simula um cenário de uso real. Lê uma chave e um texto cifrado de arquivos, decifra-o, salva o resultado e compara com a mensagem original.
    * **Validação**: Confirma que a decifragem reverte corretamente a cifragem.

* **`test_decipher_internal(...)`**:
    * **O que faz**: Realiza um ciclo completo de cifragem-decifragem com uma chave e mensagem conhecidas, definidas no código.
    * **Validação**: Verifica a integridade do par cifragem/decifragem para entradas controladas.

* **`test_execution_time()`**:
    * **O que faz**: Cifra uma mensagem longa e mede o tempo gasto.
    * **Validação**: Verifica o desempenho da cifragem contra um limite.

* **`test_invalid_character()`**:
    * **O que faz**: Fornece uma mensagem com caracteres inválidos (não presentes na matriz Polybius) para a cifragem.
    * **Validação**: Confirma que esses caracteres são ignorados e o restante da mensagem é cifrado corretamente.

Estes testes, em conjunto, fornecem uma boa cobertura para garantir que a implementação da cifra ADFGVX é correta, funcional e se comporta de maneira previsível.

## Autores

* Lucas Dantas
* Marcus Vinicius

## Licença

MIT License.
