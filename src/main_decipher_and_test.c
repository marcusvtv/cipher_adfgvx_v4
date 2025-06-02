#include <stdio.h>
#include <string.h>
#include <stdlib.h> // Para EXIT_SUCCESS, EXIT_FAILURE
#include <time.h>   // Para test_execution_time

#include "cipher_config.h"
#include "file_operations.h"
#include "adfgvx_core.h"     // Para cipher_adfgvx (usado em testes)
#include "adfgvx_decipher.h" // Para decipher_adfgvx

// --- Fun��es de Teste (Adaptadas do c�digo monol�tico) ---

/**
 * @brief Testa a fun��o de decifragem comparando com a mensagem original.
 * (Fun��o auxiliar est�tica para os testes neste arquivo)
 */
static void test_decipher(const char *test_name, char key[], char original_message[])
{
    printf("\n-> Teste de Decifragem: %s\n", test_name);
    int key_length = strlen(key);
    if (key_length == 0 || key_length >= MAX_KEY_LENGTH) {
        printf("\tERRO: Chave de teste inv�lida '%s' para o teste '%s'.\n", key, test_name);
        return;
    }
    if (strlen(original_message) == 0 && strcmp(test_name, "Teste com mensagem vazia") != 0) { // Permite teste de msg vazia
         printf("\tAVISO: Mensagem original de teste vazia para '%s'.\n", test_name);
    }


    // VLA para a matriz de cifragem
    char encoded_symbol_matrix[key_length][MAX_MESSAGE_LENGTH];
    // Usar MAX_KEY_LENGTH para symbols_per_column � mais seguro se key_length for vari�vel
    // ou inicializar um VLA com key_length. Para consist�ncia com o main original:
    int symbols_per_column[MAX_KEY_LENGTH] = {0};

    // Cifrar a mensagem usando o m�dulo adfgvx_core
    cipher_adfgvx(key, key_length, original_message, encoded_symbol_matrix, symbols_per_column);

    // Linearizar mensagem cifrada para alimentar a decifragem
    char encrypted_linear[MAX_MESSAGE_LENGTH * 2 + 1];
    int pos = 0;
    for (int i = 0; i < key_length; i++)
    {
        for (int j = 0; j < symbols_per_column[i]; j++)
        {
            if (pos < MAX_MESSAGE_LENGTH * 2) { // Protege o buffer
                encrypted_linear[pos++] = encoded_symbol_matrix[i][j];
            } else {
                printf("\tERRO INTERNO DO TESTE: Buffer de encrypted_linear cheio durante a lineariza��o.\n");
                encrypted_linear[pos] = '\0';
                return; // N�o pode continuar o teste
            }
        }
    }
    encrypted_linear[pos] = '\0';

    // Decifrar usando o m�dulo adfgvx_decipher
    char decrypted_output[MAX_MESSAGE_LENGTH];
    decipher_adfgvx(encrypted_linear, key, key_length, decrypted_output);

    printf("\t\tMensagem Original:  \"%.50s%s\"\n", original_message, strlen(original_message) > 50 ? "..." : "");
    printf("\t\tChave:              \"%s\"\n", key);
    printf("\t\tTexto Cifrado:    \"%.50s%s\"\n", encrypted_linear, strlen(encrypted_linear) > 50 ? "..." : "");
    printf("\t\tMensagem Decifrada: \"%.50s%s\"\n", decrypted_output, strlen(decrypted_output) > 50 ? "..." : "");

    if (strcmp(original_message, decrypted_output) == 0)
    {
        printf("\tSUCESSO: Mensagem decifrada corresponde � original!\n");
    }
    else
    {
        printf("\tERRO: A decifragem falhou. Mensagens n�o correspondem.\n");
    }
}

/**
 * @brief Mede o tempo de execu��o da cifragem de uma mensagem longa.
 * (Fun��o auxiliar est�tica para os testes neste arquivo)
 */
static void test_execution_time() // Nome original do monol�tico
{
    printf("\n-> Teste: Tempo de Execu��o da Cifragem\n");
    char key[] = "CHAVE123"; // Chave de 8 caracteres
    int key_length = strlen(key);

    // Criar uma mensagem longa
    char long_message[MAX_MESSAGE_LENGTH];
    memset(long_message, 'A', MAX_MESSAGE_LENGTH - 1);
    long_message[MAX_MESSAGE_LENGTH - 1] = '\0';

    // A matriz encoded_symbol_matrix deve ter a primeira dimens�o baseada no key_length real.
    // Se key_length � 8 (MAX_KEY_LENGTH-1), ent�o [MAX_KEY_LENGTH-1] � apropriado.
    char encoded_symbol_matrix[MAX_KEY_LENGTH -1][MAX_MESSAGE_LENGTH]; // Ajustado para MAX_KEY_LENGTH-1
    int symbols_per_column[MAX_KEY_LENGTH] = {0};

    clock_t start_time = clock();
    cipher_adfgvx(key, key_length, long_message, encoded_symbol_matrix, symbols_per_column);
    clock_t end_time = clock();

    double elapsed_seconds = (double)(end_time - start_time) / CLOCKS_PER_SEC;

    printf("\t\tMensagem: %d caracteres 'A'\n", (int)strlen(long_message));
    printf("\t\tChave: \"%s\"\n", key);
    printf("\t\tTempo de cifragem: %.6f segundos\n", elapsed_seconds);

    if (elapsed_seconds > 0.5) // Limite de 0.5 segundos
    {
        printf("\tAVISO: Tempo de execu��o da cifragem excedeu 0.5 segundos!\n");
    }
    else
    {
        printf("\tSUCESSO: Tempo de execu��o da cifragem dentro do limite de 0.5 segundos.\n");
    }
}

/**
 * @brief Verifica se caracteres inv�lidos s�o ignorados durante a cifragem.
 * (Fun��o auxiliar est�tica para os testes neste arquivo)
 */

 /**
 * @brief Testa a fun��o de decifragem comparando com a mensagem original.
 *
 * @note Usamos key UM e a messagem LUCAS previamente testadas tanto no site https://www.dcode.fr/adfgvx-cipher, quanto realizando a cifragem manualmente.
    Cifra: Lucas -> XF FA AD GA AG
 */
static void test_invalid_character() // Nome original do monol�tico
{
    printf("\n-> Teste: Tratamento de Caracteres Inv�lidos na Cifragem\n");
    char key[] = "UM";
    int key_length = strlen(key);
    char message_with_invalids[] = "L#UC%AS@!d"; // Esperado que apenas "LUCAS" seja cifrado

    // VLA para a matriz de cifragem
    char encoded_symbol_matrix[key_length][MAX_MESSAGE_LENGTH];
    int symbols_per_column[MAX_KEY_LENGTH] = {0};


    const char expected_cipher_for_LUCAS[] = "XFFAADGAAG";

    cipher_adfgvx(key, key_length, message_with_invalids, encoded_symbol_matrix, symbols_per_column);

    char actual_cipher[MAX_MESSAGE_LENGTH * 2 + 1] = {0}; // +1 para nulo
    int pos = 0;
    for (int i = 0; i < key_length; i++)
    {
        for (int j = 0; j < symbols_per_column[i]; j++)
        {
            if (pos < MAX_MESSAGE_LENGTH * 2) { // Protege buffer
                actual_cipher[pos++] = encoded_symbol_matrix[i][j];
            }
        }
    }
    actual_cipher[pos] = '\0';

    printf("\t\tMensagem Original com Inv�lidos: \"%s\"\n", message_with_invalids);
    printf("\t\tChave: \"%s\"\n", key);
    printf("\t\tTexto Cifrado Obtido:          \"%s\"\n", actual_cipher);
    printf("\t\tTexto Cifrado Esperado (para \"LUCAS\"): \"%s\"\n", expected_cipher_for_LUCAS);

    if (strcmp(actual_cipher, expected_cipher_for_LUCAS) == 0)
    {
        printf("\tSUCESSO: Caracteres inv�lidos ignorados e cifragem correta.\n");
    }
    else
    {
        printf("\tERRO: A mensagem cifrada est� incorreta ou os caracteres inv�lidos n�o foram tratados como esperado.\n");
    }
}


int main()
{
    char key_buffer[MAX_KEY_LENGTH];
    char original_message_for_comparison[MAX_MESSAGE_LENGTH];
    char encrypted_text_from_file[MAX_MESSAGE_LENGTH * 2 + 1];
    char decrypted_message_buffer[MAX_MESSAGE_LENGTH];
    int key_len_actual = 0;
    int status;

    printf("--- PROGRAMA DE TESTE DE DECIFRAGEM E OUTROS TESTES ADFGVX ---\n");

    // Etapa principal: Decifrar um arquivo e comparar
    printf("\n--- ETAPA PRINCIPAL: DECIFRAR ARQUIVO E COMPARAR ---\n");

    // 1. Ler chave
    printf("Lendo chave de '%s'...\n", DEFAULT_KEY_FILE);
    status = read_file(DEFAULT_KEY_FILE, key_buffer, MAX_KEY_LENGTH);
    if (status != 0) {
        fprintf(stderr, "Erro ao ler o arquivo da chave '%s'. C�digo: %d. Saindo da etapa principal.\n", DEFAULT_KEY_FILE, status);
        // Prosseguir para os testes auto-contidos
    } else {
        key_len_actual = strlen(key_buffer);
        if (key_len_actual == 0 || key_len_actual >= MAX_KEY_LENGTH) {
            fprintf(stderr, "Erro: Comprimento da chave inv�lido (%d) lido de '%s'. Saindo da etapa principal.\n", key_len_actual, DEFAULT_KEY_FILE);
            // Prosseguir para os testes auto-contidos
        } else {
            printf("Chave: \"%s\", Comprimento: %d\n", key_buffer, key_len_actual);

            // 2. Ler texto cifrado
            printf("Lendo texto cifrado de '%s'...\n", DEFAULT_ENCRYPTED_FILE);
            status = read_file(DEFAULT_ENCRYPTED_FILE, encrypted_text_from_file, sizeof(encrypted_text_from_file));
            if (status != 0) {
                fprintf(stderr, "Erro ao ler o arquivo cifrado '%s'. C�digo: %d.\n", DEFAULT_ENCRYPTED_FILE, status);
                fprintf(stderr, "Certifique-se de que este arquivo existe (gerado por uma ferramenta de cifragem).\n");
            } else {
                printf("Texto Cifrado Lido: \"%.50s%s\"\n",
                       encrypted_text_from_file, strlen(encrypted_text_from_file) > 50 ? "..." : "");

                // 3. Decifrar
                printf("Decifrando o texto lido...\n");
                decipher_adfgvx(encrypted_text_from_file, key_buffer, key_len_actual, decrypted_message_buffer);
                printf("Texto Decifrado: \"%.50s%s\"\n",
                       decrypted_message_buffer, strlen(decrypted_message_buffer) > 50 ? "..." : "");

                // 4. Salvar texto decifrado
                printf("Salvando texto decifrado em '%s'...\n", DEFAULT_DECRYPTED_FILE_FOR_TEST);
                if (write_plaintext_to_file(DEFAULT_DECRYPTED_FILE_FOR_TEST, decrypted_message_buffer) != 0) {
                    fprintf(stderr, "Falha ao salvar o texto decifrado.\n");
                } else {
                    printf("Texto decifrado salvo com sucesso.\n");
                }

                // 5. Comparar com original
                printf("Lendo mensagem original de '%s' para compara��o...\n", DEFAULT_MESSAGE_FILE);
                status = read_file(DEFAULT_MESSAGE_FILE, original_message_for_comparison, MAX_MESSAGE_LENGTH);
                if (status != 0) {
                    fprintf(stderr, "Erro ao ler o arquivo da mensagem original '%s'. C�digo: %d. Compara��o n�o ser� feita.\n", DEFAULT_MESSAGE_FILE, status);
                } else {
                    if (strcmp(original_message_for_comparison, decrypted_message_buffer) == 0) {
                        printf("VERIFICA��O: SUCESSO! Texto decifrado corresponde ao original de '%s'.\n", DEFAULT_MESSAGE_FILE);
                    } else {
                        fprintf(stderr, "VERIFICA��O: FALHA! Texto decifrado N�O corresponde ao original de '%s'.\n", DEFAULT_MESSAGE_FILE);
                    }
                }
            }
        }
    }

    // --- Executar os "outros testes" (adaptados do monol�tico) ---
    printf("\n--- EXECUTANDO TESTES INTERNOS ADICIONAIS ---\n");

    // Os testes usam chaves e mensagens embutidas.
    test_decipher("Teste Interno 1", "UM", "LUCAS");
    test_decipher("Teste Interno 2", "SEMB2025", "TESTANDO A CIFRA ADFGVX COM UMA CHAVE UM POUCO MAIOR E UMA MENSAGEM DE COMPRIMENTO MEDIO PARA VERIFICAR A CORRECAO.");
    test_decipher("Teste Interno 3 (Msg Curta)", "CHAVE", "OI");
    test_decipher("Teste Interno 4 (Msg Vazia)", "TESTE", "");


    test_execution_time(); // Usa cipher_adfgvx
    test_invalid_character(); // Usa cipher_adfgvx

    printf("\n--- FIM DO PROGRAMA DE TESTES ---\n");
    return EXIT_SUCCESS;
}

