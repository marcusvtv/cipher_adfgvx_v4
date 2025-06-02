#include "cipher_config.h"
#include "adfgvx_decipher.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Constantes symbols e square s�o necess�rias para a decifragem
// e s�o encapsuladas neste m�dulo como static.
static const char symbols[6] = {'A', 'D', 'F', 'G', 'V', 'X'};
static const char square[6][6] = {
    {'A', 'B', 'C', 'D', 'E', 'F'},
    {'G', 'H', 'I', 'J', 'K', 'L'},
    {'M', 'N', 'O', 'P', 'Q', 'R'},
    {'S', 'T', 'U', 'V', 'W', 'X'},
    {'Y', 'Z', ' ', ',', '.', '1'},
    {'2', '3', '4', '5', '6', '7'}};

/**
 * @brief Retorna o �ndice de um s�mbolo ADFGVX dentro do vetor `symbols`.
 * (Fun��o auxiliar est�tica)
 */
static int symbol_index(char c)
{
    for (int i = 0; i < 6; i++)
    {
        if (symbols[i] == c)
            return i;
    }
    return -1; // S�mbolo n�o encontrado
}

/**
 * @brief Reconstr�i as colunas originais da cifra com base na chave de transposi��o.
 * (Fun��o auxiliar est�tica - l�gica fornecida pelo utilizador)
 */
static void reverse_transposition(char *input, char *key, int key_length, char columns[][MAX_MESSAGE_LENGTH], int col_counts[])
{
    if (key_length <= 0) { // Prote��o contra key_length inv�lido
        // Zera col_counts se key_length for inv�lido para evitar uso de dados n�o inicializados
        // No entanto, a fun��o que chama deve garantir key_length > 0.
        // Se key_length � usado para dimensionar 'order', ele deve ser > 0.
        return;
    }

    int len = strlen(input);
    if (len == 0) { // Se a entrada estiver vazia, n�o h� nada a fazer.
        for(int i=0; i<key_length; ++i) col_counts[i] = 0;
        return;
    }
    int rows = len / key_length;
    int extra = len % key_length;

    // 1) monta o vetor order[] = {0,1,2,...,key_length-1}
    int order[key_length]; // VLA
    for (int i = 0; i < key_length; i++) {
        order[i] = i;
    }

    // 2) ordena order[] de acordo com key[order[j]], para obter a ordem alfab�tica
    //    dos �ndices originais da chave.
    for (int i = 0; i < key_length - 1; i++) {
        for (int j = 0; j < key_length - i - 1; j++) {
            if (key[order[j]] > key[order[j + 1]]) {
                int tmp = order[j];
                order[j] = order[j + 1];
                order[j + 1] = tmp;
            }
        }
    }
    // Agora order[i] = �ndice original da i-�sima coluna EM ORDEM ALFAB�TICA da chave.

    // 3) determina quantos s�mbolos cada coluna (identificada pelo seu �ndice original) vai ter.
    //    A l�gica fornecida: a coluna �orig_index� recebeu rows+1 s�mbolos se orig_index < extra.
    //    Isto significa que as primeiras 'extra' colunas *na ordem original da chave* s�o as mais longas.
    //    Isto � diferente da forma como a cifragem normalmente distribui (onde as primeiras 'extra'
    //    colunas *na ordem alfab�tica da chave* s�o as mais longas ao ler o texto cifrado linearmente).
    //    No entanto, vamos seguir a l�gica fornecida.
    //    Para que esta l�gica funcione, o texto cifrado (input) deve ter sido constru�do
    //    de forma que as colunas correspondentes aos primeiros 'extra' �ndices originais da chave
    //    foram preenchidas com 'rows+1' s�mbolos, e as restantes com 'rows' s�mbolos,
    //    E ENT�O estas colunas foram concatenadas na ordem alfab�tica da chave.
    //    Se for assim, ent�o, ao ler o 'input', precisamos saber o comprimento de cada
    //    coluna *na ordem alfab�tica*.
    //    A i-�sima coluna na ordem alfab�tica (que originalmente era a coluna order[i])
    //    ter� rows+1 s�mbolos se ELA (a i-�sima coluna alfab�tica) for uma das 'extra' colunas.
    //    Portanto, o comprimento da coluna order[i] � rows + (i < extra ? 1 : 0).
    //    O c�digo do utilizador faz: col_counts[orig_index] = rows + (orig_index < extra ? 1 : 0);
    //    Vou manter a l�gica do utilizador como solicitada.
    for (int i = 0; i < key_length; i++)
    {
        int orig_index = order[i]; // orig_index � o �ndice da coluna original que � a i-�sima na ordem alfab�tica
        col_counts[orig_index] = rows + (orig_index < extra ? 1 : 0);
    }


    // 4) preenche cada �columns[orig_index]� lendo do texto cifrado linearizado
    //    O texto cifrado (input) � a concatena��o das colunas na ordem alfab�tica da chave.
    //    A i-�sima coluna na ordem alfab�tica da chave � a coluna original order[i].
    //    O comprimento desta i-�sima coluna alfab�tica � o que precisamos para ler do input.
    //    Este comprimento N�O � col_counts[order[i]] (que foi calculado acima com base em orig_index < extra).
    //    Precisamos do comprimento da i-�sima coluna *alfab�tica*.
    //    Seja `len_alpha[i]` o comprimento da i-�sima coluna alfab�tica.
    //    `len_alpha[i] = rows + (i < extra ? 1 : 0);`
    //    Ent�o, lemos `len_alpha[i]` caracteres do `input` e colocamos em `columns[order[i]]`.
    //    A l�gica do utilizador no passo 4 �:
    //    `int col_index = order[i];`
    //    `for (int j = 0; j < col_counts[col_index]; j++) { columns[col_index][j] = input[pos++]; }`
    //    Isto usa `col_counts[col_index]` (onde `col_index` � o �ndice original) como o n�mero de
    //    caracteres a serem lidos do `input` para a coluna `columns[col_index]`.
    //    Isto implica que `col_counts[k]` deve ser o comprimento da coluna `k` quando ela � lida
    //    do `input` (ou seja, quando a coluna `k` aparece na ordem alfab�tica da chave).
    //    Portanto, o passo 3 do utilizador est� correto se `col_counts[orig_index]` for interpretado
    //    como o comprimento da coluna `orig_index` *quando ela � lida do texto cifrado linear*.
    //    Mas o texto cifrado � lido coluna alfab�tica por coluna alfab�tica.
    //    A i-�sima coluna alfab�tica tem `rows + (i < extra ? 1 : 0)` caracteres.
    //    Esta i-�sima coluna alfab�tica corresponde � coluna original `order[i]`.
    //    Ent�o, `columns[order[i]]` � preenchida com `rows + (i < extra ? 1 : 0)` caracteres.
    //    E `col_counts[order[i]]` deve ser igual a `rows + (i < extra ? 1 : 0)`.
    //    A l�gica do utilizador no passo 3: `col_counts[orig_index] = rows + (orig_index < extra ? 1 : 0);`
    //    A l�gica do utilizador no passo 4: usa `col_counts[col_index]` (onde `col_index = order[i]`).
    //    Vou implementar exatamente como o utilizador forneceu, assumindo que a sua cifragem
    //    produz um `input` que � decifr�vel por esta l�gica.

    // Limpa col_counts antes de recalcular, para garantir que n�o h� lixo.
    memset(col_counts, 0, key_length * sizeof(int));

    // Passo 3 do utilizador (calcula o tamanho de cada coluna original)
    for (int i = 0; i < key_length; i++) {
        int orig_index = order[i]; // order[i] � o �ndice original da i-�sima coluna alfab�tica
        // O utilizador atribui o comprimento � coluna original baseado no seu pr�prio �ndice original.
        col_counts[orig_index] = rows + (orig_index < extra ? 1 : 0);
    }

    // Passo 4 do utilizador (preenche as colunas)
    int pos = 0;
    for (int i = 0; i < key_length; i++) { // Itera sobre as colunas na ordem alfab�tica da chave
        int original_col_index_to_fill = order[i]; // Esta � a coluna original que estamos a preencher agora
        // O n�mero de caracteres a ler do 'input' para esta coluna (original_col_index_to_fill)
        // � o seu tamanho, que foi calculado em col_counts[original_col_index_to_fill].
        int num_chars_for_this_col = col_counts[original_col_index_to_fill];

        for (int j = 0; j < num_chars_for_this_col; j++) {
            if (pos < len) {
                columns[original_col_index_to_fill][j] = input[pos++];
            } else {
                // Erro: input mais curto que o esperado pelos comprimentos das colunas.
                // Preencher o resto com nulos ou retornar erro?
                // Por agora, apenas para.
                return;
            }
        }
    }
}


/**
 * @brief Reverte a organizacao em colunas, reconstruindo a sequencia de simbolos linha a linha.
 * (Funcao auxiliar estatica - logica do utilizador)
 */
static void reverse_polybius(char columns[][MAX_MESSAGE_LENGTH], int col_counts[], int key_length, char *output)
{
    if (key_length <= 0 || !output) {
        if (output) output[0] = '\0';
        return;
    }

    int max_rows = 0, pos = 0;

    for (int i = 0; i < key_length; i++)
    {
        if (col_counts[i] > max_rows)
            max_rows = col_counts[i];
    }

    for (int r = 0; r < max_rows; r++)
    {
        for (int c = 0; c < key_length; c++) // Itera sobre as colunas na ordem original da chave
        {
            if (r < col_counts[c]) // Se a coluna 'c' tiver um simbolo na linha 'r'
            {
                if (pos < MAX_MESSAGE_LENGTH * 2) { // Protege o buffer de saida 'output' (rearranged)
                    output[pos++] = columns[c][r];
                } else {
                    if (output) output[pos] = '\0'; // Tenta terminar a string
                    return; // Buffer de saida cheio
                }
            }
        }
    }
    if (output) output[pos] = '\0'; // Termina a string de saida
}

/**
 * @brief Decodifica pares de simbolos ADFGVX em caracteres da matriz Polybius.
 * (Funcao auxiliar estatica - logica do utilizador)
 */
static void decode_symbols(char *pairs, char *message)
{
    if (!pairs || !message) return;

    int len = strlen(pairs);
    int msg_index = 0;

    if (len % 2 != 0) {
        message[0] = '\0'; // Nao pode decodificar numero impar de simbolos
        return;
    }

    for (int i = 0; i < len; i += 2)
    {
        int row = symbol_index(pairs[i]);
        int col = symbol_index(pairs[i + 1]);
        if (row >= 0 && col >= 0) // Se o par de simbolos e valido
        {
            if (msg_index < MAX_MESSAGE_LENGTH - 1) { // Protege o buffer de saida 'message'
                message[msg_index++] = square[row][col];
            } else {
                break; // Buffer de mensagem cheio
            }
        } else {
            // Par de simbolos invalido.
            // O comportamento original era parar. Mantendo isso.
            break;
        }
    }
    message[msg_index] = '\0'; // Termina a string da mensagem decifrada
}

// Implementacao da funcao publica
void decipher_adfgvx(char *encrypted_text, char *key, int key_length, char *output)
{
    // Validacao basica de parametros
    if (!encrypted_text || !key || !output || key_length <= 0 || key_length >= MAX_KEY_LENGTH) {
        if (output) output[0] = '\0';
        return;
    }
    if (strlen(encrypted_text) == 0) {
        output[0] = '\0';
        return;
    }

    // VLAs para 'columns' e 'col_counts'.
    char columns[key_length][MAX_MESSAGE_LENGTH];
    int col_counts[key_length];
    // � crucial zerar col_counts e columns antes de us�-los,
    // especialmente porque reverse_transposition pode n�o preencher todas as partes se len for 0.
    memset(col_counts, 0, key_length * sizeof(int));
    for(int i=0; i<key_length; ++i) {
        memset(columns[i], 0, MAX_MESSAGE_LENGTH * sizeof(char));
    }

    // Buffer para a sequencia de simbolos apos reverter a transposicao.
    // O tamanho m�ximo � o mesmo do texto cifrado (que pode ser at� MAX_MESSAGE_LENGTH * 2).
    char rearranged_symbols[MAX_MESSAGE_LENGTH * 2 + 1]; // +1 para o nulo

    reverse_transposition(encrypted_text, key, key_length, columns, col_counts);
    reverse_polybius(columns, col_counts, key_length, rearranged_symbols);
    decode_symbols(rearranged_symbols, output);
}
