#ifndef ADFGVX_DECIPHER_H
#define ADFGVX_DECIPHER_H

// cipher_config.h � inclu�do por adfgvx_decipher.c ou main,
// mas n�o � estritamente necess�rio aqui se MAX_MESSAGE_LENGTH n�o estiver no prot�tipo.
// No entanto, a fun��o decipher_adfgvx implicitamente depende de MAX_MESSAGE_LENGTH
// para o tamanho do buffer de sa�da esperado.

/**
 * @brief Fun��o principal para decodificar a cifra ADFGVX.
 *
 * Executa a sequ�ncia de etapas para decifrar o texto cifrado.
 * A l�gica desta fun��o e suas auxiliares � baseada no c�digo fornecido pelo utilizador.
 *
 * @param encrypted_text Texto cifrado (string terminada em nulo).
 * @param key Chave de cifra (string terminada em nulo).
 * @param key_length Comprimento da chave.
 * @param output Buffer onde a mensagem decodificada ser� armazenada (deve ser grande o suficiente,
 * tipicamente MAX_MESSAGE_LENGTH conforme definido em cipher_config.h).
 * A fun��o garante a termina��o nula do buffer de sa�da.
 */
void decipher_adfgvx(char *encrypted_text, char *key, int key_length, char *output);

#endif // ADFGVX_DECIPHER_H
