/* 
 * File:   laboCryptoUtils.cpp
 * Author: patrick.mast
 *
 * Created on 30. avril 2013
 * Adapted by Julien Biefer on 30. april 2019
 */

#include <cstdlib>
#include <iostream>
#include <fstream>

using namespace std;

/*
 * Permet de lire la taille d'une image
 */
long readImageSize(const char* name) {

    // Ouverture du fichier
    FILE* file = NULL;
    file = fopen(name, "rb");
    if (file == NULL) {
        printf("Error, impossible to open file");
        system("PAUSE");
        exit(0);
    }

    // Positionnement du curseur à la fin du fichier
    fseek(file, 0, SEEK_END);
    // Lecture de la taille
    int size = ftell(file);
    // Repositionnement au début du fichier
    fseek(file, 0, SEEK_SET);

    // Fermeture du fichier
    fclose(file);

    return size;
}

/*
 * Permet de lire le contenu d'une image
 */
char* readImage(const char* name, const long size) {

    // Ouverture du fichier en lecture binaire
    FILE* file = NULL;
    file = fopen(name, "rb");
    if (file == NULL) {
        printf("Error, impossible to open file");
        system("PAUSE");
        exit(0);
    }

    // Vérification que la taille n'est pas nulle
    if (!size) {
        printf("Error, empty file");
        system("PAUSE");
        exit(0);
    }

    // Lecture du contenu
    char* content = new char[size];
    fread(content, size, 1, file);

    // Fermeture du fichier
    fclose(file);

    return content;
}

/*
 * Permet de sauver une image sur le disque
 */
bool storeImage(const char* name, const char* headers, const char* data, const long sizeHeaders, const long sizeData) {

    // Ouverture du fichier en écriture binaire
    FILE *out = NULL;
    out = fopen(name, "wb");
    if (out == NULL) {
        printf("Error, impossible to open file");
        system("PAUSE");
        return false;
    }

    // Ecriture des en-têtes et du contenu
    fwrite(headers, sizeHeaders, 1, out);
    fwrite(data, sizeData, 1, out);

    // Fermeture du fichier
    fclose(out);

    return true;
}

/* 
 * Permet de chiffrer ou de déchiffrer un document 
 */
char* RC4(char* lpBuf, const char* lpKey, unsigned const long dwBufLen, unsigned const long dwKeyLen) {

    int a, c = 0, s[256];
    int swap;
    unsigned long dwCount;
    
    // Génération du tableau de permutations
    for (a = 0; a < 256; a++) {
        s[a] = a;
    }
    for (a = 0; a < 256; a++) {
        c = (c + s[a] + lpKey[a % dwKeyLen]) % 256;
        swap = s[a];
        s[a] = s[c];
        s[c] = swap;
    }
    
    // Chiffrement par XOR
    a = 0;
    c = 0;
    for (dwCount = 0; dwCount < dwBufLen; dwCount++) {
        a = (a + 1) % 256;
        c = (c + s[a]) % 256;
        swap = s[a];
        s[a] = s[c];
        s[c] = swap;
        lpBuf[dwCount] ^= s[(s[a] + s[c]) % 256];
    }
    return lpBuf;
}