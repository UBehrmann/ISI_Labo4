/* 
 * File:   part3.cpp
 * Author: patrick.mast
 *
 * Created on 1. mai 2013, 13:14
 */

#include <cstdlib>
#include <iostream>

#include "aes.h"

using namespace std;

int main(int argc, char** argv) {

    // Le texte de 128 bits à déchiffrer
    uint8_t aes[] = {0xF2, 0x59, 0x42, 0x14, 0x10, 0xF5, 0x76, 0x64, 0x79, 0x99, 0xA4, 0x7C, 0x33, 0x8B, 0xED, 0xCC};

    // La clé dont les 24 derniers bits ne sont pas connus
    uint8_t key[] = {0x6D, 0x6F, 0x6E, 0x20, 0x6C, 0x61, 0x63, 0x20, 0x65, 0x73, 0x74, 0x20, 0x61, 0x00, 0x00, 0x00};

    uint8_t result[16];
    uint32_t ks_d[44];

    /////////////////////////////////////
    // Exemple de déchiffrement AES
    //
    // aes128_dks(ks_d, key);
    // aes128_decrypt(result, aes, ks_d);
    //
    /////////////////////////////////////

    // Code à compléter !

    // Clefs a tester
    unsigned keys = 0xff * 0xff * 0xff;

    for(unsigned i = 0; i < keys; i++) {
        key[13] = i & 0xff;
        key[14] = (i >> 8) & 0xff;
        key[15] = (i >> 16) & 0xff;

        aes128_dks(ks_d, key);
        aes128_decrypt(result, aes, ks_d);

        if(result[0] == 'j' && result[1] == ' ' && result[2] == 'a' && result[3] == 'i') {

            cout << "Key found: ";

            for(unsigned char j : key) {
                cout << hex << (int)j << " ";
            }

            cout << endl;

            cout << "Decrypted message: ";

            for(unsigned char j : result) {
                cout << j;
            }

            cout << endl << endl;
        }
    }

    return EXIT_SUCCESS;
}


