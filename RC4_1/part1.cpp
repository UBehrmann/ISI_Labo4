/* 
 * File:   part1.cpp
 * Author: patrick.mast
 *
 * Created on 30. avril 2013, 14:39
 * Adapted by Julien Biefer on 30. april 2019
 */

#include <cstdlib>
#include <iostream>
#include <fstream>

#include "laboCryptoUtils.h"

using namespace std;

int main(int argc, char** argv) {
    
    /* Compléter les parties marquées <TODO>. Il peut manquer une ou plusieurs instructions à chaque fois */

    // Noms des fichiers
    const char* file1Plain    = "src/part1_01.bmp";
	const char* file1Rc4      = "src/part1_01_rc4.bmp";
	const char* file2Rc4      = "src/part1_02_rc4.bmp";
    const char* file2Plain    = "src/part1_02.bmp";

    // Lecture des tailles des images
    long sizeFile1 = readImageSize(file1Plain);
    long sizeFile2 = readImageSize(file2Rc4);
    
    // Vérification de la compatibilité des tailles
    if (sizeFile1 != sizeFile2) {
		cout << "Les images n'ont pas la même taille" << endl;
		return EXIT_FAILURE;
	}
    
    // Lecture des images /!\ mémoire allouée
    char* image1Plain = readImage(file1Plain, sizeFile1);
    char* image1Rc4 = readImage(file1Rc4, sizeFile1);
    char* image2Rc4 = readImage(file2Rc4, sizeFile2);
	char* image2Plain = new char[static_cast<unsigned long long int>(sizeFile2)];

    // Taille du contenu de l'image
    long contentSize = sizeFile1 - HEADERS_SIZE;
    
    // Création des en-têtes
    char headers[HEADERS_SIZE];
    for (long i = 0; i < HEADERS_SIZE; ++i) {
        headers[i] = image1Plain[i];
    }

    // Création du contenu en effectuant un XOR avec le keystream
	for(long i = HEADERS_SIZE; i < contentSize; i++){

		image2Plain[i] = (char)( (image1Plain[i] ^ image1Rc4[i]) ^ image2Rc4[i] ) ;
	}

	// Création de l'image résultat
	storeImage(file2Plain, headers, image2Plain, HEADERS_SIZE, contentSize);

	// Libération de l'espace mémoire alloué par readImage
	delete[] image1Plain;
	delete[] image1Rc4;
	delete[] image2Rc4;
	delete[] image2Plain;

	return EXIT_SUCCESS;
}
