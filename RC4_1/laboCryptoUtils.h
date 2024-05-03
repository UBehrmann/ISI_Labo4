/* 
 * File:   laboCryptoUtils.h
 * Author: patrick.mast
 *
 * Created on 30. avril 2013
 * Adapted by Julien Biefer on 30. april 2019
 */

#ifndef LABOCRYPTOUTILS_H
#define	LABOCRYPTOUTILS_H

const long HEADERS_SIZE = 40;

/**
 * Permet de chiffrer ou de déchiffrer un document
 * @param lpBuf document à chiffrer/déchiffré, qui sera modifié
 * @param lpKey clé à utiliser
 * @param dwBufLen longueur du document à chiffrer/déchiffrer
 * @param dwKeyLen longueur de la clé
 * @return le document chiffré/déchiffré (sera aussi disponible via lpBuf
 */
char* RC4(char* lpBuf, const char* lpKey, unsigned const long dwBufLen, unsigned const long dwKeyLen);

/**
 * Permet de lire la taille d'une image
 * @param name nom de l'image
 * @return la taille
 */
long readImageSize(const char* name);

/**
 * Permet de lire le contenu d'une image
 * @param name nom de l'image
 * @param size taille de l'image
 * @return l'image en mémoire /!\ penser à libérer la mémoire
 */
char* readImage(const char* name, const long size);

/**
 * Permet de sauver une image sur le disque
 * @param name nom de l'image
 * @param headers en-têtes de l'image
 * @param data contenu de l'image
 * @param sizeHeaders taille des en-têtes
 * @param sizeData taille des du contenu
 * @return l'état
 */
bool storeImage(const char* name, const char* headers, const char* data, const long sizeHeaders, const long sizeData);

#endif	/* LABOCRYPTOUTILS_H */

