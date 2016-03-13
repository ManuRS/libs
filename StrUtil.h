/** 
 *@brief Module for strings handling
 * 
 *@file StrUtil.c
 *@author Manuel Reyes
 *@version 3.2
 *@date 21-02-13
 */
#ifndef STRUTIL_H_
#define STRUTIL_H_
#include "Const.h"
#include <string.h>

/**
* @brief Eliminate some characters of the string
* eliminate_chars
* @param dst string: where the ``cleaned´´ string is copy
* @param src string: the original string
* @param seps string: contain the prohibited characters
* @return Returns NULL if there is an error and src string if the process is ok.
****/
char * eliminate_chars(char * dst, const char * src, const char * seps, size_t max);



/**
* @brief converts lowercase letters in a string to uppercase letters
* to_uppercase
* @param dst string: where the convert string is copy
* @param src string: the original string
* @param max: the maximum number of elements in the chain
* @return Returns NULL if there is an error and dst string if the process is ok.
****/
char * to_uppercase(char * dst, const char * src, size_t max);




/**
*@brief replaces the first asterisk in one string by a new text. The resulting string *is stored in a new destiny.
*@param dst string: where the convert string is copy
*@param src string: the strig with the '*'
*@param ins string: the introduced string
*@param n: errors control, max size chain
*@return Returns NULL if there is an error and dst string if the process is ok
*
*******/
char * replace_asterik(char * dst, const char * src, const char *ins, size_t n);



/**
*@brief v1.0: clean spaces at the begining and at the end of a strigs
* v2.0: if there is two spaces or more together (n spaces) 
*the function eliminate n-1 spaces
*@param dst string: where the convert string is copy
*@param src string: the original strig
*@param n: errors control, max size chain
*@return Rerurns NULL if there is as error and dst string if the process is ok
*
**********/
char * clean_spaces(char * dst, const char * src, size_t n);

/**
*@brief : Delete the part of a string which is before a given fragment (included)
*@param dst string: where the new string is copied
*@param src string: the original string
*@param obj string: the given fragment
*@return Rerurns NULL if there is as error and dst string if the process is ok
*
**********/
char * user_info(char * dst, const char * src, const char * obj);


/**
@brief function is to inicialate a string with all the symbols that we want to quit from the sentence that the user has introduced. 
*Function_generateSeps:
@param seps The string to inicialate
@return The string once it has been inicialated.
@author Ana Isabel Viciana Pérez
@date 31th January 2013
*********/
void generateSeps(char seps[SYMBOLS]);
/**
* @brief converts uppercase letters in a string with lowercase letters
* @param str string: the string to lowercase
* @return Returns NULL if there is an error and str string if the process is ok.
****/
extern char * to_lowercase(char * str);
#endif /* STRUTIL_H_ */

