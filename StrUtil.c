/** 
 *@brief Module for strings handling
 * 
 *@file StrUtil.c
 *@author All module and funtions by: Manuel Reyes
 *@version 4.0
 *@date 23-05-13
 */

#include "StrUtil.h"

#include <stdio.h>
#include <stdlib.h>

/***********************************
 * Eliminate chars
 ***********************************/
extern char * eliminate_chars(char * dst, const char * src, const char * seps, size_t max){   


	/*dst it´s where I copy src without the chars of seps*/

	int count, count2, numArray=0;

	if (dst==NULL || src==NULL || seps==NULL || max<0)          /*check the pointers*/
	    return NULL;

	for(count = 0; src[count]!='\0'; count++){                  /*loop to traverse the array*/
	    numArray++;                                             /*to count the size of src*/
	}                                         

	if (numArray>max)          /*check if the size of src is more than the max size*/
    	return NULL;

	memset(dst, '\0', max);

	for(count=0; src[count]!='\0'; count++){           /*loop to traverse the array*/

    	dst[count]=src[count];
    
    	for(count2=0; seps[count2]!='\0'; count2++){             /*loop to check the ``prohibited characters´´*/
    
         	if(dst[count]==seps[count2])
         	dst[count]=' ';
    	}
	}
	return dst;
}

/***********************************
 * To uppercase
 ***********************************/
extern char * to_uppercase(char * dst, const char * src, size_t max)    /*dst it´s where I copy src in uppercase*/
{   
    int count, numArray=0;
    /*Checks*/
    if (dst==NULL || src==NULL || max<0)                              /*check the pointers*/
           return NULL;

    for(count=0; src[count]!='\0'; count++){                          /*loop to traverse the array*/
	     dst[count]='\0';
         numArray++;                                                  /*to count the size of src */
    }

    if (numArray>max)                                                 /*check if the size of src is more than the max size*/
        return NULL;
    
   memset(dst, '\0', max);
           
    /*we can use too a standard funtion called toupper for this*/
    for (count=0; src[count]!='\0'; count++){                         /*loop to traverse the array*/
       
 dst[count]=src[count];
    
        if(dst[count]>96 && dst[count]<123)
            dst[count]=dst[count]-32;                                 /*the difertent between capitals and lowercase letters in ASCII is 32*/
    }

     return dst;
}

/***********************************
 * Clean Spaces
 ***********************************/
char * clean_spaces(char * dst, const char * src, size_t n){
    
	int cont, cont2, cont3, numArray=0;
	char dstaux[100];

    /*Checks*/
    if (dst==NULL || src==NULL || n<0)                              /*check the pointers*/
           return NULL;

    for(cont=0; src[cont]!='\0'; cont++){                        /*loop to traverse the array*/
	         dst[cont]='\0';                                     /*clean dst*/
             numArray++;                                         /*to count the size of src */

    }
    if (numArray>n)                           /*check if the size of src is more than the max size*/
   
      return NULL;

    for(cont=0; cont<100; cont++){

         dstaux[cont]='\0';
    }

    /*Spaces before words*/	
    for(cont=0; src[cont]==' '; cont++){}          /*This loop ends when there is a word*/
		

    for(cont2=0; src[cont+cont2]!='\0'; cont2++){       /*Copy without spaces before words*/
		
		dstaux[cont2]=src[cont+cont2];
	}
	
    dstaux[cont2]='\0';


    /*Space after words*/
       
	
        numArray = strlen(dstaux);
        

	for(; dstaux[numArray]==' ' || dstaux[numArray]=='\0'; numArray--){
	
		dstaux[numArray]='\0';                         /*If there is a space */

    }

	/*More than one space*/

	for(cont=0, cont2=0, cont3=0; dstaux[cont]!='\0'; cont++){
		
		if(dstaux[cont]!=' '){
		
			dst[cont3]=dstaux[cont];
			cont3++;					/*To kwon de position of dst array*/
			cont2=0;                    /*Spaces counter reset*/
		}
		if(dstaux[cont]==' ' && cont2==0){

			dst[cont3]=dstaux[cont];
			cont3++;                     /*Because we write in dst*/
			cont2++;                     /*Space found*/

		}

	}
	
	dst[cont3]='\0';
	return dst;

}


/***********************************
 * Replace asterisk
 ***********************************/
char * replace_asterik(char * dst, const char * src, const char *ins, size_t n){

    int numArray, cont, cont2;
    char *aux=NULL;

    /*Checks*/
    if ( src==NULL || ins==NULL || n<0)        /*check the pointers*/
           return NULL;

    for(numArray=0; src[numArray]!='\0';  numArray++){}    /*loop count to the array*/
	                                   
                                                    
    for(cont=0; ins[cont]!='\0'; cont++, numArray++){}     /*loop to traverse the other array*/

    if(numArray>n)                             /*numArray is the size of the final string dst*/
        return NULL;

    dst=(char *)calloc(numArray,sizeof(char));

    /*Search the '*' */

    strcpy(dst,src);
    aux=strstr(dst,"*");
    if(!aux){
       return NULL;
    }
    for(cont2=1;cont2<strlen(ins);cont2++){
       aux[cont2-1]=ins[cont2]-('A'-'a');       
    }
    return dst;
}

/***********************************
 * User Info
 ***********************************/
char * user_info(char * dst, const char * src, const char * obj){
   
    int cont, cont2, indice;
    int control = 0;

    for (cont=0; src[cont]!='\0' && control != 1; cont++){
        if(src[cont] == obj[0]){            
            for (cont2=0; obj[cont2]!='\0' && src[cont+cont2]!='\0'; cont2++){
                if (src[cont+cont2] == obj[cont2]){
                    control =  1;
                
                }
                else {
                    control = 0;
                    break;
                }
            }
        }
    }
    if (control==1){
        
        for (indice=0 ;src[cont+cont2-1] != '\0'; indice++, cont++){
            
            dst[indice]=src[cont+cont2-1];
        }
        
        dst[indice] = '\0';
        return dst;
    }
    
    return NULL;

}

/***********************************
 * Generate Seps
 ***********************************/
void generateSeps(char seps[SYMBOLS]){
    int a;      /*<To use the loop>*/
    
    /**Until we hadn't had the number of symbols that we want to quit that is from 33 to 38 and from 40 to 64*/
    for(a=0; a<(SYMBOLS-1);a++){
    
    	     if (a<6){  /*<When a is 6 we will find a symbol that we won't want to quit that is ' so before of it it will execute>*/
    		   seps[a]=33+a;
		} /*<33 is the ASCII's number of the first symbol we want to quit>*/
    	     else{
    		   seps[a]=33+a+1;
    		}
	}
}
/***********************************
 * To lowercase
 ***********************************/
extern char * to_lowercase(char * str){
    int i;
    char *aux;
    if(!str){
        return NULL;
    }
    aux=(char *)calloc((strlen(str)+1),sizeof(char));
    strcpy(aux,str);
    for(i=0;i<strlen(str);i++){
       if((str[i]-'Z')>=('A'-'Z')){
            str[i]=aux[i]-('A'-'a');
       }
       else{

       }     
    }
    free(aux);
    return str;
}

