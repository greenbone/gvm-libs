/* Nessuslib -- the Nessus Library
 * Copyright (C) 2000 Renaud Deraison
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the Free
 * Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * 
 * Banner comparison functions. The problem with banner comparison is that
 * a lot of banners display the current time of the day along their lines.
 * This does not ease our task which will be to determine if a change in 
 * two banners is due to a time change or something else.
 */
 
#include <includes.h> 


#undef DEBUG
/*------------------------------------------------------------------------* 
 *                      Private definitions                               *
 *------------------------------------------------------------------------*/
 
#define abs(x) ((x)>0?(x):-(x))

#define NO_DATE 0
#define IS_DATE 1
#define NEED_CONTEXT 2
 
/*
 * Return <1> if <a> appears to be a date.
 *
 * <a> will not be a valid date if :
 *	- the timezone changes 
 *	- two numbers are separated by spaces. For instance "4 12 Sep" is
 *        *not* a date
 *
 *	- it contains something else than a digit, space, comma, semi-column,
 *	  {Mon...Sun} or {Jan..Dec}
 */
static int
is_date(a)
 char *a;
{
 int i, l;
 int space = 0;
 int digit = 0;
 
 
 l = strlen(a);
 if(l==1)return NEED_CONTEXT;
 for(i=0;i<l;i++)
 {
	 if(isdigit(a[i])){
	 	if(space && digit){
			return 0;
			}
		digit++;
		space = 0;
		continue;
		}
	 else if(a[i]==':'){
	 	space = 0;
	 	continue;
		}
	 else if(a[i]=='+'){
	 	space = 0;
	 	continue;
		}
	 else if(a[i]==' '){
	 	space++;
		continue;
		}
	 else if(a[i]==','){
	 	space = 0;
	 	continue;
		}
	 else {
		 if((!strncmp(a+i, "Mon", 3))||
		    (!strncmp(a+i, "Tue", 3))||
		    (!strncmp(a+i, "Wed", 3))||
		    (!strncmp(a+i, "Thu", 3))||
		    (!strncmp(a+i, "Fri", 3))||
		    (!strncmp(a+i, "Sat", 3))||
		    (!strncmp(a+i, "Sun", 3))||
		    (!strncmp(a+i, "Jan", 3))||
		    (!strncmp(a+i, "Feb", 3))||
		    (!strncmp(a+i, "Mar", 3))||
		    (!strncmp(a+i, "Apr", 3))||
		    (!strncmp(a+i, "May", 3))||
		    (!strncmp(a+i, "Jun", 3))||
		    (!strncmp(a+i, "Jul", 3))||
		    (!strncmp(a+i, "Aug", 3))||
		    (!strncmp(a+i, "Sep", 3))||
		    (!strncmp(a+i, "Oct", 3))||
		    (!strncmp(a+i, "Nov", 3))||
		    (!strncmp(a+i, "Dec", 3))){
			 	i+=2;
				space = 0;
				digit = 0;
				continue;
		 }
	 }
	 return 0; /* this is not a date */
 }
 return 1; /* no error -  this is a date */
}

	
/*------------------------------------------------------------------------*
 *                       Public functions                                 *
 *------------------------------------------------------------------------*/
 
 
 
/*
 * Returns <1> if <a> and <b> are not the same. This is more complicated
 * than a strcmp() as dates are taken in account.
 */
int banner_diff(a,b)
	char * a, * b;
{
	int l_a, l_b , i_a, i_b;
	char * copy = NULL;

	
	
	l_a = strlen(a);
	l_b = strlen(b);
	/*
	 * We tolerate a difference in length of 3 chars at max
	 */
	if(abs(l_a - l_b) > 3)
	{
		return 1;
	}
	
	/*
	 * <b> must always be the longest string
	 */
	if(l_b < l_a)
	{
	 char * t = a;
	 int t_i;
	 a = b;
	 b = t;
	 
	 t_i = l_a;
	 l_a = l_b;
	 l_b = t_i;
	}
	   

	for(i_a=0, i_b=0;(i_b<l_b) && (i_a<l_a);i_a++, i_b++)
	{
		if(a[i_a] != b[i_b])
		{
		 /*
		  * Once we spot a difference, we 
		  * go through the string backward, until we
		  * find another place which differs.
		  */
		  int j = 0, k = 0;
		  int res;
#ifdef DEBUG		  
		  printf("SPOTTED %c != %c\n", a[i_a], b[i_b]);
#endif
		  copy = (char*)malloc(l_b - i_b + 1);
		  bzero(copy, l_b - i_b + 1);
		  for(j=strlen(a), k=strlen(b);(j>i_a)&&(k>i_b)&&(a[j]==b[k]);j--,k--);
#ifdef DEBUG	
		  printf("END : %s\n", b+k);
#endif		 
		  bcopy (b + i_b, copy, (k-i_b) + 1);
#ifdef DEBUG	
		  printf("Copy : '%s'\n", copy);
#endif		  
		  res = is_date(copy);
#ifdef DEBUG	  
		  printf("isdate(copy) = %d\n", res);
#endif
		  
		  
		  if(res == NEED_CONTEXT)
		  {
		   copy = realloc(copy, (k-i_b) + 1 + 4);
		   bcopy (b + i_b, copy, (k-i_b) + 1 + 4);
		   res = is_date(copy);
		  }
		  
		  free(copy);
		  i_b+=(k-i_b);
		  i_a+=(j-i_a);
		  if(res==IS_DATE)continue;
		  else return 1;
		}
	}
	return 0;
}

#ifdef DEBUG
void main()
	{
		printf("%d (should be 1)\n", banner_diff("Sendmail 1.2.3",
							 "Sendmail 1.4.3"));

		printf("%d (should be 0)\n", banner_diff("Sendmail 1.2.3, 4 Oct 2000", "Sendmail 1.2.3, 29 Dec 2002"));

		
		printf("%d (should be 1)\n", banner_diff("Sendmail 1.2.4 3 Oct 2000",
		"Sendmail 1.2.5 3 Oct 2000"));

	}
#endif
