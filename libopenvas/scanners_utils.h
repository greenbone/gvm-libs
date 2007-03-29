#ifndef _NESSUSL_SCANNERS_UTILS_H
#define _NESSUSL_SCANNERS_UTILS_H

ExtFunc int comm_send_status(struct arglist *, char *, char *, int , int);
unsigned short *getpts(char *, int *);
#endif
