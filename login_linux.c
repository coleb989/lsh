/* $Header: https://svn.ita.chalmers.se/repos/security/edu/course/computer_security/trunk/lab/login_linux/login_linux.c 585 2013-01-19 10:31:04Z pk@CHALMERS.SE $ */

/* gcc -Wall -g -o mylogin login.linux.c -lcrypt */

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <string.h>
#include <signal.h>
#include <pwd.h>
#include <sys/types.h>
#include <crypt.h>

#include "pwent.h"
#include "pwent.c"

#define TRUE 1
#define FALSE 0
#define LENGTH 16
#define PWDAGE 10
#define WRGPWD 5

void sighandler() {	
	// signal handling routines
	// SIG_ING ignores the signal
	signal(SIGTSTP,SIG_IGN); // to prevent Ctrl+Z
	signal(SIGQUIT,SIG_IGN); // to prevent Ctrl+'\'
	signal(SIGINT,SIG_IGN); // to prevent Ctrl+C
}

int main(int argc, char *argv[]) {

	mypwent *passwddata;

	char important[LENGTH] = "***IMPORTANT***";

	char user[LENGTH];
	char *c_pass;
	char prompt[] = "password: ";
	char *user_pass;

	sighandler();

	while (TRUE) {
		/* check what important variable contains - do not remove, part of buffer overflow test */
		printf("Value of variable 'important' before input of login name: %s\n",
				important);

		printf("login: ");
		fflush(NULL); /* Flush all  output buffers */
		__fpurge(stdin); /* Purge any data in stdin buffer */

		if (fgets(user,LENGTH,stdin) == NULL)
			exit(0);

		user[strlen(user)-1]='\0';

		/* check to see if important variable is intact after input of login name - do not remove */
		printf("Value of variable 'important' after input of login name: %*.*s\n",
				LENGTH - 1, LENGTH - 1, important);

		user_pass = getpass(prompt);
		passwddata = mygetpwnam(user);		
		
		// if the user data is found
		if (passwddata != NULL) {
			// get the hash value of the given pwd
			c_pass = crypt(user_pass, passwddata -> passwd_salt);			
			if(c_pass == NULL) {
				printf("An error has occurred while hashing!\n");
				continue;
			}

			// if login is successful
			if (!strcmp(c_pass, passwddata -> passwd)) {

				printf(" You're in ! \n");
				
				// display failed login attempts
				printf(" Number of failed login attempts: %d\n", passwddata->pwfailed);

				// reset pwd failed variable
				passwddata -> pwfailed = 0;
				
				// increments age of the pwd
				passwddata -> pwage += 1;
				
				// prompt the user to change pwd
				if (passwddata -> pwage >= PWDAGE)
					printf("It is now time to change your password!\n");	

				// saving the modified data
				if (mysetpwent(user, passwddata)==-1) {
					printf("An error has occurred while saving!");	
					continue;
				}

				// execute /bin/sh 
				if (setuid (passwddata->uid) == -1) {
					printf("setuid failed! \n");
                                    	continue;
				}
                                else                                
					system("/bin/sh");
			
			}
			// if login is not successful
			else {
				// increments number of failed pwd
				passwddata -> pwfailed += 1;
				
				// protecting bruteforce attack
				if (passwddata -> pwfailed >= WRGPWD) {
					printf("You entered wrong password too many times.\nWait 5 minutes to try again!\n");
					sleep(300);
				}

				// saving
				if (mysetpwent(user, passwddata) == -1)
					printf("An error has occurred while saving!");
			}			
		}
		// user data not found
		else {	
			printf("The user is not found in the database! \n");				
			printf("Login Incorrect \n");
		}
	}
	return 0;
}

