
Laboratory Assignment in Computer Security Course (EDA263/DIT641)
					
					IDENTIFICATION AND AUTHENTICATION

We (my colleague and I) were required to design a simple shell program, called "lsh" which loosely replicates the popular UNIX shell programs like bash, sh and csh. The program was required to resist buffer overflow attacks, bruteforce attacks and password guessing.

To prevent against buffer overflows, we implemented a function in our program that restricts the length of user input. We deployed a hashed password algorithm with a salt value to enhance the strength of users’ passwords which makes it hard for the attacker to break. We prevented bruteforce attacks by discouraging a user from making several consecutive failed login attempts. After a certain number of failed attempts, the system hangs for a few minutes before it can accept user input again. 