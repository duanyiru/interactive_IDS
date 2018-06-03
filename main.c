#include "main.h"

void execute(char *str){
	int fd_pipe[2];
	int child_pid;
	int child_return_status;

	int i = 0;

	char* arg[MAX_ARGU_SIZE];
	
	arg[0] = strtok(str, " ");
	for(i = 1; i < MAX_ARGU_SIZE; i++){
		if((arg[i] = strtok(NULL, " ")) == NULL)
			break;
	}
	arg[i] = 0;

	if(!arg[0] ||  
		(strncmp(arg[0], "iptables", strlen(arg[0])) != 0))
		return;

	if(pipe(fd_pipe) == -1){
		perror("pipe");
		return;
	}

	if((child_pid = fork()) == -1){
		perror("fork()");
		return;
	}else if(child_pid == 0){
		/* child process */
		if(close(fd_pipe[READ_END]) == -1){
			perror("READ_END: close");
			return;
		}

		/*
			notice that iptables need to installed by Linux.
			and the program run explict the path of iptables
			instead of indirect call, i.e. use arg[0] to call
			the function is because of the security
		*/
		execvp("/sbin/iptables", arg);

		/* 
			if the program gets there, it means 
			the command run unsuccessfuly
		*/
		perror("iptables");
		fprintf(stderr, "invalid command: %s," 
			"skip it\n", str);

		return;
	}else{

		if(close(fd_pipe[WRITE_END]) == -1){
			perror("WRITE_END: close");
			return;
		}	

		if(waitpid(child_pid, &child_return_status, 0) <= 0){
			perror("waitpid");
			return;
		}
	}
}

int main(int argc, char *argv[]){
	int ret = 0;
	uid_t uid = 0;
	uid_t euid = 0;

	FILE *fp;
	const char file[] = "configuration";

	char *str;
	char command[STRING_SIZE];

	size_t len;
	ssize_t read;

	str = NULL;
	len = 0;

	/* Authentication */
	uid = getuid();
	euid = geteuid();

	if(uid != 0 || uid != euid){
		fprintf(stderr, "please run as root user\n");

		ret = 1;
		return ret;
	}

	/* 
		Load the static file, only load the file 
	   	"configuration", and check its content in 
	   	case of injection. 
	*/

	/* make file own by root */   	
	umask(S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);

	fp = fopen(file, "ab+");

	while((read = getline(&str, &len, fp)) != -1){
		memset(command, 0, sizeof(command));

		for(int i = 0; i < len && *(str + i) != '\n'; i++)
			command[i] = *(str + i);

		execute(command);

		memset(str, 0, strlen(str));
	}

	printf("Loaded rules(if have) of configuration file\n\n");

	fclose(fp);

	printf("Sniffing...\n");

	ret = captrue_traffic();

	return ret;
}