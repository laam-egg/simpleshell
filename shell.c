#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/wait.h>		// wait()
#include <fcntl.h>			// open()

#define MAX_COMMAND_LENGTH 256
#define MAX_NUM_ARGUMENTS 128

char const* prompt_sign = "osh> ";

/**
 * Prints out the given string and a marker pointing
 * at the given position in that string. This can be
 * used to indicate where the error is in a command.
 */
void locate(FILE* output, char const* str, int const pos);

/**
 * Splits the given input command into arguments.
 * The returned pointer must be deallocated using free()
 * when you're done with it!
 *
 * Upon error, this function will print out an error
 * message to stderr then return NULL.
 */
char** tokenize(char const* cmd);

/**
 * This is to conveniently free the array returned by tokenize().
 */
void free_2d_char_array(char** ptr);

/**
 * Returns the number of strings contained in
 * the array returned by tokenize().
 */
size_t len_2d_char_array(char const* const* ptr);

/**
 * Executes the input command given its tokens
 * retrieved using tokenize(command).
 */
void try_executing(char** arguments);

/**
 * Truncates a long string (in place) with trailing
 * ellipsis [...]
 * e.g. with limit = 6:
 * in_str = "AAAAAAAAAAAAAA"
 * => out_str = "AAAAAA [...]"
 *
 * It is the caller's responsibility to allocate
 * out_str as a char buffer of length (limit)
 * at least.
 */
void truncate_long_string(char* out_str, char const* in_str, int limit);

/**
 * Prints help text.
 * This function's implementation is at the bottom of
 * this file.
 */
void print_help(void);

/**
 * Program entry point
 */
int main(void) {
	print_help();
	
	char cmd[MAX_COMMAND_LENGTH] = "";
	// for command history
	char previous_cmd[MAX_COMMAND_LENGTH] = "";

	for (;;) {
		printf("osh> ");
		fflush(stdout);

		if (NULL == fgets(cmd, MAX_COMMAND_LENGTH, stdin)) {
			printf("\nInput stream interrupted, exit now.\n");
			break;
		}
		fflush(stdin);
		// strip trailing newlines, if any
		while ('\n' == cmd[strlen(cmd) - 1]) {
			cmd[strlen(cmd) - 1] = 0;
		}

		if (0 == strcmp(cmd, "")) continue;

		if (0 == strcmp(cmd, "exit")) {
			printf("Good bye!\n");
			break;
		}

		if (0 == strcmp(cmd, "!!")) {
			if (0 == strcmp("", previous_cmd)) {
				fprintf(stderr, "ERROR: No previous command.\n");
				continue;
			}
			strcpy(cmd, previous_cmd);
			truncate_long_string(previous_cmd, cmd, MAX_COMMAND_LENGTH - 1);
			printf("Re-executing previous command: %s\n", previous_cmd);
		}
		strcpy(previous_cmd, cmd);

		char** arguments = tokenize(cmd);
		try_executing(arguments);

		printf("\n");
		free_2d_char_array(arguments);
	}

	return 0;
}







//////////////////////////////
/////// IMPLEMENTATION ///////
//////////////////////////////

/**
 * Simply find the greater integer among the two.
 */
int max(int a, int b) {
	if (a > b) return a;
	return b;
}

/**
 * This function checks for pipes in the command.
 * If any, it will execute the whole command on
 * its own, and return 1. Otherwise, it will not
 * do anything further, and return 0.
 */
int check_pipes(char** arguments) {
	int N = len_2d_char_array((char const* const*)arguments);

	for (int i = 0; i < N; ++i) {
		if (0 == strcmp("|", arguments[i])) {
			arguments[i] = NULL;
			int pipe_fds[2];
			pipe(pipe_fds);

			int left_operand_pid = fork();
			if (left_operand_pid == 0) {
				dup2(pipe_fds[1], STDOUT_FILENO);
				close(pipe_fds[0]); close(pipe_fds[1]);
				try_executing(arguments);
				exit(0);
			}

			int right_operand_pid = fork();
			if (right_operand_pid == 0) {
				dup2(pipe_fds[0], STDIN_FILENO);
				close(pipe_fds[0]); close(pipe_fds[1]);
				try_executing(arguments + i + 1);
				exit(0);
			}

			close(pipe_fds[0]); close(pipe_fds[1]);
			// wait(NULL); wait(NULL);
			if (left_operand_pid > 0 && right_operand_pid > 0) {	// PARENT PROCESS
				waitpid(left_operand_pid, NULL, 0);
				waitpid(right_operand_pid, NULL, 0);
			}
			return 1;
			// thanks to recursion in the calls to try_executing(),
			// any subsequent pipes will be handled!
		}
	}

	return 0;
}

/**
 * This function is called in the child process
 * to check for any input/output redirections.
 * Support both at the same time, e.g.
 *
 * osh> sort < in.txt > out.txt
 *
 * This function will truncate the arguments
 * specifying such redirections!
 *
 * Returns 0 on success, 1 on failure, in which
 * case an error message is printed to stderr as 
 * well.
 */
int check_io_redirects(char** arguments) {
	// Check for any argument that contains only the sign < or >
	// which marks a redirect directive.

	char* input_file_name = NULL;
	char* output_file_name = NULL;
	char** fn_ptr = NULL;

	for (;;) {
		int N = len_2d_char_array((char const* const*)arguments);
		// for a redirect of form:
		//		> filename.txt
		// or
		//		< filename.txt
		// then < and > are called marks.
		int mark_loc = N - 2; 			// possible location of the mark
		int filename_loc = N - 1;		// possible location of file name
		if (mark_loc < 0 /* || filename_loc < 0 */) {
			break;
		}

		fn_ptr = NULL;
		if (0 == strcmp(">", arguments[mark_loc])) {
			if (NULL != output_file_name) {
				fprintf(stderr, "ERROR: Multiple output redirections are not allowed\n");
				return 1;
			}
			fn_ptr = &output_file_name;
		} else if (0 == strcmp("<", arguments[mark_loc])) {
			if (NULL != input_file_name) {
				fprintf(stderr, "ERROR: Multiple input redirections are not allowed\n");
				return 1;
			}
			fn_ptr = &input_file_name;
		}

		if (fn_ptr == NULL) {
			break;						// no (more) redirections detected
		} else {
			// Basically copy the filename to fn_ptr[0],
			// which could either be input_file_name or output_file_name.
			char* src_fn = arguments[filename_loc];
			fn_ptr[0] = (char*)malloc((strlen(src_fn) + 1) * sizeof(char));
			if (NULL == fn_ptr[0]) {
				fprintf(stderr, "ERROR: Could not allocate memory for file names in check_io_redirects().\n");
				return 1;
			}
			strcpy(fn_ptr[0], src_fn);
			
			free((void*)arguments[filename_loc]);
			free((void*)arguments[mark_loc]);
			arguments[filename_loc] = arguments[mark_loc] = NULL;
		}
	}

	if (input_file_name) {
		int input_fd = open(input_file_name, O_RDONLY);
		if (input_fd < 0) {
			fprintf(stderr, "Could not open file for reading:\n");
			fprintf(stderr, "    %s\n", input_file_name);
			free((void*)input_file_name);
			return 1;
		}
		dup2(input_fd, STDIN_FILENO);
		free((void*)input_file_name);
	}

	if (output_file_name) {
		int output_fd = open(output_file_name, O_WRONLY | O_CREAT | O_TRUNC, 0664);
		if (output_fd < 0) {
			fprintf(stderr, "Could not open file for writing:\n");
			fprintf(stderr, "    %s\n", output_file_name);
			free((void*)output_file_name);
			return 1;
		}
		dup2(output_fd, STDOUT_FILENO);
		free((void*)output_file_name);
	}

	// Opened files need not be closed
	// since this function is only called
	// in child processes.

	return 0;
}

void try_executing(char** arguments) {
	if (NULL == arguments) return;
	
	if (arguments[0] == NULL) return;
	if (0 == strcmp("", arguments[0])) {
		fprintf(stderr, "ERROR: Empty command? What do you mean?\n");
		return;
	}

	if (0 != check_pipes(arguments)) {
		return;
	}

	size_t num_arguments = len_2d_char_array((char const* const*)arguments);

	int execute_in_background = 0;
	if (0 == strcmp(arguments[num_arguments - 1], "&")) {
		execute_in_background = 1;
		free((void*)arguments[num_arguments - 1]);
		arguments[num_arguments - 1] = NULL;
		--num_arguments;
	}

	int pid = fork();
	if (pid < 0) {
		fprintf(stderr, "ERROR: Fork failed\n");
		return;
	} else if (pid > 0) {			// PARENT PROCESS
		if (0 == execute_in_background) {
			waitpid(pid, NULL, 0);
		}
	} else /*if (pid == 0)*/ {		// CHILD PROCESS
		if (0 != check_io_redirects(arguments)) {
			exit(1);
		}
		execvp(arguments[0], arguments);
		perror("ERROR");
		exit(1);
	}
}

void locate(FILE* output, char const* str, int const pos) {
	int const N = strlen(str);
	#define LIMIT 70
	
	if (N < LIMIT) {
		fprintf(output, "%s", str);
		if (str[N - 1] != '\n' && str[N - 1] != '\r') {
			fprintf(output, "\n");
		}
		for (int i = 0; i < pos; ++i) fprintf(output, " ");
		fprintf(output, "^\n");
		for (int i = 0; i < pos - 2; ++i) fprintf(output, " ");
		fprintf(output, "here\n\n");
	} else {
		// Command is too long, we're just gonna print out
		// a portion of it.
		char const* const ellipsis = "[...] ";
		int const ellipsis_length = strlen(ellipsis);
		char substr[LIMIT];

		int substr_start_pos = max(pos - LIMIT / 2, 0);
		char const* substr_ptr = str + substr_start_pos;
		
		int subpos = (pos - substr_start_pos) % N + ellipsis_length;
		
		snprintf(substr, LIMIT, "%s%s", ellipsis, substr_ptr);
		locate(output, substr, subpos);
	}
	#undef LIMIT
}

char** tokenize(char const* cmd) {
	char* current_token = NULL;
	
	#define CHECK_MEM(x, varName) if (x == NULL) { fprintf(stderr, "ERROR: out of memory while allocating %s.\n", varName); goto ERRORED; }
	#define isquote(x) ((x) == '"' /*|| (x) == '\''*/)

	int const N = strlen(cmd);
	if (N > MAX_COMMAND_LENGTH) {
		fprintf(stderr, "ERROR: Command too long (length = %lu)\n", strlen(cmd));
		goto ERRORED;
	}
	
	char* arguments[MAX_NUM_ARGUMENTS];
	int num_arguments = 0;
	current_token = (char*)malloc((N + 1) * sizeof(char));
	CHECK_MEM(current_token, "current_token")
	current_token[0] = 0;

	enum {
		EMPTY,
		PARSING_WORD,
		IN_QUOTE,
		IN_BACKSLASH_ESCAPE_AND_IN_QUOTE,
	} status = EMPTY;
	int j = 0;
	char c;
	
	for (int i = 0; i < N; ++i) {
		c = cmd[i];
		if (c == '\n' || c == '\r') {
			break; // end of line
		}
		if (status == EMPTY) {
			if (isquote(c)) {
				status = IN_QUOTE;
				continue; // skip the quote as it is not part of the denoted string!
			} else if (!isspace(c)) {
				status = PARSING_WORD;
			} else continue;
		}

		if (status == PARSING_WORD) {
			if (isspace(c)) {
				current_token[j] = 0;
				arguments[num_arguments] = (char*)malloc((strlen(current_token) + 1) * sizeof(char));
				CHECK_MEM(arguments[num_arguments], "arguments[num_arguments], branch PARSING_WORD")
				strcpy(arguments[num_arguments], current_token);
				
				j = 0;
				++num_arguments;
				status = EMPTY;
			} else if (isquote(c)) {
				fprintf(stderr, "ERROR: Stray quote\n");
				locate(stderr, cmd, i);
				goto ERRORED;
			} else {
				current_token[j] = c;
				++j;
			}
		}

		if (status == IN_QUOTE) {
			if (isquote(c)) {
				current_token[j] = 0;
				arguments[num_arguments] = (char*)malloc((strlen(current_token) + 1) * sizeof(char));
				CHECK_MEM(arguments[num_arguments], "arguments[num_arguments], branch IN_QUOTE")
				strcpy(arguments[num_arguments], current_token);
				
				j = 0;
				++num_arguments;
				status = EMPTY;
			} else if (c == '\\') {
				status = IN_BACKSLASH_ESCAPE_AND_IN_QUOTE;
				continue;
			} else {
				current_token[j] = c;
				++j;
			}
		}

		if (status == IN_BACKSLASH_ESCAPE_AND_IN_QUOTE) {
			current_token[j] = c;
			++j;
			status = IN_QUOTE;
		}
	}

	if (status == PARSING_WORD) {
		current_token[j] = 0;
		arguments[num_arguments] = (char*)malloc((strlen(current_token) + 1) * sizeof(char));
		CHECK_MEM(arguments[num_arguments], "arguments[num_arguments], branch PARSING_WORD (2)")
		strcpy(arguments[num_arguments], current_token);
		
		j = 0;
		++num_arguments;
		status = EMPTY;
	}

	if (status == IN_QUOTE) {
		fprintf(stderr, "ERROR: Quote not closed\n");
		locate(stderr, cmd, N - 1);
		goto ERRORED;
	}

	if (status == IN_BACKSLASH_ESCAPE_AND_IN_QUOTE) {
		fprintf(stderr, "ERROR: Quote not closed ; backslash not escaped either!\n");
		locate(stderr, cmd, N - 1);
		goto ERRORED;
	}

	char** returned_arguments = (char**)malloc((num_arguments + 1) * sizeof(char*));
	for (int i = 0; i < num_arguments; ++i) {
		returned_arguments[i] = arguments[i];
	}
	returned_arguments[num_arguments] = NULL;
	free((void*)current_token);
	return returned_arguments;

ERRORED:
	free((void*)current_token);
	return NULL;

	#undef CHECK_MEM
	#undef isquote
}

void truncate_long_string(char* out_str, char const* in_str, int limit) {
	char const* const ellipsis = " [...]";
	int const len_ellipsis = strlen(ellipsis);
	int const N = strlen(in_str);
	int const hard_limit = limit - len_ellipsis - 2;
	
	if (N > hard_limit) {
		strncpy(out_str, in_str, hard_limit);
		strcat(out_str, ellipsis);
	} else {
		strcpy(out_str, in_str);
	}
}

void free_2d_char_array(char** ptr) {
	if (NULL == ptr) return;
	
	int i = 0;
	while (ptr[i] != NULL) {
		free((void*)ptr[i]);
		++i;
	}
	free((void*)ptr);
}

size_t len_2d_char_array(char const* const* ptr) {
	size_t i = 0;
	while (ptr[i] != NULL) {
		++i;
	}
	return i;
}

void print_help(void) {
	printf(
		"A simple shell program that meets the requirements\n"
		"defined in the 'Project 1 - UNIX Shell' section\n"
		"of the book 'Operating System Concepts', 10th, 2018\n"
		"by Abraham Silberschatz.\n"
		"\n"
		"0. Enter 'exit' to quit the program.\n"
		"1. Supports running background tasks by appending '&'\n"
		"   to the end of the command.\n"
		"2. Re-run previous command by entering '!!'.\n"
		"3. * Supports redirecting input and output simultaneously.\n"
		"4. * Supports multiple pipes.\n"
		"5. * Supports double quotes to wrap string literals containing\n"
		"   spaces. Inside the quotes, you can escape special characters\n"
		"   using the backslash (any character following a backslash is)\n"
		"   interpreted literally), e.g. \\\" => \" ; \\\\ => \\ ; \\n => n\n"
		"   (currently do not translate \\n to newline, sorry!)\n"
		"6. * Messages for syntax errors.\n"
		"\n"
		"(*) these are beyond the basic requirements in the book!\n"
		"\n"
		"Enter the following commands (in order) to test all the\n"
		"features aforementioned:\n"
		"    !!\n"
		"    ls -la > output1.txt\n"
		"    tee < output1.txt | grep . | awk \"{print $9}\" > output2.txt &\n"
		"    !!\n"
		"    cat output2.txt\n"
		"    \"ls\" \"-la\" \"\\/\"\n"
		"    ABC\"\n"
		"    \"ABC\n"
		"    \"ABC\\\n"
		"    \"ABC\\\"\n"
		"    some_non_existent_program\n"
		"\n"
		"Enjoy!\n"
		"========================================================\n"
		"\n"
	);
}
