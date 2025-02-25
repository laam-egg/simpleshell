# osh

A simple shell program that meets the requirements
defined in the 'Project 1 - UNIX Shell' section
of the book 'Operating System Concepts', 10th, 2018
by Abraham Silberschatz.

## Compile and Run

On Linux:

```sh
gcc -o shell shell.c
./shell
```

## Usage

0. Enter 'exit' to quit the program.

1. Supports running background tasks by appending '&'
    to the end of the command.
2. Re-run previous command by entering '!!'.
3. * Supports redirecting input and output simultaneously.
4. * Supports multiple pipes.
5. * Supports double quotes to wrap string literals containing
    spaces. Inside the quotes, you can escape special characters
    using the backslash (any character following a backslash is)
    interpreted literally), e.g. \\\" => \" ; \\\\ => \\ ; \\n => n
    (currently do not translate \\n to newline, sorry!)
6. * Messages for syntax errors.

(*) these are beyond the basic requirements in the book!

Enter the following commands (in order) to test all the
features aforementioned:

```plain
    !!
    ls -la > output1.txt
    tee < output1.txt | grep . | awk \"{print $9}\" > output2.txt &
    !!
    cat output2.txt
    \"ls\" \"-la\" \"\\/\"
    ABC\"
    \"ABC
    \"ABC\\
    \"ABC\\\"
    some_non_existent_program
```

Enjoy!

## Author

Vũ Tùng Lâm - 22028235 - UET
