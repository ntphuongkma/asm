# Writeup
Source code
```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int fuzz(char *);

int main(int argc, char **argv) {
    printf("Let's see if you passed the right flag...\n");
    if (argc == 2)
        if (strlen(*(argv + 1)) == 32)
            if (!fuzz(*(argv + 1)))
                printf("Wrong Direction.");
            else if (!strncmp(*(argv + 1), "302753d5b52596eb75b8", 0x14))     \\0x14 = 20
                if (!strncmp(*(argv + 1) + 20, "9c11cc30e5c7", 12))
                    printf("True.");
                else
                    printf("Try again.");
            else
                printf("Try again.");
        else
            printf("Try again.");
    else
        printf("Try again.");
}

int fuzz(char *key) {
    char char1[10], char2[10], char3[10], char4[10];
    memset(char1, 0, 10);
    memset(char2, 0, 10);
    memset(char3, 0, 10);
    memset(char4, 0, 10);

    strncpy(char1, key, 8);
    strncpy(char2, key + 8, 8);
    strncpy(char3, key + 16, 8);
    strncpy(char4, key + 24, 8);

    memset(key, 0, 32);

    strcat(key, char3);
    strcat(key, char1);
    strcat(key, char4);
    strcat(key, char2);

    return 1;
}
```
***********
The main function of a C++ program has two parameters, by convention named argc and argv, which give it the command-line arguments used to launch the program.

argc is the count of arguments, and argv is an array of the strings.

=> argc is 2 when the program is run with one command-line argument.
***********
--> Chương trình xuất hiện luồng thực thi có tham số truyền vào

```if (strlen(*(argv + 1)) == 32)``` --> Tham số truyền vào có len = 32

--> Chương trình check tham số ta truyền vào bằng cách convert sắp xếp nhóm 8 ký tự một --> 4 nhóm thành một chuỗi ký tự mới ```3 - 1 - 2 - 4```. Sau đó tiến hành check với ```key```

```if (!strncmp(*(argv + 1), "302753d5b52596eb75b8", 20))``` --> 20 ký tự đầu của ```key``` là ```302753d5b52596eb75b8```

```if (!strncmp(*(argv + 1) + 20, "9c11cc30e5c7", 12))``` --> 12 ký tự còn lại là ```9c11cc30e5c7```

--> key đầy đủ: ```302753d5b52596eb75b89c11cc30e5c7```

Hàm convert
```
int fuzz(char *key) {
    char char1[10], char2[10], char3[10], char4[10];
    memset(char1, 0, 10);
    memset(char2, 0, 10);
    memset(char3, 0, 10);
    memset(char4, 0, 10);

    strncpy(char1, key, 8);
    strncpy(char2, key + 8, 8);
    strncpy(char3, key + 16, 8);
    strncpy(char4, key + 24, 8);

    memset(key, 0, 32);

    strcat(key, char3);
    strcat(key, char1);
    strcat(key, char4);
    strcat(key, char2);

    return 1;
}
```
--> Để tìm ra flag của bài này, ta chỉ việc sắp xếp lại

Reverse chay hoặc dùng script sau đó replace

# Script
```
key = "302753d5b52596eb75b89c11cc30e5c7"
char1 = []
char2 = []
char3 = []
char4 = []
for i in key[0:8]:     #3
    char1.append(i)
for i in key[8:16]:    #1
    char2.append(i)
for i in key[16:24]:   #4
    char3.append(i)
for i in key[24:32]:   #2
    char4.append(i)
print(char2,char4,char1,char3)
```
```
Flag: b52596ebcc30e5c7302753d575b89c11
```
