# Writeup

Source code

```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int check_key(char *);
int sthIdontknow(char, char);

int main(void) {
    char *usrInp;
    printf("Key? ");
    usrInp = (char *)malloc(33);
    scanf("%s", usrInp);

    int len = strlen(usrInp);
    if (len == 32) {
        int (*check)(char *) = check_key;
        if (check(&usrInp)) {
            printf("Correct key.\n");
            printf("Flag is: flag{%s}\n", usrInp);
        } else
            printf("Wrong key.\n");
    } else
        printf("Invalid.\n");
    free(usrInp);

    return 0;
}

int check_key(char *key) {
    char sth[] = "pearldarkk";
    char mySth[] = {0x45, 0xd, 0x50, 0x1c, 0x5d, 0xa, 0x46, 0x2d,
                    0x5e, 0x1f, 0x44, 0x17, 0x54, 0x2d, 0x6, 0x11,
                    0x54, 0x6, 0x34, 0x7, 0x41, 0xe, 0x52, 0x2d,
                    0x19, 0x16, 0x3e, 0x1, 0x6, 0x5a, 0x1c, 0x56};
    void *c1 = sth, *c2 = key;
    while (c2 < key + 1 && !(sthIdontknow(*(char *)(c1 + (((char *)c2 - key) % 0xA)), *(char *)c2) ^ *mySth)) {
        c2 = (char *)c2 + 1;
        ++*mySth;
    }

    if (c2 == key + 1)
        return 1;
    return 0;
}

int sthIdontknow(char b, char k) {
    char b2;
    for (size_t i = 0; i < 8; ++i) {
        if (((b >> i) & 1) == ((k >> i) & 1))
            b2 = ((1 << i) ^ -1) & b & 255;
        else
            b2 = ((1 << i) & 255) | b;
        b = (char)b2;
    }
    return b;
}
```
Trước hết, chương trình yêu cầu nhập input --> Sau đó check input ta nhập vào với len input = 32. Vì vậy ở bài này mình sẽ tập trung vào hàm ```check_key```

Viết lại cho dễ nhìn

```
int check_key(char *key) {
    char sth[] = "pearldarkk";
    char mySth[] = {0x45, 0xd, 0x50, 0x1c, 0x5d, 0xa, 0x46, 0x2d,
                    0x5e, 0x1f, 0x44, 0x17, 0x54, 0x2d, 0x6, 0x11,
                    0x54, 0x6, 0x34, 0x7, 0x41, 0xe, 0x52, 0x2d,
                    0x19, 0x16, 0x3e, 0x1, 0x6, 0x5a, 0x1c, 0x56};
    void *c1 = sth, *c2 = key;
    while (c2 < key + 1 && !(sthIdontknow(*c1(c2%0xA),*c2) ^ *mySth)) {
        c2 = (char *)c2 + 1;
        ++*mySth;
    }

    if (c2 == key + 1)
        return 1;
    return 0;
}
```
--> Tại đây, chương trình sẽ check qua từng ký tự của input nhập vào với số vòng lặp tương ứng len của input

--> ```sthIdontknow(*c1(c2%0xA),*c2) ^ *mySth``` trả về 0

--> giá trị trả về của ```sthIdontknow``` chính bằng giá trị của từng phần tử trong mảng ```mySth```

mà hàm ```sthIdontknow``` so sánh từng ký tự của ```sth``` với input ta nhập vào, nếu equal --> return input đúng 

# Script
```
sth = "pearldarkk"
mySth = [0x45, 0xd, 0x50, 0x1c, 0x5d, 0xa, 0x46, 0x2d,
                    0x5e, 0x1f, 0x44, 0x17, 0x54, 0x2d, 0x6, 0x11,
                    0x54, 0x6, 0x34, 0x7, 0x41, 0xe, 0x52, 0x2d,
                    0x19, 0x16, 0x3e, 0x1, 0x6, 0x5a, 0x1c, 0x56]
flag = []


for i in range(0,32):
    flag.append(chr(ord((sth[i%int(0xA)]))^(mySth[i])))
        
for i in range(len(flag)):
    print(flag[i],end="")
```
```
Flag: 5h1n1n'_5t4r5_ju5t_l1k3_ur_sm1l3
```

