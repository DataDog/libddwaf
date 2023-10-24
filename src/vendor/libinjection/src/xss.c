#include <string.h>
#include <stdio.h>

#include "libinjection.h"

int urlcharmap(char ch);
size_t modp_url_decode(char* dest, const char* s, size_t len);
size_t modp_rtrim(char* str, size_t len);
void modp_toprint(char* str, size_t len);

int urlcharmap(char ch) {
    switch (ch) {
    case '0': return 0;
    case '1': return 1;
    case '2': return 2;
    case '3': return 3;
    case '4': return 4;
    case '5': return 5;
    case '6': return 6;
    case '7': return 7;
    case '8': return 8;
    case '9': return 9;
    case 'a': case 'A': return 10;
    case 'b': case 'B': return 11;
    case 'c': case 'C': return 12;
    case 'd': case 'D': return 13;
    case 'e': case 'E': return 14;
    case 'f': case 'F': return 15;
    default:
        return 256;
    }
}

size_t modp_url_decode(char* dest, const char* s, size_t len)
{
    const char* deststart = dest;

    size_t i = 0;
    int d = 0;
    while (i < len) {
        switch (s[i]) {
        case '+':
            *dest++ = ' ';
            i += 1;
            break;
        case '%':
            if (i+2 < len) {
                d = (urlcharmap(s[i+1]) << 4) | urlcharmap(s[i+2]);
                if ( d < 256) {
                    *dest = (char) d;
                    dest++;
                    i += 3; /* loop will increment one time */
                } else {
                    *dest++ = '%';
                    i += 1;
                }
            } else {
                *dest++ = '%';
                i += 1;
            }
            break;
        default:
            *dest++ = s[i];
            i += 1;
        }
    }
    *dest = '\0';
    return (size_t)(dest - deststart); /* compute "strlen" of dest */
}

void modp_toprint(char* str, size_t len)
{
    size_t i;
    for (i = 0; i < len; ++i) {
        if (str[i] < 32 || str[i] > 126) {
            str[i] = '?';
        }
    }
}
size_t modp_rtrim(char* str, size_t len)
{
    while (len) {
        char c = str[len -1];
        if (c == ' ' || c == '\n' || c == '\t' || c == '\r') {
            str[len -1] = '\0';
            len -= 1;
        } else {
            break;
        }
    }
    return len;
}

int is_xss(char *linebuf) {
    size_t len = modp_rtrim(linebuf, strlen(linebuf));
    int is_xss;
    if (len == 0) {
        return 0;
    }

    len =  modp_url_decode(linebuf, linebuf, len);
    is_xss = libinjection_xss(linebuf, len);

    if (is_xss) {
        return 1;
    } else {
        return 0;
    }
}

/*int main(int argc, char **argv) {

    if (argc != 2) {
        return -1;
    }

    printf("%d\n", is_xss(argv[1]));
    return 0;
}*/


