
#include "libinjection.h"
#include "libinjection_xss.h"
#include "libinjection_html5.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define DEBUG 0
#if DEBUG >= 1
#include <stdarg.h>
static void DEBUG_PRINT(const char *format, ...) {
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
}
#elif defined(COMPILER_GCC) || defined(__clang__)
static void DEBUG_PRINT(const char *format __attribute__((unused)), ...) {}
#else
static void DEBUG_PRINT(const char *format, ...) {(void)format;}
#endif
#if DEBUG >= 2
static void DEBUGV_PRINT(const char *format, ...) {
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
}
#elif defined(COMPILER_GCC) || defined(__clang__)
static void DEBUGV_PRINT(const char *format __attribute__((unused)), ...) {}
#else
static void DEBUGV_PRINT(const char *format, ...) {(void)format;}
#endif

typedef enum attribute {
    TYPE_NONE
    , TYPE_BLACK     /* ban always */
    , TYPE_ATTR_URL   /* attribute value takes a URL-like object */
    , TYPE_STYLE
    , TYPE_ATTR_INDIRECT  /* attribute *name* is given in *value* */
} attribute_t;


static attribute_t is_black_attr(const char* s, size_t len);
static int is_black_tag(const char* s, size_t len, size_t fullLength);
static int is_black_url(const char* s, size_t len);
static int cstrcasecmp_with_null(const char *a, const char *b, size_t n);
static int html_decode_char_at(const char* src, size_t len, size_t* consumed);
static int htmlencode_startswith(const char* prefix, const char *src, size_t n);
static int is_executable_style(const char* s, size_t len);

typedef struct stringtype {
    const char* name;
    attribute_t atype;
} stringtype_t;

typedef int (*ptr_graylist_processor)(const char*, size_t);
typedef struct graylist {
    const char * name;
    ptr_graylist_processor processor;
} graylist_t;

static const int gsHexDecodeMap[256] = {
    256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
    256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
    256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
    256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
    0,   1,   2,   3,   4,   5,   6,   7,   8,   9, 256, 256,
    256, 256, 256, 256, 256,  10,  11,  12,  13,  14,  15, 256,
    256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
    256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
    256,  10,  11,  12,  13,  14,  15, 256, 256, 256, 256, 256,
    256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
    256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
    256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
    256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
    256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
    256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
    256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
    256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
    256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
    256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
    256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
    256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
    256, 256, 256, 256
};

static int html_decode_char_at(const char* src, size_t len, size_t* consumed)
{
    int val = 0;
    size_t i;
    int ch;

    if (len == 0 || src == NULL) {
        *consumed = 0;
        return -1;
    }

    *consumed = 1;
    if (*src != '&' || len < 2) {
        return (unsigned char)(*src);
    }


    if (*(src+1) != '#') {
        /* normally this would be for named entities
         * but for this case we don't actually care
         */
        return '&';
    }

    if (*(src+2) == 'x' || *(src+2) == 'X') {
        ch = (unsigned char) (*(src+3));
        ch = gsHexDecodeMap[ch];
        if (ch == 256) {
            /* degenerate case  '&#[?]' */
            return '&';
        }
        val = ch;
        i = 4;
        while (i < len) {
            ch = (unsigned char) src[i];
            if (ch == ';') {
                *consumed = i + 1;
                return val;
            }
            ch = gsHexDecodeMap[ch];
            if (ch == 256) {
                *consumed = i;
                return val;
            }
            val = (val * 16) + ch;
            if (val > 0x1000FF) {
                return '&';
            }
            ++i;
        }
        *consumed = i;
        return val;
    } else {
        i = 2;
        ch = (unsigned char) src[i];
        if (ch < '0' || ch > '9') {
            return '&';
        }
        val = ch - '0';
        i += 1;
        while (i < len) {
            ch = (unsigned char) src[i];
            if (ch == ';') {
                *consumed = i + 1;
                return val;
            }
            if (ch < '0' || ch > '9') {
                *consumed = i;
                return val;
            }
            val = (val * 10) + (ch - '0');
            if (val > 0x1000FF) {
                return '&';
            }
            ++i;
        }
        *consumed = i;
        return val;
    }
}

/*
 * Graylist processors
 */

static int iframe_authorized_sources(const char* s, size_t len)
{
    //Find the end of the tag
    const char * closeTag = memchr(s, '>', len);
    if(closeTag == NULL) {
        return 0;
    }
    
    //Okay, try to find ` src=` before the end of the tag
    while(++s < closeTag) {
        
        //If the next character is escaped, ignore it
        if (*s == '\\') {
            s += 1;
            continue;
        }
        
        if (*s == '\'' || *s == '\"') {
            // Fast forward until we find a non-escaped matching quote
            for(char key = *s++; s < closeTag && *s != key; s += 1) {
                if(*s == '\\') {
                    s += 1;
                }
            }
            continue;
        }
        
        // Wait until we find a space
        if(*s != ' ') {
            continue;
        }

        // Purge any space there may be
        while(*(++s) == ' ' && s < closeTag) {}

        //Do we have enough room for `src="`
        if (closeTag - s <= 5) {
            continue;
        }

        //Check if the next three bytes are what we're looking for, case insensitive
        char target[3] = "src";
        uint8_t match = 0xff;
        for(uint8_t i = 0; i < sizeof(target); ++i) {
            match &= (*s++ | 0x20) == target[i];
        }
        
        // We have the `src=` patterns, now, check if the URL is authorized.
        //  We are carving an exception, so we're allowed to be picky
        if(match && *(s++) == '=' && *(s++) == '"') {
            const size_t endOfString = closeTag - s;
            const char * authorized_url[] = {
                "https://www.youtube.com/",
                NULL
            };
            
            for(uint8_t i = 0; authorized_url[i]; ++i) {
                const size_t urlLength = strlen(authorized_url[i]);
                if(endOfString > urlLength && !strncmp(s, authorized_url[i], urlLength)) {
                    return 1;
                }
            }
            
            break;
        }
    }
    
    return 0;
}

/*
 * view-source:
 * data:
 * javascript:
 */
static stringtype_t BLACKATTR[] = {
    { "ACTION", TYPE_ATTR_URL }     /* form */
    , { "ATTRIBUTENAME", TYPE_ATTR_INDIRECT } /* SVG allow indirection of attribute names */
    , { "BY", TYPE_ATTR_URL }         /* SVG */
    , { "BACKGROUND", TYPE_ATTR_URL } /* IE6, O11 */
    , { "DATAFORMATAS", TYPE_BLACK }  /* IE */
    , { "DATASRC", TYPE_BLACK }       /* IE */
    , { "DYNSRC", TYPE_ATTR_URL }     /* Obsolete img attribute */
    , { "FILTER", TYPE_STYLE }        /* Opera, SVG inline style */
    , { "FORMACTION", TYPE_ATTR_URL } /* HTML 5 */
    , { "FOLDER", TYPE_ATTR_URL }     /* Only on A tags, IE-only */
    , { "FROM", TYPE_ATTR_URL }       /* SVG */
    , { "HANDLER", TYPE_ATTR_URL }    /* SVG Tiny, Opera */
    , { "HREF", TYPE_ATTR_URL }
    , { "LOWSRC", TYPE_ATTR_URL }     /* Obsolete img attribute */
    , { "POSTER", TYPE_ATTR_URL }     /* Opera 10,11 */
    , { "SRC", TYPE_ATTR_URL }
    , { "STYLE", TYPE_STYLE }
    , { "TO", TYPE_ATTR_URL }         /* SVG */
    , { "VALUES", TYPE_ATTR_URL }     /* SVG */
    , { "XLINK:HREF", TYPE_ATTR_URL }
    , { NULL, TYPE_NONE }
};

/* xmlns */
/* `xml-stylesheet` > <eval>, <if expr=> */

/*
  static const char* BLACKATTR[] = {
  "ATTRIBUTENAME",
  "BACKGROUND",
  "DATAFORMATAS",
  "HREF",
  "SCROLL",
  "SRC",
  "STYLE",
  "SRCDOC",
  NULL
  };
*/

static int iframe_authorized_sources(const char* s, size_t len);

static struct graylist BLACKTAG[] = {
    { "APPLET", NULL }
    /*    , "AUDIO" */
    , { "BASE", NULL }
    , { "COMMENT", NULL }  /* IE http://html5sec.org/#38 */
    , { "EMBED", NULL }
    /*   ,  "FORM" */
    , { "FRAME", NULL }
    , { "FRAMESET", NULL }
    , { "HANDLER", NULL } /* Opera SVG, effectively a script tag */
    , {"IFRAME", iframe_authorized_sources}
    , { "IMPORT", NULL }
    , { "ISINDEX", NULL }
    , { "LINK", NULL }
    , { "LISTENER", NULL }
    /*    , "MARQUEE" */
    , { "META", NULL }
    , { "NOSCRIPT", NULL }
    , { "OBJECT", NULL }
    , { "SCRIPT", NULL }
    , { "STYLE", NULL }
    /*    , "VIDEO" */
    , { "VMLFRAME", NULL }
    , { NULL, NULL }
};

/* The list of attributes used by Blink (Chrome) can be found here:
 * https://chromium.googlesource.com/chromium/blink/+/f8ed6f1d074c206fe7ef46f7b797ef389ba18d4b/Source/core/html/HTMLAttributeNames.in
 * $ grep "^on" blink/Source/core/html/HTMLAttributeNames.in | awk '{ print ", \"" toupper($0) "\"" }'
 *
 * By Mozilla:
 * grep 'attribute EventHandler' -r * | awk '{print $4}' > event_handlers.txt
 * sed -e's/\([^;]*\)/, "&"/' < event_handlers.txt | tr '[:lower:]' '[:upper:]'
 *
 * Merging:
 *
 * cat mozilla chrome | sort -u > total.txt
 */
static const char* BLACKATTR_ON[] = {
      "EVENTHANDLER"
    , "ONABORT"
    , "ONABSOLUTEDEVICEORIENTATION"
    , "ONACTIVATE"
    , "ONANIMATIONSTART"
    , "ONANIMATIONITERATION"
    , "ONADDSOURCEBUFFER"
    , "ONADDSTREAM"
    , "ONADDTRACK"
    , "ONAFTERPRINT"
    , "ONAFTERSCRIPTEXECUTE"
    , "ONANIMATIONCANCEL"
    , "ONANIMATIONEND"
    , "ONANIMATIONITERATION"
    , "ONANIMATIONSTART"
    , "ONAPPINSTALLED"
    , "ONAUDIOEND"
    , "ONAUDIOPROCESS"
    , "ONAUDIOSTART"
    , "ONAUTOCOMPLETE"
    , "ONAUTOCOMPLETEERROR"
    , "ONAUXCLICK"
    , "ONBEFOREACTIVATE"
    , "ONBEFORECOPY"
    , "ONBEFORECUT"
    , "ONBEFOREPASTE"
    , "ONBEFOREPRINT"
    , "ONBEFORESCRIPTEXECUTE"
    , "ONBEFOREUNLOAD"
    , "ONBLOCKED"
    , "ONBLUR"
    , "ONBOUNCE"
    , "ONBOUNDARY"
    , "ONBUFFEREDAMOUNTLOW"
    , "ONCACHED"
    , "ONCANCEL"
    , "ONCANPLAY"
    , "ONCANPLAYTHROUGH"
    , "ONCHANGE"
    , "ONCHARGINGCHANGE"
    , "ONCHARGINGTIMECHANGE"
    , "ONCHECKING"
    , "ONCLICK"
    , "ONCLOSE"
    , "ONCOMPLETE"
    , "ONCONNECT"
    , "ONCONNECTIONAVAILABLE"
    , "ONCONTEXTMENU"
    , "ONCONTROLLERCHANGE"
    , "ONCOPY"
    , "ONCUECHANGE"
    , "ONCUT"
    , "ONDATA"
    , "ONDATAAVAILABLE"
    , "ONDATACHANNEL"
    , "ONDBLCLICK"
    , "ONDEVICECHANGE"
    , "ONDEVICELIGHT"
    , "ONDEVICEMOTION"
    , "ONDEVICEORIENTATION"
    , "ONDEVICEPROXIMITY"
    , "ONDISCHARGINGTIMECHANGE"
    , "ONDOWNLOADING"
    , "ONDRAG"
    , "ONDRAGEND"
    , "ONDRAGENTER"
    , "ONDRAGEXIT"
    , "ONDRAGLEAVE"
    , "ONDRAGOVER"
    , "ONDRAGSTART"
    , "ONDRAIN"
    , "ONDROP"
    , "ONDURATIONCHANGE"
    , "ONEMPTIED"
    , "ONENCRYPTED"
    , "ONEND"
    , "ONENDED"
    , "ONENTER"
    , "ONERROR"
    , "ONEXIT"
    , "ONFETCH"
    , "ONFILTERCHANGE"
    , "ONFINISH"
    , "ONFOCUS"
    , "ONFOCUSIN"
    , "ONFOCUSOUT"
    , "ONFOO"
    , "ONFORMCHANGE"
    , "ONFORMINPUT"
    , "ONFULLSCREENCHANGE"
    , "ONFULLSCREENERROR"
    , "ONGOTPOINTERCAPTURE"
    , "ONHASHCHANGE"
    , "ONICECANDIDATE"
    , "ONICECONNECTIONSTATECHANGE"
    , "ONICEGATHERINGSTATECHANGE"
    , "ONINPUT"
    , "ONINSTALL"
    , "ONINVALID"
    , "ONKEYDOWN"
    , "ONKEYPRESS"
    , "ONKEYSTATUSESCHANGE"
    , "ONKEYUP"
    , "ONLANGUAGECHANGE"
    , "ONLEVELCHANGE"
    , "ONLOAD"
    , "ONLOADEDDATA"
    , "ONLOADEDMETADATA"
    , "ONLOADEND"
    , "ONLOADING"
    , "ONLOADINGDONE"
    , "ONLOADINGERROR"
    , "ONLOADSTART"
    , "ONLOSTPOINTERCAPTURE"
    , "ONMARK"
    , "ONMESSAGE"
    , "ONMESSAGEERROR"
    , "ONMOUSEDOWN"
    , "ONMOUSEENTER"
    , "ONMOUSELEAVE"
    , "ONMOUSEMOVE"
    , "ONMOUSEOUT"
    , "ONMOUSEOVER"
    , "ONMOUSEUP"
    , "ONMOUSEWHEEL"
    , "ONONLINE"
    , "ONMOZFULLSCREENCHANGE"
    , "ONMOZFULLSCREENERROR"
    , "ONMOZORIENTATIONCHANGE"
    , "ONMUTE"
    , "ONNEGOTIATIONNEEDED"
    , "ONNOMATCH"
    , "ONNOTIFICATIONCLICK"
    , "ONNOTIFICATIONCLOSE"
    , "ONNOUPDATE"
    , "ONOBSOLETE"
    , "ONOFFLINE"
    , "ONONLINE"
    , "ONOPEN"
    , "ONORIENTATIONCHANGE"
    , "ONOVERCONSTRAINED"
    , "ONPAGEHIDE"
    , "ONPAGESHOW"
    , "ONPASTE"
    , "ONPAUSE"
    , "ONPHOTO"
    , "ONPHOTOERROR"
    , "ONPLAY"
    , "ONPLAYING"
    , "ONPOINTERCANCEL"
    , "ONPOINTERDOWN"
    , "ONPOINTERENTER"
    , "ONPOINTERLEAVE"
    , "ONPOINTERLOCKCHANGE"
    , "ONPOINTERLOCKERROR"
    , "ONPOINTERMOVE"
    , "ONPOINTEROUT"
    , "ONPOINTEROVER"
    , "ONPOINTERUP"
    , "ONPOPSTATE"
    , "ONPROGRESS"
    , "ONPROPERTYCHANGE"
    , "ONPUSH"
    , "ONPUSHSUBSCRIPTIONCHANGE"
    , "ONRATECHANGE"
    , "ONREADYSTATECHANGE"
    , "ONREMOVESOURCEBUFFER"
    , "ONREMOVESTREAM"
    , "ONREMOVETRACK"
    , "ONREQUESTPROGRESS"
    , "ONRESET"
    , "ONRESIZE"
    , "ONRESOURCETIMINGBUFFERFULL"
    , "ONRESPONSEPROGRESS"
    , "ONRESULT"
    , "ONRESUME"
    , "ONSCROLL"
    , "ONSEARCH"
    , "ONSEEKED"
    , "ONSEEKING"
    , "ONSELECT"
    , "ONSELECTSTART"
    , "ONSELECTIONCHANGE"
    , "ONSELECTSTART"
    , "ONSHIPPINGADDRESSCHANGE"
    , "ONSHIPPINGOPTIONCHANGE"
    , "ONSHOW"
    , "ONSIGNALINGSTATECHANGE"
    , "ONSOMETHING"
    , "ONSOUNDEND"
    , "ONSOUNDSTART"
    , "ONSOURCECLOSED"
    , "ONSOURCEENDED"
    , "ONSOURCEOPEN"
    , "ONSPEECHEND"
    , "ONSPEECHSTART"
    , "ONSTALLED"
    , "ONSTART"
    , "ONSTATECHANGE"
    , "ONSTOP"
    , "ONSTORAGE"
    , "ONSUSPEND"
    , "ONSUBMIT"
    , "ONSUCCESS"
    , "ONSUSPEND"
    , "ONTERMINATE"
    , "ONTIMEOUT"
    , "ONTIMEUPDATE"
    , "ONTOGGLE"
    , "ONTOUCHSTART"
    , "ONTOUCHMOVE"
    , "ONTOUCHEND"
    , "ONTONECHANGE"
    , "ONTOUCHCANCEL"
    , "ONTOUCHEND"
    , "ONTOUCHMOVE"
    , "ONTOUCHSTART"
    , "ONTRACK"
    , "ONTRANSITIONCANCEL"
    , "ONTRANSITIONEND"
    , "ONTRANSITIONRUN"
    , "ONTRANSITIONSTART"
    , "ONTYPECHANGE"
    , "ONUNLOAD"
    , "ONUNMUTE"
    , "ONUPDATE"
    , "ONUPDATEEND"
    , "ONUPDATEFOUND"
    , "ONUPDATEREADY"
    , "ONUPDATESTART"
    , "ONUPGRADENEEDED"
    , "ONUSERPROXIMITY"
    , "ONVERSIONCHANGE"
    , "ONVISIBILITYCHANGE"
    , "ONVOICESCHANGED"
    , "ONVOLUMECHANGE"
    , "ONVRDISPLAYACTIVATE"
    , "ONVRDISPLAYCONNECT"
    , "ONVRDISPLAYDEACTIVATE"
    , "ONVRDISPLAYDISCONNECT"
    , "ONVRDISPLAYPRESENTCHANGE"
    , "ONWAITING"
    , "ONWEBKITANIMATIONSTART"
    , "ONWEBKITANIMATIONITERATION"
    , "ONWAITINGFORKEY"
    , "ONWARNING"
    , "ONWEBKITANIMATIONEND"
    , "ONWEBKITANIMATIONITERATION"
    , "ONWEBKITANIMATIONSTART"
    , "ONWEBKITFULLSCREENCHANGE"
    , "ONWEBKITFULLSCREENERROR"
    , "ONWEBKITTRANSITIONEND"
    , "ONWHEEL"
    , NULL
};


/* Given 2 strings a and b, will check if a (of size n) is a prefix of b. a
 * should be null terminated, but the terminator is not taken into account in
 * the prefix search.
 * a must be in uppercase.
 *
 * return 0 if a is prefix of b
 * return 1 if not
 */
static int cstrcasecmp_with_null(const char *a, const char *b, size_t n)
{
    char ca;
    char cb;
    DEBUGV_PRINT("Comparing to %s %.*s\n", a, (int)n, b);
    while (n-- > 0) {
        cb = *b++;
        if (cb == '\0') continue;

        ca = *a++;

        if (cb >= 'a' && cb <= 'z') {
            cb -= 0x20;
        }
        DEBUGV_PRINT("Comparing %c vs %c with %d left\n", ca, cb, (int)n);
        if (ca != cb) {
            return 1;
        }
    }

    if (*a == 0) {
        DEBUG_PRINT(" MATCH \n");
        return 0;
    } else {
        return 1;
    }
}

/*
 * Does an HTML encoded  binary string (const char*, length) start with
 * a all uppercase c-string (null terminated), case insensitive!
 *
 * also ignore any embedded nulls in the HTML string!
 *
 * return 1 if match / starts with
 * return 0 if not
 */
static int htmlencode_startswith(const char *a, const char *b, size_t n)
{
    size_t consumed;
    int cb;
    int first = 1;
    DEBUG_PRINT("Comparing %s with %.*s\n", a,(int)n,b);
    while (n > 0) {
        if (*a == 0) {
            DEBUG_PRINT("Match EOL!\n");
            return 1;
        }
        cb = html_decode_char_at(b, n, &consumed);
        b += consumed;
        n -= consumed;

        if (first && cb <= 32) {
            /* ignore all leading whitespace and control characters */
            continue;
        }
        first = 0;

        if (cb == 0) {
            /* always ignore null characters in user input */
            continue;
        }

        if (cb == 10) {
            /* always ignore vertical tab characters in user input */
            /* who allows this?? */
            continue;
        }

        if (cb >= 'a' && cb <= 'z') {
            /* upcase */
            cb -= 0x20;
        }

        if (*a != (char) cb) {
            DEBUG_PRINT("    %c != %c\n", *a, cb);
            /* mismatch */
            return 0;
        }
        a++;
    }

    return (*a == 0) ? 1 : 0;
}

static int is_black_tag(const char* s, size_t len, size_t fullLength)
{
    if (len < 3) {
        return 0;
    }

    const struct graylist * black = BLACKTAG;
    while (black->name != NULL) {
        if (cstrcasecmp_with_null(black->name, s, len) == 0) {
            if(black->processor != NULL && black->processor(s, fullLength)) {
                DEBUG_PRINT("Processor for tag %s whitelisted this match\n", black->name);
                return 0;
            }
            
            DEBUG_PRINT("Got black tag %s\n", *black);
            return 1;
        }
        black += 1;
    }

    return 0;
}

static attribute_t is_black_attr(const char* s, size_t len)
{
    stringtype_t* black;

    if (len < 2) {
        return TYPE_NONE;
    }

    if (len >= 5) {
        /* JavaScript on.* */
        if ((s[0] == 'o' || s[0] == 'O') && (s[1] == 'n' || s[1] == 'N')) {

            const char **black_on_attr = BLACKATTR_ON;

            DEBUG_PRINT("Got JavaScript on- attribute name\n");
            while (*black_on_attr != NULL) {
                if (cstrcasecmp_with_null(*black_on_attr, s, len) == 0) {
                    DEBUG_PRINT("Got black on attr %s\n", *black_on_attr);
                    return TYPE_BLACK;
                }
                black_on_attr += 1;
            }
        }

#if 0
        // 2017-10-09 - commented out to prevent some false positives:
        // https://admin-infra.sqreen.io/test_attacks/59de90aa36fe25000a02b2fe
        /* XMLNS can be used to create arbitrary tags */
        if (cstrcasecmp_with_null("XMLNS", s, 5) == 0 || cstrcasecmp_with_null("XLINK", s, 5) == 0) {
            DEBUG_PRINT("Got XMLNS and XLINK tags\n");
            return TYPE_BLACK;
        }
#endif
    }

    black = BLACKATTR;
    while (black->name != NULL) {
        if (cstrcasecmp_with_null(black->name, s, len) == 0) {
            DEBUG_PRINT("Got banned attribute name %s\n", black->name);
            return black->atype;
        }
        black += 1;
    }

    return TYPE_NONE;
}

static int is_executable_style(const char* remain_page, size_t len_attr_value)
{
    /* the previous parser already tells us where the attribute stops (len_attr_value is the length of the substring) */
    int i = 0;
    int in_comment = 0;
    char *attr_value = calloc(1, len_attr_value + 1);

    if (!attr_value) {
    /* malloc failed */
        return -1;
    }

    while(len_attr_value > 0)
    {
        int exit_comment = 0;

        /* ignore comments */
        if (len_attr_value > 1 && remain_page[0] == '/' && remain_page[1] == '*') {
            in_comment = 1;
            ++remain_page;
            --len_attr_value;
        }

        if (len_attr_value > 1 && remain_page[0] == '*' && remain_page[1] == '/') {
            in_comment = 0;
            exit_comment = 1;
            ++remain_page;
            --len_attr_value;
        }

        /* new css property; init comment*/
        if (remain_page[0] == ':' && in_comment) {
            in_comment = 0;
        }

        if (!in_comment && !exit_comment) {
            attr_value[i] = remain_page[0];
            ++i;
        }

        ++remain_page;
        --len_attr_value;
    }
        /* if the attribute contains those three keywords, it is likely to be an injection, we ignore hex injection atm */
        /***
        TODO: support for hex injection such as
        <DIV STYLE="background-image:\0075\0072\006C\0028'\006a\0061\0076\0061\0073\0063\0072\0069\0070\0074\003a\0061\006c\0065\0072\0074\0028.1027\0058.1053\0053\0027\0029'\0029">
        ***/
    if (strstr(attr_value, "javascript") || strstr(attr_value, "expression") || strstr(attr_value, "url")){
        free(attr_value);
        return 1;
    }

    free(attr_value);
    return 0;
}

static int is_black_url(const char* s, size_t len)
{

    static const char* data_url = "DATA";
    static const char* viewsource_url = "VIEW-SOURCE";

    /* obsolete but interesting signal */
    static const char* vbscript_url = "VBSCRIPT";

    /* covers JAVA, JAVASCRIPT, + colon */
    static const char* javascript_url = "JAVA";

    /* skip whitespace */
    while (len > 0 && (*s <= 32 || *s >= 127)) {
        /*
         * HEY: this is a signed character.
         *  We are intentionally skipping high-bit characters too
         *  since they are not ASCII, and Opera sometimes uses UTF-8 whitespace.
         *
         * Also in EUC-JP some of the high bytes are just ignored.
         */
        ++s;
        --len;
    }

    if (htmlencode_startswith(data_url, s, len)) {
        return 1;
    }

    if (htmlencode_startswith(viewsource_url, s, len)) {
        return 1;
    }

    if (htmlencode_startswith(javascript_url, s, len)) {
        return 1;
    }

    if (htmlencode_startswith(vbscript_url, s, len)) {
        return 1;
    }
    return 0;
}

int libinjection_is_xss(const char* s, size_t len, int flags)
{
    h5_state_t h5;
    attribute_t attr = TYPE_NONE;

    libinjection_h5_init(&h5, s, len, (enum html5_flags) flags);
    while (libinjection_h5_next(&h5)) {
        if (h5.token_type != ATTR_VALUE) {
            attr = TYPE_NONE;
        }
        DEBUG_PRINT("h5 pos: %d\n", h5.pos);
        DEBUG_PRINT("%s\n", h5.s);
        DEBUG_PRINT("%*s^\n", (int) h5.pos, "");
        DEBUG_PRINT("start: %s\n", h5.token_start);


        if (h5.token_type == DOCTYPE) {
            DEBUG_PRINT("DOC TYPE\n");
            return 1;
        } else if (h5.token_type == TAG_NAME_OPEN) {
            DEBUG_PRINT("TAG NAME OPEN\n");
            if (is_black_tag(h5.token_start, h5.token_len, h5.len - h5.pos)) {
                return 1;
            }
        } else if (h5.token_type == ATTR_NAME) {
            DEBUG_PRINT("ATTR NAME\n");
            attr = is_black_attr(h5.token_start, h5.token_len);
        } else if (h5.token_type == ATTR_VALUE) {
            DEBUG_PRINT("ATTR VALUE\n");
            /*
             * IE6,7,8 parsing works a bit differently so
             * a whole <script> or other black tag might be hiding
             * inside an attribute value under HTML 5 parsing
             * See http://html5sec.org/#102
             * to avoid doing a full reparse of the value, just
             * look for "<".  This probably need adjusting to
             * handle escaped characters
             */
            /*
              if (memchr(h5.token_start, '<', h5.token_len) != NULL) {
              return 1;
              }
            */

            switch (attr) {
                case TYPE_NONE:
                    break;
                case TYPE_BLACK:
                    DEBUG_PRINT("BLACK\n");
                    return 1;
                case TYPE_ATTR_URL:
                    if (is_black_url(h5.token_start, h5.token_len)) {
                        DEBUG_PRINT("BLACK URL\n");
                        return 1;
                    }
                    break;
                case TYPE_STYLE:
                    if (is_executable_style(h5.token_start, h5.token_len)) {
                        DEBUG_PRINT("EXEC STYLE\n");
                        return 1;
                    }
                    break;
                case TYPE_ATTR_INDIRECT:
                    /* an attribute name is specified in a _value_ */
                    if (is_black_attr(h5.token_start, h5.token_len)) {
                        DEBUG_PRINT("BLACK ATTR\n");
                        return 1;
                    }
                    break;
            }
            attr = TYPE_NONE;
        } else if (h5.token_type == TAG_COMMENT) {
            DEBUG_PRINT("TAG COMMENT\n");
            /* IE uses a "`" as a tag ending char */
            if (memchr(h5.token_start, '`', h5.token_len) != NULL) {
                DEBUG_PRINT("BACK TICK\n");
#if 0
                // 2017-10-09 - commented out to prevent some false positives:
                // https://admin-infra.sqreen.io/test_attacks/59de941d36698c00079902f1
                return 1;
#endif
            }

            /* IE conditional comment */
            if (h5.token_len > 3) {
                if (h5.token_start[0] == '[' &&
                    (h5.token_start[1] == 'i' || h5.token_start[1] == 'I') &&
                    (h5.token_start[2] == 'f' || h5.token_start[2] == 'F')) {
                DEBUG_PRINT("[if");
                    return 1;
                }
                if ((h5.token_start[0] == 'x' || h5.token_start[0] == 'X') &&
                    (h5.token_start[1] == 'm' || h5.token_start[1] == 'M') &&
                    (h5.token_start[2] == 'l' || h5.token_start[2] == 'L')) {
                DEBUG_PRINT("xml");
                    return 1;
                }
            }

            if (h5.token_len > 5) {
                /*  IE <?import pseudo-tag */
                if (cstrcasecmp_with_null("IMPORT", h5.token_start, 6) == 0) {
                DEBUG_PRINT("import ");
                    return 1;
                }

                /*  XML Entity definition */
                if (cstrcasecmp_with_null("ENTITY", h5.token_start, 6) == 0) {
                DEBUG_PRINT("entity ");
                    return 1;
                }
            }
        }
        DEBUG_PRINT("NOTHING\n");
    }
    return 0;
}


/*
 * wrapper
 */
int libinjection_xss(const char* s, size_t len)
{
    if (libinjection_is_xss(s, len, DATA_STATE)) {
        DEBUG_PRINT("DATA\n");
        return 1;
    }
    if (libinjection_is_xss(s, len, VALUE_NO_QUOTE)) {
        DEBUG_PRINT("NO QUOTE\n");
        return 1;
    }
    if (libinjection_is_xss(s, len, VALUE_SINGLE_QUOTE)) {
        DEBUG_PRINT("SINGLE QUOTE\n");
        return 1;
    }
    if (libinjection_is_xss(s, len, VALUE_DOUBLE_QUOTE)) {
        DEBUG_PRINT("DOUBLE QUOTE\n");
        return 1;
    }
    if (libinjection_is_xss(s, len, VALUE_BACK_QUOTE)) {
        DEBUG_PRINT("BACK QUOTE\n");
        return 1;
    }

    return 0;
}
