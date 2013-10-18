#define STRLEN(s) (sizeof(s) - 1)

#define KEY_NUL "<NUL>"
#define KEY_SOH "<SOH>"
#define KEY_STX "<STX>"
#define KEY_ETX "<ETX>"
#define KEY_EOT "<EOT>"
#define KEY_ENQ "<ENQ>"
#define KEY_ACK "<ACK>"
#define KEY_BEL "<BEL>"
#define KEY_BS "<BS>"
#define KEY_TAB "<TAB>"
#define KEY_LF "<LF>"
#define KEY_VT "<VT>"
#define KEY_FF "<FF>"
#define KEY_CR "<CR>"
#define KEY_SO "<SO>"
#define KEY_SI "<SI>"
#define KEY_DLE "<DLE>"
#define KEY_DC1 "<DC1>"
#define KEY_DC2 "<DC2>"
#define KEY_DC3 "<DC3>"
#define KEY_DC4 "<DC4>"
#define KEY_NAK "<NAK>"
#define KEY_SYN "<SYN>"
#define KEY_ETB "<ETB>"
#define KEY_CAN "<CAN>"
#define KEY_EM "<EM>"
#define KEY_SUB "<SUB>"
#define KEY_ESC "<ESC>"
#define KEY_FS "<FS>"
#define KEY_GS "<GS>"
#define KEY_RS "<RS>"
#define KEY_US "<US>"
#define KEY_SPCE " "
#define KEY_EXCL "!"
#define KEY_DQUO "\""
#define KEY_HASH "#"
#define KEY_DLLR "$"
#define KEY_PERC "%"
#define KEY_AMPR "&"
#define KEY_SQUO "'"
#define KEY_LPAR "("
#define KEY_RPAR ")"
#define KEY_STAR "*"
#define KEY_PLUS "+"
#define KEY_COMA ","
#define KEY_HYPH "-"
#define KEY_PERI "."
#define KEY_FWSL "/"
#define KEY_0 "0"
#define KEY_1 "1"
#define KEY_2 "2"
#define KEY_3 "3"
#define KEY_4 "4"
#define KEY_5 "5"
#define KEY_6 "6"
#define KEY_7 "7"
#define KEY_8 "8"
#define KEY_9 "9"
#define KEY_COLN ":"
#define KEY_SEMI ";"
#define KEY_LESS "<"
#define KEY_EQUL "="
#define KEY_MORE ">"
#define KEY_QUES "?"
#define KEY_AT "@"
#define KEY_U_A "A"
#define KEY_U_B "B"
#define KEY_U_C "C"
#define KEY_U_D "D"
#define KEY_U_E "E"
#define KEY_U_F "F"
#define KEY_U_G "G"
#define KEY_U_H "H"
#define KEY_U_I "I"
#define KEY_U_J "J"
#define KEY_U_K "K"
#define KEY_U_L "L"
#define KEY_U_M "M"
#define KEY_U_N "N"
#define KEY_U_O "O"
#define KEY_U_P "P"
#define KEY_U_Q "Q"
#define KEY_U_R "R"
#define KEY_U_S "S"
#define KEY_U_T "T"
#define KEY_U_U "U"
#define KEY_U_V "V"
#define KEY_U_W "W"
#define KEY_U_X "X"
#define KEY_U_Y "Y"
#define KEY_U_Z "Z"
#define KEY_OSBR "["
#define KEY_BKSL "\\"
#define KEY_CSBR "]"
#define KEY_CART "^"
#define KEY_USCR "_"
#define KEY_ACNT "`"
#define KEY_L_A "a"
#define KEY_L_B "b"
#define KEY_L_C "c"
#define KEY_L_D "d"
#define KEY_L_E "e"
#define KEY_L_F "f"
#define KEY_L_G "g"
#define KEY_L_H "h"
#define KEY_L_I "i"
#define KEY_L_J "j"
#define KEY_L_K "k"
#define KEY_L_L "l"
#define KEY_L_M "m"
#define KEY_L_N "n"
#define KEY_L_O "o"
#define KEY_L_P "p"
#define KEY_L_Q "q"
#define KEY_L_R "r"
#define KEY_L_S "s"
#define KEY_L_T "t"
#define KEY_L_U "u"
#define KEY_L_V "v"
#define KEY_L_W "w"
#define KEY_L_X "x"
#define KEY_L_Y "y"
#define KEY_L_Z "z"
#define KEY_OCLY "{"
#define KEY_PIPE "|"
#define KEY_CCLY "}"
#define KEY_TLDE "~"
#define KEY_DEL "<DEL>"
#define KEY_UNKNOWN "<?>"
#define KEY_HOME "<HOME>"
#define KEY_INSERT "<INS>"
#define KEY_DELETE "<DEL>"
#define KEY_END "<END>"
#define KEY_PGUP "<PGUP>"
#define KEY_PGDN "<PGDN>"
#define KEY_BREAK "<BRK>"
#define KEY_F1 "<F1>"
#define KEY_F2 "<F2>"
#define KEY_F3 "<F3>"
#define KEY_F4 "<F4>"
#define KEY_F5 "<F5>"
#define KEY_F6 "<F6>"
#define KEY_F7 "<F7>"
#define KEY_F8 "<F8>"
#define KEY_F9 "<F9>"
#define KEY_F10 "<F10>"
#define KEY_F11 "<F11>"
#define KEY_F12 "<F12>"

char *ascii[128]= {
    KEY_NUL,
    KEY_SOH,
    KEY_STX,
    KEY_ETX,
    KEY_EOT,
    KEY_ENQ,
    KEY_ACK,
    KEY_BEL,
    KEY_BS,
    KEY_TAB,
    KEY_LF,
    KEY_VT,
    KEY_FF,
    KEY_CR,
    KEY_SO,
    KEY_SI,
    KEY_DLE,
    KEY_DC1,
    KEY_DC2,
    KEY_DC3,
    KEY_DC4,
    KEY_NAK,
    KEY_SYN,
    KEY_ETB,
    KEY_CAN,
    KEY_EM,
    KEY_SUB,
    KEY_ESC,
    KEY_FS,
    KEY_GS,
    KEY_RS,
    KEY_US,
    KEY_SPCE,
    KEY_EXCL,
    KEY_DQUO,
    KEY_HASH,
    KEY_DLLR,
    KEY_PERC,
    KEY_AMPR,
    KEY_SQUO,
    KEY_LPAR,
    KEY_RPAR,
    KEY_STAR,
    KEY_PLUS,
    KEY_COMA,
    KEY_HYPH,
    KEY_PERI,
    KEY_FWSL,
    KEY_0,
    KEY_1,
    KEY_2,
    KEY_3,
    KEY_4,
    KEY_5,
    KEY_6,
    KEY_7,
    KEY_8,
    KEY_9,
    KEY_COLN,
    KEY_SEMI,
    KEY_LESS,
    KEY_LESS,
    KEY_MORE,
    KEY_QUES,
    KEY_AT,
    KEY_U_A,
    KEY_U_B,
    KEY_U_C,
    KEY_U_D,
    KEY_U_E,
    KEY_U_F,
    KEY_U_G,
    KEY_U_H,
    KEY_U_I,
    KEY_U_J,
    KEY_U_K,
    KEY_U_L,
    KEY_U_M,
    KEY_U_N,
    KEY_U_O,
    KEY_U_P,
    KEY_U_Q,
    KEY_U_R,
    KEY_U_S,
    KEY_U_T,
    KEY_U_U,
    KEY_U_V,
    KEY_U_W,
    KEY_U_X,
    KEY_U_Y,
    KEY_U_Z,
    KEY_OSBR,
    KEY_BKSL,
    KEY_CSBR,
    KEY_CART,
    KEY_USCR,
    KEY_ACNT,
    KEY_L_A,
    KEY_L_B,
    KEY_L_C,
    KEY_L_D,
    KEY_L_E,
    KEY_L_F,
    KEY_L_G,
    KEY_L_H,
    KEY_L_I,
    KEY_L_J,
    KEY_L_K,
    KEY_L_L,
    KEY_L_M,
    KEY_L_N,
    KEY_L_O,
    KEY_L_P,
    KEY_L_Q,
    KEY_L_R,
    KEY_L_S,
    KEY_L_T,
    KEY_L_U,
    KEY_L_V,
    KEY_L_W,
    KEY_L_X,
    KEY_L_Y,
    KEY_L_Z,
    KEY_OCLY,
    KEY_PIPE,
    KEY_CCLY,
    KEY_TLDE,
    KEY_DEL
};

char *upper[16] = {
    KEY_UNKNOWN,
    KEY_UNKNOWN,
    KEY_UNKNOWN,
    KEY_UNKNOWN,
    KEY_HOME,
    KEY_INSERT,
    KEY_DELETE,
    KEY_END,
    KEY_PGUP,
    KEY_PGDN,
    KEY_UNKNOWN,
    KEY_UNKNOWN,
    KEY_UNKNOWN,
    KEY_BREAK,
    KEY_UNKNOWN,
    KEY_UNKNOWN
};

char *fncs[16] = {
    KEY_F1,
    KEY_F2,
    KEY_F3,
    KEY_F4,
    KEY_F5,
    KEY_F6,
    KEY_F7,
    KEY_F8,
    KEY_F9,
    KEY_F10,
    KEY_F11,
    KEY_F12,
    KEY_UNKNOWN,
    KEY_UNKNOWN,
    KEY_UNKNOWN,
    KEY_UNKNOWN
};
