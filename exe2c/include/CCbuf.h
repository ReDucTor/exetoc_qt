// Copyright(C) 1999-2005 LiuTaoTao，bookaa@rorsoft.com

#ifndef	CCbuf_h
#define CCbuf_h
#include <cstdio>
class CCbuf
{
public:
        char f_str;	//因为有'和"两种string形式 Because there 'and "two kinds of string form
        char * m_p;
        SIZEOF	m_len;

        CCbuf();
        ~CCbuf(){};

        void LoadFile(FILE *f);
        void OneChar(int c);
        void OneLine(const char * pstr);
};

#endif	//CCbuf_h
