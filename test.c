int good_secretAdd(int sec) {
    return sec + 1;
}

char buf[256];
char bad_secretRead(int sec) {
    return buf[sec];
}

int bad_secretLoop(int sec) {
    int res = 0;
    for(int i = 0; i < sec; i++) {
        sec += i;
    }
    return res;
}

void good_zeroLoop(char *secBuf) {
    for(int i = 0; i < 100; i++) {
        secBuf[i] = 0;
    }
}

double bad_castToFloat(int sec) {
    return (double)sec + 1.5;
}

int good_publicLoop(int sec, int pub) {
    int res = 0;
    for(int i = 0; i < pub; i++) {
        if(i == 100000) {
            for(int j = 0; j < sec; j++);
        }
        
        res += sec;
        res += i;
    }
    return res;
}

int good_publicRead(int sec, int pub) {
    return buf[pub];
}
