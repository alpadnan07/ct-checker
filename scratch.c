int main(){
    unsigned char a = *(unsigned char *)0xdeadbeef;
    *((unsigned char *)0xcafebabe) = a;
}