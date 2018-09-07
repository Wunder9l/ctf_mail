#include <iostream>
#include <cstring>

struct parsed_numbers{
    int size;
    int numbers[64];
};

struct numbers_struct
{
    int size;
    int buffer[64];
} ;

int parse_expr(char* buf, parsed_numbers* res){
    char* number_start = buf;
    int index= 0;
    char ops[100];
    int op_index = 0;
    memset(ops, 0, 100);

    while(true){
        char a = buf[index];
        if (a < '0' || a > '9') {
            int length = buf + index - number_start;
            char* temp_buf = (char*) malloc(length + 1);
            memcpy(temp_buf, number_start, length);
            temp_buf[length] = '\0';
            if (!strcmp(temp_buf, "0")){
                puts("prevent division by zero");
                return 0;
            }
            int atoi_res = atoi(temp_buf);
            if (atoi_res > 0) {
                res->numbers[res->size] = atoi_res;
                res->size++;
            }
            if (a!=0 && (buf[index+1] < '0' || buf[index+1] > '9')) {
                puts("expression error!");
                return 0;
            }
            number_start = buf + index + 1;
            if (ops[op_index] == 0) {
                ops[op_index] = a;
            } else {
                switch (a){
                    case '*':
                    case '/':
                    case '%':
                        if (ops[op_index] == '+' || ops[op_index] == '-') {
                            ops[++op_index] = a;
                        } else {
                            eval(res, ops[op_index]);
                            ops[op_index] = a;
                        }
                        break;
                    case '+':
                    case '-':
                        eval(res, ops[op_index]);
                        ops[op_index] = a;
                        break;
                    default:
                        eval(res, ops[op_index]);
                        op_index--;
                        break;
                }
            }
            if (a == 0) {
                break;
            }
        }
        index++;
    }
    while (op_index >= 0){
        eval(res, ops[op_index--]);
    }
    return 1;
}


void eval(struct numbers_struct * numbers, char operation)
{
    if(operation == '+')
    {
        int a = numbers->buffer[numbers->size  - 2];
        int b = numbers->buffer[numbers->size  - 1];
        numbers->buffer[numbers->size  - 1] = a+b;
    }
    else if(operation > '+')
    {
        if(operation == '-')
        {
            int a = numbers->buffer[numbers->size  - 2];
            int b = numbers->buffer[numbers->size  - 1];
            numbers->buffer[numbers->size  - 1] = a-b;
        }
        else if (operation == '/')
        {
            int a = numbers->buffer[numbers->size  - 2];
            int b = numbers->buffer[numbers->size  - 1];
            numbers->buffer[numbers->size  - 1] = a/b;
        }
    }
    else if (operation == '*')
    {
        int a = numbers->buffer[numbers->size  - 2];
        int b = numbers->buffer[numbers->size  - 1];
        numbers->buffer[numbers->size  - 1] = a*b;
    }
    numbers->size = numbers->size - 1;
}

int get_expr(char * buf, int size)
{
    char a;
    int counter = 0;
    while(counter < size)
    {
        if(EOF == (a=getchar()))
            break;
        if('\n' == a)
            break;
        switch(a)
        {
            case '-':
            case '+':
            case '*':
            case '/':
            case '%':
                buf[counter++]=a;
                break;
            default:
                if(a<'0') continue;
                if(a > '9') continue;
                buf[counter++]=a;
                break;
        }
    }
    buf[counter] = 0;
    return counter;
}

int main(int argc, char ** argv)
{
    int size = 0x100;
    char * buf = malloc(size);

    int count = get_expr(buf, size);
    printf("Math string: %s \n length: %d\n", buf, count);
    return 0;

}

int main() {
    std::cout << "Hello, World!" << std::endl;
    return 0;
}