#include <stdio.h>
#include <stdint.h>

#define F (1 << 14) // 1 as real number
#define INT_MAX ((1 << 31) - 1)
#define INT_MIN (-(1 << 31))

// x and y are real numbers
// n is an integer
int32_t int_to_f(int32_t n); // integer to float
int32_t f_to_int_rounding_0(int32_t x); // float to integer with rounding toward zer0
int32_t f_to_int_rounding_nearest(int32_t x); // floating point to integer with rounding toward nearest
int32_t add_f(int32_t x, int32_t y); // float adding
int32_t sub_f(int32_t x, int32_t y); // float subtracting (x-y)
int32_t add_f_and_int(int32_t x, int32_t n); // float and int adding
int32_t sub_f_and_int(int32_t x, int32_t n); // float and int subtracting
int32_t mul_f(int32_t x, int32_t y); // float multiplying
int32_t mul_f_and_int(int32_t x, int32_t y); // float and int multipling
int32_t div_f(int32_t x, int32_t y); // float dividing
int32_t div_f_and_int(int32_t x, int32_t n); // float and integer deviding

int32_t int_to_f(int32_t n) {
    return n * F;
}

int32_t f_to_int_rounding_0(int32_t x) {
    return x / F;
}

int32_t f_to_int_rounding_nearest(int32_t x) {
    if (x>=0)
        return (x + F / 2) / F;
    else
        return (x - F / 2) / F;
}

int32_t add_f(int32_t x, int32_t y) {
    return 	x + y;
}

int32_t sub_f(int32_t x, int32_t y) {
    return 	x - y;
}

int32_t add_f_and_int(int32_t x, int32_t n){
    return x + n * F;
}

int32_t sub_f_and_int(int32_t x, int32_t n){
    return 	x - n * F;
}

int32_t mul_f(int32_t x, int32_t y){
    return ((int64_t) x) * y / F;
}
int32_t mul_f_and_int(int32_t x, int32_t y){
    return x * y;
}

int32_t div_f(int32_t x, int32_t y){
    return ((int64_t) x) * F / y;
}

int32_t div_f_and_int(int32_t x, int32_t n){
    return x/n;
}
