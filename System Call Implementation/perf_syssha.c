#include "kernel/types.h"
#include "user/user.h"
//#include "string.h"
#define MAX_INPUT_SIZE 512

int main(int argc, char *argv[]) {
    uint64 startR, endR, startU, endU;

    char input[MAX_INPUT_SIZE] = {0};
    int input_length = 0;
    char output[32];  // SHA256 produces 32 bytes output

    // Concatenate all arguments into input
    for (int i = 1; i < argc; i++) {
        // Make sure we don't overflow the buffer
        if (input_length + strlen(argv[i]) < MAX_INPUT_SIZE) {
            // Copy the argument into the buffer
            strcpy(input + input_length, argv[i]);
            input_length += strlen(argv[i]);

            // If it's not the last argument, add a space
            if (i < argc - 1) {
                input[input_length] = ' ';
                input_length++;
            }
        }
    }

    // Print the input string for debugging
    printf("Input string: %s\n", input);

    int len = strlen(input);

    int iterations = 10000;
    
    // Warm up run
    sha256(input, output, len);
    
    startR = get_cycle_count();
    startU = uptime();
    
    for(int i = 0; i < iterations; i++) {
        if(sha256(input, output, len) < 0){
            printf("sha256 failed\n");
            exit(1);
        }
    }
    
    endR = get_cycle_count();
    endU = uptime();

    printf("SHA256 hash: ");
    for(int i = 0; i < 32; i++){
        printf("%x", output[i] & 0xff);
    }
    printf("\n");
    
    uint64 cycles = endR - startR;
    uint64 avg_cycles = cycles / iterations;
    
    printf("Total cycles: %ld\n", cycles);
    printf("Iterations: %d\n", iterations);
    printf("Average cycles per iteration: %ld\n", avg_cycles);

    uint64 ticks = endU - startU;
    uint64 avg_ticks = ticks / iterations;
    
    printf("Total ticks: %ld\n", ticks);
    printf("Iterations: %d\n", iterations);
    printf("Average ticks per iteration: %ld\n", avg_ticks);

    exit(0);
}