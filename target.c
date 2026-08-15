#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int main() {
    char filename[100];
    char input[256];
    char buffer[64];

    printf("Enter filename to backup: ");
    fgets(filename, sizeof(filename), stdin);
    filename[strcspn(filename, "\n")] = 0;  
    char command[512];
    snprintf(command, sizeof(command), "tar -czf %s.tar.gz ./data", filename);
    system(command);

    printf("Enter log file to read (e.g., app.log): ");
    fgets(filename, sizeof(filename), stdin);
    filename[strcspn(filename, "\n")] = 0;
    
    FILE *fp = fopen(filename, "r");
    if (fp) {
        while (fgets(buffer, sizeof(buffer), fp)) {
            printf("%s", buffer);
        }
        fclose(fp);
    }

    
    printf("Enter a long string: ");
    fgets(input, sizeof(input), stdin);
    input[strcspn(input, "\n")] = 0;
    char smallBuffer[16];
    
    strcpy(smallBuffer, input);   
    printf("Copied: %s\n", smallBuffer);

    
    srand(time(NULL));   
    int token = rand();  
    printf("Generated token (weak): %d\n", token);

    return 0;
}