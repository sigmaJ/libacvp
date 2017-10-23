#include <murl/murl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>


//function for handling response - just prints the data as a char string.
//pray that the data is actually a char string
void function_pt(void *ptr, size_t size, size_t nmemb, void *stream){
    printf("%s\n", (char*)ptr);
}

int main() {
    CURL *hnd;

    /*
     * Setup Curl
     */
    hnd = curl_easy_init();
    curl_easy_setopt(hnd, CURLOPT_URL, "http://httpbin.org/ip");
    curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, function_pt);
    
    /*
     * Send the HTTP POST request
     */
    curl_easy_perform(hnd);
    
    return 0;
 }
