/*****************************************************************************
* Copyright (c) 2016, Cisco Systems, Inc.
* All rights reserved.

* Redistribution and use in source and binary forms, with or without modification,
* are permitted provided that the following conditions are met:
*
* 1. Redistributions of source code must retain the above copyright notice,
*    this list of conditions and the following disclaimer.
*
* 2. Redistributions in binary form must reproduce the above copyright notice,
*    this list of conditions and the following disclaimer in the documentation
*    and/or other materials provided with the distribution.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
* AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
* FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
* DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
* SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
* CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
* OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
* USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*****************************************************************************/
/*
 * This module is not part of libacvp.  Rather, it's a simple app that
 * demonstrates how to use libacvp. Software that use libacvp
 * will need to implement a similar module.
 *
 * It will default to 127.0.0.1 port 443 if no arguments are given.
 */

#include "app_main_wolf.h"

int main(int argc, char **argv)
{
    ACVP_RESULT rv;
    ACVP_LOG_LVL level;
    ACVP_CTX *ctx;
    char ssl_version[10];
    char value[] = "same";
    
    //Location of errors will be reported prior to the return of any of these 3 functions
    
    //Parses command line arguments
    rv = wolf_acvp_parseargs(argc, argv, &level);
    if (rv != ACVP_SUCCESS) {
        exit(1);
    }
    
    //Prepares registration information and registers with the ACVP server
    rv = wolf_acvp_register(&ctx, ssl_version, level);
    if (rv != ACVP_SUCCESS) {
        exit(1);
    }
    
    //Processes tests, sends output to server, and retrieves test results from server
    rv = wolf_acvp_run(ctx);
    if (rv != ACVP_SUCCESS) {
        exit(1);
    }

    return (0);
}

