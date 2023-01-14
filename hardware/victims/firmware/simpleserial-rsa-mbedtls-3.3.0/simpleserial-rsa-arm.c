/*
    This file is part of the ChipWhisperer Example Targets
    Copyright (C) 2016-2017 NewAE Technology Inc.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "hal.h"
#include "simpleserial.h"
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

// #define __arm__

#if defined(__arm__) || defined(__riscv__) || defined(__riscv)

#include "mbedtls/rsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

#include "mbedtls/sha256.h"
#include "mbedtls/oid.h"
#include "mbedtls/build_info.h"

#include "mbedtls/platform.h"


#define mbedtls_calloc calloc
#define mbedtls_free free



/*
 * Example RSA-1024 keypair, for test purposes
 */
#define RSA_KEY_LEN 128

#define RSA_N   "9292758453063D803DD603D5E777D788" \
                "8ED1D5BF35786190FA2F23EBC0848AEA" \
                "DDA92CA6C3D80B32C4D109BE0F36D6AE" \
                "7130B9CED7ACDF54CFC7555AC14EEBAB" \
                "93A89813FBF3C4F8066D2D800F7C38A8" \
                "1AE31942917403FF4946B0A83D3D3E05" \
                "EE57C6F5F5606FB5D4BC6CD34EE0801A" \
                "5E94BB77B07507233A0BC7BAC8F90F79"

#define RSA_E   "10001"

#define RSA_D   "24BF6185468786FDD303083D25E64EFC" \
                "66CA472BC44D253102F8B4A9D3BFA750" \
                "91386C0077937FE33FA3252D28855837" \
                "AE1B484A8A9A45F7EE8C0C634F99E8CD" \
                "DF79C5CE07EE72C7F123142198164234" \
                "CABB724CF78B8173B9F880FC86322407" \
                "AF1FEDFDDE2BEB674CA15F3E81A1521E" \
                "071513A1E85B5DFA031F21ECAE91A34D"

#define RSA_P   "C36D0EB7FCD285223CFB5AABA5BDA3D8" \
                "2C01CAD19EA484A87EA4377637E75500" \
                "FCB2005C5C7DD6EC4AC023CDA285D796" \
                "C3D9E75E1EFC42488BB4F1D13AC30A57"

#define RSA_Q   "C000DF51A7C77AE8D7C7370C1FF55B69" \
                "E211C2B9E5DB1ED0BF61D0D9899620F4" \
                "910E4168387E3C30AA1E00C339A79508" \
                "8452DD96A9A5EA5D9DCA68DA636032AF"

#define RSA_DP  "C1ACF567564274FB07A0BBAD5D26E298" \
                "3C94D22288ACD763FD8E5600ED4A702D" \
                "F84198A5F06C2E72236AE490C93F07F8" \
                "3CC559CD27BC2D1CA488811730BB5725"

#define RSA_DQ  "4959CBF6F8FEF750AEE6977C155579C7" \
                "D8AAEA56749EA28623272E4F7D0592AF" \
                "7C1F1313CAC9471B5C523BFE592F517B" \
                "407A1BD76C164B93DA2D32A383E58357"

#define RSA_QP  "9AE7FBC99546432DF71896FC239EADAE" \
                "F38D18D2B2F0E2DD275AA977E2BF4411" \
                "F5A3B2A5D33605AEBBCCBA7FEB9F2D2F" \
                "A74206CEC169D74BF5A8C50D6F48EA08"

#define PT_LEN  24
#define RSA_PT  "\xAA\xBB\xCC\x03\x02\x01\x00\xFF\xFF\xFF\xFF\xFF" \
                "\x11\x22\x33\x0A\x0B\x0C\xCC\xDD\xDD\xDD\xDD\xDD"

const char MESSAGE[] =  "Hello World!";


int ret = 1;
int exit_code = MBEDTLS_EXIT_FAILURE;
unsigned c;
size_t i;
mbedtls_rsa_context rsa;
mbedtls_mpi N, P, Q, D, E, DP, DQ, QP;
mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;
unsigned char result[1024];
const char *pers = "rsa_decrypt";

unsigned char rsa_plaintext[PT_LEN];
unsigned char rsa_decrypted[PT_LEN];
unsigned char rsa_ciphertext[RSA_KEY_LEN];



void rsa_init(void)
{
    mbedtls_rsa_init( &rsa);
    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_entropy_init( &entropy );
    mbedtls_mpi_init( &N ); mbedtls_mpi_init( &P ); mbedtls_mpi_init( &Q );
    mbedtls_mpi_init( &D ); mbedtls_mpi_init( &E ); mbedtls_mpi_init( &DP );
    mbedtls_mpi_init( &DQ ); mbedtls_mpi_init( &QP );


    mbedtls_mpi_read_string( &N , 16, RSA_N  ) ;
    mbedtls_mpi_read_string( &E , 16, RSA_E  ) ;
    mbedtls_mpi_read_string( &D , 16, RSA_D  ) ;
    mbedtls_mpi_read_string( &P , 16, RSA_P  ) ;
    mbedtls_mpi_read_string( &Q , 16, RSA_Q  ) ;
    mbedtls_mpi_read_string( &DP, 16, RSA_DP ) ;
    mbedtls_mpi_read_string( &DQ, 16, RSA_DQ ) ;
    mbedtls_mpi_read_string( &QP, 16, RSA_QP ) ;

    if( ( ret = mbedtls_rsa_import( &rsa, &N, &P, &Q, &D, &E ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_rsa_import returned %d\n\n",
                        ret );
        goto exit;
    }

    if( ( ret = mbedtls_rsa_complete( &rsa ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_rsa_complete returned %d\n\n",
                        ret );
        goto exit;
    }

    //Make valid data first, otherwise system barfs
    memcpy( rsa_plaintext, RSA_PT, PT_LEN );
    mbedtls_rsa_pkcs1_encrypt( &rsa, mbedtls_ctr_drbg_random, &ctr_drbg, PT_LEN,
                           rsa_plaintext, rsa_ciphertext );

exit:
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );
    mbedtls_rsa_free( &rsa );
    mbedtls_mpi_free( &N ); mbedtls_mpi_free( &P ); mbedtls_mpi_free( &Q );
    mbedtls_mpi_free( &D ); mbedtls_mpi_free( &E ); mbedtls_mpi_free( &DP );
    mbedtls_mpi_free( &DQ ); mbedtls_mpi_free( &QP );

    mbedtls_exit( exit_code );
}





uint8_t buf[128];
uint8_t hash[32];
#if SS_VER == SS_VER_2_1
uint8_t real_dec(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *pt)
#else
uint8_t real_dec(uint8_t *pt, uint8_t len)
#endif
{
    rsa_init();

    int ret = 0;
    //first need to hash our message
    memset(buf, 0, 128);
    mbedtls_sha256(MESSAGE, 12, hash, 0);

    trigger_high();
    ret = mbedtls_rsa_pkcs1_decrypt( &rsa, mbedtls_ctr_drbg_random,
                                            &ctr_drbg, &i,
                                            buf, result, 1024 );
    trigger_low();

    //send back first 48 bytes
#if SS_VER == SS_VER_2_1
    simpleserial_put('r', 128, buf);
#else
    simpleserial_put('r', 48, buf);
#endif
    return ret;
}


uint8_t get_pt(uint8_t *pt, uint8_t len)
{
}

#endif
