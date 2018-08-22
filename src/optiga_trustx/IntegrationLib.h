/**
* MIT License
*
* Copyright (c) 2018 Infineon Technologies AG
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE
*
*
* \file 
*
* \brief   This file defines APIs, types and data structures used in the
*          Integration Library implementation.
*
* \ingroup  grIntLib
* @{
*/

#ifndef _H_INT_LIBRARY_H_
#define _H_INT_LIBRARY_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include "CommandLib.h"
#include "Datatypes.h"
#include "OcpCommonIncludes.h"



/****************************************************************************
 *
 * Definitions
 *
 ****************************************************************************/

///Requested operation completed without any error
#define INT_LIB_OK                          0x75AB1C02         

///Null parameter(s)
#define INT_LIB_NULL_PARAM                  0x80002001

///Invalid data in response
#define INT_LIB_INVALID_RESPONSE            (INT_LIB_NULL_PARAM + 1)

///Invalid access condition
#define INT_LIB_INVALID_AC                  (INT_LIB_NULL_PARAM + 2)

///Length of input is zero
#define INT_LIB_ZEROLEN_ERROR               (INT_LIB_NULL_PARAM + 3)

///Invalid or unsupported parameter(s)
#define INT_LIB_INVALID_PARAM               (INT_LIB_NULL_PARAM + 4)

///Invalid Length
#define INT_LIB_INVALID_LENGTH              (INT_LIB_NULL_PARAM + 5)

///Malloc Failures
#define INT_LIB_MALLOC_FAILURE              (INT_LIB_NULL_PARAM + 6)

///Certificate format is not valid
#define INT_LIB_INVALID_CERTIFICATE_FORMAT	(INT_LIB_NULL_PARAM + 7)

///General error
#define INT_LIB_ERROR                       0xFE5A5502

/**
 * \brief Structure to specify general purpose data object parameters for read
 */
typedef struct sReadGPData_d
{
    ///OID of data object
    uint16_t wOID;

    ///Offset within the data object
    uint16_t wOffset;

    ///Number of data bytes to read
    uint16_t wLength;
}sReadGPData_d;

/**
 * \brief Structure to specify general purpose data object parameters for write
 */
typedef struct sWriteGPData_d
{
    ///OID of data object
    uint16_t wOID;

    ///Offset within the data object
    uint16_t wOffset;

    ///Number of data bytes to write
    uint16_t wLength;

    ///Data bytes to be written
    uint8_t *prgbData;

    ///Write option
    eWriteOption_d   eWriteOption;
}sWriteGPData_d;


/**
 * \brief Structure to specify inputs for One-Way Authentication Public Key Scheme
 */
typedef struct sOneWayAuth_d
{
	///CA Certificate
	sbBlob_d sCaCert;

	///OID of device certificate signed by the CA certificate
	uint16_t wOIDDevCertificate;

	///OID of private key paired with the public key in the device certificate
	uint16_t wOIDDevPrivKey;

	///Length of the challenge
	uint16_t wChallengeLen;
}sOneWayAuth_d;


#ifdef MODULE_ENABLE_ONE_WAY_AUTH
/**
* \brief Performs One-Way Authentication Public Key Scheme to prove the authenticity of the 
* device which incorporates Security Chip.
*/
LIBRARY_EXPORTS int32_t IntLib_Authenticate(const sOneWayAuth_d *PpsOneWayAuth);

#endif /* MODULE_ENABLE_ONE_WAY_AUTH*/

#ifdef MODULE_ENABLE_READ_WRITE
/**
 * \brief Read the specified general purpose data object from the Security Chip.
 */
LIBRARY_EXPORTS int32_t IntLib_ReadGPData(const sReadGPData_d *PpsGDVector, sbBlob_d *PpsGPData);

/**
 * \brief Write to the specified general purpose data object to the Security Chip.
 */
LIBRARY_EXPORTS int32_t IntLib_WriteGPData(const sWriteGPData_d *PpsGDVector);

#endif /* MODULE_ENABLE_READ_WRITE*/

#ifdef __cplusplus
}
#endif

#endif //_H_INT_LIBRARY_H_

/**
* @}
*/
