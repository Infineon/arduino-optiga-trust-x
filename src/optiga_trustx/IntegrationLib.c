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
* \brief   This file implements the APIs, types and data structures used in the
*          Integration library implementation.
*
* \ingroup  grIntLib
* @{
*/

#include <stdint.h>
#include "IntegrationLib.h"
#include "CryptoLib.h"
#include "MemoryMgmt.h"
#include "Util.h"

/// @cond hidden

///Length of metadata
#define LENGTH_METADATA             0x1C

///Length of certificate
#define LENGTH_CERTIFICATE          1728

///Length of R and S vector
#define LENGTH_RS_VECTOR            0x40

///Length of maximum additional bytes to encode sign in DER
#define MAXLENGTH_SIGN_ENCODE       0x08

///Length of Signature
#define LENGTH_SIGNATURE            (LENGTH_RS_VECTOR + MAXLENGTH_SIGN_ENCODE)

///size of public key for NIST-P256
#define LENGTH_PUB_KEY_NISTP256     0x41

///Position of data field in metadata
#define METADATA_MAX_LEN            0x001C

///Offset of Length in the metadata
#define OFFSET_TLV_LENGTH		    0x01

///Size of TLV Format Header
#define TLV_HEADER_SIZE             0x02

///Length of metadata header
#define METADATA_HEADER_SIZE        TLV_HEADER_SIZE

///Value for parsig failure
#define PARSE_FAILURE               0xFF

///TLV position for Length
#define POS_LEN                     0x01

///TLV position for Value
#define POS_VAL                     0x02

///Already Found
#define VALUE_TAG_FOUND             0x9B

///Length of R and S vector
#define VALUE_TAG_NOTFOUND          0x31

///ASN Tag for sequence
#define ASN_TAG_SEQUENCE          	0x30

///ASN Tag for integer
#define ASN_TAG_INTEGER          		0x02

///msb bit mask
#define MASK_MSB          					0x80

///TLS Identity Tag
#define TLS_TAG          					0xC0

/**
 * \brief Enumeration to object ids.
 */
typedef enum eObjectId_d
{
    ///Life Cycle State Global
    eLCSG = 0xE0C0,
    ///Life Cycle State Application
    eLCSA = 0xF1C0
}eObjectId_d;

/**
 * \brief Structure to specify general purpose data object parameters for read
 */
typedef struct sACVector_d
{
    ///OID of data object
    uint8_t bLcsA;
    
    uint8_t bLcsG;
    
    uint8_t bLcsO;

    sbBlob_d *psMetaData;
    
}sACVector_d;

/**
 * \brief Operators available in simple and complex Access Conditions
 */

typedef enum eOperator_d {
	/// Equal
    eOP_EQUAL = 0xFA,
	/// Greater than
    eOP_GREATER_THAN = 0xFB,
	/// Less than
    eOP_LESS_THAN = 0xFC,
	/// AND
    eOP_AND = 0xFD,
	/// OR
    eOP_OR = 0xFE
} eOperator_d;

/**
 * \brief Meta data tags
 */
typedef enum eMetaDataTag_d 
{
	/// Object Life Cycle
    eLCSO =     0xC0,
	/// Change AC
    eCHANGE_AC = 0xD0,
	/// Read AC
    eREAD_AC =  0xD1
} eMetaDataTag_d;

/**
 * \brief IDs associated with the metadata access condition (simple and complex)
 */
typedef enum eAccessConditionID_d 
{
	/// Always
    eACID_ALW = 0x00, 
	/// Global life cycle status 
    eACID_LCSG = 0x70, 
	/// Application specific life cycle status 
    eACID_LCSA = 0xE0, 
	/// Data object specific life cycle status 
    eACID_LCSO = 0xE1, 
	/// Never
    eACID_NEV = 0xFF 
} eAccessConditionID_d;



#ifdef MODULE_ENABLE_READ_WRITE
/**
 *
 * Implementation to get the metadata tag position.<br>
 * Returns error if metadata is not correct<br>
 * (if duplication of tag, metadata length / Tag length more than max length of metadata).<br> <br>
 *
 * PpbPos contains the actual position of the tag if found.<br>
 * PpbPos contains 0xFF if tag not found.This is considering that metatdata length is 28 bytes.
 * The return value in this case is #INT_LIB_OK.<br>
 *   
 * \param[in]  Pprgbmetadata   Pointer to the buffer that contains metadata
 * \param[in]  PbTag           Tag type.
 * \param[in]  PpbPos          Pointer to tag position in metadata
 *   
 * \retval    #INT_LIB_OK      Successful execution
 * \retval    #INT_LIB_ERROR   Failure in execution
 *
 */
static int32_t IntLib_GetTagPos (const uint8_t* Pprgbmetadata, uint8_t PbTag, puint8_t PpbPos)
{
    int32_t i4Status = (int32_t)INT_LIB_ERROR;
    uint8_t bMetadataSize, bAcLen;
    uint8_t bTempPos, bAlreadyFound=VALUE_TAG_NOTFOUND;

    do
    {
        if (NULL == Pprgbmetadata || NULL == PpbPos)
        {
            break;
        }

        bMetadataSize = Pprgbmetadata[OFFSET_TLV_LENGTH];

        *PpbPos = 0xFF;
        
        if (METADATA_MAX_LEN < (bMetadataSize + METADATA_HEADER_SIZE))        
        {
            //Metadata Corrupted [Length field in Metadata is more than METADATA_MAX_SIZE]
            break;
        }

        bTempPos = METADATA_HEADER_SIZE;

        for(;;)
        {
            if (Pprgbmetadata[bTempPos] == PbTag)
            {
                if (VALUE_TAG_FOUND == bAlreadyFound)
                {
                    i4Status = (int32_t)INT_LIB_ERROR;
                    break;
                }
                i4Status = INT_LIB_OK;
                *PpbPos = bTempPos;
                bAlreadyFound = VALUE_TAG_FOUND;
            }

            if(0xFF == Pprgbmetadata[bTempPos])
            {
                //Length field in Metadata is not correct
                break;
            }
            bAcLen = Pprgbmetadata[bTempPos+1];

            //Is metadata Corrupted?
            if (METADATA_MAX_LEN <= (bAcLen+bTempPos+1))
            {
                //Metadata Corrupted
                break;
            }

            bTempPos += (bAcLen+2);

            if(bMetadataSize <= (bTempPos-METADATA_HEADER_SIZE))
            {
                i4Status = INT_LIB_OK;
                break;
            }
        }
    } while(0);

    return i4Status;
}

/**
 *
 * Implementation to verify expressions related to LCSA, LCSG, LCSO.<br>
 * 
 * \param[in]     PpsACVal             Pointer to the access condition vector
 * \param[in]     PprgbAC              Pointer to the AC expression
 * \param[in,out] PpwVerifyOver        Pointer to verification status
 *   
 * \retval    #INT_LIB_OK       Successful execution
 * \retval    #INT_LIB_ERROR    Failure in execution
 *
 */
static int32_t IntLib_VerifyLcsAGO(const sACVector_d* PpsACVal, const uint8_t* PprgbAC,puint16_t PpwVerifyOver)
{
    int32_t i4Status = (int32_t)INT_LIB_ERROR;
    uint8_t bVal, bLcs = 0x00;
    eOperator_d eOp ;
    
	// Life cycle state of object
    #define LCS_O_VAL			(PpsACVal->bLcsO)
	// Life cycle state of application
    #define LCS_A_VAL			(PpsACVal->bLcsA)
	// Life cycle state of Global
    #define LCS_G_VAL			(PpsACVal->bLcsG)
    
    do
    {
        if((NULL == PpwVerifyOver) 
            || (NULL == PpsACVal) || (NULL == PprgbAC))
        {
            break;
        }

        bLcs = LCS_A_VAL;
        if ((uint8_t)eACID_LCSG == *PprgbAC)
        {
            bLcs = LCS_G_VAL;
        }
        else if((uint8_t)eACID_LCSO == *PprgbAC)
        {
            bLcs = LCS_O_VAL;
        }
       
        eOp = (eOperator_d)(*(PprgbAC+1));
        bVal = *(PprgbAC+2);

        if(eOp == eOP_GREATER_THAN)
        {
            if(bLcs > bVal)
            {
                i4Status = INT_LIB_OK;
            }
        }
        else if(eOp == eOP_LESS_THAN)
        {
            if(bLcs < bVal)
            {
                i4Status = INT_LIB_OK;
            }
        } 
        else if(eOp == eOP_EQUAL)
        {
            if(bLcs == bVal)
            {
                i4Status = INT_LIB_OK;
            }
        }
        else
        {
            i4Status = (int32_t)INT_LIB_ERROR;
            *PpwVerifyOver = TRUE;
            break;
        }
    } while(0);
    return i4Status;
#undef LCS_O_VAL
#undef LCS_A_VAL
#undef LCS_G_VAL    
}

/**
 *
 * Implementation to validate the access conditions.<br>
 *   
 * \param[in]  PpsACVal   Pointer to the buffer that contains metadata
 *   
 * \retval    #INT_LIB_OK       Successful execution
 * \retval    #INT_LIB_ERROR    Failure in execution
 *
 */
static int32_t IntLib_CheckAccessCondition(const sACVector_d *PpsACVal)
{
    int32_t i4Status = (int32_t)INT_LIB_ERROR;
    int32_t i4StatusCurr = (int32_t)INT_LIB_ERROR;
    int32_t i4StatusPrev = (int32_t)INT_LIB_OK;
    uint16_t wIndex = 0, wLen, wIDCount = 0;
    uint16_t wVerificationOver = 0;
    uint8_t bComplexAcOP = 0x00;
    puint8_t prgbAccessCode;

	// Remaining bytes of the access condition
    #define REMAINING_BYTES (wLen - wIndex)

    do
    {
        if((NULL == PpsACVal) || (NULL == PpsACVal->psMetaData) 
                    || (NULL == PpsACVal->psMetaData->prgbStream))
        {
            break;
        }

        wLen = PpsACVal->psMetaData->wLen;
        prgbAccessCode = PpsACVal->psMetaData->prgbStream;
 
        while(wIndex < wLen)
        {
            switch((eAccessConditionID_d)*(prgbAccessCode+wIndex))
            {
                case  eACID_ALW:
                case  eACID_NEV:
                    if((REMAINING_BYTES > 1) || (wIDCount > 0))
                    {
                        wVerificationOver = TRUE;
                        break;
                    }
                    i4StatusCurr = INT_LIB_OK;
                    if((uint8_t)eACID_NEV == *(prgbAccessCode+wIndex))
                    {
                        i4StatusCurr = (int32_t)INT_LIB_ERROR;
                    }
                    wIndex++;
                    wIDCount++;
                    break;

                case  eACID_LCSO:
                case  eACID_LCSA:
                case  eACID_LCSG:
                    //including access id
                    if(REMAINING_BYTES < 3)
                    {
                        //because of invalid access coding
                        wVerificationOver = TRUE;
                        break;
                    }

                    i4StatusCurr = IntLib_VerifyLcsAGO(PpsACVal, prgbAccessCode+wIndex, &wVerificationOver);
                    if(TRUE == wVerificationOver)
                    {
                        //because of invalid access coding
                        break;
                    }

                    wIndex+=3;
                    wIDCount++;
                    break;

                default:
                    //because of invalid access coding
                    i4StatusPrev = (int32_t)INT_LIB_ERROR;
                    i4StatusCurr = (int32_t)INT_LIB_ERROR;
                    wVerificationOver = TRUE;
                    break;
            }//switch

            if(wVerificationOver)
            {
                break;
            }

            if(bComplexAcOP == (uint8_t)eOP_AND)
            {
                if(i4StatusCurr != i4StatusPrev)
                {
                    i4StatusCurr = (int32_t)INT_LIB_ERROR;
                }
            }

            if(wIndex == wLen)
            {
                break;
            }

            // for operator
            if(REMAINING_BYTES < 3)
            {
                i4StatusPrev = (int32_t)INT_LIB_ERROR;
                i4StatusCurr = (int32_t)INT_LIB_ERROR;
                //wVerificationOver = TRUE;
                break;
            }

            bComplexAcOP = *(prgbAccessCode+wIndex);
            switch(bComplexAcOP)
            { 
                case  eOP_AND:
                    i4StatusPrev = i4StatusCurr;
                    i4StatusCurr = (int32_t)INT_LIB_ERROR;    				
                    break;

                case  eOP_OR:
                    i4StatusPrev = INT_LIB_OK;
                    if(i4StatusCurr == INT_LIB_OK)
                    {
                        //Note: further validation not required 
                        //because the metadata itself is protected by checksum 
                        wVerificationOver = TRUE;
                    }
                    break;

                default:
                    //because of invalid access coding
					i4StatusPrev = (int32_t)INT_LIB_ERROR;
                    i4StatusCurr = (int32_t)INT_LIB_ERROR; 
                    wVerificationOver = TRUE;
                    break;
            }//switch

            if(wVerificationOver)
            {
                break;
            }

            wIndex++;
            wIDCount++; //indication of complex AC
        }//while

        if((i4StatusPrev == INT_LIB_OK) &&
        (i4StatusCurr == INT_LIB_OK))
        {
            i4Status = INT_LIB_OK;
        }

    }while(0);

    return i4Status; 
#undef REMAINING_BYTES
}



/**
 *
 * Reads either LcsA or LcsG based on request.<br>
 *   
 * \param[in]  PeLcsType   ObjectId of LcsA or LcsG
 * \param[in,out]  PpbValue    Pointer for returning life cycle state.
 *   
 * \retval    #INT_LIB_OK       Successful execution
 * \retval    #INT_LIB_ERROR    Failure in execution
 *
 */
static int32_t IntLib_ReadLcs(eObjectId_d PeLcsType,uint8_t *PpbValue)
{
    int32_t i4Status  = (int32_t)INT_LIB_ERROR;
    sGetData_d sGDVector;
    sCmdResponse_d sResponse;
    do
    {          
        if(NULL == PpbValue)
        {
            i4Status = (int32_t)INT_LIB_NULL_PARAM;
            break;
        }    
        sGDVector.wOID = (uint16_t)PeLcsType;
        sGDVector.wLength = 1;
        sGDVector.wOffset = 0;
        sGDVector.eDataOrMdata = eDATA;
        
        sResponse.prgbBuffer = PpbValue;
        sResponse.wBufferLength = 1;
        sResponse.wRespLength = 0;

        i4Status = CmdLib_GetDataObject(&sGDVector,&sResponse);
        if(CMD_LIB_OK != i4Status)
        {
            break;
        }
        //check if the length is 1
        if((0x01 != sResponse.wRespLength))
        {
            i4Status = (int32_t)INT_LIB_INVALID_RESPONSE;
            *PpbValue = 0x00;
            break;
        }
        i4Status = INT_LIB_OK;
    }while(FALSE);
   return i4Status; 
}





/**
 *
 * Verifies the requested access condition in the metadata.<br>
 *   
 * \param[in]  PeMetaDataTag     Type of access condition
 * \param[in]  PpsACVal         Pointer to metadata.
 *   
 * \retval    #INT_LIB_OK       Successful execution
 * \retval    #INT_LIB_ERROR    Failure in execution
 *
 */
static int32_t IntLib_VerifyAC(eMetaDataTag_d PeMetaDataTag, sACVector_d *PpsACVal)
{
    int32_t i4Status  = (int32_t)INT_LIB_ERROR;
    uint8_t bTagLocation = 0;
    do
    {
        if((NULL == PpsACVal)||(NULL == PpsACVal->psMetaData)||
            (NULL == PpsACVal->psMetaData->prgbStream))
        {
            i4Status = (int32_t)INT_LIB_NULL_PARAM;
            break;
        }
        
        //get tag position of lcsO and read lcsO.
        //LCO may not be found for all object.It is not an error
        i4Status = IntLib_GetTagPos(PpsACVal->psMetaData->prgbStream,(uint8_t)eLCSO,&bTagLocation);
        if(INT_LIB_OK == i4Status)
        {
            //get the LcsO value from TLV
            PpsACVal->bLcsO = (PpsACVal->psMetaData->prgbStream)[bTagLocation+2];            
        }
        else
        {
            //LcsO not present
            PpsACVal->bLcsO = 0x00;
        }
        //reset tag location
        bTagLocation = 0;
        //get tag position
        i4Status = IntLib_GetTagPos(PpsACVal->psMetaData->prgbStream,(uint8_t)PeMetaDataTag,&bTagLocation);
        if((INT_LIB_OK != i4Status) || (PARSE_FAILURE == bTagLocation))
        {
			i4Status = (int32_t)INT_LIB_ERROR;
            break;
        }
        //check access condition        
        PpsACVal->psMetaData->wLen = *(PpsACVal->psMetaData->prgbStream + (bTagLocation+POS_LEN));
        PpsACVal->psMetaData->prgbStream += (bTagLocation+POS_VAL);
        
        i4Status = IntLib_CheckAccessCondition(PpsACVal);
    }while(FALSE);
    
    return i4Status;
}
#endif /* MODULE_ENABLE_READ_WRITE*/

#ifdef MODULE_ENABLE_ONE_WAY_AUTH
/**
*
* Formats the Signature into DER encoded.<br>
*   
* \param[in,out]  PpsFormatedSignature     Pointer to structure which holds formatted signature
* \param[in]  PpbRawSignature          Pointer to raw signature .
* \param[in]  PwSignLength             Length of raw signature.
*   
* \retval    #INT_LIB_OK       
* \retval    #INT_LIB_ERROR    
* \retval    #INT_LIB_NULL_PARAM 
* \retval    #INT_LIB_ZEROLEN_ERROR   
*
*/
static int32_t IntLib_FormatSignature(sbBlob_d *PpsFormatedSignature,const uint8_t* PpbRawSignature, uint16_t PwSignLength)
{
    int32_t i4Status = (int32_t)INT_LIB_ERROR;
    uint8_t bIndex = 0;
    do
    {            
        if((NULL == PpsFormatedSignature)||(NULL == PpsFormatedSignature->prgbStream)||
            (NULL == PpbRawSignature))
        {
            i4Status = (int32_t)INT_LIB_NULL_PARAM;
            break;
        }
        if((0 == PpsFormatedSignature->wLen)||(0 == PwSignLength))
        {
            i4Status = (int32_t)INT_LIB_ZEROLEN_ERROR;
            break;         
        }
		//check to see oif input buffer is short, 
		// or signture plus 6 byte considering der encoding  is more than 0xff
        if((PpsFormatedSignature->wLen < PwSignLength)||(0xFF < (PwSignLength + 6)))
        {
            //send lib error
            break;         
        }
        //Encode ASN sequence
        *(PpsFormatedSignature->prgbStream + 0) = ASN_TAG_SEQUENCE;
		//Length of RS and encoding bytes
        *(PpsFormatedSignature->prgbStream + 1) = LENGTH_RS_VECTOR + 4;
        //Encode integer
        *(PpsFormatedSignature->prgbStream + 2) = ASN_TAG_INTEGER;
        //Check if the integer is negative
        bIndex = 4;
        *(PpsFormatedSignature->prgbStream + 3) = 0x20;
        if(PpbRawSignature[0] & MASK_MSB)
        {
            *(PpsFormatedSignature->prgbStream + 3) = 0x21;
            *(PpsFormatedSignature->prgbStream + bIndex++) = 0x00;
        }
        
        //copy R
        memmove(PpsFormatedSignature->prgbStream + bIndex,PpbRawSignature,(LENGTH_RS_VECTOR/2));
        bIndex+=(LENGTH_RS_VECTOR/2);
        //Encode integer
        *(PpsFormatedSignature->prgbStream + bIndex++) = ASN_TAG_INTEGER;
        //Check if the integer is negative
        *(PpsFormatedSignature->prgbStream + bIndex) = 0x20;
        if(PpbRawSignature[LENGTH_RS_VECTOR/2] & MASK_MSB)
        {
            *(PpsFormatedSignature->prgbStream + bIndex) = 0x21;
            bIndex++;
            *(PpsFormatedSignature->prgbStream + bIndex) = 0x00;
        }
        bIndex++;

        //copy S
        OCP_MEMCPY(PpsFormatedSignature->prgbStream + bIndex,PpbRawSignature+(LENGTH_RS_VECTOR/2),(LENGTH_RS_VECTOR/2));
        bIndex += (LENGTH_RS_VECTOR/2);
        //Sequence length is "index-2"
        *(PpsFormatedSignature->prgbStream + 1) = (bIndex-2);
        //Total length is equal to index
        PpsFormatedSignature->wLen = bIndex;
        
        i4Status = INT_LIB_OK;
        
    }while(FALSE);
    
    return i4Status;
}


/**
*
* Verifies and validates the Security Chip certificate.<br>
*   
* \param[in]  PpsCaCert              pointer to CA Certificate
* \param[in]  PpsOPTIGACert          pointer to Security Chip Certificate
*   
* \retval    #INT_LIB_OK       
* \retval    #INT_LIB_ERROR    
* \retval    #INT_LIB_NULL_PARAM    
*
*/
static int32_t IntLib_ValidateCertificate(sCertificate_d *PpsCaCert,sCertificate_d *PpsOPTIGACert)
{
    int32_t i4Status = (int32_t)INT_LIB_ERROR;
    sSignatureVector_d sSignatureVector ;
    do
    {
        if((NULL == PpsCaCert)||(NULL == PpsCaCert->sCertData.prgbStream)||
            (NULL == PpsCaCert->sCertSignature.prgbStream)||
            (NULL == PpsCaCert->sPublicKey.prgbStream)||
            (NULL == PpsOPTIGACert)||(NULL == PpsOPTIGACert->sCertData.prgbStream)||
            (NULL == PpsOPTIGACert->sCertSignature.prgbStream)||
            (NULL == PpsOPTIGACert->sPublicKey.prgbStream))
        {
            i4Status = (int32_t)INT_LIB_NULL_PARAM;
            break;
        }
        //verify signature of the Security Chip certificate
        sSignatureVector.psMessage = &PpsOPTIGACert->sCertData;
        sSignatureVector.psSignature = &PpsOPTIGACert->sCertSignature;
        sSignatureVector.psPublicKey = &PpsCaCert->sPublicKey;
        i4Status = CryptoLib_VerifySignature(&sSignatureVector);
        if(CRYPTO_LIB_OK != i4Status)
        {
            break;
        }         
        i4Status = INT_LIB_OK;
    }while(FALSE);
    
    return i4Status;
}


/**
*
* Reads end entity device certificate, allocate memory based on size of the certificate and returns memory pointer, length in PpsBlobOPTIGACert.<br>
*   
* \param[in]  PwCertOID              Certificate OID
* \param[in,out]  PpsBlobOPTIGACert  Pointer to memory containing read certificate
*   
* \retval    #INT_LIB_OK       
* \retval    #INT_LIB_ERROR    
* \retval    #INT_LIB_MALLOC_FAILURE    
*
*/
static int32_t IntLib_GetEndEntityCertificate(uint16_t PwCertOID,sbBlob_d* PpsBlobOPTIGACert)
{
    int32_t i4Status  = (int32_t)INT_LIB_ERROR;
    sReadGPData_d sReadGPData;
    sbBlob_d sBlobCertificate;
    uint8_t rgbRawOPTIGACert[LENGTH_CERTIFICATE];
    uint16_t wTagLen;
    uint32_t dwCertLen;
    do 
    {
#define LENGTH_CERTLIST_LEN		3
#define LENGTH_CERTLEN			3
#define LENGTH_TAGlEN_PLUS_TAG  3
#define LENGTH_MINIMUM_DATA		10
        
        //Read complete certificate
        sReadGPData.wOffset = 0x00;
        sReadGPData.wLength = 0xFFFF;
        sReadGPData.wOID = PwCertOID;

        //Reading available certificate data
        sBlobCertificate.prgbStream = rgbRawOPTIGACert;
        sBlobCertificate.wLen = sizeof(rgbRawOPTIGACert);      
        i4Status = IntLib_ReadGPData(&sReadGPData,&sBlobCertificate);
        if(INT_LIB_OK != i4Status)
        {
            break;
        }
        
        //Validate TLV
        if((TLS_TAG != rgbRawOPTIGACert[0]) && (ASN_TAG_SEQUENCE != rgbRawOPTIGACert[0]))
        {
            i4Status = (int32_t)INT_LIB_INVALID_CERTIFICATE_FORMAT;
            break;
        }
        
        if(TLS_TAG == rgbRawOPTIGACert[0])
        {
			//Check minimum length must be 10
			if(sBlobCertificate.wLen < LENGTH_MINIMUM_DATA)
			{
				i4Status = (int32_t)INT_LIB_INVALID_CERTIFICATE_FORMAT;
				break;
			}
            wTagLen = Utility_GetUint16 (&rgbRawOPTIGACert[1]);
            dwCertLen = Utility_GetUint24(&rgbRawOPTIGACert[6]);
            //Length checks
            if((wTagLen != (sBlobCertificate.wLen - LENGTH_TAGlEN_PLUS_TAG)) ||           \
                (Utility_GetUint24(&rgbRawOPTIGACert[3]) != (uint32_t)(wTagLen - LENGTH_CERTLIST_LEN)) ||   \
                ((dwCertLen > (uint32_t)(wTagLen - (LENGTH_CERTLIST_LEN  + LENGTH_CERTLEN))) || (dwCertLen == 0x00)))
            {
                i4Status = (int32_t)INT_LIB_INVALID_CERTIFICATE_FORMAT;
                break;
            }
            
            sBlobCertificate.prgbStream = &rgbRawOPTIGACert[9];
            sBlobCertificate.wLen = (uint16_t)dwCertLen;
        }
        
        //Allocate memory for available certificate ,copy certificate and return to caller
        PpsBlobOPTIGACert->prgbStream = (uint8_t*)OCP_MALLOC(sBlobCertificate.wLen);
        if(NULL == PpsBlobOPTIGACert->prgbStream)
        {
            i4Status = (int32_t)INT_LIB_MALLOC_FAILURE;
            break;
        }
        OCP_MEMCPY(PpsBlobOPTIGACert->prgbStream,sBlobCertificate.prgbStream,sBlobCertificate.wLen);
        PpsBlobOPTIGACert->wLen = sBlobCertificate.wLen;
        i4Status = INT_LIB_OK;
    } while (FALSE);

#undef LENGTH_CERTLIST_LEN
#undef LENGTH_CERTLEN
#undef LENGTH_TAGlEN_PLUS_TAG
#undef LENGTH_MINIMUM_DATA
    return i4Status;
}

/**
*
* Verifies the PKI domain of the device certificate.<br>
*   
* \param[in]        PpsCaCert               Pointer to CA Certificate
* \param[in]        PwCertOID				Certificate OID
* \param[in,out]    PpsOPTIGAPublicKey	    Pointer to end entity device public key
*   
* \retval    #INT_LIB_OK       
* \retval    #INT_LIB_ERROR      
*
*/
static int32_t IntLib_VerifyPKIDomain(const sbBlob_d *PpsCaCert,uint16_t PwCertOID, const sbBlob_d *PpsOPTIGAPublicKey)
{
	int32_t i4Status  = (int32_t)INT_LIB_ERROR;
	uint8_t rgbCAPublicKey[LENGTH_PUB_KEY_NISTP256];
	sbBlob_d sBlobOPTIGACert;
	sCertificate_d sParsedCACert;
	sCertificate_d sParsedOPTIGACert;

	do 
	{
		sBlobOPTIGACert.prgbStream = NULL;
		//Get end entity device certificate
		i4Status = IntLib_GetEndEntityCertificate(PwCertOID,&sBlobOPTIGACert);
		if(INT_LIB_OK != i4Status)
		{
			break;
		}
		//Parse CA certificate
		sParsedCACert.sPublicKey.prgbStream = rgbCAPublicKey;
		sParsedCACert.sPublicKey.wLen = sizeof(rgbCAPublicKey);
		i4Status = CryptoLib_ParseCertificate(PpsCaCert,&sParsedCACert);
		if(CRYPTO_LIB_OK != i4Status)
		{
			break;
		}
		//Parse device certificate
		sParsedOPTIGACert.sPublicKey.prgbStream = PpsOPTIGAPublicKey->prgbStream;
		sParsedOPTIGACert.sPublicKey.wLen = PpsOPTIGAPublicKey->wLen;
		i4Status = CryptoLib_ParseCertificate(&sBlobOPTIGACert,&sParsedOPTIGACert);
		if(CRYPTO_LIB_OK != i4Status)
		{
			break;
		}
		//Validate CA Certificate
		i4Status = IntLib_ValidateCertificate(&sParsedCACert,&sParsedOPTIGACert);
		if(INT_LIB_OK != i4Status)
		{
			break;
		}
	} while (FALSE);
    //Clear allocated memory
	if(NULL != sBlobOPTIGACert.prgbStream)
	{
		OCP_FREE(sBlobOPTIGACert.prgbStream);
	}
    return i4Status;
}

/**
*
* Authenticate end device entity.<br>
*   
* \param[in]  PwChallengeLen		Length of the challenge to be generated
* \param[in]  PpsOPTIGAPublicKey	Pointer blob to store end entity device public key
* \param[in]  PwOPTIGAPrivKey		Private key to be used for set auth scheme
*   
* \retval    #INT_LIB_OK       
* \retval    #INT_LIB_ERROR    
* \retval    #INT_LIB_MALLOC_FAILURE   
*
*/
static int32_t IntLib_AuthenticateEndEntity(uint16_t PwChallengeLen,sbBlob_d *PpsOPTIGAPublicKey,uint16_t PwOPTIGAPrivKey)
{
    int32_t i4Status  = (int32_t)INT_LIB_ERROR;
    uint8_t* pbRandomNumber = NULL;
    uint8_t rgbOPTIGASignature[LENGTH_SIGNATURE];
    uint16_t wLenRandomNumber;
    uint16_t wLenOPTIGASignature;
    sCmdResponse_d sCmdResponse;
    sAuthMsg_d sAuthMsg;
    sbBlob_d sBlobOPTIGASignature;
    sbBlob_d sBlobRandomNumber;
    sSignatureVector_d sSignatureVector;
    do 
    {
        //Allocate the memory to store generated random number
        pbRandomNumber = (uint8_t*)OCP_MALLOC(PwChallengeLen);
        if(NULL == pbRandomNumber)
        {
            i4Status = (int32_t)INT_LIB_MALLOC_FAILURE;
            break;
        }
        //Get PwChallengeLen byte random stream
        sCmdResponse.prgbBuffer = pbRandomNumber;
        sCmdResponse.wBufferLength = PwChallengeLen;
        i4Status = CryptoLib_GetRandom(PwChallengeLen,&sCmdResponse);
        if(CRYPTO_LIB_OK != i4Status)
        {
            break;
        }
        //Save received random number length
        wLenRandomNumber = sCmdResponse.wRespLength;

		//Initiate authenticate commands
		sAuthMsg.eAuthScheme = eECDSA;
		sAuthMsg.prgbRnd = pbRandomNumber;
		sAuthMsg.wRndLength = wLenRandomNumber;
		sAuthMsg.wOIDDevPrivKey = PwOPTIGAPrivKey;

		sCmdResponse.prgbBuffer = rgbOPTIGASignature + MAXLENGTH_SIGN_ENCODE;
		sCmdResponse.wBufferLength = sizeof(rgbOPTIGASignature) - MAXLENGTH_SIGN_ENCODE;

		i4Status = CmdLib_GetSignature(&sAuthMsg,&sCmdResponse);
		if(CMD_LIB_OK != i4Status)
		{
			break;
		}
		//Save OPTIGA Trust X signature length
		wLenOPTIGASignature = sCmdResponse.wRespLength;

		//Verify the signature on the random number by Security Chip
		//Format signature
		sBlobOPTIGASignature.prgbStream = rgbOPTIGASignature;
		sBlobOPTIGASignature.wLen = wLenOPTIGASignature;
		i4Status = IntLib_FormatSignature(&sBlobOPTIGASignature,sCmdResponse.prgbBuffer,wLenOPTIGASignature);        
		if(INT_LIB_OK != i4Status)        
		{
			break;
		}

		sBlobRandomNumber.prgbStream = pbRandomNumber;
		sBlobRandomNumber.wLen = wLenRandomNumber;

		sSignatureVector.psSignature = &sBlobOPTIGASignature;
		sSignatureVector.psMessage = &sBlobRandomNumber;
		sSignatureVector.psPublicKey = PpsOPTIGAPublicKey;
		i4Status = CryptoLib_VerifySignature(&sSignatureVector);
		if(CRYPTO_LIB_OK != i4Status)
		{
			break;
		}
        i4Status = INT_LIB_OK;     
	} while (FALSE);
	if(NULL != pbRandomNumber)
	{
		OCP_FREE(pbRandomNumber);
	}
    
    return i4Status;
}



#endif /* MODULE_ENABLE_ONE_WAY_AUTH*/
/// @endcond 

#ifdef MODULE_ENABLE_ONE_WAY_AUTH
/**
* Performs One-Way Authentication Public Key Scheme and proves the authenticity of the 
* device which incorporates the security chip. 
*
* The application on security chip must be opened using #CmdLib_OpenApplication before using this API.<br> 
* <br>
* The API performs One-Way Authentication Public Key Scheme in the following way:<br>
*
* - Reads the device certificate from the security chip, as specified by \ref sOneWayAuth_d.wOIDDevCertificate.<br>
*
* - Verifies the device certificate signature using the public key from CA certificate \ref sOneWayAuth_d.sCaCert.<br>
*
* - A random number of length \ref sOneWayAuth_d.wChallengeLen is generated on the host. This is used as a challenge to be sent to the security chip.<br>
*
* - Issues SetAuthScheme APDU command based on the private key provided in \ref sOneWayAuth_d.wOIDDevPrivKey.<br>
*
* - Issues SetAuthMsg and GetAuthMsg APDU commands to security chip to get signature on the challenge.<br>
*
* - Verifies the signature using the public key extracted from the device certificate.<br>
*
* Notes: <br>
* - CA certificate must be provided in DER encoded binary format.<br>
* - The current implementation is based on ECC NIST P 256 bit key length.<br>
* - The wChallengeLen must range from 8 to 256 bytes. It is recommended to use a minimum challenge length of 16 bytes. If the length is out of this range, #INT_LIB_INVALID_LENGTH error is returned.<br>
* - This API supports device certificate objects in "One-Way Authentication" and "TLS" identity format only. Identity validation failures will return #INT_LIB_INVALID_CERTIFICATE_FORMAT error.<br>
* - For TLS identity, certificates chaining must be encoded as per RFC-5246.<br>
* - Under some erroneous conditions, error codes from Command Library and crypto Library can also be returned.<br>
* - If the return code is #CMD_DEV_EXEC_ERROR, it might indicate that the application on the
*   security chip is either closed or a reset has occurred. In such a case, user must invoke #CmdLib_OpenApplication before attempting any interaction with the security chip.<br>
*
* <br>
* \param[in]  PpsOneWayAuth      Pointer to sOneWayAuth_d to provide inputs for One-Way Authentication Public Key Scheme
* 
* \retval    #INT_LIB_OK       
* \retval    #INT_LIB_ERROR  
* \retval    #INT_LIB_ZEROLEN_ERROR  
* \retval    #INT_LIB_NULL_PARAM         
* \retval    #INT_LIB_INVALID_LENGTH
* \retval    #INT_LIB_MALLOC_FAILURE
* \retval    #INT_LIB_INVALID_CERTIFICATE_FORMAT
* \retval    #CMD_DEV_ERROR  
* \retval    #CMD_DEV_EXEC_ERROR  
*/
int32_t IntLib_Authenticate(const sOneWayAuth_d *PpsOneWayAuth)
{
	int32_t i4Status  = (int32_t)INT_LIB_ERROR;
	sbBlob_d sBlobOPTIGAPublicKey;
	uint8_t rgbOPTIGAPublicKey[LENGTH_PUB_KEY_NISTP256];

	do
	{
		if((NULL==PpsOneWayAuth)||(NULL==PpsOneWayAuth->sCaCert.prgbStream))
		{
			i4Status = (int32_t)INT_LIB_NULL_PARAM;
			break;
		}

/// @cond hidden
#define CA_CERT PpsOneWayAuth->sCaCert
/// @endcond 

		//check if the length of the response is not zero
		if(0x00 == CA_CERT.wLen)
		{
			i4Status = (int32_t)INT_LIB_ZEROLEN_ERROR;
			break;
		}

		//Check if Challenge length is in between 8 to 256
		if((CHALLENGE_MIN_LEN > PpsOneWayAuth->wChallengeLen) || (CHALLENGE_MAX_LEN < PpsOneWayAuth->wChallengeLen))
		{
			i4Status = (int32_t)INT_LIB_INVALID_LENGTH;
			break;
		}
		
		//Buffer to store device public key
		sBlobOPTIGAPublicKey.prgbStream = rgbOPTIGAPublicKey;
		sBlobOPTIGAPublicKey.wLen = sizeof(rgbOPTIGAPublicKey);

		//Certificate verification
		i4Status = IntLib_VerifyPKIDomain(&CA_CERT,PpsOneWayAuth->wOIDDevCertificate,&sBlobOPTIGAPublicKey);
		if(INT_LIB_OK != i4Status)
		{
			break;
		}

		//Perform authentication
		i4Status = IntLib_AuthenticateEndEntity(PpsOneWayAuth->wChallengeLen,&sBlobOPTIGAPublicKey,PpsOneWayAuth->wOIDDevPrivKey);
		if(INT_LIB_OK != i4Status)
		{
			break;
		}
	}while(FALSE);

/// @cond hidden
#undef CA_CERT
/// @endcond 

    return i4Status;
}


#endif /* MODULE_ENABLE_ONE_WAY_AUTH*/

#ifdef MODULE_ENABLE_READ_WRITE
/**
* Reads the specified general purpose data object from the security chip.
*
* The application on security chip must be opened using #CmdLib_OpenApplication before using this API.<br>
* <br>
* The API reads the data object in the following way:<br>
*
* - Reads the application life cycle status(LcsA) and global life cycle status(LcsG)
*
* - Reads the metadata of the data object. <br>
*
* - Verifies the read access conditions of the data object. <br>
* 
* - Reads the data object, if read access is permitted. <br>
*
* Notes: <br>
* - Under some erroneous conditions,error codes from Command Library and Crypto Library can also be returned.<br> 
* - If the return code is #CMD_DEV_EXEC_ERROR, it might indicate that the application on the
*   security chip is either closed or a reset has occurred. In such a case, user must invoke #CmdLib_OpenApplication before attempting any interaction with the security chip.<br>
*
*
* \param[in]  PpsGDVector         Pointer to Get Data parameters
* \param[in,out]  PpsGPData           Pointer to data buffer for response
*
* \retval    #INT_LIB_OK   
* \retval    #INT_LIB_NULL_PARAM     
* \retval    #INT_LIB_INVALID_RESPONSE    
* \retval    #INT_LIB_INVALID_AC     
* \retval    #INT_LIB_ZEROLEN_ERROR     
* \retval    #INT_LIB_ERROR       
* \retval    #CMD_DEV_ERROR     
* \retval    #CMD_DEV_EXEC_ERROR          
*/
int32_t IntLib_ReadGPData(const sReadGPData_d *PpsGDVector, sbBlob_d *PpsGPData)
{
    //lint --e{818} suppress "PpsGPData is out parameter"
    int32_t i4Status  = (int32_t)INT_LIB_ERROR;
    sGetData_d sGDVector;
    sCmdResponse_d sCmdResponse;
    uint8_t prgbMetaData[LENGTH_METADATA];
    sbBlob_d sMetaData = {LENGTH_METADATA,prgbMetaData};
    sACVector_d sReadACVector;
    uint8_t bRecvMetaDataLen;
    do
    {
        if((NULL == PpsGDVector)||(NULL == PpsGPData)||(NULL == PpsGPData->prgbStream))
        {
            i4Status = (int32_t)INT_LIB_NULL_PARAM;
            break; 
        }
        //check if the buffer length is zero
        if(0x00 == PpsGPData->wLen)
        {
            i4Status = (int32_t)INT_LIB_ZEROLEN_ERROR;
            break;
        }

		//Read lcsA
        i4Status = IntLib_ReadLcs(eLCSA,&(sReadACVector.bLcsA));
        if(INT_LIB_OK != i4Status)
        {
           break; 
        }
        //Read lcsG
        i4Status = IntLib_ReadLcs(eLCSG,&(sReadACVector.bLcsG));
        if(INT_LIB_OK != i4Status)
        {
           break; 
        }    
        //check if OID is for lcsA or lcaG
        if((uint16_t)eLCSA == PpsGDVector->wOID)
        {
            //return the read value
            *(PpsGPData->prgbStream) = sReadACVector.bLcsA;
            PpsGPData->wLen = 0x01;
            break;
        }
        if((uint16_t)eLCSG == PpsGDVector->wOID)
        {
            //return the read value
            *(PpsGPData->prgbStream) = sReadACVector.bLcsG;
            PpsGPData->wLen = 0x01;
            break;
        }
            
        //Get metadata of oid
        sGDVector.wOID = PpsGDVector->wOID;
        sGDVector.wLength = LENGTH_METADATA;
        sGDVector.wOffset = 0;
        sGDVector.eDataOrMdata = eMETA_DATA;
        
        sCmdResponse.prgbBuffer = prgbMetaData;
        sCmdResponse.wBufferLength = sizeof(prgbMetaData);
        sCmdResponse.wRespLength = 0;

        i4Status = CmdLib_GetDataObject(&sGDVector,&sCmdResponse);
        if(CMD_LIB_OK != i4Status)
        {
            break;
        }        
        //Check the length
        bRecvMetaDataLen = *(sCmdResponse.prgbBuffer + POS_LEN );
        if((bRecvMetaDataLen != (sCmdResponse.wRespLength-POS_VAL)))
        {
            i4Status = (int32_t)INT_LIB_INVALID_RESPONSE;
            break;
        }
        //Check read access condition
        sReadACVector.psMetaData = &sMetaData;
        i4Status = IntLib_VerifyAC(eREAD_AC,&sReadACVector);
        if(INT_LIB_OK != i4Status)
        {
            i4Status = (int32_t)INT_LIB_INVALID_AC;
            break;
        }
        //If access condition satisfied, get the data
        sGDVector.wOID = PpsGDVector->wOID;
        sGDVector.wLength = PpsGDVector->wLength;
        sGDVector.wOffset = PpsGDVector->wOffset;
        sGDVector.eDataOrMdata = eDATA;
        
        sCmdResponse.prgbBuffer = PpsGPData->prgbStream;
        sCmdResponse.wBufferLength = PpsGPData->wLen;
        sCmdResponse.wRespLength = 0;

        i4Status = CmdLib_GetDataObject(&sGDVector,&sCmdResponse);
        if(CMD_LIB_OK != i4Status)
        {
            break;
        }
        PpsGPData->wLen = sCmdResponse.wRespLength;
	    i4Status = INT_LIB_OK;
    }while(FALSE);
    //in case of error, update length to 0
    if((INT_LIB_OK != i4Status)&&(NULL != PpsGPData))
    {
        PpsGPData->wLen = 0;
    }
    return i4Status;
}


/**
* Writes to the specified general purpose data object to the security chip.
*
* The application on security chip must be opened using #CmdLib_OpenApplication before using this API.<br>
* <br>
* The API writes to data object in the following way:<br>
*
* - Reads the application life cycle status(LcsA) and global life cycle status(LcsG)
*
* - Reads the metadata of the data object. <br>
*
* - Verifies the write access conditions of the data object. <br>
* 
* - Writes to the data object, if write access is permitted. <br>
*
* Notes: <br>
* - Under some erroneous conditions,error codes from Command Library and Crypto Library can also be returned.<br>
* - If the return code is #CMD_DEV_EXEC_ERROR, it might indicate that the application on the
*   security chip is either closed or a reset has occurred. In such a case, user must invoke #CmdLib_OpenApplication before attempting any interaction with the security chip.<br>
*
*
* \param[in]  PpsSDVector         Pointer to Set Data parameters
*
* \retval    #INT_LIB_OK       
* \retval    #INT_LIB_NULL_PARAM     
* \retval    #INT_LIB_INVALID_RESPONSE     
* \retval    #INT_LIB_INVALID_AC    
* \retval    #INT_LIB_ERROR      
* \retval    #CMD_DEV_ERROR     
* \retval    #CMD_DEV_EXEC_ERROR    
*/
int32_t IntLib_WriteGPData(const sWriteGPData_d *PpsSDVector)
{
    int32_t i4Status  = (int32_t)INT_LIB_ERROR;
    uint8_t prgbMetaData[LENGTH_METADATA];
    uint8_t bRecvMetaDataLen;

    sSetData_d sSDVector;
    sGetData_d sGDVector;
    sCmdResponse_d sCmdResponse;
    sbBlob_d sMetaData = {LENGTH_METADATA,prgbMetaData};
    sACVector_d sWriteACVector;

    do
    {
        if(NULL == PpsSDVector)
        {
            i4Status = (int32_t)INT_LIB_NULL_PARAM;
            break; 
        }
        if(0x00 == PpsSDVector->wLength)
        {
            i4Status = (int32_t)INT_LIB_ZEROLEN_ERROR;
            break;
        }
        
        //Read lcsA
        i4Status = IntLib_ReadLcs(eLCSA,&(sWriteACVector.bLcsA));
        if(INT_LIB_OK != i4Status)
        {
           break; 
        }
        //Read lcsG
        i4Status = IntLib_ReadLcs(eLCSG,&(sWriteACVector.bLcsG));
        if(INT_LIB_OK != i4Status)
        {
           break; 
        }   

        //Do not read meta data if OID is lcsA or lcsG
        if(((uint16_t)eLCSA != PpsSDVector->wOID)&&
            ((uint16_t)eLCSG != PpsSDVector->wOID))
        {
            //Get metada data of oid
            sGDVector.wOID = PpsSDVector->wOID;
            sGDVector.wLength = LENGTH_METADATA;
            sGDVector.wOffset = 0;
            sGDVector.eDataOrMdata = eMETA_DATA;
            
            sCmdResponse.prgbBuffer = prgbMetaData;
            sCmdResponse.wBufferLength = sizeof(prgbMetaData);
            sCmdResponse.wRespLength = 0;

            i4Status = CmdLib_GetDataObject(&sGDVector,&sCmdResponse);
            if(CMD_LIB_OK != i4Status)
            {
                break;
            }        
            //Check the length
            bRecvMetaDataLen = *(sCmdResponse.prgbBuffer + POS_LEN );
            //response length contains data + 2 byte Tag,Len
            if((bRecvMetaDataLen != (sCmdResponse.wRespLength-2)))
            {
                i4Status = (int32_t)INT_LIB_INVALID_RESPONSE;
                break;
            }         
            //Check change access condition
            sWriteACVector.psMetaData = &sMetaData;
            i4Status = IntLib_VerifyAC(eCHANGE_AC,&sWriteACVector);
            if(INT_LIB_OK != i4Status)
            {
                i4Status = (int32_t)INT_LIB_INVALID_AC;
                break;
            }
        }
        //If access condition satisfied, set the data
        sSDVector.wOID = PpsSDVector->wOID;
        sSDVector.wOffset = PpsSDVector->wOffset;
        sSDVector.eDataOrMdata = eDATA;
        sSDVector.eWriteOption = PpsSDVector->eWriteOption;
        sSDVector.prgbData = PpsSDVector->prgbData;
        sSDVector.wLength = PpsSDVector->wLength;
        
        i4Status = CmdLib_SetDataObject(&sSDVector);
        if(CMD_LIB_OK != i4Status)
        {
            break;
        }   
        i4Status = INT_LIB_OK;
    }while(FALSE);
    return i4Status;
}
#endif /* MODULE_ENABLE_READ_WRITE*/
