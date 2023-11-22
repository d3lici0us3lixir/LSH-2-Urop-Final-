# include "hight.h"
/***************************************************************************
 *
 * Created July, 2005
 * Modified Dec, 2013
 * File : KISA_HIGHT_ECB.c
 *
 * Description : Core routines for the enhanced HIGHT
 *
 **************************************************************************/


/*************** Macros ***************************************************/

/*************** Global Variables *****************************************/

/*************** Function *************************************************/

HIGHT::HIGHT() {

}

void    HIGHT_KeySched(
    BYTE* UserKey,
    DWORD   UserKeyLen,
    BYTE* RoundKey)
{
    int     i, j;

    for (i = 0; i < 4; i++) {
        RoundKey[i] = UserKey[i + 12];
        RoundKey[i + 4] = UserKey[i];
    }

    for (i = 0; i < 8; i++) {
        for (j = 0; j < 8; j++)
            RoundKey[8 + 16 * i + j] = (BYTE)(UserKey[(j - i) & 7] + Delta[16 * i + j]);
        // Use "&7"  instead of the "%8" for Performance

        for (j = 0; j < 8; j++)
            RoundKey[8 + 16 * i + j + 8] = (BYTE)(UserKey[((j - i) & 7) + 8] + Delta[16 * i + j + 8]);
    }
}

/*************** Encryption*************************************************/

void    HIGHT_Encrypt(
    BYTE* RoundKey,
    BYTE* Data)

{
    DWORD   XX[8];

    // First Round
    XX[1] = Data[1];
    XX[3] = Data[3];
    XX[5] = Data[5];
    XX[7] = Data[7];

    XX[0] = (Data[0] + RoundKey[0]) & 0xFF;
    XX[2] = (Data[2] ^ RoundKey[1]);
    XX[4] = (Data[4] + RoundKey[2]) & 0xFF;
    XX[6] = (Data[6] ^ RoundKey[3]);

    // Encryption Round 
#define HIGHT_ENC(k, i0,i1,i2,i3,i4,i5,i6,i7) {                         \
        XX[i0] = (XX[i0] ^ (HIGHT_F0[XX[i1]] + RoundKey[4*k+3])) & 0xFF;    \
        XX[i2] = (XX[i2] + (HIGHT_F1[XX[i3]] ^ RoundKey[4*k+2])) & 0xFF;    \
        XX[i4] = (XX[i4] ^ (HIGHT_F0[XX[i5]] + RoundKey[4*k+1])) & 0xFF;    \
        XX[i6] = (XX[i6] + (HIGHT_F1[XX[i7]] ^ RoundKey[4*k+0])) & 0xFF;    \
    }

    HIGHT_ENC(2, 7, 6, 5, 4, 3, 2, 1, 0);
    HIGHT_ENC(3, 6, 5, 4, 3, 2, 1, 0, 7);
    HIGHT_ENC(4, 5, 4, 3, 2, 1, 0, 7, 6);
    HIGHT_ENC(5, 4, 3, 2, 1, 0, 7, 6, 5);
    HIGHT_ENC(6, 3, 2, 1, 0, 7, 6, 5, 4);
    HIGHT_ENC(7, 2, 1, 0, 7, 6, 5, 4, 3);
    HIGHT_ENC(8, 1, 0, 7, 6, 5, 4, 3, 2);
    HIGHT_ENC(9, 0, 7, 6, 5, 4, 3, 2, 1);
    HIGHT_ENC(10, 7, 6, 5, 4, 3, 2, 1, 0);
    HIGHT_ENC(11, 6, 5, 4, 3, 2, 1, 0, 7);
    HIGHT_ENC(12, 5, 4, 3, 2, 1, 0, 7, 6);
    HIGHT_ENC(13, 4, 3, 2, 1, 0, 7, 6, 5);
    HIGHT_ENC(14, 3, 2, 1, 0, 7, 6, 5, 4);
    HIGHT_ENC(15, 2, 1, 0, 7, 6, 5, 4, 3);
    HIGHT_ENC(16, 1, 0, 7, 6, 5, 4, 3, 2);
    HIGHT_ENC(17, 0, 7, 6, 5, 4, 3, 2, 1);
    HIGHT_ENC(18, 7, 6, 5, 4, 3, 2, 1, 0);
    HIGHT_ENC(19, 6, 5, 4, 3, 2, 1, 0, 7);
    HIGHT_ENC(20, 5, 4, 3, 2, 1, 0, 7, 6);
    HIGHT_ENC(21, 4, 3, 2, 1, 0, 7, 6, 5);
    HIGHT_ENC(22, 3, 2, 1, 0, 7, 6, 5, 4);
    HIGHT_ENC(23, 2, 1, 0, 7, 6, 5, 4, 3);
    HIGHT_ENC(24, 1, 0, 7, 6, 5, 4, 3, 2);
    HIGHT_ENC(25, 0, 7, 6, 5, 4, 3, 2, 1);
    HIGHT_ENC(26, 7, 6, 5, 4, 3, 2, 1, 0);
    HIGHT_ENC(27, 6, 5, 4, 3, 2, 1, 0, 7);
    HIGHT_ENC(28, 5, 4, 3, 2, 1, 0, 7, 6);
    HIGHT_ENC(29, 4, 3, 2, 1, 0, 7, 6, 5);
    HIGHT_ENC(30, 3, 2, 1, 0, 7, 6, 5, 4);
    HIGHT_ENC(31, 2, 1, 0, 7, 6, 5, 4, 3);
    HIGHT_ENC(32, 1, 0, 7, 6, 5, 4, 3, 2);
    HIGHT_ENC(33, 0, 7, 6, 5, 4, 3, 2, 1);

    // Final Round
    Data[1] = (BYTE)XX[2];
    Data[3] = (BYTE)XX[4];
    Data[5] = (BYTE)XX[6];
    Data[7] = (BYTE)XX[0];

    Data[0] = (BYTE)(XX[1] + RoundKey[4]);
    Data[2] = (BYTE)(XX[3] ^ RoundKey[5]);
    Data[4] = (BYTE)(XX[5] + RoundKey[6]);
    Data[6] = (BYTE)(XX[7] ^ RoundKey[7]);
}



void main()
{
    BYTE pdwRoundKey[136] = { 0, };																									// Round keys for encryption or decryption
    BYTE pbUserKey[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff }; 		// User secret key
    BYTE pbData[8] = { 0, }; 															// input plaintext to be encrypted

    int i;

    // Print user secret key
    printf("Key        : ");
    for (i = 0; i < 16; i++)
        printf("%02X ", pbUserKey[i]);

    // Print plaintext to be encrypted
    printf("\nPlaintext  : ");
    for (i = 0; i < 8; i++)
        printf("%02X ", pbData[i]);

    // Derive roundkeys from user secret key
    HIGHT_KeySched(pbUserKey, 16, pdwRoundKey);

    // Encryption
    printf("\n\nEncryption....\n");
    HIGHT_Encrypt(pdwRoundKey, pbData);

    // print encrypted data(ciphertext)
    printf("Ciphertext : ");
    for (i = 0; i < 8; i++)
        printf("%02X ", pbData[i]);


}