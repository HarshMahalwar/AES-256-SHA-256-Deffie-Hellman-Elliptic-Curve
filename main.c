#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h> 

int MOD = 173;    

struct AES_256
{
  uint8_t RoundKeyFunction[240];
};



uint8_t sbox[256] = {
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

uint8_t rsbox[256] = {
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };


uint8_t Rcon[11] = {
  0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

#define GetSbox(num) (sbox[(num)])
typedef uint8_t s8_t[4][4];

void KeyExpansion(uint8_t* RoundKeyFunction, uint8_t* Key)
{
  unsigned i, j, k;
  uint8_t TempArray[4]; 
  for (i = 0; i < 8; ++i)
  {
    RoundKeyFunction[(i * 4) + 0] = Key[(i * 4) + 0];
    RoundKeyFunction[(i * 4) + 1] = Key[(i * 4) + 1];
    RoundKeyFunction[(i * 4) + 2] = Key[(i * 4) + 2];
    RoundKeyFunction[(i * 4) + 3] = Key[(i * 4) + 3];
  }

  // All other round keys are found from the previous round keys.
  for (i = 8; i < 4 * (14 + 1); ++i)
  {
    {
      k = (i - 1) * 4;
      TempArray[0]=RoundKeyFunction[k + 0];
      TempArray[1]=RoundKeyFunction[k + 1];
      TempArray[2]=RoundKeyFunction[k + 2];
      TempArray[3]=RoundKeyFunction[k + 3];

    }

    if (i % 8 == 0)
    {
      {
        uint8_t u8tmp = TempArray[0];
        TempArray[0] = TempArray[1];
        TempArray[1] = TempArray[2];
        TempArray[2] = TempArray[3];
        TempArray[3] = u8tmp;
      }

      {
        TempArray[0] = GetSbox(TempArray[0]);
        TempArray[1] = GetSbox(TempArray[1]);
        TempArray[2] = GetSbox(TempArray[2]);
        TempArray[3] = GetSbox(TempArray[3]);
      }

      TempArray[0] = TempArray[0] ^ Rcon[i/8];
    }
    if (i % 8 == 4)
    {
      {
        TempArray[0] = GetSbox(TempArray[0]);
        TempArray[1] = GetSbox(TempArray[1]);
        TempArray[2] = GetSbox(TempArray[2]);
        TempArray[3] = GetSbox(TempArray[3]);
      }
    }
    j = i * 4; k=(i - 8) * 4;
    RoundKeyFunction[j + 0] = RoundKeyFunction[k + 0] ^ TempArray[0];
    RoundKeyFunction[j + 1] = RoundKeyFunction[k + 1] ^ TempArray[1];
    RoundKeyFunction[j + 2] = RoundKeyFunction[k + 2] ^ TempArray[2];
    RoundKeyFunction[j + 3] = RoundKeyFunction[k + 3] ^ TempArray[3];
  }
}


void AES_Obj(struct AES_256* obj, uint8_t* key)
{
  KeyExpansion(obj->RoundKeyFunction, key);
}



void AddRoundKey(uint8_t round, s8_t* Matrix, uint8_t* RoundKeyFunction)
{
  uint8_t i,j;
  for (i = 0; i < 4; ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      (*Matrix)[i][j] ^= RoundKeyFunction[(round * 4 * 4) + (i * 4) + j];
    }
  }
}
void SubBytes(s8_t* Matrix)
{
  uint8_t i, j;
  for (i = 0; i < 4; ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      (*Matrix)[j][i] = GetSbox((*Matrix)[j][i]);
    }
  }
}


void ShiftRows(s8_t* Matrix)
{
  uint8_t temp;
  temp = (*Matrix)[0][1];
  (*Matrix)[0][1] = (*Matrix)[1][1];
  (*Matrix)[1][1] = (*Matrix)[2][1];
  (*Matrix)[2][1] = (*Matrix)[3][1];
  (*Matrix)[3][1] = temp;
  temp           = (*Matrix)[0][2];
  (*Matrix)[0][2] = (*Matrix)[2][2];
  (*Matrix)[2][2] = temp;
  temp           = (*Matrix)[1][2];
  (*Matrix)[1][2] = (*Matrix)[3][2];
  (*Matrix)[3][2] = temp;
  temp           = (*Matrix)[0][3];
  (*Matrix)[0][3] = (*Matrix)[3][3];
  (*Matrix)[3][3] = (*Matrix)[2][3];
  (*Matrix)[2][3] = (*Matrix)[1][3];
  (*Matrix)[1][3] = temp;
}

uint8_t HelperMixCol(uint8_t x)
{
  return ((x<<1) ^ (((x>>7) & 1) * 0x1b));
}

void MixColumns(s8_t* Matrix)
{
  uint8_t i;
  uint8_t Tmp, Tm, t;
  for (i = 0; i < 4; ++i)
  {  
    t   = (*Matrix)[i][0];
    Tmp = (*Matrix)[i][0] ^ (*Matrix)[i][1] ^ (*Matrix)[i][2] ^ (*Matrix)[i][3] ;
    Tm  = (*Matrix)[i][0] ^ (*Matrix)[i][1] ; Tm = HelperMixCol(Tm);  (*Matrix)[i][0] ^= Tm ^ Tmp ;
    Tm  = (*Matrix)[i][1] ^ (*Matrix)[i][2] ; Tm = HelperMixCol(Tm);  (*Matrix)[i][1] ^= Tm ^ Tmp ;
    Tm  = (*Matrix)[i][2] ^ (*Matrix)[i][3] ; Tm = HelperMixCol(Tm);  (*Matrix)[i][2] ^= Tm ^ Tmp ;
    Tm  = (*Matrix)[i][3] ^ t ;              Tm = HelperMixCol(Tm);  (*Matrix)[i][3] ^= Tm ^ Tmp ;
  }
}


#define Multiply(x, y)                                \
      (  ((y & 1) * x) ^                              \
      ((y>>1 & 1) * HelperMixCol(x)) ^                       \
      ((y>>2 & 1) * HelperMixCol(HelperMixCol(x))) ^                \
      ((y>>3 & 1) * HelperMixCol(HelperMixCol(HelperMixCol(x)))) ^         \
      ((y>>4 & 1) * HelperMixCol(HelperMixCol(HelperMixCol(HelperMixCol(x))))))   \


#define getSBoxInvert(num) (rsbox[(num)])


void InvMixColumns(s8_t* Matrix)
{
  int i;
  uint8_t a, b, c, d;
  for (i = 0; i < 4; ++i)
  { 
    a = (*Matrix)[i][0];
    b = (*Matrix)[i][1];
    c = (*Matrix)[i][2];
    d = (*Matrix)[i][3];

    (*Matrix)[i][0] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09);
    (*Matrix)[i][1] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
    (*Matrix)[i][2] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
    (*Matrix)[i][3] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e);
  }
}


// The SubBytes Function Substitutes the values in the
// Matrix matrix with values in an S-box.
void InvSubBytes(s8_t* Matrix)
{
  uint8_t i, j;
  for (i = 0; i < 4; ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      (*Matrix)[j][i] = getSBoxInvert((*Matrix)[j][i]);
    }
  }
}

void InvShiftRows(s8_t* Matrix)
{
  uint8_t temp;

  // Rotate first row 1 columns to right  
  temp = (*Matrix)[3][1];
  (*Matrix)[3][1] = (*Matrix)[2][1];
  (*Matrix)[2][1] = (*Matrix)[1][1];
  (*Matrix)[1][1] = (*Matrix)[0][1];
  (*Matrix)[0][1] = temp;

  // Rotate second row 2 columns to right 
  temp = (*Matrix)[0][2];
  (*Matrix)[0][2] = (*Matrix)[2][2];
  (*Matrix)[2][2] = temp;

  temp = (*Matrix)[1][2];
  (*Matrix)[1][2] = (*Matrix)[3][2];
  (*Matrix)[3][2] = temp;

  // Rotate third row 3 columns to right
  temp = (*Matrix)[0][3];
  (*Matrix)[0][3] = (*Matrix)[1][3];
  (*Matrix)[1][3] = (*Matrix)[2][3];
  (*Matrix)[2][3] = (*Matrix)[3][3];
  (*Matrix)[3][3] = temp;
}



void Cipher(s8_t* Matrix, uint8_t* RoundKeyFunction)
{
  uint8_t round = 0;


  AddRoundKey(0, Matrix, RoundKeyFunction);


  for (round = 1; ; ++round)
  {
    SubBytes(Matrix);
    ShiftRows(Matrix);
    if (round == 14) {
      break;
    }
    MixColumns(Matrix);
    AddRoundKey(round, Matrix, RoundKeyFunction);
  }
  // Add round key to last round
  AddRoundKey(14, Matrix, RoundKeyFunction);
}

void InvCipher(s8_t* Matrix, uint8_t* RoundKeyFunction)
{
  uint8_t i;

  AddRoundKey(14, Matrix, RoundKeyFunction);

  for (i = (14 - 1); i >= 0; --i)
  {
    InvShiftRows(Matrix);
    InvSubBytes(Matrix);
    AddRoundKey(i, Matrix, RoundKeyFunction);
    if (i == 0) 
      break;
    InvMixColumns(Matrix);
  }

}


void AES_encrypt(struct AES_256* obj, uint8_t* buf)
{
  Cipher((s8_t*)buf, obj->RoundKeyFunction);
}

void AES_DECRYPT(struct AES_256* obj, uint8_t* buf)
{
  InvCipher((s8_t*)buf, obj->RoundKeyFunction);
}




int AES_BOB(uint8_t Key[], uint8_t message[], uint8_t decrypted_text[]) {
    struct AES_256 obj;
    uint8_t PlainText[32]; 
    for(int i = 0; i < 32; i++) 
        PlainText[i] = message[i];
    AES_Obj(&obj, Key);
    AES_DECRYPT(&obj, PlainText);

    for(int i = 0; i < 32; i++) 
        decrypted_text[i] = PlainText[i];
    return 0;
}

int AES_ALICE(uint8_t Key[], uint8_t message[], uint8_t ciphertext[]) {
    uint8_t Plaintext[32]; 
    for(int i = 0; i < 32; i++) 
        Plaintext[i] = message[i];
    struct AES_256 obj;
    AES_Obj(&obj, Key);
    AES_encrypt(&obj, Plaintext);

    for(int i = 0; i < 32; i++) 
        ciphertext[i] = Plaintext[i];

}


#define DRBN(a,b,c) if (a > 0xffffffff - (c)) ++b; a += c;
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))


typedef struct {
	unsigned char data[64];
	unsigned int datalen;
	unsigned int bitlen[2];
	unsigned int Matrix[8];
} SHA_256;

unsigned int k[64] = {
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

void SHA_TRANSFORM(SHA_256 *obj, unsigned char data[])
{
	unsigned int a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

	for (i = 0, j = 0; i < 16; ++i, j += 4)
		m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
	for (; i < 64; ++i)
		m[i] = (ROTRIGHT(m[i - 2],17) ^ ROTRIGHT(m[i - 2],19) ^ ((m[i - 2]) >> 10)) + m[i - 7] + (ROTRIGHT(m[i - 15],7) ^ ROTRIGHT(m[i - 15],18) ^ ((m[i - 15]) >> 3)) + m[i - 16];

	a = obj->Matrix[0];
	b = obj->Matrix[1];
	c = obj->Matrix[2];
	d = obj->Matrix[3];
	e = obj->Matrix[4];
	f = obj->Matrix[5];
	g = obj->Matrix[6];
	h = obj->Matrix[7];

	for (i = 0; i < 64; ++i) {
		t1 = h + (ROTRIGHT(e,6) ^ ROTRIGHT(e,11) ^ ROTRIGHT(e,25)) + (((e) & (f)) ^ (~(e) & (g))) + k[i] + m[i];
		t2 = (ROTRIGHT(a,2) ^ ROTRIGHT(a,13) ^ ROTRIGHT(a,22)) + (((a) & (b)) ^ ((a) & (c)) ^ ((b) & (c)));
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}

	obj->Matrix[0] += a;
	obj->Matrix[1] += b;
	obj->Matrix[2] += c;
	obj->Matrix[3] += d;
	obj->Matrix[4] += e;
	obj->Matrix[5] += f;
	obj->Matrix[6] += g;
	obj->Matrix[7] += h;
}

void SHA256Init(SHA_256 *obj)
{
	obj->datalen = 0;
	obj->bitlen[0] = 0;
	obj->bitlen[1] = 0;
	obj->Matrix[0] = 0x6a09e667;
	obj->Matrix[1] = 0xbb67ae85;
	obj->Matrix[2] = 0x3c6ef372;
	obj->Matrix[3] = 0xa54ff53a;
	obj->Matrix[4] = 0x510e527f;
	obj->Matrix[5] = 0x9b05688c;
	obj->Matrix[6] = 0x1f83d9ab;
	obj->Matrix[7] = 0x5be0cd19;
}

void SHA256Update(SHA_256 *obj, unsigned char data[], unsigned int len)
{
	for (unsigned int i = 0; i < len; ++i) {
		obj->data[obj->datalen] = data[i];
		obj->datalen++;
		if (obj->datalen == 64) {
			SHA_TRANSFORM(obj, obj->data);
			DRBN(obj->bitlen[0], obj->bitlen[1], 512);
			obj->datalen = 0;
		}
	}
}

void SHA256Final(SHA_256 *obj, unsigned char hash[])
{
	unsigned int i = obj->datalen;

	if (obj->datalen < 56) {
		obj->data[i++] = 0x80;
		while (i < 56)
			obj->data[i++] = 0x00;
	}
	else {
		obj->data[i++] = 0x80;
		while (i < 64)
			obj->data[i++] = 0x00;
		SHA_TRANSFORM(obj, obj->data);
		memset(obj->data, 0, 56);
	}

	DRBN(obj->bitlen[0], obj->bitlen[1], obj->datalen * 8);
	obj->data[63] = obj->bitlen[0];
	obj->data[62] = obj->bitlen[0] >> 8;
	obj->data[61] = obj->bitlen[0] >> 16;
	obj->data[60] = obj->bitlen[0] >> 24;
	obj->data[59] = obj->bitlen[1];
	obj->data[58] = obj->bitlen[1] >> 8;
	obj->data[57] = obj->bitlen[1] >> 16;
	obj->data[56] = obj->bitlen[1] >> 24;
	SHA_TRANSFORM(obj, obj->data);

	for (i = 0; i < 4; ++i) {
		hash[i] = (obj->Matrix[0] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 4] = (obj->Matrix[1] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 8] = (obj->Matrix[2] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 12] = (obj->Matrix[3] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 16] = (obj->Matrix[4] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 20] = (obj->Matrix[5] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 24] = (obj->Matrix[6] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 28] = (obj->Matrix[7] >> (24 - i * 8)) & 0x000000ff;
	}
}

char* SHA256(unsigned char* data, uint8_t Result[]) {
	int strLen = strlen((char*)data);
	SHA_256 obj;
	unsigned char hash[32];
	char* hashStr = (char*)malloc(65);
	strcpy(hashStr, "");

	SHA256Init(&obj);
	SHA256Update(&obj, (unsigned char*)data, strLen);
	SHA256Final(&obj, hash);

	char s[3];
	for (int i = 0; i < 32; i++) {
		sprintf(s, "%02x", hash[i]);
        Result[i] = hash[i];
		strcat(hashStr, s);
	}

	return hashStr;
}

int SecondSHA(uint8_t Key[], uint8_t Message[], uint8_t Result[]) {

    unsigned char K1[32], M[32], M1[32];
    for(int i = 0; i < 32; i++) 
        K1[i] = (Key[i] ^ 0x02) % 0xff;
    printf("\n");
    for(int i = 0; i < 32; i++)     
        M[i] = (Message[i] | K1[i]) % 0xff;    

    unsigned char K2[32];
    for(int i = 0; i < 32; i++) 
        K2[i] = (Key[i] ^ 0x01) % 0xff;

    SHA256(M, Result);

    for(int i = 0; i < 32; i++) 
        M1[i] = (M[i] | K2[i]) % 0xff;
    SHA256(M1, Result);
    printf("\n");
    return 1;
}

int FirstSHA(uint8_t K[], uint8_t a, uint8_t b) {
    unsigned char Key[2] = {a, b};
    char* sha256 = SHA256(Key, K);
    return 1;
}

int compute(int a, int m, int n)
{
    int r;
    int y = 1;
 
    while (m > 0)
    {
        r = m % 2;
 
        // fast exponention
        if (r == 1) {
            y = (y*a) % n;
        }
        a = a*a % n;
        m = m / 2;
    }
 
    return y;
}
 

int Step2(int32_t x, int32_t y, int32_t a, int32_t b)
{
// C program to demonstrate the Diffie-Hellman algorithm
    int gx = x, gy = y, Ax, Bx, Ay, By; 
    Ax = compute(gx, a, MOD), Ay = compute(gy, a, MOD);
    Bx = compute(gx, b, MOD), By = compute(gy, b, MOD);
    int keyAx = compute(Bx, a, MOD), keyAy = compute(By, a, MOD);
    int keyBx = compute(Ax, b, MOD), keyBy = compute(Ay, b, MOD);  
    printf("Alice's secret key is (%d, %d)\nBob's secret key is (%d, %d)", keyAx, keyAy, keyBx, keyBy);
    uint8_t key_Alice[32], key_Bob[32];
    FirstSHA(key_Alice, (uint8_t) keyAx, (uint8_t)keyAy);
    FirstSHA(key_Bob, (uint8_t) keyBx, (uint8_t)keyBy);

    printf("\nkey_Alice:\n");
    for(int i = 0; i < 32; i++)
        printf("%02x ", key_Alice[i]);
    printf("\nkey_Bob:\n");
    for (int i = 0; i < 32; i++)
        printf("%02x ", key_Bob[i]);
    printf("\n");
    uint8_t CipherText[32], MessageBob[32], MAC_alice[32], MAC_bob[32], MessageAlice[32] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0xa6, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 
                           0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0xa6, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};

    printf("Plain Text Alice(Ma):\n");
    for(int i = 0; i < 32; i++) 
        printf("%02x ", MessageAlice[i]);
    printf("\n");

    AES_ALICE(key_Alice, MessageAlice, CipherText);

    printf("Encrypted Text Alice:\n");
    for(int i = 0; i < 32; i++) 
        printf("%02x ", CipherText[i]);
    printf("\n");

    AES_BOB(key_Bob, CipherText, MessageBob);

    printf("Decrypted Text Bob(Mb):\n");
    for(int i = 0; i < 32; i++) 
        printf("%02x ", MessageBob[i]);
    printf("\n");

    SecondSHA(key_Alice, MessageAlice, MAC_alice);

    printf("MAC Alice(MACa):\n");
    for(int i = 0; i < 32; i++) 
        printf("%02x ", MAC_alice[i]);
    printf("\n");
    SecondSHA(key_Bob, MessageBob, MAC_bob);
    printf("MAC Bob(MACb):\n");
    for(int i = 0; i < 32; i++) 
        printf("%02x ", MAC_bob[i]);
    printf("\n");
    return 0;
}


int Step1()
{
    int32_t x, y, a = 23, b = 11, MOD = 173;
    bool flag = false;
    for (int32_t i = 0; i < 173; i++)
    {
        int32_t tempy = (i * i) % MOD;

        for (int32_t j = 0; j < 173; j++)
        {
            int32_t tempx = ((j * j * j) % MOD + (a * j) % MOD + b) % MOD;
            if (tempx == tempy)
            {
                x = j;
                y = i;
                flag = true;
                break;
            }
        }
        if (flag == 1)
            break;
    }

    printf("x: %d y: %d", x, y);

    uint32_t alice_private, bob_private;
    printf("\nEnter the private key of Alice (between 1 and 150): ");
    scanf("%d", &alice_private);
    printf("\nEnter the private key of Bob  (between 1 and 150): ");
    scanf("%d", &bob_private);
    Step2(x, y, alice_private, bob_private);
}


int main() {
    Step1();
    return 0;
}
