package aes;

// This class uses the NIST AES standard found at: http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
public class AES
{
	// Final Globals...
	private final int Nb;
	private final int Nr;
	private final int Nk;
	
	private final int[] w;
	
	private final byte[] sBox = {
			(byte) 0x63, (byte) 0x7c, (byte) 0x77, (byte) 0x7b, (byte) 0xf2, (byte) 0x6b, (byte) 0x6f, (byte) 0xc5, (byte) 0x30, (byte) 0x01, (byte) 0x67, (byte) 0x2b, (byte) 0xfe, (byte) 0xd7, (byte) 0xab, (byte) 0x76,
			(byte) 0xca, (byte) 0x82, (byte) 0xc9, (byte) 0x7d, (byte) 0xfa, (byte) 0x59, (byte) 0x47, (byte) 0xf0, (byte) 0xad, (byte) 0xd4, (byte) 0xa2, (byte) 0xaf, (byte) 0x9c, (byte) 0xa4, (byte) 0x72, (byte) 0xc0,
			(byte) 0xb7, (byte) 0xfd, (byte) 0x93, (byte) 0x26, (byte) 0x36, (byte) 0x3f, (byte) 0xf7, (byte) 0xcc, (byte) 0x34, (byte) 0xa5, (byte) 0xe5, (byte) 0xf1, (byte) 0x71, (byte) 0xd8, (byte) 0x31, (byte) 0x15,
			(byte) 0x04, (byte) 0xc7, (byte) 0x23, (byte) 0xc3, (byte) 0x18, (byte) 0x96, (byte) 0x05, (byte) 0x9a, (byte) 0x07, (byte) 0x12, (byte) 0x80, (byte) 0xe2, (byte) 0xeb, (byte) 0x27, (byte) 0xb2, (byte) 0x75,
			(byte) 0x09, (byte) 0x83, (byte) 0x2c, (byte) 0x1a, (byte) 0x1b, (byte) 0x6e, (byte) 0x5a, (byte) 0xa0, (byte) 0x52, (byte) 0x3b, (byte) 0xd6, (byte) 0xb3, (byte) 0x29, (byte) 0xe3, (byte) 0x2f, (byte) 0x84,
			(byte) 0x53, (byte) 0xd1, (byte) 0x00, (byte) 0xed, (byte) 0x20, (byte) 0xfc, (byte) 0xb1, (byte) 0x5b, (byte) 0x6a, (byte) 0xcb, (byte) 0xbe, (byte) 0x39, (byte) 0x4a, (byte) 0x4c, (byte) 0x58, (byte) 0xcf,
			(byte) 0xd0, (byte) 0xef, (byte) 0xaa, (byte) 0xfb, (byte) 0x43, (byte) 0x4d, (byte) 0x33, (byte) 0x85, (byte) 0x45, (byte) 0xf9, (byte) 0x02, (byte) 0x7f, (byte) 0x50, (byte) 0x3c, (byte) 0x9f, (byte) 0xa8,
			(byte) 0x51, (byte) 0xa3, (byte) 0x40, (byte) 0x8f, (byte) 0x92, (byte) 0x9d, (byte) 0x38, (byte) 0xf5, (byte) 0xbc, (byte) 0xb6, (byte) 0xda, (byte) 0x21, (byte) 0x10, (byte) 0xff, (byte) 0xf3, (byte) 0xd2,
			(byte) 0xcd, (byte) 0x0c, (byte) 0x13, (byte) 0xec, (byte) 0x5f, (byte) 0x97, (byte) 0x44, (byte) 0x17, (byte) 0xc4, (byte) 0xa7, (byte) 0x7e, (byte) 0x3d, (byte) 0x64, (byte) 0x5d, (byte) 0x19, (byte) 0x73,
			(byte) 0x60, (byte) 0x81, (byte) 0x4f, (byte) 0xdc, (byte) 0x22, (byte) 0x2a, (byte) 0x90, (byte) 0x88, (byte) 0x46, (byte) 0xee, (byte) 0xb8, (byte) 0x14, (byte) 0xde, (byte) 0x5e, (byte) 0x0b, (byte) 0xdb,
			(byte) 0xe0, (byte) 0x32, (byte) 0x3a, (byte) 0x0a, (byte) 0x49, (byte) 0x06, (byte) 0x24, (byte) 0x5c, (byte) 0xc2, (byte) 0xd3, (byte) 0xac, (byte) 0x62, (byte) 0x91, (byte) 0x95, (byte) 0xe4, (byte) 0x79,
			(byte) 0xe7, (byte) 0xc8, (byte) 0x37, (byte) 0x6d, (byte) 0x8d, (byte) 0xd5, (byte) 0x4e, (byte) 0xa9, (byte) 0x6c, (byte) 0x56, (byte) 0xf4, (byte) 0xea, (byte) 0x65, (byte) 0x7a, (byte) 0xae, (byte) 0x08,
			(byte) 0xba, (byte) 0x78, (byte) 0x25, (byte) 0x2e, (byte) 0x1c, (byte) 0xa6, (byte) 0xb4, (byte) 0xc6, (byte) 0xe8, (byte) 0xdd, (byte) 0x74, (byte) 0x1f, (byte) 0x4b, (byte) 0xbd, (byte) 0x8b, (byte) 0x8a,
			(byte) 0x70, (byte) 0x3e, (byte) 0xb5, (byte) 0x66, (byte) 0x48, (byte) 0x03, (byte) 0xf6, (byte) 0x0e, (byte) 0x61, (byte) 0x35, (byte) 0x57, (byte) 0xb9, (byte) 0x86, (byte) 0xc1, (byte) 0x1d, (byte) 0x9e,
			(byte) 0xe1, (byte) 0xf8, (byte) 0x98, (byte) 0x11, (byte) 0x69, (byte) 0xd9, (byte) 0x8e, (byte) 0x94, (byte) 0x9b, (byte) 0x1e, (byte) 0x87, (byte) 0xe9, (byte) 0xce, (byte) 0x55, (byte) 0x28, (byte) 0xdf,
			(byte) 0x8c, (byte) 0xa1, (byte) 0x89, (byte) 0x0d, (byte) 0xbf, (byte) 0xe6, (byte) 0x42, (byte) 0x68, (byte) 0x41, (byte) 0x99, (byte) 0x2d, (byte) 0x0f, (byte) 0xb0, (byte) 0x54, (byte) 0xbb, (byte) 0x16}; 
	// End of sBox Def

	private final byte[] invSBox = {
			(byte) 0x52, (byte) 0x09, (byte) 0x6a, (byte) 0xd5, (byte) 0x30, (byte) 0x36, (byte) 0xa5, (byte) 0x38, (byte) 0xbf, (byte) 0x40, (byte) 0xa3, (byte) 0x9e, (byte) 0x81, (byte) 0xf3, (byte) 0xd7, (byte) 0xfb,
			(byte) 0x7c, (byte) 0xe3, (byte) 0x39, (byte) 0x82, (byte) 0x9b, (byte) 0x2f, (byte) 0xff, (byte) 0x87, (byte) 0x34, (byte) 0x8e, (byte) 0x43, (byte) 0x44, (byte) 0xc4, (byte) 0xde, (byte) 0xe9, (byte) 0xcb,
			(byte) 0x54, (byte) 0x7b, (byte) 0x94, (byte) 0x32, (byte) 0xa6, (byte) 0xc2, (byte) 0x23, (byte) 0x3d, (byte) 0xee, (byte) 0x4c, (byte) 0x95, (byte) 0x0b, (byte) 0x42, (byte) 0xfa, (byte) 0xc3, (byte) 0x4e,
			(byte) 0x08, (byte) 0x2e, (byte) 0xa1, (byte) 0x66, (byte) 0x28, (byte) 0xd9, (byte) 0x24, (byte) 0xb2, (byte) 0x76, (byte) 0x5b, (byte) 0xa2, (byte) 0x49, (byte) 0x6d, (byte) 0x8b, (byte) 0xd1, (byte) 0x25,
			(byte) 0x72, (byte) 0xf8, (byte) 0xf6, (byte) 0x64, (byte) 0x86, (byte) 0x68, (byte) 0x98, (byte) 0x16, (byte) 0xd4, (byte) 0xa4, (byte) 0x5c, (byte) 0xcc, (byte) 0x5d, (byte) 0x65, (byte) 0xb6, (byte) 0x92,
			(byte) 0x6c, (byte) 0x70, (byte) 0x48, (byte) 0x50, (byte) 0xfd, (byte) 0xed, (byte) 0xb9, (byte) 0xda, (byte) 0x5e, (byte) 0x15, (byte) 0x46, (byte) 0x57, (byte) 0xa7, (byte) 0x8d, (byte) 0x9d, (byte) 0x84,
			(byte) 0x90, (byte) 0xd8, (byte) 0xab, (byte) 0x00, (byte) 0x8c, (byte) 0xbc, (byte) 0xd3, (byte) 0x0a, (byte) 0xf7, (byte) 0xe4, (byte) 0x58, (byte) 0x05, (byte) 0xb8, (byte) 0xb3, (byte) 0x45, (byte) 0x06,
			(byte) 0xd0, (byte) 0x2c, (byte) 0x1e, (byte) 0x8f, (byte) 0xca, (byte) 0x3f, (byte) 0x0f, (byte) 0x02, (byte) 0xc1, (byte) 0xaf, (byte) 0xbd, (byte) 0x03, (byte) 0x01, (byte) 0x13, (byte) 0x8a, (byte) 0x6b,
			(byte) 0x3a, (byte) 0x91, (byte) 0x11, (byte) 0x41, (byte) 0x4f, (byte) 0x67, (byte) 0xdc, (byte) 0xea, (byte) 0x97, (byte) 0xf2, (byte) 0xcf, (byte) 0xce, (byte) 0xf0, (byte) 0xb4, (byte) 0xe6, (byte) 0x73,
			(byte) 0x96, (byte) 0xac, (byte) 0x74, (byte) 0x22, (byte) 0xe7, (byte) 0xad, (byte) 0x35, (byte) 0x85, (byte) 0xe2, (byte) 0xf9, (byte) 0x37, (byte) 0xe8, (byte) 0x1c, (byte) 0x75, (byte) 0xdf, (byte) 0x6e,
			(byte) 0x47, (byte) 0xf1, (byte) 0x1a, (byte) 0x71, (byte) 0x1d, (byte) 0x29, (byte) 0xc5, (byte) 0x89, (byte) 0x6f, (byte) 0xb7, (byte) 0x62, (byte) 0x0e, (byte) 0xaa, (byte) 0x18, (byte) 0xbe, (byte) 0x1b,
			(byte) 0xfc, (byte) 0x56, (byte) 0x3e, (byte) 0x4b, (byte) 0xc6, (byte) 0xd2, (byte) 0x79, (byte) 0x20, (byte) 0x9a, (byte) 0xdb, (byte) 0xc0, (byte) 0xfe, (byte) 0x78, (byte) 0xcd, (byte) 0x5a, (byte) 0xf4,
			(byte) 0x1f, (byte) 0xdd, (byte) 0xa8, (byte) 0x33, (byte) 0x88, (byte) 0x07, (byte) 0xc7, (byte) 0x31, (byte) 0xb1, (byte) 0x12, (byte) 0x10, (byte) 0x59, (byte) 0x27, (byte) 0x80, (byte) 0xec, (byte) 0x5f,
			(byte) 0x60, (byte) 0x51, (byte) 0x7f, (byte) 0xa9, (byte) 0x19, (byte) 0xb5, (byte) 0x4a, (byte) 0x0d, (byte) 0x2d, (byte) 0xe5, (byte) 0x7a, (byte) 0x9f, (byte) 0x93, (byte) 0xc9, (byte) 0x9c, (byte) 0xef,
			(byte) 0xa0, (byte) 0xe0, (byte) 0x3b, (byte) 0x4d, (byte) 0xae, (byte) 0x2a, (byte) 0xf5, (byte) 0xb0, (byte) 0xc8, (byte) 0xeb, (byte) 0xbb, (byte) 0x3c, (byte) 0x83, (byte) 0x53, (byte) 0x99, (byte) 0x61,
			(byte) 0x17, (byte) 0x2b, (byte) 0x04, (byte) 0x7e, (byte) 0xba, (byte) 0x77, (byte) 0xd6, (byte) 0x26, (byte) 0xe1, (byte) 0x69, (byte) 0x14, (byte) 0x63, (byte) 0x55, (byte) 0x21, (byte) 0x0c, (byte) 0x7d }; 
	// End of invSBox Def
	
	private final int[] Rcon = {0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000};
	
	// Globals allocated here for speed...
	byte[][] state = new byte[4][4];
	byte[][] invState = new byte[4][4];
	
	//
	// End of all globals...
	//
	
	public AES(AES_Length algorithm, byte[] key)
	{
		Nb = algorithm.Nb();
		Nr = algorithm.Nr();
		Nk = algorithm.Nk();
		
		w = new int[Nb * (Nr + 1)];
		KeyExpansion(key);
	}
	
	public void decrypt(byte[] in, byte[] out)
	{
		// Copy input to state.
		invState[0][0] = in[0];
		invState[1][0] = in[1];
		invState[2][0] = in[2];
		invState[3][0] = in[3];
		invState[0][1] = in[4];
		invState[1][1] = in[5];
		invState[2][1] = in[6];
		invState[3][1] = in[7];
		invState[0][2] = in[8];
		invState[1][2] = in[9];
		invState[2][2] = in[10];
		invState[3][2] = in[11];
		invState[0][3] = in[12];
		invState[1][3] = in[13];
		invState[2][3] = in[14];
		invState[3][3] = in[15];
		
		// Round Nr
		addRoundKey(invState, Nr);
		
		if(Nr > 10)
		{
			if(Nr > 12)
			{
				// Round 13
				invShiftRows(invState);
				invSubBytes(invState);
				addRoundKey(invState, 13);
				invMixColumns(invState);
				
				// Round 12
				invShiftRows(invState);
				invSubBytes(invState);
				addRoundKey(invState, 12);
				invMixColumns(invState);
			}
			
			// Round 11
			invShiftRows(invState);
			invSubBytes(invState);
			addRoundKey(invState, 11);
			invMixColumns(invState);
			
			// Round 10
			invShiftRows(invState);
			invSubBytes(invState);
			addRoundKey(invState, 10);
			invMixColumns(invState);
		}
		
		// Round 9
		invShiftRows(invState);
		invSubBytes(invState);
		addRoundKey(invState, 9);
		invMixColumns(invState);
		
		// Round 8
		invShiftRows(invState);
		invSubBytes(invState);
		addRoundKey(invState, 8);
		invMixColumns(invState);
		
		// Round 7
		invShiftRows(invState);
		invSubBytes(invState);
		addRoundKey(invState, 7);
		invMixColumns(invState);
		
		// Round 6
		invShiftRows(invState);
		invSubBytes(invState);
		addRoundKey(invState, 6);
		invMixColumns(invState);
		
		// Round 5
		invShiftRows(invState);
		invSubBytes(invState);
		addRoundKey(invState, 5);
		invMixColumns(invState);
		
		// Round 4
		invShiftRows(invState);
		invSubBytes(invState);
		addRoundKey(invState, 4);
		invMixColumns(invState);
		
		// Round 3
		invShiftRows(invState);
		invSubBytes(invState);
		addRoundKey(invState, 3);
		invMixColumns(invState);
		
		// Round 2
		invShiftRows(invState);
		invSubBytes(invState);
		addRoundKey(invState, 2);
		invMixColumns(invState);
		
		// Round 1
		invShiftRows(invState);
		invSubBytes(invState);
		addRoundKey(invState, 1);
		invMixColumns(invState);

		// Round 0
		invShiftRows(invState);
		invSubBytes(invState);
		addRoundKey(invState, 0);
		
		// Copy state to the out array.
		out[0] = invState[0][0];
		out[1] = invState[1][0];
		out[2] = invState[2][0];
		out[3] = invState[3][0];
		out[4] = invState[0][1];
		out[5] = invState[1][1];
		out[6] = invState[2][1];
		out[7] = invState[3][1];
		out[8] = invState[0][2];
		out[9] = invState[1][2];
		out[10] = invState[2][2];
		out[11] = invState[3][2];
		out[12] = invState[0][3];
		out[13] = invState[1][3];
		out[14] = invState[2][3];
		out[15] = invState[3][3];
	}
	
	private void invShiftRows(byte[][] pState)
	{
		// row 1
		byte temp = pState[1][0];
		pState[1][0] = pState[1][3];
		pState[1][3] = pState[1][2];
		pState[1][2] = pState[1][1];
		pState[1][1] = temp;
		
		// row 2
		temp = pState[2][0];
		pState[2][0] = pState[2][2];
		pState[2][2] = temp;
		temp = pState[2][1];
		pState[2][1] = pState[2][3];
		pState[2][3] = temp;
		
		// row 3
		temp = pState[3][0];
		pState[3][0] = pState[3][1];
		pState[3][1] = pState[3][2];
		pState[3][2] = pState[3][3];
		pState[3][3] = temp;
	}
	
	// This subBytes method uses a table of calculated values in sBox to speed this method up.
	private void invSubBytes(byte[][] pState)
	{
		pState[0][0] = invSBox[pState[0][0] & 0xFF];
		pState[1][0] = invSBox[pState[1][0] & 0xFF];
		pState[2][0] = invSBox[pState[2][0] & 0xFF];
		pState[3][0] = invSBox[pState[3][0] & 0xFF];
		pState[0][1] = invSBox[pState[0][1] & 0xFF];
		pState[1][1] = invSBox[pState[1][1] & 0xFF];
		pState[2][1] = invSBox[pState[2][1] & 0xFF];
		pState[3][1] = invSBox[pState[3][1] & 0xFF];
		pState[0][2] = invSBox[pState[0][2] & 0xFF];
		pState[1][2] = invSBox[pState[1][2] & 0xFF];
		pState[2][2] = invSBox[pState[2][2] & 0xFF];
		pState[3][2] = invSBox[pState[3][2] & 0xFF];
		pState[0][3] = invSBox[pState[0][3] & 0xFF];
		pState[1][3] = invSBox[pState[1][3] & 0xFF];
		pState[2][3] = invSBox[pState[2][3] & 0xFF];
		pState[3][3] = invSBox[pState[3][3] & 0xFF];
	}
	
	private void invMixColumns(byte[][] pState)
	{
			// column 0
			byte s0 = pState[0][0];
			byte s1 = pState[1][0];
			byte s2 = pState[2][0];
			byte s3 = pState[3][0];
			pState[0][0] = (byte) (multiply((byte)0x0e, s0)^multiply((byte)0x0b, s1)^multiply((byte)0x0d, s2)^multiply((byte)0x09, s3));
			pState[1][0] = (byte) (multiply((byte)0x09, s0)^multiply((byte)0x0e, s1)^multiply((byte)0x0b, s2)^multiply((byte)0x0d, s3));
			pState[2][0] = (byte) (multiply((byte)0x0d, s0)^multiply((byte)0x09, s1)^multiply((byte)0x0e, s2)^multiply((byte)0x0b, s3));
			pState[3][0] = (byte) (multiply((byte)0x0b, s0)^multiply((byte)0x0d, s1)^multiply((byte)0x09, s2)^multiply((byte)0x0e, s3));
			
			// column 1
			s0 = pState[0][1];
			s1 = pState[1][1];
			s2 = pState[2][1];
			s3 = pState[3][1];
			pState[0][1] = (byte) (multiply((byte)0x0e, s0)^multiply((byte)0x0b, s1)^multiply((byte)0x0d, s2)^multiply((byte)0x09, s3));
			pState[1][1] = (byte) (multiply((byte)0x09, s0)^multiply((byte)0x0e, s1)^multiply((byte)0x0b, s2)^multiply((byte)0x0d, s3));
			pState[2][1] = (byte) (multiply((byte)0x0d, s0)^multiply((byte)0x09, s1)^multiply((byte)0x0e, s2)^multiply((byte)0x0b, s3));
			pState[3][1] = (byte) (multiply((byte)0x0b, s0)^multiply((byte)0x0d, s1)^multiply((byte)0x09, s2)^multiply((byte)0x0e, s3));
			
			// column 2
			s0 = pState[0][2];
			s1 = pState[1][2];
			s2 = pState[2][2];
			s3 = pState[3][2];
			pState[0][2] = (byte) (multiply((byte)0x0e, s0)^multiply((byte)0x0b, s1)^multiply((byte)0x0d, s2)^multiply((byte)0x09, s3));
			pState[1][2] = (byte) (multiply((byte)0x09, s0)^multiply((byte)0x0e, s1)^multiply((byte)0x0b, s2)^multiply((byte)0x0d, s3));
			pState[2][2] = (byte) (multiply((byte)0x0d, s0)^multiply((byte)0x09, s1)^multiply((byte)0x0e, s2)^multiply((byte)0x0b, s3));
			pState[3][2] = (byte) (multiply((byte)0x0b, s0)^multiply((byte)0x0d, s1)^multiply((byte)0x09, s2)^multiply((byte)0x0e, s3));
			
			// column 3
			s0 = pState[0][3];
			s1 = pState[1][3];
			s2 = pState[2][3];
			s3 = pState[3][3];
			pState[0][3] = (byte) (multiply((byte)0x0e, s0)^multiply((byte)0x0b, s1)^multiply((byte)0x0d, s2)^multiply((byte)0x09, s3));
			pState[1][3] = (byte) (multiply((byte)0x09, s0)^multiply((byte)0x0e, s1)^multiply((byte)0x0b, s2)^multiply((byte)0x0d, s3));
			pState[2][3] = (byte) (multiply((byte)0x0d, s0)^multiply((byte)0x09, s1)^multiply((byte)0x0e, s2)^multiply((byte)0x0b, s3));
			pState[3][3] = (byte) (multiply((byte)0x0b, s0)^multiply((byte)0x0d, s1)^multiply((byte)0x09, s2)^multiply((byte)0x0e, s3));
	}
	
	// This is the AES encryption algorithm.
	public void encrypt(byte[] in, byte[] out)
	{
		// Copy input to state.
		state[0][0] = in[0];
		state[1][0] = in[1];
		state[2][0] = in[2];
		state[3][0] = in[3];
		state[0][1] = in[4];
		state[1][1] = in[5];
		state[2][1] = in[6];
		state[3][1] = in[7];
		state[0][2] = in[8];
		state[1][2] = in[9];
		state[2][2] = in[10];
		state[3][2] = in[11];
		state[0][3] = in[12];
		state[1][3] = in[13];
		state[2][3] = in[14];
		state[3][3] = in[15];
		
		// Round 0
		addRoundKey(state, 0);
		
		// Round 1
		subBytes(state);
		shiftRows(state);
		mixColumns(state);
		addRoundKey(state, 1);
		
		// Round 2
		subBytes(state);
		shiftRows(state);
		mixColumns(state);
		addRoundKey(state, 2);
				
		// Round 3
		subBytes(state);
		shiftRows(state);
		mixColumns(state);
		addRoundKey(state, 3);
		
		// Round 4
		subBytes(state);
		shiftRows(state);
		mixColumns(state);
		addRoundKey(state, 4);
		
		// Round 5
		subBytes(state);
		shiftRows(state);
		mixColumns(state);
		addRoundKey(state, 5);
		
		// Round 6
		subBytes(state);
		shiftRows(state);
		mixColumns(state);
		addRoundKey(state, 6);
		
		// Round 7
		subBytes(state);
		shiftRows(state);
		mixColumns(state);
		addRoundKey(state, 7);
		
		// Round 8
		subBytes(state);
		shiftRows(state);
		mixColumns(state);
		addRoundKey(state, 8);
		
		// Round 9
		subBytes(state);
		shiftRows(state);
		mixColumns(state);
		addRoundKey(state, 9);
		
		if(Nr > 10)
		{
			// Round 10
			subBytes(state);
			shiftRows(state);
			mixColumns(state);
			addRoundKey(state, 10);
			
			// Round 11
			subBytes(state);
			shiftRows(state);
			mixColumns(state);
			addRoundKey(state, 11);
			
			if(Nr > 12)
			{
				// Round 12
				subBytes(state);
				shiftRows(state);
				mixColumns(state);
				addRoundKey(state, 12);
				
				// Round 13
				subBytes(state);
				shiftRows(state);
				mixColumns(state);
				addRoundKey(state, 13);
			}
		}

		// Round Nr
		subBytes(state);
		shiftRows(state);
		addRoundKey(state, Nr);
		
		// Copy state to the out array.
		out[0] = state[0][0];
		out[1] = state[1][0];
		out[2] = state[2][0];
		out[3] = state[3][0];
		out[4] = state[0][1];
		out[5] = state[1][1];
		out[6] = state[2][1];
		out[7] = state[3][1];
		out[8] = state[0][2];
		out[9] = state[1][2];
		out[10] = state[2][2];
		out[11] = state[3][2];
		out[12] = state[0][3];
		out[13] = state[1][3];
		out[14] = state[2][3];
		out[15] = state[3][3];
	}

	// This subBytes method uses a table of calculated values in sBox to speed this method up.
	private void subBytes(byte[][] pState)
	{
		pState[0][0] = sBox[pState[0][0] & 0xFF];
		pState[1][0] = sBox[pState[1][0] & 0xFF];
		pState[2][0] = sBox[pState[2][0] & 0xFF];
		pState[3][0] = sBox[pState[3][0] & 0xFF];
		pState[0][1] = sBox[pState[0][1] & 0xFF];
		pState[1][1] = sBox[pState[1][1] & 0xFF];
		pState[2][1] = sBox[pState[2][1] & 0xFF];
		pState[3][1] = sBox[pState[3][1] & 0xFF];
		pState[0][2] = sBox[pState[0][2] & 0xFF];
		pState[1][2] = sBox[pState[1][2] & 0xFF];
		pState[2][2] = sBox[pState[2][2] & 0xFF];
		pState[3][2] = sBox[pState[3][2] & 0xFF];
		pState[0][3] = sBox[pState[0][3] & 0xFF];
		pState[1][3] = sBox[pState[1][3] & 0xFF];
		pState[2][3] = sBox[pState[2][3] & 0xFF];
		pState[3][3] = sBox[pState[3][3] & 0xFF];
	}
	
	private void shiftRows(byte[][] pState)
	{
		// row 1
		byte temp = pState[1][0];
		pState[1][0] = pState[1][1];
		pState[1][1] = pState[1][2];
		pState[1][2] = pState[1][3];
		pState[1][3] = temp;
		
		// row 2
		temp = pState[2][0];
		pState[2][0] = pState[2][2];
		pState[2][2] = temp;
		temp = pState[2][1];
		pState[2][1] = pState[2][3];
		pState[2][3] = temp;
		
		// row 3
		temp = pState[3][0];
		pState[3][0] = pState[3][3];
		pState[3][3] = pState[3][2];
		pState[3][2] = pState[3][1];
		pState[3][1] = temp;
	}
	
	private void mixColumns(byte[][] pState)
	{
			// column 0
			byte s0 = pState[0][0];
			byte s1 = pState[1][0];
			byte s2 = pState[2][0];
			byte s3 = pState[3][0];
			pState[0][0] = (byte) (multiply((byte)0x02, s0)^multiply((byte)0x03, s1)^s2^s3);
			pState[1][0] = (byte) (s0^multiply((byte)0x02, s1)^multiply((byte)0x03, s2)^s3);
			pState[2][0] = (byte) (s0^s1^multiply((byte)0x02, s2)^multiply((byte)0x03, s3));
			pState[3][0] = (byte) (multiply((byte)0x03, s0)^s1^s2^multiply((byte)0x02, s3));
			
			// column 1
			s0 = pState[0][1];
			s1 = pState[1][1];
			s2 = pState[2][1];
			s3 = pState[3][1];
			pState[0][1] = (byte) (multiply((byte)0x02, s0)^multiply((byte)0x03, s1)^s2^s3);
			pState[1][1] = (byte) (s0^multiply((byte)0x02, s1)^multiply((byte)0x03, s2)^s3);
			pState[2][1] = (byte) (s0^s1^multiply((byte)0x02, s2)^multiply((byte)0x03, s3));
			pState[3][1] = (byte) (multiply((byte)0x03, s0)^s1^s2^multiply((byte)0x02, s3));
			
			// column 2
			s0 = pState[0][2];
			s1 = pState[1][2];
			s2 = pState[2][2];
			s3 = pState[3][2];
			pState[0][2] = (byte) (multiply((byte)0x02, s0)^multiply((byte)0x03, s1)^s2^s3);
			pState[1][2] = (byte) (s0^multiply((byte)0x02, s1)^multiply((byte)0x03, s2)^s3);
			pState[2][2] = (byte) (s0^s1^multiply((byte)0x02, s2)^multiply((byte)0x03, s3));
			pState[3][2] = (byte) (multiply((byte)0x03, s0)^s1^s2^multiply((byte)0x02, s3));
			
			// column 3
			s0 = pState[0][3];
			s1 = pState[1][3];
			s2 = pState[2][3];
			s3 = pState[3][3];
			pState[0][3] = (byte) (multiply((byte)0x02, s0)^multiply((byte)0x03, s1)^s2^s3);
			pState[1][3] = (byte) (s0^multiply((byte)0x02, s1)^multiply((byte)0x03, s2)^s3);
			pState[2][3] = (byte) (s0^s1^multiply((byte)0x02, s2)^multiply((byte)0x03, s3));
			pState[3][3] = (byte) (multiply((byte)0x03, s0)^s1^s2^multiply((byte)0x02, s3));
	}
	
	private void addRoundKey(byte[][] pState, int round)
	{
		// column 0
		int word = w[round*Nb];
		pState[0][0] ^= (byte) (word >> 24);
		pState[1][0] ^= (byte) (word >> 16);
		pState[2][0] ^= (byte) (word >> 8);
		pState[3][0] ^= (byte) (word);
			
		// column 1
		word = w[round*Nb + 1];
		pState[0][1] ^= (byte) (word >> 24);
		pState[1][1] ^= (byte) (word >> 16);
		pState[2][1] ^= (byte) (word >> 8);
		pState[3][1] ^= (byte) (word);
			
		// column 2
		word = w[round*Nb + 2];
		pState[0][2] ^= (byte) (word >> 24);
		pState[1][2] ^= (byte) (word >> 16);
		pState[2][2] ^= (byte) (word >> 8);
		pState[3][2] ^= (byte) (word);
			
		// column 3
		word = w[round*Nb + 3];
		pState[0][3] ^= (byte) (word >> 24);
		pState[1][3] ^= (byte) (word >> 16);
		pState[2][3] ^= (byte) (word >> 8);
		pState[3][3] ^= (byte) (word);
	}

	// This is a function that is defined in the AES standard to multiply two bytes in F(2^8). This is the slow version.
	private byte multiply(byte a, byte b)
	{
		byte p =0;
		byte counter;
		byte hi_bit_set;
		
		for(counter = 0; counter < 8; counter++)
		{
			if((b&1) != 0)
			{
				p ^= a;
			}
			
			hi_bit_set = (byte) (a & 0x80);
			a <<= 1;
			
			if(hi_bit_set != 0)
			{
				a ^= 0x1b;
			}
			b >>>= 1;
		}
		
		return p;
	}
	
	// Key Expansion as described in fips-197 standard
	private void KeyExpansion(byte[] key)
	{
		int temp;
		int i = 0;
		
		while (i < Nk)
		{
			w[i] = (int)(((key[4*i] & 0xFF) << 24) | ((key[4*i+1] & 0xFF) << 16) | ((key[4*i+2] & 0xFF) << 8) | (key[4*i+3]& 0xFF));
			i++;
		}
		
		i = Nk;

		while (i < Nb * (Nr + 1))
		{
			temp = w[i-1];
			if(i % Nk == 0)
			{
				temp = SubWord(RotWord(temp)) ^ Rcon[i/Nk-1];
			}
			else if(Nk > 6 && (i % Nk == 4))
			{
				temp = SubWord(temp);
			}
			
			w[i] = w[i-Nk] ^ temp;
			i++;
		}
	}
	
	// Private method needed by Key Expansion
	private int SubWord(int pWord)
	{
		return (int)((sBox[(pWord >> 24) & 0xFF] & 0xFF) << 24 |
				(sBox[(pWord >> 16) & 0xFF] & 0xFF) << 16 |
				(sBox[(pWord >> 8) & 0xFF] & 0xFF) << 8 |
				sBox[pWord & 0xFF] & 0xFF);
	}
	
	// Private method needed by Key Expansion
	private int RotWord(int pWord)
	{
		return ((((pWord & 0xFFFFFFFF) >> 24) & 0xFF) ^ (pWord << 8));
	}
}