package aestesting;

import static org.junit.Assert.assertTrue;

import org.junit.Test;

import aes.AES;
import aes.AES_Length;

public class AESTest {
	
	@Test
	public void AES256Check()
	{
		// This is to make sure the sample key expands like the AES standard dictates. It uses a sample key from the nist fips 197 document key expand section.
		byte[] testKey = {(byte)0x60, (byte)0x3d, (byte)0xeb, (byte)0x10, (byte)0x15, (byte)0xca, (byte)0x71, (byte)0xbe, (byte)0x2b, (byte)0x73, (byte)0xae, (byte)0xf0, (byte)0x85, (byte)0x7d, (byte)0x77, (byte)0x81, (byte)0x1f, (byte)0x35, (byte)0x2c, (byte)0x07, (byte)0x3b, (byte)0x61, (byte)0x08, (byte)0xd7, (byte)0x2d, (byte)0x98, (byte)0x10, (byte)0xa3, (byte)0x09, (byte)0x14, (byte)0xdf, (byte)0xf4};
		AES testRun = new AES(AES_Length.AES_256, testKey); // this matches the AES standard (check with breakpoint debugging).

		// create new AES key like the one used in FIPS-197 C.3.
		byte[] key = {(byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08, (byte)0x09, (byte)0x0a, (byte)0x0b, (byte)0x0c, (byte)0x0d, (byte)0x0e, (byte)0x0f, (byte)0x10, (byte)0x11, (byte)0x12, (byte)0x13, (byte)0x14, (byte)0x15, (byte)0x16, (byte)0x17, (byte)0x18, (byte)0x19, (byte)0x1a, (byte)0x1b, (byte)0x1c, (byte)0x1d, (byte)0x1e, (byte)0x1f};
		AES algorTest = new AES(AES_Length.AES_256, key);

		// This test to make sure that the encryption is correct.
		byte[] plainText1 = {(byte)0x00, (byte)0x11, (byte)0x22, (byte)0x33, (byte)0x44, (byte)0x55, (byte)0x66, (byte)0x77, (byte)0x88, (byte)0x99, (byte)0xaa, (byte)0xbb, (byte)0xcc, (byte)0xdd, (byte)0xee, (byte)0xff};
		byte[] cipherText1 = new byte[plainText1.length];
			algorTest.encrypt(plainText1, cipherText1);
			
		// Check to make sure the text message was encrypted correctly per FIPS-197 appendix C.3...	
		assertTrue(cipherText1[0] == (byte)0x8e);
		assertTrue(cipherText1[1] == (byte)0xa2);
		assertTrue(cipherText1[2] == (byte)0xb7);
		assertTrue(cipherText1[3] == (byte)0xca);
		assertTrue(cipherText1[4] == (byte)0x51);
		assertTrue(cipherText1[5] == (byte)0x67);
		assertTrue(cipherText1[6] == (byte)0x45);
		assertTrue(cipherText1[7] == (byte)0xbf);
		assertTrue(cipherText1[8] == (byte)0xea);
		assertTrue(cipherText1[9] == (byte)0xfc);
		assertTrue(cipherText1[10] == (byte)0x49);
		assertTrue(cipherText1[11] == (byte)0x90);
		assertTrue(cipherText1[12] == (byte)0x4b);
		assertTrue(cipherText1[13] == (byte)0x49);
		assertTrue(cipherText1[14] == (byte)0x60);
		assertTrue(cipherText1[15] == (byte)0x89);

		// Need to make sure the decrypted text is the same as the text we started with.
		byte[] decryptedText = new byte[cipherText1.length];
			algorTest.decrypt(cipherText1, decryptedText);
		
		for(int i =0; i<decryptedText.length;i++)
		{
			// Check to see if the decrypted text is the same as the plaintext...
			assertTrue(decryptedText[i] == plainText1[i]);
		}
	}
}
