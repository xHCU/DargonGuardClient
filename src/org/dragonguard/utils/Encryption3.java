package org.dragonguard.utils;

import java.util.Base64;

import org.dragonguard.KeyXor2;

public class Encryption3 {

	public byte[] xor(byte[] key) {
		int len = key.length;
		int[] xorkey = new KeyXor2().Key;
		int keyLen = xorkey.length;

		byte[] result = new byte[len];
		for(int i=0;i<len;i++) {
			result[i] = (byte)(key[i] ^ xorkey[i % keyLen]);
		}
		return result;
	}
	
	public String encryptXORBase64(String s) {
		return Base64.getEncoder().encodeToString(xor(s.getBytes()));
	}

	public String decryptXORBase64(String s) {
		return new String(xor(Base64.getDecoder().decode(s)));
	}
	
	public String XOR(String s) {
    	return new String(xor(s.getBytes()));
    }
}
