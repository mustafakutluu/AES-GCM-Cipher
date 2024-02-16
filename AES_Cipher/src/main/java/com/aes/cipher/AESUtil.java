package com.aes.cipher;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

/**
 * 
 * @author mustafa.kutlu
 * @version 44
 *
 */

public class AESUtil {
	
	public static final int GCM_IV_LENGTH = 16;
	public static final int GCM_T_LENGTH = 12;
	public static final String CIPHER_ALGORTIHM = "AES/GCM/PKCS5Padding";

	public static byte[] encryptToByte(String input, SecretKey key) throws BadPaddingException, IllegalBlockSizeException,
			InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		Cipher cipher = Cipher.getInstance(CIPHER_ALGORTIHM);
		cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_T_LENGTH, new byte[GCM_IV_LENGTH]));
		return cipher.doFinal(input.getBytes());
	}

	public static String encrypt(String input, String password) throws NoSuchPaddingException, NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException {

		SecretKey key = AESKeyGenerator.generateKey(password);

		return Base64.getEncoder().encodeToString(encryptToByte(input, key));
	}

	public static String encrypt(String data, SecretKey key) throws BadPaddingException, IllegalBlockSizeException,
			InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {

		return Base64.getEncoder().encodeToString(encryptToByte(data, key));
	}

	public static boolean isEncrypted(String encrypted, String base64Key) {
		try {
			decrypt(Base64.getDecoder().decode(encrypted), AESKeyGenerator.generateKey(base64Key));
			return true;
		} catch (Exception e) {
			return false;
		}
	}

	public static boolean isEncrypted(String encrypted, SecretKey key) {
		try {
			decrypt(Base64.getDecoder().decode(encrypted), key);
			return true;
		} catch (Exception e) {
			return false;
		}
	}

	private static String decrypt(byte[] data, SecretKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
			BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {

		Cipher cipher = Cipher.getInstance(CIPHER_ALGORTIHM);
		cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_T_LENGTH, new byte[GCM_IV_LENGTH]));
		return new String(cipher.doFinal(data));

	}

	public static String decrypt(String data, String base64Key)
			throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
		String decryptValue;
		try {
			decryptValue = decrypt(Base64.getDecoder().decode(data), AESKeyGenerator.generateKey(base64Key));
		} catch (Exception e) {
			decryptValue = data;
		}
		return decryptValue;
	}

	public static String decrypt(String data, SecretKey key)
			throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
		try {
			return decrypt(Base64.getDecoder().decode(data), key);
		} catch (Exception e) {
			return data;
		}

	}
	
	//https://www.baeldung.com/java-aes-encryption-decryption
	
//	public static void encryptFile(String algorithm, SecretKey key, IvParameterSpec iv, File inputFile, File outputFile)
//			throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException,
//			IllegalBlockSizeException {
//
//		Cipher cipher = Cipher.getInstance(algorithm);
//		cipher.init(Cipher.ENCRYPT_MODE, key, iv);
//		FileInputStream inputStream = new FileInputStream(inputFile);
//		FileOutputStream outputStream = new FileOutputStream(outputFile);
//		byte[] buffer = new byte[64];
//		int bytesRead;
//		while ((bytesRead = inputStream.read(buffer)) != -1) {
//			byte[] output = cipher.update(buffer, 0, bytesRead);
//			if (output != null) {
//				outputStream.write(output);
//			}
//		}
//		byte[] outputBytes = cipher.doFinal();
//		if (outputBytes != null) {
//			outputStream.write(outputBytes);
//		}
//		inputStream.close();
//		outputStream.close();
//	}
}