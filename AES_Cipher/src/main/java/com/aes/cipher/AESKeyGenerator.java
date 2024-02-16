package com.aes.cipher;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class AESKeyGenerator {
	
	public static final String ALGORTIHM = "AES";
	public static final String SECRET_KEY_ALGORITHM = "PBKDF2WithHmacSHA256";
	public static final String SALT = "UTF-8";

	public static SecretKey generateKey(String password) throws NoSuchAlgorithmException, InvalidKeySpecException {
		SecretKeyFactory factory = SecretKeyFactory.getInstance(SECRET_KEY_ALGORITHM);
		KeySpec spec = new PBEKeySpec(password.toCharArray(), SALT.getBytes(), 65536, 256);
		SecretKey secret = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), ALGORTIHM);
		return secret;
	}
	
	public static SecretKey generateKeyFromFile(String filePath) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		
		Path path = Paths.get(filePath);

		byte[] keyBytes = Files.readAllBytes(path);
		return generateKey(Base64.getEncoder().encodeToString(keyBytes));
	}

}
