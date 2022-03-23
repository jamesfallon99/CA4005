//As stated in the declaration provided, the code was wrote by me - James Fallon.
//I have stated in the comments what sources I used to help complete this assignment

import java.math.BigInteger;
import java.security.*;
import java.nio.charset.StandardCharsets; //used to encode in utf-8
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Random; //used to generate a random salt
import java.io.ByteArrayOutputStream; //used for concatenating byte arrays
import java.io.FileNotFoundException;
import java.io.IOException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.PrintWriter;


public class Assignment1 implements Assignment1Interface {

    public static void main(String[] args) throws NoSuchAlgorithmException, FileNotFoundException{
        Assignment1 assignment1 = new Assignment1();
        String password = "5s@>j=23Hxk/k2A$"; //strong password
        byte[] encodedPassword = assignment1.encodePassword(password); //encode password using UTF-8

        byte[] salt = assignment1.generate128BitValue(); //Generate a random salt value

        BigInteger saltBigInteger = new BigInteger(1, salt); //convert the salt to a big integer (this allows to easily convert to hexadecimal for outputting to a file)
        //converts bigInteger to string - used this site for help https://www.baeldung.com/java-byte-arrays-hex-strings
        
        PrintWriter saltToFile = new PrintWriter("Salt.txt"); //open the salt.txt file
        saltToFile.println(saltBigInteger.toString(16)); //write the salt in hexademical to the file salt.txt
        saltToFile.close(); //close the file
        
        byte[] hashedKey = assignment1.generateKey(encodedPassword, salt); //Generate the hashed key by concatenating the password and salt together and hashing 200 times using SHA-256

        byte[] iv = assignment1.generate128BitValue(); //Generate a random iv value
        BigInteger ivBigInteger = new BigInteger(1, iv); //convert to BigInteger in order to write out to file in hex

        PrintWriter ivToFile = new PrintWriter("IV.txt"); //open iv.txt file
        ivToFile.println(ivBigInteger.toString(16)); //write out to file in hex
        ivToFile.close(); //close the file

        try{ //https://howtodoinjava.com/java/io/read-file-content-into-byte-array/ used this site to help convert the plaintext to a byte array.
        
        Path path = Paths.get(args[0]); //The input binary file will be the Java class file resulting from compiling your program
        //try reading the file from the command line
        byte[] data = Files.readAllBytes(path); //Convert the file into an array of bytes

        byte[] encryptedFile = assignment1.encryptAES(data, iv, hashedKey); //Encrypt the file using AES
        BigInteger encryptedFileBigInteger = new BigInteger(1, encryptedFile); //Convert to a BigInteger in order to convert to hex

        System.out.print(encryptedFileBigInteger.toString(16)); //this is necessary as the assignment wants to output to standard output the result of encrypting this file in hex

        // PrintWriter encryptAESToFile = new PrintWriter("Encryption.txt");
        // encryptAESToFile.println(encryptedFileBigInteger.toString(16));
        // encryptAESToFile.close();
        //Didn't need this as outputting to file via standard out
        
       
        //byte[] decryptedFile = assignment1.decryptAES(encryptedFile, iv, hashedKey); //after testing decrypt, it works and decrypts the encrypted text back to the original This also removes the padding we originally put in
        }

        catch(IOException e){
            System.out.println("An error occurred");
        }

        //public modulus
        String publicModulus = "c406136c12640a665900a9df4df63a84fc855927b729a3a106fb3f379e8e4190ebba442f67b93402e535b18a5777e6490e67dbee954bb02175e43b6481e7563d3f9ff338f07950d1553ee6c343d3f8148f71b4d2df8da7efb39f846ac07c865201fbb35ea4d71dc5f858d9d41aaa856d50dc2d2732582f80e7d38c32aba87ba9";
        
        //convert public modulus to bigInteger
        BigInteger modulus = new BigInteger(publicModulus, 16);//The radix is 16 and this will convert the BigInteger to hexadecimal - https://www.geeksforgeeks.org/biginteger-tostring-method-in-java/

        //exponent
        BigInteger exp = new BigInteger("65537");

        byte[] RSAPassword = assignment1.encryptRSA(encodedPassword, exp, modulus); //encrypt encoded password using RSA. This takes the encryption exponent given in the assignment spec and his public modulus
        
        BigInteger RSAPasswordBigInteger = new BigInteger(1, RSAPassword); // convert to BigInteger

        PrintWriter RSAPasswordToFile = new PrintWriter("Password.txt"); //open Password.txt
        RSAPasswordToFile.println(RSAPasswordBigInteger.toString(16));//write to file in hex
        RSAPasswordToFile.close(); //close file

    }
    /* Method generateKey returns the key as an array of bytes and is generated from the given password and salt. */
	public byte[] generateKey(byte[] password, byte[] salt){

        byte[] hashedKeySHA256 = new byte[32];

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream(); //Create an byte array output stream
        //https://stackoverflow.com/questions/5513152/easy-way-to-concatenate-two-byte-arrays used this site to help understand how to concatenate two byte arrays
        try{
            outputStream.write(password); //write the password to this output stream
            outputStream.write(salt); //the salt will be written after the password concatenating the two

        byte[] concatenatePasswordAndSalt = outputStream.toByteArray(); //convert to a byte array
        
        //learned how to use SHA-256 from https://www.geeksforgeeks.org/sha-256-hash-in-java/
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256"); //The message digest class provides the SHA-256 hash function
        hashedKeySHA256 = concatenatePasswordAndSalt; //hashedKeySHA256 will be our resulting array

        for(int i=0; i<200; i++){ //hash the key 200 times using SHA-256
            hashedKeySHA256 = messageDigest.digest(hashedKeySHA256); //calculate the digest and return in a byte array
        }

        }
        catch(NoSuchAlgorithmException |IOException error){
            System.out.println("An error occurred");
        }

        return hashedKeySHA256;
        
    }

		
    /* Method encryptAES returns the AES encryption of the given plaintext as an array of bytes using the given iv and key */  
	public byte[] encryptAES(byte[] plaintext, byte[] iv, byte[] key){
        byte[] encrytedBytes = new byte[16];

        try{//https://docs.oracle.com/javase/7/docs/api/javax/crypto/Cipher.html - This site helped understand how to encrypt and decrypt using the Cipher class

            Key AESKey = new SecretKeySpec(key, "AES");
            IvParameterSpec initialisationVector = new IvParameterSpec(iv);//https://docs.oracle.com/javase/7/docs/api/javax/crypto/spec/IvParameterSpec.html - This gave me an understanding of IvParameterSpec

            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            
            int amountToPad = AmountOfPadding(plaintext); //Get the amount of padding needed

            byte[] paddedFile = paddingFile(plaintext, amountToPad); //pad the file before encryption

            cipher.init(Cipher.ENCRYPT_MODE, AESKey, initialisationVector);
            //System.out.println(cipher.getBlockSize()); - Block size is 16 bytes which is 128 bits
            encrytedBytes = cipher.doFinal(paddedFile); //encrypt the file using AES and store result in a byte array

        }
        catch(NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException| NoSuchPaddingException| InvalidAlgorithmParameterException| InvalidKeyException error) //https://stackoverflow.com/questions/3495926/can-i-catch-multiple-java-exceptions-in-the-same-catch-clause - Didn't know how to catch multiple exceptions
        { 
            System.out.println("An error occurred");
        }

        return encrytedBytes;
    }
		
    /* Method decryptAES returns the AES decryption of the given ciphertext as an array of bytes using the given iv and key */
    public byte[] decryptAES(byte[] ciphertext, byte[] iv, byte[] key){ //Similar to encryption but we just pass through the encrypted text and select DECRYPT_MODE
        byte[] decrypted = new byte[16];
        
        try{

        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        Key AESKey = new SecretKeySpec(key, "AES");
        IvParameterSpec initialisationVector = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, AESKey, initialisationVector); //cipher.init takes a AESKey of type Key and iv of type IvParameterSpec
        decrypted = cipher.doFinal(ciphertext); //return the descrypted bytes and stores in a byte array
        
        }

        catch(NoSuchPaddingException | NoSuchAlgorithmException |InvalidKeyException |InvalidAlgorithmParameterException |IllegalBlockSizeException|BadPaddingException error){

        }
        //Need to remove the padding once we get the descrypted bytes
        int indexWherePaddingBegins = 0;
        for(int i=decrypted.length -1; i>=0; i--){ //Loop through the decrypted array starting from the end of the array and if it finds a 1 bit we know this is where the padding starts.
            if(decrypted[i] == (byte) 1){
                indexWherePaddingBegins = i; //get the position of the start of the padding so we can use it later
                break;
            }
        }
        int amountOfPaddingToTakeAway = decrypted.length - indexWherePaddingBegins; //Get the amount of padding to take away from the decrypted 
        
        byte[] decryptedWithNoPadding = new byte[decrypted.length - amountOfPaddingToTakeAway]; //Create a new array that will store the decrypted file without the padding that we had initially put on to it
        System.arraycopy(decrypted, 0, decryptedWithNoPadding, 0, decrypted.length - amountOfPaddingToTakeAway); //Copy the decrypted file to this new array without the padding
        
        return decryptedWithNoPadding;
    }
				
    /* Method encryptRSA returns the encryption of the given plaintext using the given encryption exponent and modulus */
    public byte[] encryptRSA(byte[] plaintext, BigInteger exponent, BigInteger modulus){
        BigInteger password = new BigInteger(plaintext); //convert the plaintext password into a BigInteger
        BigInteger encryptedPassword = modExp(password, exponent, modulus); //Pass through the password, exponent and modulus to get the modular expoentiation

        byte[] RSAPassword = encryptedPassword.toByteArray(); //convert to a byte array (Converting BigInteger values to an array of bytes incorrectly - note that the BigInteger method toByteArray() uses a twos complement representation and may add an extra leading zero-valued byte if the first bit is set. )
        //Removing the leading 0 bit if present in the array
        byte[] RSAPasswordRemoveLeadingZero = new byte[RSAPassword.length-1];
        if(RSAPassword[0] == (byte) 0){
            System.arraycopy(RSAPassword, 1, RSAPasswordRemoveLeadingZero, 0, RSAPassword.length -1); //Copy the array, the length is one less than RSAPassword's length. Start copying from position 1 as we don't want the leading 0
            return RSAPasswordRemoveLeadingZero;
        }
        return RSAPassword;

    }
	 
    /* Method modExp returns the result of raising the given base to the power of the given exponent using the given modulus */ 
    public BigInteger modExp(BigInteger base, BigInteger exponent, BigInteger modulus){
        String binaryExp = exponent.toString(2); //convert the exponent to binary - based off of notes
       /*
        password is the base (p)
        exponent (e)
        modulus (N)
        p^e (mod N)

        y is 1 initially
        From Notes, the right to left modular exponentiation is:

        y = 1
        for i = 0 to k-1 do 
	    if xi = 1 then y = (y*a) mod n end if
	    a = (a*a) mod n
        end for
        
        if the bit is 1, then base * y (mod n)
        otherwise, base * base (mod n)
        */
        BigInteger y = new BigInteger("1");
        for(int i=0; i< binaryExp.length(); i++){
            if(binaryExp.charAt(i) == '1'){
                y = (y.multiply(base)).mod(modulus);
            }
            base = (base.multiply(base)).mod(modulus);
        }
        return y;
    }

    public byte[] encodePassword(String password){
        //"The password you use should be encoded using UTF-8"
        byte[] encodedPassword = password.getBytes(StandardCharsets.UTF_8); //encoding password using UTF-8
        return encodedPassword;
        //https://www.baeldung.com/java-string-encode-utf-8 - used this site to help understand how to encode in UTF-8
    }

    public byte[] generate128BitValue(){
        Random randomValue = new SecureRandom();
        byte[] rValue = new byte[16]; //There's 128 bits in 16 bytes (128/8)
        randomValue.nextBytes(rValue);
        return rValue;
        //https://www.javamex.com/tutorials/cryptography/pbe_salt.shtml - used this site to help understand how to generate a secure random value.
        //Used this method to generate the salt and the iv
        //A salt is a unique value that can be added to the end of the password
        //to create a different hash value. It adds more security to the hashing process
        // especially against brute force attacks.
    }

    public int AmountOfPadding(byte[] fileToPad){
        //get the amount of padding needed
        //There's 128 bits in 16 bytes (128 / 8)
        int amountOfPadding;
        if(fileToPad.length % 16 == 0){ //in order to get the padding, we can get the remainder after dividing by 16 as there's 16 bytes (128 bits) in a block.
        //If there's no remainder, the amount of padding is a full 16 byte (128 bit) block
            amountOfPadding = 16;
        }
        else{
            amountOfPadding = 16 - fileToPad.length % 16; //otherwise get the remainder and take away from 16 to get the amount we need to pad
        }
        return amountOfPadding;
    }

    public byte[] paddingFile(byte[] fileToPad, int amountOfPadding){//https://www.baeldung.com/java-array-copy learned how to copy an array and include extra bits from this site
        byte[] fileWithPadding = new byte[fileToPad.length + amountOfPadding];
        System.arraycopy(/*src*/fileToPad, /*srcPos*/0, /*dest*/fileWithPadding, /*destPos*/0, /*length*/fileToPad.length);
        //This copies an array from one array to another array, starting with the source array, source position, destination array, the position of the destination array and the length we want to copy
        fileWithPadding[fileToPad.length] = (byte) 1; //casting to a byte
        for(int i=fileToPad.length + 1; i< fileWithPadding.length; i++){
            //i=fileToPad.length because we want to start the padding when the first block ends
            fileWithPadding[i] = (byte) 0; //casting to a byte but unsure if this is padding correctly
        }
        return fileWithPadding;
    }

}