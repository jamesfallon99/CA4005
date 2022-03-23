//As stated in the declaration provided, the code was wrote by me - James Fallon.
//I have stated in the comments what sources I used to help complete this assignment

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.util.Random;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Assignment2 implements Assignment2Interface {

    public static void main(String[] args) {
        Assignment2 assignment2 = new Assignment2();
        
        String primeModulus = "b59dd79568817b4b9f6789822d22594f376e6a9abc0241846de426e5dd8f6eddef00b465f38f509b2b18351064704fe75f012fa346c5e2c442d7c99eac79b2bc8a202c98327b96816cb8042698ed3734643c4c05164e739cb72fba24f6156b6f47a7300ef778c378ea301e1141a6b25d48f1924268c62ee8dd3134745cdf7323";
        BigInteger primeModulusBigInt = new BigInteger(primeModulus, 16); //Converting the prime modulus to BigInteger and setting the radix to 16 as it's hexadecimal

        BigInteger one = new BigInteger("1");
        BigInteger primeModulusMinusOne = primeModulusBigInt.subtract(one);

        String generator = "44ec9d52c8f9189e49cd7c70253c2eb3154dd4f08467a64a0267c9defe4119f2e373388cfa350a4e66e432d638ccdc58eb703e31d4c84e50398f9f91677e88641a2d2f6157e2f4ec538088dcf5940b053c622e53bab0b4e84b1465f5738f549664bd7430961d3e5a2e7bceb62418db747386a58ff267a9939833beefb7a6fd68";
        BigInteger generatorBigInt = new BigInteger(generator, 16); ////Converting the generator to BigInteger and setting the radix to 16 as it's hexadecimal

        BigInteger minValueOne = new BigInteger("1");
        
        //Private key x
        BigInteger secretKey = assignment2.generateRandomValue(primeModulusBigInt, minValueOne);
        //System.out.println(secretKey.compareTo(primeModulusBigInt.subtract(BigInteger.ONE)));
        //System.out.println(secretKey.compareTo(BigInteger.ONE));
        //Secret key x is in the correct range (1 < x < p-1)
        
        //public key y
        BigInteger y = assignment2.generateY(generatorBigInt, secretKey, primeModulusBigInt);

        BigInteger minValueZero = new BigInteger("0");
        //Choose a random value k with 0 < k < p-1 and gcd(k,p-1) = 1
        //BigInteger randomK = assignment2.generateRandomValue(primeModulusBigInt, minValueZero);//Not sure how to handle gcd(k, p-1) = 1 so just using same method I used for generating the secret key and changing the minimum value to 0
        
        //BigInteger gcd = assignment2.calculateGCD(k, primeModulusBigInt.subtract(BigInteger.ONE));
        // System.out.println(gcd);
        // System.out.println(randomK);
        BigInteger k = new BigInteger("98126456420087741716451700506528816634827429450857625816509548333726605640190035751929326992174933412599705511815677589110111440384186710315899744517654709259139558032108089078638818763327174010392812799094882861303474627983258157857408425392601327399765208645309556030395507523585915462496272874155699528267");
        //The GCD(k, p-1) = 1 for this value of k
        BigInteger r = assignment2.generateR(generatorBigInt, k, primeModulusBigInt);
        //System.out.println(r);
        try{
            PrintWriter yToFile = new PrintWriter("y.txt"); //open the y.txt file
            yToFile.println(y.toString(16)); //write y in hexademical to the file y.txt
            yToFile.close(); //close the file
            //System.out.println(y);

            PrintWriter rToFile = new PrintWriter("r.txt"); //open the r.txt file
            rToFile.println(r.toString(16)); //write r in hexademical to the file r.txt
            rToFile.close(); //close the file
            }
            catch(FileNotFoundException e){
                System.out.println("txt file not found");
            }
        try{
        
            Path path = Paths.get(args[0]); //Taking in the class file from the command line as this is the file we will digitially sign
            //try reading the file from the command line
            byte[] m = Files.readAllBytes(path); //Convert the file into an array of bytes
            // for(int i=0; i<m.length; i++){
            // System.out.print(m[i]);
            // }
            // if(assignment2.calculateGCD(k, primeModulusMinusOne) == BigInteger.ONE){
            //     BigInteger s = assignment2.generateS(m, secretKey, r, k, primeModulusMinusOne);
            //     System.out.println(s);
            // }
            // else{
            //     System.out.println("No inverse exists");
            // }
            BigInteger s = assignment2.generateS(m, secretKey, r, k, primeModulusMinusOne);
            PrintWriter sToFile = new PrintWriter("s.txt"); //open the s.txt file
            sToFile.println(s.toString(16)); //write s in hexademical to the file r.txt
            sToFile.close(); //close the file

        }
        catch(IOException e){
            System.out.println("An error occurred");
        }
    }
    //This methods handles the following:
    //Generate a random secret key x with 1 < x < p-1
    // Or Choose a random value k with 0 < k < p-1 and gcd(k,p-1) = 1
    public BigInteger generateRandomValue(BigInteger primeModulus, BigInteger minValue){
        //https://www.quickprogrammingtips.com/java/creating-a-random-biginteger-in-java.html Used this site to help understand how to create a random BigInteger which will be used as the secret key
        
        Random rand = new Random();
        BigInteger secretKey;
        BigInteger one = new BigInteger("1");
        BigInteger primeModulusMinusOne = primeModulus.subtract(one);

        do{ //https://www.javatpoint.com/java-do-while-loop Used this site to understand a do-while loop
            secretKey = new BigInteger(primeModulus.bitLength(), rand);
        }
        //https://www.geeksforgeeks.org/biginteger-compareto-method-in-java/
        while(secretKey.compareTo(primeModulusMinusOne) != -1 && secretKey.compareTo(minValue/*min value*/) != 1);

        /*BigInteger.compareTo() will return:
        0: if the value of this BigInteger is equal to that of the BigInteger object passed as a parameter.
        1: if the value of this BigInteger is greater than that of the BigInteger object passed as a parameter.
        -1: if the value of this BigInteger is less than that of the BigInteger object passed as a parameter.*/
        return secretKey;
    }

    /* Method generateY returns the public key y and is generated from the given generator, secretKey  and modulus */
        
	public BigInteger generateY(BigInteger generator, BigInteger secretKey, BigInteger modulus){
        BigInteger y = generator.modPow(secretKey, modulus); //https://www.geeksforgeeks.org/biginteger-modpow-method-in-java/ used this to help understand modPow - a quick way of doing modular exponentiation
        return y;
    }
		
    /* Method generateR generates the first part of the ElGamal signature from the given generator, random value k and modulus */
           
	public BigInteger generateR(BigInteger generator, BigInteger k, BigInteger modulus){
        BigInteger r = generator.modPow(k, modulus);
        return r;
    }
		
    /* Method generateS generates the second part of the ElGamal signature from the given plaintext, secretKey, first signature part r, random value k and modulus */
           
    public BigInteger generateS(byte[] plaintext, BigInteger secretKey, BigInteger r, BigInteger k, BigInteger modulus){
        // for(int i=0; i<plaintext.length; i++){
        //     System.out.print(plaintext[i]);
        // }
        //System.out.println("/////////////////////////");
        BigInteger s = BigInteger.ZERO;//temporary and will be overwritten when we hit the try statement
        try{
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        byte[] hashedPlaintext = messageDigest.digest(plaintext); //Hashed plaintext
        // Calculate (H(m)-xr) (mod p-1)
        BigInteger hashedPlaintextBigInt = new BigInteger(hashedPlaintext); //Convert hashed plaintext into BigInteger
        BigInteger xTimesR = secretKey.multiply(r);
        
        BigInteger a = (hashedPlaintextBigInt.subtract(xTimesR)).mod(modulus);
        //System.out.println(a);
        
        BigInteger b = calculateInverse(k, modulus);

        s = a.multiply(b);

        }
        catch(NoSuchAlgorithmException e){
            System.out.println("An error occurred");
        }

        return s;
    }
        
    /* Method calculateGCD returns the GCD of the given val1 and val2 */
    
    //If the GCD of two numbers  val1 and val2 is 1 then val1 and val2 are relatively prime. This methods checks to see if the GCD is 1
    public BigInteger calculateGCD(BigInteger val1, BigInteger val2){ //https://www.baeldung.com/java-two-relatively-prime-numbers used this to help understand how to get the gcd
        BigInteger temp;
        while(!val2.equals(BigInteger.ZERO)){
            temp = val2;
            val2 = val1.mod(val2);
            val1 = temp;

        }
        return val1; //gcd after all the iterations
    }
				
        /* Method calculateInverse returns the modular inverse of the given val using the given modulus */
        
    public BigInteger calculateInverse(BigInteger val, BigInteger modulus){
        //Calculate k^-1 (mod p-1)
        //Multiplicative inverse only exists if GCD = 1
        //BigInteger checkGCD = calculateGCD(val, modulus);
        //System.out.println(checkGCD);

        //If our checkGCD = 1 then we can move on to the extended euclidean algorithm. We know GCD is 1 as we hardcoded k which had this in mind.
        BigInteger modulusCopy = modulus; //https://www.geeksforgeeks.org/multiplicative-inverse-under-modulo-m/ Used this site to help implement the inverse
        BigInteger y = new BigInteger("0");
        BigInteger x = new BigInteger("1");

        while(val.compareTo(BigInteger.ONE) == 1){ //while val is greater than one
            BigInteger quotient = val.divide(modulus);
            BigInteger temp = modulus;
            modulus = val.mod(modulus);
            val = temp;
            temp = y;

            y = quotient.multiply(y);
            y = x.subtract(y);
            x = temp;
        }
        if(x.compareTo(BigInteger.ZERO) == -1){ //Check to see if x is less than zero (is x negative)
            x = x.add(modulusCopy); //if it is, make it positive by adding the modulusCopy
        }
        return x; //x is our inverse
    }
    
}
