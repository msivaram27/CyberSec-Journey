import java.math.BigInteger;
import java.util.Random;
import java.util.Scanner;

public class RSA {

    public static void main(String[] args) {
        RSA rsa = new RSA();

        // Step 1: Generate key pair
        KeyPair keyPair = rsa.generateKeyPair();
        BigInteger publicKey = keyPair.getPublicKey();
        BigInteger privateKey = keyPair.getPrivateKey();
        BigInteger n = keyPair.getModulus();

        System.out.println("Public Key: (e = " + publicKey + ", n = " + n + ")");
        System.out.println("Private Key: (d = " + privateKey + ", n = " + n + ")");

        // Step 2: Get user input for the message
        Scanner scanner = new Scanner(System.in);
        System.out.println("Enter a message to encrypt (numeric only): ");
        String message = scanner.nextLine();

        // Step 3: Encrypt and Decrypt the message
        System.out.println("Original message: " + message);

        // Encrypt the message
        BigInteger encryptedMessage = rsa.encrypt(new BigInteger(message), publicKey, n);
        System.out.println("Encrypted message: " + encryptedMessage);

        // Decrypt the message
        BigInteger decryptedMessage = rsa.decrypt(encryptedMessage, privateKey, n);
        System.out.println("Decrypted message: " + decryptedMessage);
    }

    // RSA Key Pair Generation
    public KeyPair generateKeyPair() {
        // Step 1: Generate two large prime numbers p and q
        BigInteger p = generatePrime(512);
        BigInteger q = generatePrime(512);

        // Step 2: Compute n = p * q
        BigInteger n = p.multiply(q);

        // Step 3: Compute Euler's Totient function φ(n) = (p-1) * (q-1)
        BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

        // Step 4: Choose a public exponent e (usually 65537)
        BigInteger e = new BigInteger("65537");

        // Step 5: Compute the private exponent d using Extended Euclidean Algorithm
        BigInteger d = e.modInverse(phi);

        return new KeyPair(e, d, n);
    }

    // RSA Encryption: C = M^e mod n
    public BigInteger encrypt(BigInteger message, BigInteger publicKey, BigInteger n) {
        return message.modPow(publicKey, n);
    }

    // RSA Decryption: M = C^d mod n
    public BigInteger decrypt(BigInteger encryptedMessage, BigInteger privateKey, BigInteger n) {
        return encryptedMessage.modPow(privateKey, n);
    }

    // Generate a random prime number with the specified bit length
    public BigInteger generatePrime(int bitLength) {
        BigInteger prime;
        Random random = new Random();
        do {
            prime = new BigInteger(bitLength, random);
        } while (!prime.isProbablePrime(100));  // Check if the number is a probable prime
        return prime;
    }

    // KeyPair class to hold public and private keys
    public class KeyPair {
        private BigInteger publicKey;
        private BigInteger privateKey;
        private BigInteger modulus;

        public KeyPair(BigInteger publicKey, BigInteger privateKey, BigInteger modulus) {
            this.publicKey = publicKey;
            this.privateKey = privateKey;
            this.modulus = modulus;
        }

        public BigInteger getPublicKey() {
            return publicKey;
        }

        public BigInteger getPrivateKey() {
            return privateKey;
        }

        public BigInteger getModulus() {
            return modulus;
        }
    }
}
