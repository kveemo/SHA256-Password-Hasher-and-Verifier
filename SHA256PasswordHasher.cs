using System;
using System.Security.Cryptography;
using System.Text;

public class PasswordHasher
{
    public static string HashPassword(string password)
    {
        // Generate a random salt
        byte[] salt = GenerateSalt();

        // Convert the password string to a byte array
        byte[] passwordBytes = Encoding.UTF8.GetBytes(password);

        // Combine the password bytes with the salt
        byte[] combinedBytes = new byte[passwordBytes.Length + salt.Length];
        Array.Copy(passwordBytes, 0, combinedBytes, 0, passwordBytes.Length);
        Array.Copy(salt, 0, combinedBytes, passwordBytes.Length, salt.Length);

        // Compute the hash
        byte[] hashBytes;
        using (SHA256 sha256 = SHA256.Create())
        {
            hashBytes = sha256.ComputeHash(combinedBytes);
        }

        // convert the hash and salt to base64 strings for storage
        string hash = Convert.ToBase64String(hashBytes);
        string saltString = Convert.ToBase64String(salt);

        // Concatenate the hash and salt 
        string hashedPassword = $"{saltString}:{hash}";

        return hashedPassword;
    }

    private static byte[] GenerateSalt()
    {
        byte[] salt = new byte[16]; // 16 byte salt
        using (var rng = new RNGCryptoServiceProvider())
        {
            rng.GetBytes(salt);
        }
        return salt;
    }

    public class PasswordVerifier
    {
        public static bool VerifyPassword(string storedHashedPassword, string password)
        {
            // split the stored hash into salt and hash parts
            string[] parts = storedHashedPassword.Split(':');
            if (parts.Length != 2)
            {
                throw new ArgumentException("Invalid hashed password format");
            }

            byte[] storedSalt = Convert.FromBase64String(parts[0]);
            string storedHash = parts[1];

            // compute the hash using the stored salt and the inputted password
            string computedHash = ComputeHash(password, storedSalt);

            // =compare the computed hash with stored hash
            return storedHash == computedHash;
        }

        private static string ComputeHash(string password, byte[] salt)
        {
            // convert the password to a byte array
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);

            // salt the passo
            byte[] combinedBytes = new byte[passwordBytes.Length + salt.Length];
            Array.Copy(passwordBytes, 0, combinedBytes, 0, passwordBytes.Length);
            Array.Copy(salt, 0, combinedBytes, passwordBytes.Length, salt.Length);

            // compute the hash vlaue
            byte[] hashBytes;
            using (SHA256 sha256 = SHA256.Create())
            {
                hashBytes = sha256.ComputeHash(combinedBytes);
            }

            // convert the hash to a base64 string
            string hash = Convert.ToBase64String(hashBytes);

            return hash;
        }

        static void Main(string[] args)
        {
            Console.WriteLine("hello, enter your password:");
            string password = Console.ReadLine();

            string hashedPassword = PasswordHasher.HashPassword(password);

            Console.WriteLine("hashed password:");
            Console.WriteLine(hashedPassword);

            Console.WriteLine("enter the hashed password:");
            string storedHashedPassword = Console.ReadLine();

            Console.WriteLine("enter password to verify:");
            password = Console.ReadLine();

            bool isValid = PasswordVerifier.VerifyPassword(storedHashedPassword, password);

            if (isValid)
            {
                Console.WriteLine("valid.");
            }
            else
            {
                Console.WriteLine("invalid");
            }
        }


    }
}