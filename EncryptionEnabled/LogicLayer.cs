using System.Security.Cryptography;
namespace EncryptionEnabled
{
    public class LogicLayer : IEncryptor
    {
        #region Interface Implementations
        public bool EncryptString(string inputString, string encrptionKey, out string? encryptedString, out string errorMessage)
        {
            return PrivateEncryptString(inputString, encrptionKey, out encryptedString, out byte[] systemDecrytpionKey, out byte[] systemIVByte, out errorMessage);
        }
        public bool CheckPassword(string inputString, string encryptedString, string decryptionKey, byte[] systemDecrytpionKey, byte[] systemIVByte, out string errorMessage)
        {
            return PrivateCheckPassword(inputString, encryptedString, decryptionKey, systemDecrytpionKey, systemIVByte, out errorMessage);
        }
        #endregion
        private static bool PrivateEncryptString(string inputString, string encrptionKey, out string? encryptedString,out byte[] systemDecrytpionKey,out byte[] systemIVByte , out string errorMessage)
        {
            errorMessage = string.Empty;
            encryptedString = string.Empty;
            byte[]? key = null;
            byte[]? iv = null;
            try
            {
                string? selfEncryptedString = TranslateString(inputString, encrptionKey);
                using (Aes aesAlg = Aes.Create()) // Pre Built AES algorithm Used for Security
                {
                    aesAlg.GenerateKey();
                    aesAlg.GenerateIV();
                    key = aesAlg.Key;
                    iv = aesAlg.IV;
                    encryptedString = EncryptStringToBytes_Aes(selfEncryptedString, key, iv);
                }
                
                if (string.IsNullOrEmpty(encryptedString))
                {
                    errorMessage = "Encryption Failed";
                    return false;
                    
                }
                return true;
            }
            catch (Exception ex)
            {
                
                errorMessage = ex.Message;
                return false;
            }
            finally
            {
                systemDecrytpionKey = key;
                systemIVByte = iv;
            }

        }

        
        private static bool PrivateCheckPassword(string originalString, string encryptedString, string userDecryptionKey, byte[] systemDecrytpionKey, byte[] systemIVByte ,out string errorMessage)
        {
            errorMessage = string.Empty;
            try
            {
                string aesDecrypted = DecryptStringFromBytes_Aes(encryptedString, systemDecrytpionKey, systemIVByte);
                string? tempEncryptedPassword = TranslateString(aesDecrypted, userDecryptionKey);
                
                if (tempEncryptedPassword == encryptedString)
                {
                    return true;
                }
                return false;
            }
            catch (Exception ex)
            {
                errorMessage = ex.Message;
                return false;
            }

        }
        static string EncryptStringToBytes_Aes(string? plainText, byte[] Key, byte[] IV)
        {
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                    {
                        swEncrypt.Write(plainText);
                    }
                    return Convert.ToBase64String(msEncrypt.ToArray());
                }
            }
        }

        static string DecryptStringFromBytes_Aes(string cipherTextString, byte[] Key, byte[] IV)
        {
            if (cipherTextString == null || cipherTextString.Length <= 0)
                throw new ArgumentNullException("cipherTextString");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            byte[] cipherText = Convert.FromBase64String(cipherTextString);

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                {
                    return srDecrypt.ReadToEnd();
                }
            }
        }
        internal static string? TranslateString(string inputString, string userKey)
        {
            return CombineEncryption(inputString, userKey);

        }
        internal static string? CombineEncryption(string inputString, string encryptionKey)
        {
            try
            {
                int maxLength = Math.Max(inputString.Length, encryptionKey.Length);
                char[] result = new char[maxLength * 2]; // Max length of result could be twice the length of the longer string

                for (int i = 0; i < maxLength; i++)
                {
                    if (i < inputString.Length)
                        result[i * 2] = inputString[i];
                    else
                        result[i * 2] = '0';

                    if (i < encryptionKey.Length)
                        result[i * 2 + 1] = encryptionKey[encryptionKey.Length - 1 - i];
                    else
                        result[i * 2 + 1] = '0';
                }
                string combinedString = new string(result);
                if (!string.IsNullOrEmpty(combinedString))
                {
                    var splitList = SplitEncryptedString(combinedString);
                    if (splitList != null)
                    {
                        return CombineSplitStrings(splitList);
                    }
                    else
                    {
                        return null;
                    }
                }
                else
                {
                    return null;
                }
            }
            catch (Exception) { return null; }
        }

        internal static string CombineSplitStrings(List<string> splitList)
        {
            return string.Join("", splitList);
        }
        internal static int SumOfDigits(int number)
        {
            int sum = 0;
            while (number > 0)
            {
                sum += number % 10;
                number /= 10;
            }
            return sum;
        }

        internal static List<string>? SplitEncryptedString(string encryptedString)
        {
            try
            {
                int length = encryptedString.Length;
                int sumOfDigits = SumOfDigits(length);
                int parts = length / sumOfDigits;
                List<string> splitList = new();

                int partLength = length / parts;
                int remainingLength = length % parts;

                int currentIndex = 0;
                for (int i = 0; i < parts; i++)
                {
                    int currentPartLength = partLength;
                    if (remainingLength > 0)
                    {
                        currentPartLength++;
                        remainingLength--;
                    }
                    splitList.Add(encryptedString.Substring(currentIndex, currentPartLength));
                    currentIndex += currentPartLength;
                }
                return ReplaceEvenIndexedCharacters(splitList);
            }
            catch (Exception)
            {
                return null;
            }


        }

        internal static List<string>? ReplaceEvenIndexedCharacters(List<string> splitList)
        {
            try
            {
                for (int i = 0; i < splitList.Count; i++)
                {
                    if (i % 2 == 0) // Process only strings at even index positions in the list
                    {
                        char[] chars = splitList[i].ToCharArray();
                        for (int j = 0; j < chars.Length; j++)
                        {
                            if (j % 2 == 0) // Replace characters at even positions
                            {
                                int position = j;
                                while (position > 9) // Sum the digits if the position exceeds 9
                                {
                                    position = SumOfDigits(position);
                                }
                                chars[j] = (char)('0' + position);
                            }
                        }
                        splitList[i] = new string(chars);
                    }
                }
                return splitList;
            }
            catch (Exception)
            {
                return null;
            }
        }
    }

}
