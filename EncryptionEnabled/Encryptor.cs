
namespace EncryptionEnabled
{
    public interface IEncryptor
    {
        public bool EncryptString(string inputString, string encrptionKey, out string? encryptedString, out string errorMessage);

        public bool CheckPassword(string inputString, string encryptedString, string decryptionKey, byte[] systemDecrytpionKey, byte[] systemIVByte, out string errorMessage);
    }
}
