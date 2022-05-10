using System;



namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        string alphabets = "abcdefghijklmnopqrstuvwxyz";
        public int index(char c)
        {
            for (int i = 0; i < alphabets.Length; i++)
            {
                if (alphabets[i] == c)
                {
                    return i;
                }
            }
            return -1;
        }
        public char Vigenere(char plainChar, char keyChar)
        {
            return alphabets[(index(plainChar) + index(keyChar)) % 26];
        }
        public char DeVigenere(char cipherChar, char keyOrPlainChar)
        {
            return alphabets[(index(cipherChar) - index(keyOrPlainChar) + 26) % 26];
        }
        public string Analyse(string plainText, string cipherText)
        {
            // throw new NotImplementedException();
            string keystream = "";
            string keystream2 = "";
            cipherText = cipherText.ToLower();
            for (int i = 0; i < cipherText.Length; i++)
            {
                keystream += DeVigenere(cipherText[i], plainText[i]);
            }
            for (int i = 1; i < keystream.Length; i++)
            {
                if (keystream.Substring(0, i).Contains(keystream.Substring(i, i)))
                {
                    keystream2 = keystream.Substring(0, i);
                    break;
                }
            }
            return keystream2;
        }
        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            string keystream = "";
            for (int i = 0; i < cipherText.Length; i++)
            {
                int j = i % key.Length;
                keystream += key[j];
            }
            String plaintext = "";
            for (int i = 0; i < cipherText.Length; i++)
            {
                plaintext += DeVigenere(cipherText[i], keystream[i]);
            }
            return plaintext;
        }
        public string Encrypt(string plainText, string key)
        {
            string keystream = "";
            for (int i = 0; i < plainText.Length; i++)
            {
                int j = i % key.Length;
                keystream += key[j];
            }
            String ciphertext = "";
            for (int i = 0; i < plainText.Length; i++)
            {
                ciphertext += Vigenere(plainText[i], keystream[i]);
            }
            return ciphertext;

        }
    }
}