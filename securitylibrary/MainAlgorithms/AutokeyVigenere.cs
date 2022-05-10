using System;



namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
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
            //throw new NotImplementedException();
            string keystream = "";
            string keystream2 = "";
            cipherText = cipherText.ToLower();
            for (int i = 0; i < cipherText.Length; i++)
            {
                keystream += DeVigenere(cipherText[i], plainText[i]);
            }
            for (int i = 0; i < keystream.Length; i++)
            {
                if (keystream.Contains(plainText.Substring(0, keystream.Length - i)))
                {
                    break;
                }
                keystream2 += keystream[i];
            }
            return keystream2;
        }
        public string Decrypt(string cipherText, string key)
        {
            // throw new NotImplementedException();
            cipherText = cipherText.ToLower();
            string keystream = "";
            keystream = key;
            String plaintext = "";
            for (int i = 0; i < cipherText.Length; i++)
            {
                plaintext += DeVigenere(cipherText[i], keystream[i]);
                if (keystream.Length < cipherText.Length)
                {
                    keystream += plaintext[i];
                }
            }
            return plaintext;
        }
        public string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();
            string keystream = "";
            keystream = key;
            for (int i = 0; i < plainText.Length; i++)
            {
                int j = i % plainText.Length;
                keystream += plainText[j];
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