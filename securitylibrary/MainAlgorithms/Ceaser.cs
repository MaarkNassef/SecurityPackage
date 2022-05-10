namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        char[] alphabet = new char[] { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };
        string cipher = "";
        string palin = "";

        public string Encrypt(string plainText, int key)
        {
            for (int i = 0; i < plainText.Length; i++)
            {
                for (int j = 0; j < alphabet.Length; j++)
                {
                    if (alphabet[j] == plainText[i])
                    {
                        cipher = cipher + alphabet[(j + key) % 26];
                        break;
                    }

                }
            }
            return cipher;
        }

        public string Decrypt(string cipherText, int key)
        {
            cipherText = cipherText.ToLower();
            for (int i = 0; i < cipherText.Length; i++)
            {
                for (int j = 0; j < alphabet.Length; j++)
                {
                    if (alphabet[j] == cipherText[i])
                    {
                        int res = j - key;
                        if (res < 0)
                        {
                            res = res + 26;
                        }
                        palin = palin + alphabet[res];
                        break;
                    }

                }
            }
            return palin;


        }

        public int Analyse(string plainText, string cipherText)
        {
            int ret = 0;
            int rets = 0;
            cipherText = cipherText.ToLower();
            plainText = plainText.ToLower();

            for (int i = 0; i < alphabet.Length; i++)
            {
                if (plainText[0] == alphabet[i])
                    ret = i;
                if (cipherText[0] == alphabet[i])
                    rets = i;
            }
            if (rets - ret < 0)
            {
                return (rets - ret) + 26;
            }
            return (rets - ret);
        }
    }
}
