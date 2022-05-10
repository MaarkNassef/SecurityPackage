using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;



namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            int key = 2;
            for (int i = 1; i < 10; i++)
            {
                if (this.Encrypt(plainText, i).ToUpper() == cipherText)
                {
                    key = i;
                    break;
                }
            }
            return key;
        }
        public string Decrypt(string cipherText, int key)
        {
            double x = (double)cipherText.Length / key;
            int rounded = (int)Math.Ceiling(x);
            char[,] matrix = new char[key, rounded];
            int count = 0;
            string cText = cipherText.ToLower();
            String plain = "";
            for (int i = 0; i < key; i++)
            {
                for (int j = 0; j < rounded; j++)
                {
                    if (count < cText.Length)
                    {
                        matrix[i, j] = cText[count];
                        count++;
                    }
                }
            }
            for (int i = 0; i < rounded; i++)
            {
                for (int j = 0; j < key; j++)
                {
                    if (matrix[j, i] != '\0')
                    {
                        plain = plain + matrix[j, i];
                    }
                }
            }
            return plain;
        }
        public string Encrypt(string plainText, int key)
        {
            double x = (double)plainText.Length / key;
            int rounded = (int)Math.Ceiling(x);
            char[,] matrix = new char[key, rounded];
            int count = 0;
            String cipher = "";
            string pText = plainText.ToUpper();
            for (int i = 0; i < rounded; i++)
            {
                for (int j = 0; j < key; j++)
                {
                    if (count < pText.Length)
                    {
                        matrix[j, i] = pText[count];
                        count++;
                    }

                }
            }
            for (int i = 0; i < key; i++)
            {
                for (int j = 0; j < rounded; j++)
                {
                    if (matrix[i, j] != '\0')
                    {
                        cipher = cipher + matrix[i, j];
                    }
                }
            }
            return cipher;
        }
    }
}