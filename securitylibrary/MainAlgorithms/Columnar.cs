using System;
using System.Collections.Generic;
using System.Linq;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
            for (int key = 2; key < plainText.Length; key++)
            {
                List<int> result = new List<int>();
                int cols = key;
                int rows = (int)Math.Ceiling((double)plainText.Length / (double)key);
                char[,] pMatrix = new char[rows, cols];
                for (int i = 0; i < rows; i++)
                {
                    for (int j = 0; j < cols; j++)
                    {
                        if (i * cols + j >= plainText.Length)
                        {
                            continue;
                        }
                        else
                        {
                            pMatrix[i, j] = plainText[i * cols + j];
                        }
                    }
                }
                string semiCiphered = "";
                for (int i = 0; i < cols; i++)
                {
                    for (int j = 0; j < rows; j++)
                    {
                        //if (pMatrix[j,i]!='\0')
                        semiCiphered += pMatrix[j, i];
                    }
                }
                for (int i = 0; i <= rows * cols - rows; i += rows)
                {
                    for (int j = 0; j <= cipherText.Length - rows; j++)
                    {
                        if (semiCiphered.Substring(i, rows)[rows - 1] == '\0')
                        {
                            string word1 = semiCiphered.Substring(i, rows - 1);
                            string word2 = cipherText.Substring(j, rows - 1);
                            if (word1 == word2)
                            {
                                result.Add((int)Math.Ceiling((double)j / (double)rows) + 1);
                                break;
                            }
                        }
                        else if (semiCiphered.Substring(i, rows) == cipherText.Substring(j, rows))
                        {
                            result.Add((j / rows) + 1);
                            break;
                        }
                    }
                }
                if (key == result.Count)
                {
                    return result;
                }
            }
            return null;
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            string plainText = "";
            cipherText = cipherText.ToLower();
            int cipherTextegnth = cipherText.Length;
            int lenghtkey = key.Max(); //Number of cols
            int rows = cipherTextegnth / lenghtkey; // Number of rows
            if (cipherTextegnth % lenghtkey != 0)
            {
                rows = rows + 1;
            }
            int k = 0;
            char[,] array = new char[rows, lenghtkey];
            string[] plain = new string[lenghtkey];
            for (int i = 0; i < lenghtkey; i++)
            {

                for (int j = 0; j < rows; j++)
                {
                    if (k == cipherTextegnth)
                        break;
                    else
                    {
                        array[j, i] = cipherText[k];
                        k++;

                    }
                }

            }

            char[,] matrix = new char[rows, lenghtkey];
            for (int i = 0; i < key.Count; i++)
            {
                for (int j = 0; j < rows; j++)
                {
                    matrix[j, i] = array[j, key[i] - 1];
                }
            }
            for (int i = 0; i < rows; i++)
            {
                for (int j = 0; j < lenghtkey; j++)
                {
                    plainText += matrix[i, j];
                }
            }
            return plainText;

        }

        public string Encrypt(string plainText, List<int> key)
        {
            //throw new NotImplementedException();
            string cipherText = "";
            int plainlegnth = plainText.Length;
            int lenghtkey = key.Count;
            int rows = plainlegnth / lenghtkey;//3
            if (plainlegnth % lenghtkey != 0)
            {
                rows = rows + 1;
            }
            int k = 0;
            char[,] array = new char[rows, lenghtkey];//3*5
            string[] cipherd = new string[lenghtkey];
            for (int i = 0; i < rows; i++)
            {

                for (int j = 0; j < lenghtkey; j++)
                {
                    if (k == plainlegnth)
                        array[i, j] = 'x';
                    else
                    {
                        array[i, j] = plainText[k];
                        k++;
                    }
                }

            }
            for (int i = 0; i < lenghtkey; i++)
            {
                for (int j = 0; j < rows; j++)
                {
                    cipherd[key[i] - 1] += array[j, i];
                }
            }
            for (int i = 0; i < lenghtkey; i++)
            {
                cipherText = cipherText + cipherd[i];
            }
            return cipherText;
        }
    }
}
