using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        char[] alphabets = new char[] { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };
        
        public string Analyse(string plainText, string cipherText)
        {
            string key = "";
            string notTaken = "";
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            for (int i = 0; i < alphabets.Length; i++)
            {
                if (!cipherText.Contains(alphabets[i]))
                {
                    notTaken += alphabets[i];
                }
            }
            int notTakenIndex = 0;
            for (int i = 0; i < alphabets.Length;i++ )
            {
                bool isFound = false;
                int index = -1;
                for (int j = 0; j < plainText.Length; j++)
                {
                    if (alphabets[i] == plainText[j])
                    {
                        isFound = true;
                        index = j;
                    }
                }
                if (isFound)
                {
                    key += cipherText[index];
                }
                else
                {
                    key += notTaken[notTakenIndex];
                    notTakenIndex ++;
                }
            }
            key = key.ToLower();   
            return key;
        }

        public string Decrypt(string cipherText, string key)
        {
            string plainText = "";
            cipherText = cipherText.ToLower();
            key = key.ToLower();
            for (int i = 0; i < cipherText.Length; i++)
            {
                for (int j = 0; j < key.Length; j++)
                {
                    if (cipherText[i] == key[j])
                    {
                        plainText += alphabets[j];
                    }
                }
            }
            return plainText;
        }

        public string Encrypt(string plainText, string key)
        {
            string cipherText = "";
            for (int i = 0; i < plainText.Length; i++)
            {
                for (int j = 0; j < alphabets.Length; j++)
                {
                    if (plainText[i] == alphabets[j])
                    {
                        cipherText += key[j];
                    }
                }
            }
            return cipherText;
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            cipher =   cipher.ToLower();
            double[] sizes = new double[26];
            int[] index = new int[26];
            string freqArrange = "";
            string freqInEnglish = "ETAOINSRHLDCUMFPGWYBVKXJQZ";

            for (int i = 0; i < alphabets.Length; i++)
            {
                sizes[i] = 0;
                index[i] = i;
                for (int j = 0; j < cipher.Length; j++)
                {
                    if (alphabets[i] == cipher[j])
                    {
                        sizes[i]++;
                    }
                }
                sizes[i] *= 100;
                sizes[i] /=cipher.Length;
            }
            for (int i = 0; i < 26; i++)
            {
                for (int j = i; j < 26; j++)
                {
                    if (i == j)
                    {
                        continue;
                    }
                    else if (sizes[i] < sizes[j])
                    {
                        double tempSize = sizes[i];
                        sizes[i] = sizes[j];
                        sizes[j] = tempSize;
                        int tempIndex = index[i];
                        index[i] = index[j];
                        index[j] = tempIndex;
                    }
                }
            }
            for (int i = 0; i < 26; i++)
            {
                freqArrange += alphabets[index[i]];
            }
            string key = this.Analyse(freqInEnglish.ToLower(),freqArrange);
            return this.Decrypt(cipher, key);
        }
    }
}
