using System;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographicTechnique<string, string>
    {
        /// <summary>
        /// The most common diagrams in english (sorted): TH, HE, AN, IN, ER, ON, RE, ED, ND, HA, AT, EN, ES, OF, NT, EA, TI, TO, IO, LE, IS, OU, AR, AS, DE, RT, VE
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="cipherText"></param>
        /// <returns></returns>
        public string Analyse(string plainText)
        {
            throw new NotImplementedException();
        }

        public string Analyse(string plainText, string cipherText)
        {
            throw new NotSupportedException();
        }

        public string Decrypt(string cipherText, string key)
        {
            /* WHAT TO DO.. GET PLAIN TEXT
            1. matrix <= Key
                1.1 key=>alphabets=>matrix + All alphabets
            2. Decrypt
             */
            string plainTextWithX = "";
            string plainText = "";
            cipherText = cipherText.ToLower();
            char[,] matrix = new char[5, 5];
            string alphabets = "abcdefghijklmnopqrstuvwxyz";
            key = key.ToLower();
            key = key + alphabets;
            int index = 0;
            for (int i = 0; i < key.Length; i++)
            {
                if (key[i] == 'j') //Add i instead of j in matrix if it's not exist.
                {
                    if (pContains(matrix, 'i') == -1)
                    {
                        matrix[index / 5, index % 5] = 'i';
                        index++;
                    }
                }
                else if (pContains(matrix, key[i]) == -1) //Add unique character in matrix if it's not exist.
                {
                    matrix[index / 5, index % 5] = key[i];
                    index++;
                }
            }
            for (int i = 0; i < cipherText.Length; i += 2) //Decryption Loop.
            {
                int index1, index2, rowChar1, rowChar2, colChar1, colChar2;
                index1 = pContains(matrix, cipherText[i]);
                index2 = pContains(matrix, cipherText[i + 1]);
                rowChar1 = index1 / 5;
                rowChar2 = index2 / 5;
                colChar1 = index1 % 5;
                colChar2 = index2 % 5;
                if (rowChar1 == rowChar2)
                {
                    plainTextWithX += matrix[rowChar1, (colChar1 + 4) % 5];
                    plainTextWithX += matrix[rowChar2, (colChar2 + 4) % 5];
                }
                else if (colChar1 == colChar2)
                {
                    plainTextWithX += matrix[(rowChar1 + 4) % 5, colChar1];
                    plainTextWithX += matrix[(rowChar2 + 4) % 5, colChar2];
                }
                else
                {
                    plainTextWithX += matrix[rowChar1, colChar2];
                    plainTextWithX += matrix[rowChar2, colChar1];
                }
            }
            for (int i = 0; i < plainTextWithX.Length; i++)
            {
                if (plainTextWithX[i] == 'x' && i % 2 == 1) // There is X at the second place in the part consists of two characters.
                {
                    if (i + 1 == plainTextWithX.Length) //There is X at the end of the text.
                    {
                        break; // You don't need to continue as it is the end.
                    }
                    else if (plainTextWithX[i - 1] == plainTextWithX[i + 1]) //Before and after X are the same.
                    {
                        continue; // Don't put it in the string.
                    }
                }
                plainText += plainTextWithX[i]; //Base Case: Put the character in the string.
            }
            return plainText;
        }

        public string Encrypt(string plainText, string key)
        {
            string alphabet = "abcdefghiklmnopqrstuvwxyz";
            char[,] matrix = new char[5, 5];
            int index1 = 0;
            bool isFound1 = false;
            int x = 0, y = 0;
            int length1 = key.Length;
            string CipherText = "";
            //Enter key in matrix
            while (length1 > 0)
            {
                isFound1 = false;
                for (int i = 0; i < 5; i++)
                {
                    for (int j = 0; j < 5; j++)
                    {
                        if (index1 < key.Length && key[index1] == matrix[i, j])
                        {
                            isFound1 = true;
                            length1--;
                            break;
                        }
                    }
                    if (isFound1)
                    {
                        index1++;
                        break;
                    }
                }
                if (isFound1 == false)
                {
                    if (key[index1] == 'j')
                    {
                        matrix[x, y++] = 'i';
                        index1++;
                    }
                    else
                    {

                        matrix[x, y++] = key[index1++];
                    }
                    length1--;
                    if (y % 5 == 0)
                    {
                        x++;
                        y = 0;
                    }
                }
            }
            length1 = 0;
            isFound1 = false;
            index1 = 0;
            //complete martrix with other characters
            if (key.Length != 25)
            {
                while (length1 < 25)
                {
                    isFound1 = false;
                    for (int j = 0; j < 5; j++)
                    {
                        for (int k = 0; k < 5; k++)
                        {
                            if (index1 < alphabet.Length && alphabet[index1] == matrix[j, k])
                            {
                                isFound1 = true;
                                length1++;
                                break;
                            }
                        }
                        if (isFound1)
                        {
                            index1++;
                            break;
                        }
                    }
                    if (isFound1 == false)
                    {
                        matrix[x, y++] = alphabet[index1++];
                        length1++;
                        if (y % 5 == 0)
                        {
                            x++;
                            y = 0;
                        }
                    }
                }
            }
            char[] Text = new char[plainText.Length + 5000];
            for (int i = 0; i < plainText.Length; i++)
            {
                Text[i] = plainText[i];
            }
            int len = plainText.Length;
            for (int i = 0; i < len; i += 2)
            {
                if (Text[i] == Text[i + 1])
                {
                    for (int j = len - 1; j > i; j--)
                    {

                        Text[j + 1] = Text[j];
                    }
                    Text[i + 1] = 'x';
                    len++;
                }
            }
            // if length of plainText is odd
            if (len % 2 != 0)
            {
                len++;
                Text[len] = 'x';
            }
            int[] p1 = new int[4];
            int[] p2 = new int[4];
            int counterOfP1 = 0;
            length1 = len;
            index1 = 0;
            while (length1 > 0)
            {
                for (int j = 0; j < 5; j++)
                {
                    for (int k = 0; k < 5; k++)
                    {
                        if (index1 < Text.Length && Text[index1] == matrix[j, k])
                        {
                            p1[counterOfP1++] = j;
                            p1[counterOfP1++] = k;
                            length1--;
                            break;
                        }
                    }
                }
                if (length1 > 0)
                {
                    index1++;
                }
                if (counterOfP1 == 4)
                {
                    if (p1[1] == p1[3])
                    {
                        if (p1[0] == 4)
                        {
                            p2[0] = 0;
                        }
                        else
                        {
                            p2[0] = p1[0] + 1;
                        }
                        p2[1] = p1[1];
                        if (p1[2] == 4)
                        {
                            p2[2] = 0;
                        }
                        else
                        {
                            p2[2] = p1[2] + 1;
                        }
                        p2[3] = p1[3];
                    }
                    else if (p1[0] == p1[2])
                    {
                        p2[0] = p1[0];
                        if (p1[1] == 4)
                        {
                            p2[1] = 0;
                        }
                        else
                        {
                            p2[1] = p1[1] + 1;
                        }
                        p2[2] = p1[2];
                        if (p1[3] == 4)
                        {
                            p2[3] = 0;
                        }
                        else
                        {
                            p2[3] = p1[3] + 1;
                        }
                    }
                    else
                    {
                        p2[0] = p1[0];
                        p2[1] = p1[3];
                        p2[2] = p1[2];
                        p2[3] = p1[1];
                    }
                    CipherText = CipherText + matrix[p2[0], p2[1]];
                    CipherText = CipherText + matrix[p2[2], p2[3]];
                    counterOfP1 = 0;
                }
            }
            return CipherText;
        }

        public int pContains(char[,] matrix, char c)
        {
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    if (matrix[i, j] == c)
                    {
                        return i * 5 + j;
                    }
                }
            }
            return -1;
        }

    }
}
