using System;
using System.Collections.Generic;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class DES : CryptographicTechnique
    {
        public override string Decrypt(string cipherText, string key)
        {
            string[,] plainMatrix = InitialPermutation(ToBinaryMatrix(cipherText));
            string[,] keyMatrix = PermutedChoice1(ToBinaryMatrix(key));
            List<string[,]> keys = new List<string[,]>();
            for (int i = 0; i < 16; i++)
            {
                int[] shiftAmount = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };
                string[,] newKey = keyMatrix;
                newKey = leftCircularShift(newKey, shiftAmount[i]);
                newKey = PermutedChoice2(newKey);
                keys.Add(newKey);
            }
            for (int i = 0; i < 16; i++)
            {
                plainMatrix = RoundForDecryption(plainMatrix, keys[15 - i]);
            }
            plainMatrix = _32bitSwap(divideMatrix(plainMatrix, "Right"), divideMatrix(plainMatrix, "Left"));
            plainMatrix = InverseInitialPermutations(plainMatrix);
            return ToHex(plainMatrix);
        }

        public override string Encrypt(string plainText, string key)
        {
            string[,] plainMatrix = ToBinaryMatrix(plainText);
            string[,] keyMatrix = ToBinaryMatrix(key);
            plainMatrix = InitialPermutation(plainMatrix);
            keyMatrix = PermutedChoice1(keyMatrix);
            for (int i = 0; i < 16; i++)
            {
                int[] shiftAmount = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };
                keyMatrix = leftCircularShift(keyMatrix, shiftAmount[i]);
                plainMatrix = Round(plainMatrix, keyMatrix);
            }
            plainMatrix = _32bitSwap(divideMatrix(plainMatrix, "Right"), divideMatrix(plainMatrix, "Left"));
            plainMatrix = InverseInitialPermutations(plainMatrix);
            return ToHex(plainMatrix);
        }

        public string[,] ToBinaryMatrix(string input)
        {
            string[,] res = new string[8, 8];
            for (int i = 0, k = 2; i < 8; i++, k += 2)
            {
                string OneRow = input.Substring(k, 2);
                OneRow = extendTillEightBits(Convert.ToString(Convert.ToInt32(OneRow, 16), 2));
                for (int j = 0; j < 8; j++)
                {
                    res[i, j] = OneRow[j].ToString();
                }
            }
            return res;
        }
        public string[,] InitialPermutation(string[,] input)
        {
            int[,] IP = { { 58, 50, 42, 34, 26, 18, 10, 2 },
                          { 60, 52, 44, 36, 28, 20, 12, 4 },
                          { 62, 54, 46, 38, 30, 22, 14, 6 },
                          { 64, 56, 48, 40, 32, 24, 16, 8 },
                          { 57, 49, 41, 33, 25, 17, 9, 1 },
                          { 59, 51, 43, 35, 27, 19, 11, 3 },
                          { 61, 53, 45, 37, 29, 21, 13, 5 },
                          { 63, 55, 47, 39, 31, 23, 15, 7 }};
            string[,] res = new string[input.GetLength(0), input.GetLength(1)];
            for (int i = 0; i < input.GetLength(0); i++)
            {
                for (int j = 0; j < input.GetLength(1); j++)
                {
                    int row = (IP[i, j] - 1) / 8, col = (IP[i, j] - 1) % 8;
                    res[i, j] = input[row, col].ToString();
                }
            }
            return res;
        }
        public string[,] PermutedChoice1(string[,] input)
        {
            int[,] PMat = { { 57, 49, 41, 33, 25, 17, 9 },
                            { 1, 58, 50, 42, 34, 26, 18 },
                            { 10, 2, 59, 51, 43, 35, 27},
                            { 19, 11, 3, 60, 52, 44, 36},
                            { 63, 55, 47, 39, 31, 23, 15},
                            { 7, 62, 54, 46, 38, 30, 22},
                            { 14, 6, 61, 53, 45, 37, 29},
                            { 21, 13, 5, 28, 20, 12, 4}
            };
            string[,] res = new string[PMat.GetLength(0), PMat.GetLength(1)];
            for (int i = 0; i < PMat.GetLength(0); i++)
            {
                for (int j = 0; j < PMat.GetLength(1); j++)
                {
                    int row = (PMat[i, j] - 1) / 8, col = (PMat[i, j] - 1) % 8;
                    res[i, j] = input[row, col].ToString();
                }
            }
            return res;
        }
        public string[,] leftCircularShift(string[,] input, int shiftAmount)
        {
            string[,] res = input;
            for (int shift = 0; shift < shiftAmount; shift++)
            {
                string stHalf = string.Empty;
                string ndHalf = string.Empty;
                for (int i = 0; i < res.GetLength(0) / 2; i++)
                {
                    for (int j = 0; j < res.GetLength(1); j++)
                    {
                        stHalf += res[i, j];
                    }
                }
                for (int i = res.GetLength(0) / 2; i < res.GetLength(0); i++)
                {
                    for (int j = 0; j < res.GetLength(1); j++)
                    {
                        ndHalf += res[i, j];
                    }
                }
                stHalf = stHalf.Substring(1) + stHalf[0];
                ndHalf = ndHalf.Substring(1) + ndHalf[0];
                int k = 0;
                for (int i = 0; i < res.GetLength(0) / 2; i++)
                {
                    for (int j = 0; j < res.GetLength(1); j++)
                    {
                        res[i, j] = stHalf[k++].ToString();
                    }
                }
                k = 0;
                for (int i = res.GetLength(0) / 2; i < res.GetLength(0); i++)
                {
                    for (int j = 0; j < res.GetLength(1); j++)
                    {
                        res[i, j] = ndHalf[k++].ToString();
                    }
                }
            }
            return res;
        }
        public string[,] PermutedChoice2(string[,] input)
        {
            int[,] PMat = { { 14, 17, 11, 24, 1, 5 },
                            { 3, 28, 15, 6, 21, 10},
                            { 23, 19, 12, 4, 26, 8},
                            { 16, 7, 27, 20, 13, 2},
                            { 41, 52, 31, 37, 47, 55},
                            { 30, 40, 51, 45, 33, 48},
                            { 44, 49, 39, 56, 34, 53},
                            { 46, 42, 50, 36, 29, 32}};
            string[,] res = new string[PMat.GetLength(0), PMat.GetLength(1)];
            for (int i = 0; i < PMat.GetLength(0); i++)
            {
                for (int j = 0; j < PMat.GetLength(1); j++)
                {
                    int row = (PMat[i, j] - 1) / 7, col = (PMat[i, j] - 1) % 7;
                    res[i, j] = input[row, col].ToString();
                }
            }
            return res;
        }
        public string extendTillEightBits(string s)
        {
            int diff = 8 - s.Length;
            string res = string.Empty;
            for (int i = 0; i < diff; i++)
            {
                res += '0';
            }
            res += s;
            return res;
        }
        public string extendTillFourBits(string s)
        {
            int diff = 4 - s.Length;
            string res = string.Empty;
            for (int i = 0; i < diff; i++)
            {
                res += '0';
            }
            res += s;
            return res;
        }
        public string extendTillTwoBits(string s)
        {
            int diff = 2 - s.Length;
            string res = string.Empty;
            for (int i = 0; i < diff; i++)
            {
                res += '0';
            }
            res += s;
            return res;
        }
        public string XOROP(string s1, string s2)
        {
            string res = string.Empty;
            if (s1 == s2)
            {
                res += '0';
            }
            else
            {
                res += '1';
            }

            return res;
        }
        public string[,] XORMAT(string[,] input1, string[,] input2)
        {
            string[,] res = new string[input1.GetLength(0), input1.GetLength(1)];
            for (int i = 0; i < input1.GetLength(0); i++)
            {
                for (int j = 0; j < input1.GetLength(1); j++)
                {
                    res[i, j] = XOROP(input1[i, j], input2[i, j]);
                }
            }
            return res;
        }
        public string[,] SubBox(string[,] input)
        {
            List<int[,]> SBOX = new List<int[,]>();
            int[,] s1 = {{ 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 },
                         { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 },
                         { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 },
                         { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 } };
            int[,] s2 = {{15, 1 , 8 , 14, 6 , 11, 3 , 4 , 9 , 7, 2 , 13, 12, 0, 5 , 10},
                         {3 , 13, 4 , 7 , 15, 2 , 8 , 14, 12, 0, 1 , 10, 6 , 9, 11, 5},
                         {0 , 14, 7 , 11, 10, 4 , 13, 1 , 5 , 8, 12, 6 , 9 , 3, 2 , 15},
                         {13, 8 , 10, 1 , 3 , 15, 4 , 2 , 11, 6, 7 , 12, 0 , 5, 14, 9}};
            int[,] s3 = {{10, 0, 9 ,14, 6, 3, 15, 5 ,1 ,13, 12, 7, 11, 4 ,2 ,8},
                         {13, 7, 0 ,9 ,3 ,4 , 6, 10, 2, 8, 5 ,14, 12, 11, 15, 1},
                         {13, 6, 4 ,9 ,8 ,15, 3, 0 ,11, 1, 2 ,12, 5 ,10 ,14 ,7},
                         {1 ,10, 13, 0, 6, 9, 8, 7 ,4 ,15, 14, 3, 11, 5 ,2 ,12}};
            int[,] s4 ={{7 ,13, 14, 3, 0, 6 ,9 ,10 ,1 ,2 ,8 ,5 ,11 ,12, 4 ,15},
                        {13, 8, 11, 5, 6, 15, 0, 3 ,4 ,7 ,2 ,12, 1 ,10, 14, 9},
                        {10, 6, 9 ,0 ,12, 11, 7, 13,15, 1, 3,14, 5 ,2 , 8 ,4},
                        {3 ,15, 0 ,6 ,10, 1 ,13, 8 ,9 ,4 ,5 ,11, 12, 7, 2 ,14}};
            int[,] s5 = { { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 },
                        {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 },
                        {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0,14 },
                        {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 } };
            int[,] s6 = { { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 },
                        { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 },
                        {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 },
                        {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 } };
            int[,] s7 = { { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 },
                        {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
                        {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 },
                        {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 } };
            int[,] s8 = { { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 },
                        {1 ,15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 },
                        {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
                        { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 }};
            SBOX.Add(s1);
            SBOX.Add(s2);
            SBOX.Add(s3);
            SBOX.Add(s4);
            SBOX.Add(s5);
            SBOX.Add(s6);
            SBOX.Add(s7);
            SBOX.Add(s8);
            string[,] res = new string[8, 4];
            for (int i = 0; i < input.GetLength(0); i++)
            {
                string OneRow = string.Empty;
                for (int j = 0; j < input.GetLength(1); j++)
                {
                    OneRow += input[i, j];
                }
                int rowNum = int.Parse(Convert.ToString(Convert.ToInt32(OneRow.Substring(0, 1) + OneRow.Substring(5, 1), 2), 10), System.Globalization.NumberStyles.Integer);
                int colNum = int.Parse(Convert.ToString(Convert.ToInt32(OneRow.Substring(1, 4), 2), 10), System.Globalization.NumberStyles.Integer);
                string newRow = extendTillFourBits(Convert.ToString(Convert.ToInt32(SBOX[i][rowNum, colNum].ToString(), 10), 2));
                for (int j = 0; j < newRow.Length; j++)
                {
                    res[i, j] = newRow[j].ToString();
                }
            }
            return res;
        }
        public string[,] divideMatrix(string[,] input1, string s)
        {
            string[,] res = new string[4, 8];
            if (s == "left" || s == "Left")
            {
                for (int i = 0; i < 4; i++)
                {
                    for (int j = 0; j < 8; j++)
                    {
                        res[i, j] = input1[i, j];
                    }
                }
            }
            if (s == "Right" || s == "right")
            {
                for (int i = 4; i < 8; i++)
                {
                    for (int j = 0; j < 8; j++)
                    {
                        res[i - 4, j] = input1[i, j];
                    }
                }
            }
            return res;
        }
        public string[,] Expansion(string[,] input1)
        {
            int[,] Expand = { { 32, 1, 2, 3, 4, 5 },
                              {4, 5, 6, 7, 8, 9 },
                              { 8, 9, 10, 11, 12, 13},
                              { 12, 13, 14, 15, 16, 17},
                              {16, 17, 18, 19, 20, 21 },
                              {20, 21, 22, 23, 24, 25 },
                              {24, 25, 26, 27, 28, 29 },
                              {28, 29, 30, 31, 32, 1 }};
            string[,] res = new string[Expand.GetLength(0), Expand.GetLength(1)];
            for (int i = 0; i < Expand.GetLength(0); i++)
            {
                for (int j = 0; j < Expand.GetLength(1); j++)
                {
                    int row = (Expand[i, j] - 1) / 8, col = (Expand[i, j] - 1) % 8;
                    res[i, j] = input1[row, col].ToString();
                }
            }
            return res;
        }
        public string[,] _32bitSwap(string[,] right, string[,] left)
        {
            string[,] spConcatinate = new string[8, 8];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 8; j++)
                {
                    spConcatinate[i, j] = right[i, j];
                }
            }
            for (int i = 4; i < 8; i++)
            {
                for (int j = 0; j < 8; j++)
                {
                    spConcatinate[i, j] = left[i - 4, j];
                }
            }
            return spConcatinate;
        }
        public string[,] Merge(string[,] right, string[,] left)
        {
            return _32bitSwap(left, right);
        }
        public static string[,] Permutation(string[,] input1)
        {
            int[,] per = { { 16, 7, 20, 21 },
                           {29 ,12, 28, 17 },
                           {1, 15, 23, 26 },
                           { 5, 18, 31, 10},
                           {2, 8, 24, 14 },
                           {32, 27, 3 ,9 },
                           { 19, 13, 30, 6},
                           {22 ,11, 4, 25 }};
            string[,] res = new string[per.GetLength(0), per.GetLength(1)];
            for (int i = 0; i < per.GetLength(0); i++)
            {
                for (int j = 0; j < per.GetLength(1); j++)
                {
                    int row = (per[i, j] - 1) / 4, col = (per[i, j] - 1) % 4;
                    res[i, j] = input1[row, col].ToString();
                }
            }
            string[,] arr = new string[4, 8];
            int counter1 = 0;
            int counter2 = 0;
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 8; j++)
                {
                    arr[i, j] = res[counter2, counter1++];
                    if (counter1 == 4)
                    {
                        counter1 = 0;
                        counter2++;
                    }
                }
            }
            return arr;
        }
        public string[,] Round(string[,] plainMatrix, string[,] key)
        {
            string[,] LeftMatrix = divideMatrix(plainMatrix, "Left");
            string[,] RightMatrix = divideMatrix(plainMatrix, "Right");
            string[,] SpareRightMatrix = divideMatrix(plainMatrix, "Right");
            string[,] newKey = PermutedChoice2(key);
            RightMatrix = Expansion(RightMatrix);
            RightMatrix = XORMAT(newKey, RightMatrix);
            RightMatrix = SubBox(RightMatrix);
            RightMatrix = Permutation(RightMatrix);
            RightMatrix = XORMAT(RightMatrix, LeftMatrix);
            LeftMatrix = SpareRightMatrix;
            return Merge(RightMatrix, LeftMatrix);
        }
        public string[,] RoundForDecryption(string[,] plainMatrix, string[,] key)
        {
            string[,] LeftMatrix = divideMatrix(plainMatrix, "Left");
            string[,] RightMatrix = divideMatrix(plainMatrix, "Right");
            string[,] SpareRightMatrix = divideMatrix(plainMatrix, "Right");
            RightMatrix = Expansion(RightMatrix);
            RightMatrix = XORMAT(key, RightMatrix);
            RightMatrix = SubBox(RightMatrix);
            RightMatrix = Permutation(RightMatrix);
            RightMatrix = XORMAT(RightMatrix, LeftMatrix);
            LeftMatrix = SpareRightMatrix;
            return Merge(RightMatrix, LeftMatrix);
        }
        public string[,] InverseInitialPermutations(string[,] input1)
        {
            int[,] inv = { { 40, 8, 48, 16, 56, 24, 64, 32 },
                           {39, 7, 47, 15, 55, 23, 63, 31 },
                           {38, 6, 46, 14, 54, 22, 62, 30 },
                           {37, 5, 45, 13, 53, 21, 61, 29 },
                           {36, 4, 44, 12, 52, 20, 60 ,28 },
                           {35, 3 ,43, 11, 51, 19, 59 ,27 },
                           {34, 2, 42, 10, 50, 18, 58, 26 },
                           {33, 1, 41, 9, 49, 17, 57, 25}};
            string[,] res = new string[inv.GetLength(0), inv.GetLength(1)];
            for (int i = 0; i < inv.GetLength(0); i++)
            {
                for (int j = 0; j < inv.GetLength(1); j++)
                {
                    int row = (inv[i, j] - 1) / 8, col = (inv[i, j] - 1) % 8;
                    res[i, j] = input1[row, col].ToString();
                }
            }
            return res;
        }
        public string ToHex(string[,] input)
        {
            string res = string.Empty;
            for (int i = 0; i < input.GetLength(0); i++)
            {
                string newRow = string.Empty;
                for (int j = 0; j < input.GetLength(1); j++)
                {
                    newRow += input[i, j];
                }
                res += extendTillTwoBits(Convert.ToString(Convert.ToInt32(newRow, 2), 16));
            }
            return "0x" + res.ToUpper();
        }
    }
}
