using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {
        public override string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            key = key.ToLower();
            string[,] cipherMatrix = StToMx(cipherText);
            string[,] keyMatrix = StToMx(key);
            for (int i = 0; i <= 9; i++)
            {
                keyMatrix = RoundKey(keyMatrix, i);
            }
            cipherMatrix = XORMAT(cipherMatrix, keyMatrix);
            for (int i = 9; i > 0; i--)
            {
                cipherMatrix = InvShiftRows(cipherMatrix);
                cipherMatrix = InvSubBytes(cipherMatrix);
                keyMatrix = StToMx(key);
                for (int j = 0; j < i; j++)
                {
                    keyMatrix = RoundKey(keyMatrix, j);
                }
                cipherMatrix = XORMAT(keyMatrix, cipherMatrix);
                cipherMatrix = InvMixColumns(cipherMatrix);
            }
            cipherMatrix = InvShiftRows(cipherMatrix);
            cipherMatrix = InvSubBytes(cipherMatrix);
            keyMatrix = StToMx(key);
            cipherMatrix = XORMAT(keyMatrix, cipherMatrix);
            return ToString(cipherMatrix);
        }

        public override string Encrypt(string plainText, string key)
        {
            string[,] plainMatrix = StToMx(plainText);
            string[,] keyMatrix = StToMx(key);
            plainMatrix = XORMAT(plainMatrix, keyMatrix);
            for (int i = 0; i < 9; i++)
            {
                plainMatrix = SubBytes(plainMatrix);
                plainMatrix = ShiftRows(plainMatrix);
                plainMatrix = MixColumns(plainMatrix);
                keyMatrix = RoundKey(keyMatrix,i);
                plainMatrix = XORMAT(plainMatrix,keyMatrix);
            }
            plainMatrix = SubBytes(plainMatrix);
            plainMatrix = ShiftRows(plainMatrix);
            keyMatrix = RoundKey(keyMatrix,9);
            plainMatrix = XORMAT(plainMatrix, keyMatrix);
            return ToString(plainMatrix);
        }
        public string[,] MixColumns(string[,] input)
        {
            string[,] res = new string[4, 4];
            string[,] GF = { { "02", "03", "01", "01" } ,
                             { "01", "02", "03", "01" } ,
                             { "01", "01", "02", "03" } ,
                             { "03", "01", "01", "02" }};
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    for (int k = 0; k < 4; k++)
                    {
                        string s1 = extendTillEightBits(Convert.ToString(Convert.ToInt32(input[k, j], 16), 2));
                        string s2 = GF[i, k];
                        if (res[i, j] == null)
                        {
                            res[i, j] = multiplyByX(s1, s2);
                        }
                        else
                        {
                            res[i, j] = XOROP(multiplyByX(s1, s2), res[i, j]);
                        }
                    }
                }
            }
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    res[i, j] = extendTillTwoBits(Convert.ToString(Convert.ToInt32(res[i, j], 2), 16));
                }
            }
            return res;

        }
        public string[,] SubBytes(string[,] arr)
        {
            string[,] SBOX = new string[16, 16] { { "63", "7C", "77", "7B", "F2", "6B", "6F", "C5", "30", "01", "67", "2B", "FE", "D7", "AB", "76" },
                                                  { "CA", "82", "C9", "7D", "FA", "59", "47", "F0", "AD", "D4", "A2", "AF", "9C", "A4", "72", "C0" },
                                                  { "B7", "FD", "93", "26", "36", "3F", "F7", "CC", "34", "A5", "E5", "F1", "71", "D8", "31", "15" },
                                                  { "04", "C7", "23", "C3", "18", "96", "05", "9A", "07", "12", "80", "E2", "EB", "27", "B2", "75" },
                                                  { "09", "83", "2C", "1A", "1B", "6E", "5A", "A0", "52", "3B", "D6", "B3", "29", "E3", "2F", "84" },
                                                  { "53", "D1", "00", "ED", "20", "FC", "B1", "5B", "6A", "CB", "BE", "39", "4A", "4C", "58", "CF" },
                                                  { "D0", "EF", "AA", "FB", "43", "4D", "33", "85", "45", "F9", "02", "7F", "50", "3C", "9F", "A8" },
                                                  { "51", "A3", "40", "8F", "92", "9D", "38", "F5", "BC", "B6", "DA", "21", "10", "FF", "F3", "D2" },
                                                  { "CD", "0C", "13", "EC", "5F", "97", "44", "17", "C4", "A7", "7E", "3D", "64", "5D", "19", "73" },
                                                  { "60", "81", "4F", "DC", "22", "2A", "90", "88", "46", "EE", "B8", "14", "DE", "5E", "0B", "DB" },
                                                  { "E0", "32", "3A", "0A", "49", "06", "24", "5C", "C2", "D3", "AC", "62", "91", "95", "E4", "79" },
                                                  { "E7", "C8", "37", "6D", "8D", "D5", "4E", "A9", "6C", "56", "F4", "EA", "65", "7A", "AE", "08" },
                                                  { "BA", "78", "25", "2E", "1C", "A6", "B4", "C6", "E8", "DD", "74", "1F", "4B", "BD", "8B", "8A" },
                                                  { "70", "3E", "B5", "66", "48", "03", "F6", "0E", "61", "35", "57", "B9", "86", "C1", "1D", "9E" },
                                                  { "E1", "F8", "98", "11", "69", "D9", "8E", "94", "9B", "1E", "87", "E9", "CE", "55", "28", "DF" },
                                                  { "8C", "A1", "89", "0D", "BF", "E6", "42", "68", "41", "99", "2D", "0F", "B0", "54", "BB", "16" } };
            string[,] res = new string[4, 4];
            string hex = "";
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    hex = arr[i, j].ToUpper();
                    res[i, j] = extendTillTwoBits(SBOX[int.Parse(hex.Substring(0, 1), System.Globalization.NumberStyles.HexNumber), int.Parse(hex.Substring(1, 1), System.Globalization.NumberStyles.HexNumber)]).ToLower();
                    hex = "";
                }
            }
            return res;
        }
        public string[,] RoundKey(string[,] arr, int rconCounter)
        {
            string[,] Rcon = new string[4, 10] { { "01" , "02" , "04" , "08", "10" , "20" , "40" , "80" , "1b" , "36" },
{ "00" , "00" , "00" ,"00" , "00" , "00" ,"00" ,"00", "00" ,"00" } ,
{ "00" , "00" , "00" ,"00" , "00" , "00" , "00" , "00" ,"00" ,"00" },
{ "00" , "00" , "00" , "00", "00" , "00" , "00" , "00" ,"00" ,"00" } };
            string[,] SBOX = new string[16, 16] { { "63", "7C", "77", "7B", "F2", "6B", "6F", "C5", "30", "01", "67", "2B", "FE", "D7", "AB", "76" },
                                                  { "CA", "82", "C9", "7D", "FA", "59", "47", "F0", "AD", "D4", "A2", "AF", "9C", "A4", "72", "C0" },
                                                  { "B7", "FD", "93", "26", "36", "3F", "F7", "CC", "34", "A5", "E5", "F1", "71", "D8", "31", "15" },
                                                  { "04", "C7", "23", "C3", "18", "96", "05", "9A", "07", "12", "80", "E2", "EB", "27", "B2", "75" },
                                                  { "09", "83", "2C", "1A", "1B", "6E", "5A", "A0", "52", "3B", "D6", "B3", "29", "E3", "2F", "84" },
                                                  { "53", "D1", "00", "ED", "20", "FC", "B1", "5B", "6A", "CB", "BE", "39", "4A", "4C", "58", "CF" },
                                                  { "D0", "EF", "AA", "FB", "43", "4D", "33", "85", "45", "F9", "02", "7F", "50", "3C", "9F", "A8" },
                                                  { "51", "A3", "40", "8F", "92", "9D", "38", "F5", "BC", "B6", "DA", "21", "10", "FF", "F3", "D2" },
                                                  { "CD", "0C", "13", "EC", "5F", "97", "44", "17", "C4", "A7", "7E", "3D", "64", "5D", "19", "73" },
                                                  { "60", "81", "4F", "DC", "22", "2A", "90", "88", "46", "EE", "B8", "14", "DE", "5E", "0B", "DB" },
                                                  { "E0", "32", "3A", "0A", "49", "06", "24", "5C", "C2", "D3", "AC", "62", "91", "95", "E4", "79" },
                                                  { "E7", "C8", "37", "6D", "8D", "D5", "4E", "A9", "6C", "56", "F4", "EA", "65", "7A", "AE", "08" },
                                                  { "BA", "78", "25", "2E", "1C", "A6", "B4", "C6", "E8", "DD", "74", "1F", "4B", "BD", "8B", "8A" },
                                                  { "70", "3E", "B5", "66", "48", "03", "F6", "0E", "61", "35", "57", "B9", "86", "C1", "1D", "9E" },
                                                  { "E1", "F8", "98", "11", "69", "D9", "8E", "94", "9B", "1E", "87", "E9", "CE", "55", "28", "DF" },
                                                  { "8C", "A1", "89", "0D", "BF", "E6", "42", "68", "41", "99", "2D", "0F", "B0", "54", "BB", "16" } };
            string[,] arr2 = new string[4, 1];
            int countColoumn = 3;
            string index = arr[0, 3];
            //shift to up
            for (int i = 0; i < 3; i++)
            {
                arr2[i, 0] = arr[i + 1, countColoumn];
            }
            arr2[3, 0] = index; int countRow = 0;
            index = arr2[countRow, 0];
            //convert to SBOX
            for (int i = 0; i < 4; i++)
            {
                arr2[i, 0] = SBOX[int.Parse(index.Substring(0, 1), System.Globalization.NumberStyles.HexNumber), int.Parse(index.Substring(1, 1), System.Globalization.NumberStyles.HexNumber)];
                if (i != 3)
                {
                    countRow++;
                }
                index = arr2[countRow, 0];
            }
            //three XOR operation
            string hex = "";
            for (int i = 0; i < 4; i++)
            {
                hex = XOROP(extendTillEightBits(Convert.ToString(Convert.ToInt32(arr[i, 0], 16), 2)), extendTillEightBits(Convert.ToString(Convert.ToInt32(arr2[i, 0], 16), 2)));
                hex = XOROP(extendTillEightBits(hex), extendTillEightBits(Convert.ToString(Convert.ToInt32(Rcon[i, rconCounter], 16), 2)));
                arr[i, 0] = extendTillTwoBits(Convert.ToString(Convert.ToInt32(hex, 2), 16));
            }
            //rconCounter++;
            int count = 0;
            //other columns XOR
            while (count < 3)
            {
                hex = "";
                for (int i = 0; i < 4; i++)
                {
                    hex = XOROP(extendTillEightBits(Convert.ToString(Convert.ToInt32(arr[i, count], 16), 2)), extendTillEightBits(Convert.ToString(Convert.ToInt32(arr[i, count + 1], 16), 2)));
                    arr[i, count + 1] = extendTillTwoBits(Convert.ToString(Convert.ToInt32(hex, 2), 16));
                }
                count++;
            }
            return arr;
        }
        public string[,] ShiftRows(string[,] input)
        {
            string[,] matrix = new string[4, 4];
            int counter = 0;
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    matrix[i, j] = input[i, (j + counter) % 4];
                }
                counter++;
            }
            return matrix;
        }
        public string[,] InvMixColumns(string[,] input)
        {
            string[,] res = new string[4, 4];
            string[,] GF = { { "0e", "0b", "0d", "09" } ,
                             { "09", "0e", "0b", "0d" } ,
                             { "0d", "09", "0e", "0b" } ,
                             { "0b", "0d", "09", "0e" }};
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    for (int k = 0; k < 4; k++)
                    {
                        string s1 = extendTillEightBits(Convert.ToString(Convert.ToInt32(input[k, j], 16), 2));
                        string s2 = GF[i, k];
                        if (res[i, j] == null)
                        {
                            res[i, j] = multiplyByX(s1, s2);
                        }
                        else
                        {
                            res[i, j] = XOROP(multiplyByX(s1, s2), res[i, j]);
                        }
                    }
                }
            }
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    res[i, j] = extendTillTwoBits(Convert.ToString(Convert.ToInt32(res[i, j], 2), 16));
                }
            }
            return res;

        }
        public string[,] InvSubBytes(string[,] input)
        {
            string[,] SBOX = new string[16, 16] { { "63", "7C", "77", "7B", "F2", "6B", "6F", "C5", "30", "01", "67", "2B", "FE", "D7", "AB", "76" },
                                                  { "CA", "82", "C9", "7D", "FA", "59", "47", "F0", "AD", "D4", "A2", "AF", "9C", "A4", "72", "C0" },
                                                  { "B7", "FD", "93", "26", "36", "3F", "F7", "CC", "34", "A5", "E5", "F1", "71", "D8", "31", "15" },
                                                  { "04", "C7", "23", "C3", "18", "96", "05", "9A", "07", "12", "80", "E2", "EB", "27", "B2", "75" },
                                                  { "09", "83", "2C", "1A", "1B", "6E", "5A", "A0", "52", "3B", "D6", "B3", "29", "E3", "2F", "84" },
                                                  { "53", "D1", "00", "ED", "20", "FC", "B1", "5B", "6A", "CB", "BE", "39", "4A", "4C", "58", "CF" },
                                                  { "D0", "EF", "AA", "FB", "43", "4D", "33", "85", "45", "F9", "02", "7F", "50", "3C", "9F", "A8" },
                                                  { "51", "A3", "40", "8F", "92", "9D", "38", "F5", "BC", "B6", "DA", "21", "10", "FF", "F3", "D2" },
                                                  { "CD", "0C", "13", "EC", "5F", "97", "44", "17", "C4", "A7", "7E", "3D", "64", "5D", "19", "73" },
                                                  { "60", "81", "4F", "DC", "22", "2A", "90", "88", "46", "EE", "B8", "14", "DE", "5E", "0B", "DB" },
                                                  { "E0", "32", "3A", "0A", "49", "06", "24", "5C", "C2", "D3", "AC", "62", "91", "95", "E4", "79" },
                                                  { "E7", "C8", "37", "6D", "8D", "D5", "4E", "A9", "6C", "56", "F4", "EA", "65", "7A", "AE", "08" },
                                                  { "BA", "78", "25", "2E", "1C", "A6", "B4", "C6", "E8", "DD", "74", "1F", "4B", "BD", "8B", "8A" },
                                                  { "70", "3E", "B5", "66", "48", "03", "F6", "0E", "61", "35", "57", "B9", "86", "C1", "1D", "9E" },
                                                  { "E1", "F8", "98", "11", "69", "D9", "8E", "94", "9B", "1E", "87", "E9", "CE", "55", "28", "DF" },
                                                  { "8C", "A1", "89", "0D", "BF", "E6", "42", "68", "41", "99", "2D", "0F", "B0", "54", "BB", "16" } };
            string[,] result = new string[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    for (int k = 0; k < 16; k++)
                    {
                        for (int l = 0; l < 16; l++)
                        {
                            if (input[i, j].ToUpper() == SBOX[k, l])
                            {
                                result[i, j] = Convert.ToString(k, 16) + Convert.ToString(l, 16);
                            }
                        }
                    }
                }
            }
            return result;
        }
        public string[,] InvShiftRows(string[,] input)
        {
            string[,] matrix = new string[4, 4];
            int counter = 4;
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    matrix[i, j] = input[i, (j + counter) % 4];
                }
                counter--;
            }
            return matrix;
        }
        public string XOROP(string s1, string s2)
        {
            string res = string.Empty;
            for (int i = 0; i < 8; i++)
            {
                if (s1[i] == s2[i])
                {
                    res += '0';
                }
                else
                {
                    res += '1';
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
        public string multiplyByX(string s1, string by)
        {
            if (by == "01")
            {
                return s1;
            }
            else if (by == "02")
            {
                if (s1[0] == '0')
                {
                    return s1.Substring(1, s1.Length - 1) + "0";
                }
                else
                {
                    return XOROP(s1.Substring(1, s1.Length - 1) + "0", "00011011");
                }
            }
            else if (by == "03")
            {
                return XOROP(multiplyByX(s1, "02"), s1);
            }
            else if (by == "09")
            {
                return XOROP(multiplyByX(multiplyByX(multiplyByX(s1, "02"), "02"), "02"), s1); //x*9=(((x*2)*2)*2)+x
            }
            else if (by == "0b")
            {
                return XOROP(multiplyByX(XOROP(multiplyByX(multiplyByX(s1, "02"), "02"), s1), "02"), s1); //x*11=((((x*2)*2)+x)*2)+x
            }
            else if (by == "0d")
            {
                return XOROP(multiplyByX(multiplyByX(multiplyByX(s1, "03"), "02"), "02"), s1); //x*13=(((x*3)×2)×2)+x
            }
            else if (by == "0e")
            {
                return multiplyByX(XOROP(multiplyByX(multiplyByX(s1, "03"), "02"), s1), "02"); //x*14=(((x*3)×2)+x)×2
            }
            return string.Empty;
        }
        public string ToString(string[,] input)
        {
            string res = string.Empty;
            for (int i = 0; i < input.GetLength(1); i++)
            {
                for (int j = 0; j < input.GetLength(0); j++)
                {
                    res += input[j, i];
                }
            }
            return "0x"+res.ToUpper();
        }
        public string[,] StToMx(string s)
        {
            int counter1 = 2;
            string[,] convToMx = new string[4, 4];
            string sub = "";
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    sub = s.Substring(counter1, 2);
                    convToMx[j, i] = sub;
                    counter1 = counter1 + 2;
                }
            }
            return convToMx;
        }
        public string[,] XORMAT(string[,] input1 , string[,] input2)
        {
            string[,] res = new string[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    res[i, j] = XOROP(extendTillEightBits(Convert.ToString(Convert.ToInt32(input1[i, j], 16), 2)), extendTillEightBits(Convert.ToString(Convert.ToInt32(input2[i, j], 16), 2)));
                    res[i, j] = extendTillTwoBits(Convert.ToString(Convert.ToInt32(res[i,j],2),16));
                }
            }
            return res;
        }
    }
}
