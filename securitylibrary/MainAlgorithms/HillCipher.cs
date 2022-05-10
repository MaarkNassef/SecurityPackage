using System;
using System.Collections.Generic;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher : ICryptographicTechnique<string, string>, ICryptographicTechnique<List<int>, List<int>>
    {
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            int rowSize = 2;
            int colSize = 2;
            int[,] cipherMatrix = fillingMatrix(cipherText, rowSize, true);
            int[,] plainMatrix = fillingMatrix(plainText, rowSize, true);
            int[,] keyMatrix = new int[rowSize, colSize];
            List<int> result = new List<int>();
            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    for (int k = 0; k < 26; k++)
                    {
                        for (int l = 0; l < 26; l++)
                        {
                            keyMatrix[0, 0] = i;
                            keyMatrix[0, 1] = j;
                            keyMatrix[1, 0] = k;
                            keyMatrix[1, 1] = l;
                            int[,] MatrixMultiplication = matrixMultiplication(keyMatrix, plainMatrix, colSize);
                            if (cipherMatrix[0, 0] == MatrixMultiplication[0, 0] % 26 &&
                                cipherMatrix[0, 1] == MatrixMultiplication[0, 1] % 26 &&
                                cipherMatrix[1, 0] == MatrixMultiplication[1, 0] % 26 &&
                                cipherMatrix[1, 1] == MatrixMultiplication[1, 1] % 26)
                            {
                                result.Add(i);
                                result.Add(j);
                                result.Add(k);
                                result.Add(l);
                                return result;
                            }
                        }
                    }
                }
            }
            throw new InvalidAnlysisException();
        }

        public string Analyse(string plainText, string cipherText)
        {
            throw new NotImplementedException();
        }

        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            int rowSize = (int)Math.Sqrt(key.Count);
            int colSize = (int)Math.Ceiling((double)cipherText.Count / (double)rowSize);
            int[,] cipherMatrix = fillingMatrix(cipherText, rowSize, true);
            int[,] keyMatrix = fillingMatrix(key, rowSize);
            int[,] plainMatrix = matrixMultiplication(inverse(keyMatrix), cipherMatrix, rowSize);
            List<int> result = new List<int>();
            for (int i = 0; i < colSize; i++)
            {
                for (int j = 0; j < rowSize; j++)
                {
                    result.Add((plainMatrix[j, i]) % 26);
                }
            }
            return result;
        }

        public string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }

        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            int size = (int)Math.Sqrt(key.Count); //Rows of plain text ,m*m of Key.
            int colSize = (int)Math.Ceiling((double)plainText.Count / (double)size);//Columns of plain text.
            int[,] plainMatrix = new int[size, colSize];
            int[,] mul = new int[size, colSize];
            int[,] keyMatrix = new int[size, size];
            int XsMustBeAdded = plainText.Count - (size * (plainText.Count / size));
            List<int> result = new List<int>();
            //Filling key with rowwise.
            keyMatrix = fillingMatrix(key, size);
            //Filling Plain with columnwise. with respect to X for empty places.
            plainMatrix = fillingMatrix(plainText, size, true, 23);
            //Matrix Multiplication.
            mul = matrixMultiplication(keyMatrix, plainMatrix, size);
            for (int i = 0; i < colSize; i++)
            {
                for (int j = 0; j < size; j++)
                {
                    result.Add((mul[j, i]) % 26);
                }
            }
            return result;
        }

        public string Encrypt(string plainText, string key)
        {
            throw new NotImplementedException();
        }

        public List<int> Analyse3By3Key(List<int> plain3, List<int> cipher3)
        {
            int rowSize = 3;
            int colSize = 3;
            int[,] cipherMatrix = fillingMatrix(cipher3, rowSize, true);
            int[,] plainMatrix = fillingMatrix(plain3, rowSize, true);
            int[,] keyMatrix = matrixMultiplication(cipherMatrix, inverse(plainMatrix), rowSize);
            List<int> result = new List<int>();
            for (int i = 0; i < rowSize; i++)
            {
                for (int j = 0; j < colSize; j++)
                {
                    result.Add((keyMatrix[i, j]) % 26);
                }
            }
            return result;
        }

        public string Analyse3By3Key(string plain3, string cipher3)
        {
            throw new NotImplementedException();
        }
        public int[,] fillingMatrix(List<int> list, int rowSize, bool columnwise = false, int spaces = 0)
        {
            int columnSize = (int)Math.Ceiling((double)list.Count / (double)rowSize);
            int[,] matrix = new int[rowSize, columnSize];
            if (!columnwise)
            {
                for (int i = 0; i < rowSize; i++)
                {
                    for (int j = 0; j < columnSize; j++)
                    {
                        if (i * rowSize + j >= list.Count)
                        {
                            matrix[i, j] = spaces;
                        }
                        else
                        {
                            matrix[i, j] = list[i * columnSize + j];
                        }
                    }
                }
            }
            else
            {
                for (int i = 0; i < columnSize; i++)
                {
                    for (int j = 0; j < rowSize; j++)
                    {
                        if (i * rowSize + j >= list.Count)
                        {
                            matrix[j, i] = spaces;
                        }
                        else
                        {
                            matrix[j, i] = list[i * rowSize + j];
                        }
                    }
                }
            }
            return matrix;
        }
        public int[,] matrixMultiplication(int[,] matrix1, int[,] matrix2, int size)
        {
            int columnSize2 = matrix2.Length / size;
            int[,] matrix = new int[size, columnSize2];
            for (int i = 0; i < size; i++)
            {
                for (int j = 0; j < columnSize2; j++)
                {
                    for (int k = 0; k < size; k++)
                    {
                        matrix[i, j] += matrix1[i, k] * matrix2[k, j];
                    }
                }
            }
            return matrix;
        }
        public int[,] subMatrix(int[,] matrix, int i, int j)
        {
            int size = matrix.GetLength(0);
            int index = 0;
            int[,] result = new int[size - 1, size - 1];
            for (int k = 0; k < size; k++)
            {
                for (int l = 0; l < size; l++)
                {
                    if (i == k || j == l)
                    {
                        continue;
                    }
                    result[index / (size - 1), index % (size - 1)] = matrix[k, l];
                    index++;
                }
            }
            return result;
        }
        public int determinant(int[,] matrix)
        {
            int size = matrix.GetLength(0);
            if (size == 1)
            {
                return matrix[0, 0];
            }
            int result = 0;
            for (int i = 0; i < size; i++)
            {
                result += (int)Math.Pow(-1, i % 2) * matrix[0, i] * determinant(subMatrix(matrix, 0, i));
            }
            return result;
        }
        public int multiplicativeInverse(int a, int mod)
        {
            int Q, A1 = 1, A2 = 0, A3 = mod, B1 = 0, B2 = 1, B3 = a;
            int tB1, tB2, tB3;
            while (B3 != 1)
            {
                Q = A3 / B3;
                tB1 = A1 - Q * B1;
                tB2 = A2 - Q * B2;
                tB3 = A3 - Q * B3;
                A1 = B1;
                A2 = B2;
                A3 = B3;
                B1 = tB1;
                B2 = tB2;
                B3 = tB3;
            }
            return (B2 + mod) % mod;
        }
        public int[,] inverse(int[,] matrix)
        {
            int[,] result = new int[matrix.GetLength(0), matrix.GetLength(0)];
            int MultiplicativeInverse = multiplicativeInverse((determinant(matrix) % 26 + 26) % 26, 26);
            for (int i = 0; i < matrix.GetLength(0); i++)
            {
                for (int j = 0; j < matrix.GetLength(0); j++)
                {
                    result[j, i] = MultiplicativeInverse * (int)Math.Pow(-1, i + j) * determinant(subMatrix(matrix, i, j));
                    result[j, i] = ((result[j, i] % 26) + 26) % 26;
                }
            }
            return result;
        }
    }
}
