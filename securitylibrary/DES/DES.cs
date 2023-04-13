using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class DES : CryptographicTechnique
    {
        //step1 convert 
        public static Dictionary<string, char> CONVERTBinaryToHexadecimal(Dictionary<string, char> B_to_H)
        {
            B_to_H.Add("0000", '0');
            B_to_H.Add("0001", '1');
            B_to_H.Add("0010", '2');
            B_to_H.Add("0011", '3');
            B_to_H.Add("0100", '4');
            B_to_H.Add("0101", '5');
            B_to_H.Add("0110", '6');
            B_to_H.Add("0111", '7');
            B_to_H.Add("1000", '8');
            B_to_H.Add("1001", '9');
            B_to_H.Add("1010", 'A');
            B_to_H.Add("1011", 'B');
            B_to_H.Add("1100", 'C');
            B_to_H.Add("1101", 'D');
            B_to_H.Add("1110", 'E');
            B_to_H.Add("1111", 'F');
            return B_to_H;
        }
        public char BinaryToHexadecimal(string current_text, Dictionary<string, char> B_to_H)
        {
            return B_to_H[current_text];
        }

        public Dictionary<int, string> ConvertNumberToBinary(Dictionary<int, string> N_To_B)
        {
            N_To_B.Add(0, "0000");
            N_To_B.Add(1, "0001");
            N_To_B.Add(2, "0010");
            N_To_B.Add(3, "0011");
            N_To_B.Add(4, "0100");
            N_To_B.Add(5, "0101");
            N_To_B.Add(6, "0110");
            N_To_B.Add(7, "0111");
            N_To_B.Add(8, "1000");
            N_To_B.Add(9, "1001");
            N_To_B.Add(10, "1010");
            N_To_B.Add(11, "1011");
            N_To_B.Add(12, "1100");
            N_To_B.Add(13, "1101");
            N_To_B.Add(14, "1110");
            N_To_B.Add(15, "1111");
            return N_To_B;
        }
        public string NumberToBinary(int current_TEXT, Dictionary<int, string> N_To_B)
        {
            return N_To_B[current_TEXT];
        }
        public Dictionary<string, int> ConvertBinaryToNumber(Dictionary<string, int> B_To_N)
        {
            B_To_N.Add("00", 0);
            B_To_N.Add("01", 1);
            B_To_N.Add("10", 2);
            B_To_N.Add("11", 3);
            B_To_N.Add("0000", 0);
            B_To_N.Add("0001", 1);
            B_To_N.Add("0010", 2);
            B_To_N.Add("0011", 3);
            B_To_N.Add("0100", 4);
            B_To_N.Add("0101", 5);
            B_To_N.Add("0110", 6);
            B_To_N.Add("0111", 7);
            B_To_N.Add("1000", 8);
            B_To_N.Add("1001", 9);
            B_To_N.Add("1010", 10);
            B_To_N.Add("1011", 11);
            B_To_N.Add("1100", 12);
            B_To_N.Add("1101", 13);
            B_To_N.Add("1110", 14);
            B_To_N.Add("1111", 15);
            return B_To_N;
        }
        public int BinaryToNumber(string current_TEXT, Dictionary<string, int> B_TO_N)
        {
            return B_TO_N[current_TEXT];
        }
        public Dictionary<char, string> ConvertHexadecimalToBinary(Dictionary<char, string> H_To_B)
        {
            H_To_B.Add('0', "0000");
            H_To_B.Add('1', "0001");
            H_To_B.Add('2', "0010");
            H_To_B.Add('3', "0011");
            H_To_B.Add('4', "0100");
            H_To_B.Add('5', "0101");
            H_To_B.Add('6', "0110");
            H_To_B.Add('7', "0111");
            H_To_B.Add('8', "1000");
            H_To_B.Add('9', "1001");
            H_To_B.Add('A', "1010");
            H_To_B.Add('B', "1011");
            H_To_B.Add('C', "1100");
            H_To_B.Add('D', "1101");
            H_To_B.Add('E', "1110");
            H_To_B.Add('F', "1111");
            return H_To_B;
        }

        public string HexadecimalToBinary(char current_text, Dictionary<char, string> H_To_B)
        {

            return H_To_B[current_text];
        }


        public int[] PermutationFunction(int[] plainBlock, int choise)
        {
            int[] false_result = new int[1];
            int[] Result;

            int[] Initial_Permutation =
            {
                         58, 50, 42, 34, 26, 18, 10,  2,
                         60, 52, 44, 36, 28, 20, 12,  4,
                         62, 54, 46, 38, 30, 22, 14,  6,
                         64, 56, 48, 40, 32, 24, 16,  8,
                         57, 49, 41, 33, 25, 17,  9,  1,
                         59, 51, 43, 35, 27, 19, 11,  3,
                         61, 53, 45, 37, 29, 21, 13,  5,
                         63, 55, 47, 39, 31, 23, 15,  7,

            };

            int[] Permutation_Choice1 =
            {
                          57, 49, 41, 33, 25, 17, 9,
                           1, 58, 50, 42, 34, 26, 18,
                          10,  2, 59, 51, 43, 35, 27,
                          19, 11,  3, 60, 52, 44, 36,
                          63, 55, 47, 39, 31, 23, 15,
                           7, 62, 54, 46, 38, 30, 22,
                          14,  6, 61, 53, 45, 37, 29,
                          21, 13,  5, 28, 20, 12,  4,

           };

            int[] Permutation_Choice2 =
            {
                          14, 17, 11, 24, 1,   5,
                           3, 28, 15,  6, 21, 10,
                          23, 19, 12,  4, 26,  8,
                          16,  7, 27, 20, 13,  2,
                          41, 52, 31, 37, 47, 55,
                          30, 40, 51, 45, 33, 48,
                          44, 49, 39, 56, 34, 53,
                          46, 42, 50, 36, 29, 32,
            };
            int[] E_Permutation_selection =
            {
                         32,  1,  2,  3,  4,  5,
                          4,  5,  6,  7,  8,  9,
                          8,  9, 10, 11, 12, 13,
                         12, 13, 14, 15, 16, 17,
                         16, 17, 18, 19, 20, 21,
                         20, 21, 22, 23, 24, 25,
                         24, 25, 26, 27, 28, 29,
                         28, 29, 30, 31, 32,  1,
            };
            int[] Permutation =
            {
                        16,  7, 20, 21,
                        29, 12, 28, 17,
                         1, 15, 23, 26,
                         5, 18, 31, 10,
                         2,  8, 24, 14,
                        32, 27,  3,  9,
                        19, 13, 30,  6,
                        22, 11,  4, 25,
            };
            int[] Initial_Permutation_Inverse =
            {
                      40, 8, 48, 16, 56, 24, 64, 32,
                      39, 7, 47, 15, 55, 23, 63, 31,
                      38, 6, 46, 14, 54, 22, 62, 30,
                      37, 5, 45, 13, 53, 21, 61, 29,
                      36, 4, 44, 12, 52, 20, 60, 28,
                      35, 3, 43, 11, 51, 19, 59, 27,
                      34, 2, 42, 10, 50, 18, 58, 26,
                      33, 1, 41,  9, 49, 17, 57, 25,
            };


            if (choise == 0)
            {
                Result = new int[64];
                for (int i = 0; i < 8; i++)
                    for (int j = 0; j < 8; j++)
                        Result[i * 8 + j] = plainBlock[Initial_Permutation[i * 8 + j] - 1];
                return Result;
            }

            else if (choise == 1)
            {
                Result = new int[56];
                for (int i = 0; i < 8; i++)
                    for (int j = 0; j < 7; j++)
                        Result[i * 7 + j] = plainBlock[Permutation_Choice1[i * 7 + j] - 1];
                return Result;
            }

            else if (choise == 2)
            {
                Result = new int[48];
                for (int i = 0; i < 8; i++)
                    for (int j = 0; j < 6; j++)
                        Result[i * 6 + j] = plainBlock[Permutation_Choice2[i * 6 + j] - 1];
                return Result;
            }

            else if (choise == 3)
            {
                Result = new int[48];
                for (int i = 0; i < 8; i++)
                    for (int j = 0; j < 6; j++)
                        Result[i * 6 + j] = plainBlock[E_Permutation_selection[i * 6 + j] - 1];
                return Result;
            }

            else if (choise == 4)
            {
                Result = new int[32];
                for (int i = 0; i < 8; i++)
                    for (int j = 0; j < 4; j++)
                        Result[i * 4 + j] = plainBlock[Permutation[i * 4 + j] - 1];
                return Result;
            }

            else if (choise == 5)
            {
                Result = new int[64];
                for (int i = 0; i < 8; i++)
                    for (int j = 0; j < 8; j++)
                        Result[i * 8 + j] = plainBlock[Initial_Permutation_Inverse[i * 8 + j] - 1];
                return Result;
            }

            return false_result;

        }


        public int[] Shift_Function(int[] plainBlock, int number_round)
        {
            int[] result = new int[28];
            if (number_round == 1 || number_round == 2 || number_round == 9 || number_round == 16)
            {
                for (int i = 0; i < 28; i++)
                    result[i] = plainBlock[(i + 1) % 28];

            }
            else
            {
                for (int i = 0; i < 28; i++)
                    result[i] = plainBlock[(i + 2) % 28];

            }

            return result;
        }
        public int[] XOR_function(int[] left, int[] right)
        {
            int[] result = new int[left.Length];
            int i = 0;
            while (i < left.Length)
            {
                if (left[i] == right[i])
                {
                    result[i] = 0;

                }

                else
                {
                    result[i] = 1;

                }
                i++;
            }
            return result;
        }


        public int[] SBox_function(int[] plainblock, Dictionary<string, int> B_To_N, Dictionary<int, string> N_To_B)
        {
            int[] Sbox1 =
            {
                          14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 ,
                           0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
                           4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
                          15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13
            };
            int[] Sbox2 =
            {
                          15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
                           3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 ,
                           0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
                          13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9
            };
            int[] Sbox3 =
            {
                       10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 ,
                       13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 ,
                       13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 ,
                        1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12
            };
            int[] Sbox4 =
            {
                        7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 ,
                       13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 ,
                       10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 ,
                       3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14
            };
            int[] Sbox5 =
            {
                         2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 ,
                       14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 ,
                       4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 ,
                       11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 ,
            };
            int[] Sbox6 =
            {
                         12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 ,
                       10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 ,
                       9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 ,
                       4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 ,
            };
            int[] Sbox7 =
            {
                       4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 ,
                       13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 ,
                       1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 ,
                       6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 ,
            };
            int[] Sbox8 =
            {
                       13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 ,
                       1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 ,
                       7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 ,
                       2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11,
            };

            int[] Result = new int[32];
            int index = 0;
            string INTESECTIONBLOOCK = " ";

            for (int i = 0; i < 8; i++)
            {
                string finalblock = "";
                int j = 0;
                while (j < 6)
                {
                    finalblock = finalblock + plainblock[i * 6 + j].ToString();
                    j++;
                }


                string rowindex = finalblock[0].ToString() + finalblock[5].ToString();

                string colindex = finalblock.Substring(1, 4);

                int finalrow = BinaryToNumber(rowindex, B_To_N);

                int finalcol = BinaryToNumber(colindex, B_To_N);


                switch (i)
                {
                    case 0:
                        INTESECTIONBLOOCK = NumberToBinary(Sbox1[finalrow * 16 + finalcol], N_To_B);
                        break;
                    case 1:
                        INTESECTIONBLOOCK = NumberToBinary(Sbox2[finalrow * 16 + finalcol], N_To_B);
                        break;
                    case 2:
                        INTESECTIONBLOOCK = NumberToBinary(Sbox3[finalrow * 16 + finalcol], N_To_B);
                        break;
                    case 3:
                        INTESECTIONBLOOCK = NumberToBinary(Sbox4[finalrow * 16 + finalcol], N_To_B);
                        break;
                    case 4:
                        INTESECTIONBLOOCK = NumberToBinary(Sbox5[finalrow * 16 + finalcol], N_To_B);
                        break;
                    case 5:
                        INTESECTIONBLOOCK = NumberToBinary(Sbox6[finalrow * 16 + finalcol], N_To_B);
                        break;
                    case 6:
                        INTESECTIONBLOOCK = NumberToBinary(Sbox7[finalrow * 16 + finalcol], N_To_B);
                        break;
                    case 7:
                        INTESECTIONBLOOCK = NumberToBinary(Sbox8[finalrow * 16 + finalcol], N_To_B);
                        break;
                }
                int K = 0;
                while (K < 4)
                {
                    Result[index] = int.Parse(INTESECTIONBLOOCK[K].ToString());
                    index++;
                    K++;
                }
            }
            return Result;
        }

        public override string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.Substring(2);

            key = key.Substring(2);

            Dictionary<char, string> dectionaryHexToBin = new Dictionary<char, string>();
            Dictionary<string, char> dectionaryBinToHex = new Dictionary<string, char>();
            Dictionary<string, int> dectionarybinToNum = new Dictionary<string, int>();
            Dictionary<int, string> dectionaryNumToBin = new Dictionary<int, string>();

            dectionaryBinToHex = CONVERTBinaryToHexadecimal(dectionaryBinToHex);
            dectionaryHexToBin = ConvertHexadecimalToBinary(dectionaryHexToBin);
            dectionarybinToNum = ConvertBinaryToNumber(dectionarybinToNum);
            dectionaryNumToBin = ConvertNumberToBinary(dectionaryNumToBin);

            int[] blockdata = new int[64];

            int[] dataKey = new int[64];

            int[] c_part = new int[28];

            int[] d_part = new int[28];

            int[] Left = new int[32];

            int[] Right = new int[32];

            List<int[]> ArrayOfkeys = new List<int[]>();
            int counter = 0;
            for (int i = 0; i < 16; i++)
            {
                string result = HexadecimalToBinary(cipherText[i], dectionaryHexToBin);
                int jj = 0;
                while (jj < 4)
                {
                    blockdata[counter] = int.Parse(result[jj] + " ");
                    counter++;
                    jj++;
                }
            }
            counter = 0;
            for (int i = 0; i < 16; i++)
            {
                string result = HexadecimalToBinary(key[i], dectionaryHexToBin);
                for (int j = 0; j < 4; j++)
                {
                    dataKey[counter] = int.Parse(result[j] + " ");
                    counter++;
                }
            }
            blockdata = PermutationFunction(blockdata, 0);
            for (int i = 0; i < 32; i++)
            {
                Left[i] = blockdata[i];
                Right[i] = blockdata[i + 32];
            }
            dataKey = PermutationFunction(dataKey, 1);
            for (int i = 0; i < 28; i++)
            {
                c_part[i] = dataKey[i];
                d_part[i] = dataKey[i + 28];
            }
            for (int i = 1; i <= 16; i++)
            {
                dataKey = new int[56];
                c_part = Shift_Function(c_part, i);
                d_part = Shift_Function(d_part, i);

                for (int j = 0; j < 28; j++)
                {
                    dataKey[j] = c_part[j];
                    dataKey[j + 28] = d_part[j];
                }
                dataKey = PermutationFunction(dataKey, 2);
                ArrayOfkeys.Add(dataKey);
            }
            for (int Round_index = 15; Round_index >= 0; Round_index--)
            {
                int[] firsttemp = Right;
                Right = PermutationFunction(Right, 3);
                int[] plaintext = new int[48];
                plaintext = XOR_function(Right, ArrayOfkeys[Round_index]);
                plaintext = SBox_function(plaintext, dectionarybinToNum, dectionaryNumToBin);
                plaintext = PermutationFunction(plaintext, 4);
                int[] secondTemp = XOR_function(plaintext, Left);
                Left = firsttemp;
                Right = secondTemp;

            }
            int[] Swap = Left;
            Left = Right;
            Right = Swap;
            int index2 = 0;
            while (index2 < 32)
            {
                blockdata[index2] = Left[index2];
                blockdata[index2 + 32] = Right[index2];
                index2++;
            }
            blockdata = PermutationFunction(blockdata, 5);
            string plaintext_hexa = "0x";
            for (int i = 0; i < 16; i++)
            {
                string t = "";
                for (int j = 0; j < 4; j++)
                {
                    t = t + blockdata[i * 4 + j];
                }
                plaintext_hexa = plaintext_hexa + BinaryToHexadecimal(t, dectionaryBinToHex);
            }
            return plaintext_hexa;
        }

        public override string Encrypt(string plainText, string key)
        {
            plainText = plainText.Substring(2);
            key = key.Substring(2);
            Dictionary<char, string> dectionaryHexToBin = new Dictionary<char, string>();
            Dictionary<string, char> dectionaryBinToHex = new Dictionary<string, char>();
            Dictionary<string, int> dectionarybinToNum = new Dictionary<string, int>();
            Dictionary<int, string> dectionaryNumToBin = new Dictionary<int, string>();

            dectionaryBinToHex = CONVERTBinaryToHexadecimal(dectionaryBinToHex);
            dectionaryHexToBin = ConvertHexadecimalToBinary(dectionaryHexToBin);
            dectionarybinToNum = ConvertBinaryToNumber(dectionarybinToNum);
            dectionaryNumToBin = ConvertNumberToBinary(dectionaryNumToBin);
            int[] blockdata = new int[64];
            int[] dataKey = new int[64];
            int[] c_part = new int[28];
            int[] d_part = new int[28];
            int[] Left = new int[32];
            int[] Right = new int[32];
            int counter = 0;
            for (int i = 0; i < 16; i++)
            {
                string binaryresult = HexadecimalToBinary(plainText[i], dectionaryHexToBin);
                int jj = 0;
                while (jj < 4)
                {
                    blockdata[counter] = int.Parse(binaryresult[jj] + " ");
                    counter++;
                    jj++;
                }
            }
            counter = 0;
            for (int i = 0; i < 16; i++)
            {
                string binaryresult = HexadecimalToBinary(key[i], dectionaryHexToBin);
                int kk = 0;
                while (kk < 4)
                {
                    dataKey[counter] = int.Parse(binaryresult[kk] + " ");
                    counter++;
                    kk++;
                }
            }
            dataKey = PermutationFunction(dataKey, 1);
            int index22 = 0;
            while (index22 < 28)
            {
                c_part[index22] = dataKey[index22];
                d_part[index22] = dataKey[index22 + 28];
                index22++;
            }
            blockdata = PermutationFunction(blockdata, 0);
            int index3 = 0;
            while (index3 < 32)
            {
                Left[index3] = blockdata[index3];
                Right[index3] = blockdata[index3 + 32];
                index3++;
            }
            for (int Round = 1; Round <= 16; Round++)
            {
                dataKey = new int[56];

                c_part = Shift_Function(c_part, Round);

                d_part = Shift_Function(d_part, Round);

                int index4 = 0;
                while (index4 < 28)
                {
                    dataKey[index4] = c_part[index4];
                    dataKey[index4 + 28] = d_part[index4];
                    index4++;
                }
                dataKey = PermutationFunction(dataKey, 2);
                int[] firstresult = Right;
                Right = PermutationFunction(Right, 3);

                int[] cipherresult = new int[48];

                cipherresult = XOR_function(Right, dataKey);

                cipherresult = SBox_function(cipherresult, dectionarybinToNum, dectionaryNumToBin);

                cipherresult = PermutationFunction(cipherresult, 4);

                int[] Temp = XOR_function(cipherresult, Left);

                Left = firstresult;

                Right = Temp;

            }

            int[] Swap = Left;
            Left = Right;
            Right = Swap;
            int index5 = 0;
            string resulthexaaa = "0x";
            while (index5 < 32)
            {
                blockdata[index5] = Left[index5];
                blockdata[index5 + 32] = Right[index5];
                index5++;
            }
            blockdata = PermutationFunction(blockdata, 5);

            for (int i = 0; i < 16; i++)
            {
                string rest = "";
                for (int j = 0; j < 4; j++)
                    rest = rest + blockdata[i * 4 + j];
                resulthexaaa = resulthexaaa + BinaryToHexadecimal(rest, dectionaryBinToHex);
            }
            return resulthexaaa;
        }
    }
}


