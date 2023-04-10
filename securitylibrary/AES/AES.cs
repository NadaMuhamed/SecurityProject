using System;
using System.CodeDom.Compiler;
using System.Collections.Generic;
using System.Data.SqlTypes;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{

    public class AES : CryptographicTechnique
    {
        public override string Decrypt(string cipherText, string key)
        {
            string plantext;
            key = key.ToLower();
            cipherText = cipherText.ToLower();
            string[] keys = new string[11];
            string[,] Matcipher = new string[4, 4];
            string[,] Matkey = new string[4, 4];
            Matcipher = convertStringToMat(cipherText);
            Matkey = convertStringToMat(key);
            keys[0] = key;
            for (int i = 1; i <1; i++)
            {
                Matkey = AddRoundKey(Matkey, i-1);
                keys[i] = convertMatToString(Matkey);
            }
            Matkey = convertStringToMat(keys[10]);

            Matcipher = stateXORcipherkey(Matcipher, Matkey);
            Matcipher = inverse_shift_rows(Matcipher);
            Matcipher = sub_byte(Matcipher, InvSBOXbuilder);
            for (int i = 9; i > 0; i--)
            {
                Matkey = convertStringToMat(keys[i]);
                Matcipher = stateXORcipherkey(Matcipher, Matkey);
                Matcipher = MixColumn(Matcipher, InvMixCon);
                Matcipher = shift_rows(Matcipher);
                Matcipher = sub_byte(Matcipher, InvSBOXbuilder);

            }

            Matcipher = stateXORcipherkey(Matcipher, Matkey);
            plantext = convertMatToString(Matkey);
            return "0x" + plantext;
        }

        public override string Encrypt(string plainText, string key)
        {
            string str;
            key = key.ToLower();
            plainText = plainText.ToLower();
            string[,] stat = new string[4, 4];
            string[,] Matplain = new string[4, 4];
            string[,] Matkey = new string[4, 4];
            Matplain = convertStringToMat(plainText);
            Matkey = convertStringToMat(key);
            stat = stateXORcipherkey(Matplain, Matkey);

            for (int i = 0; i < 9; i++)
            {
                stat = sub_byte(stat, SBOXbuilder);
                stat = shift_rows(stat);
                stat = MixColumn(stat, MixCon);
                Matkey = AddRoundKey(Matkey,i);
                stat = stateXORcipherkey(stat, Matkey);

            }
            stat = sub_byte(stat, SBOXbuilder);
            stat = shift_rows(stat);
            Matkey = AddRoundKey(Matkey, 9);

            stat = stateXORcipherkey(stat, Matkey);
            str = convertMatToString(stat);
            return str;
        }



        public string[,] convertStringToMat(string str)
        {
            string[,] Matriex = new string[4, 4];
            int index =2;
         
            for(int j=0;j<4;j++)
            {
                for(int i=0;i<4;i++)
                {
                    Matriex[i, j] = "";
                    Matriex[i, j] += str[index];
                    Matriex[i, j] += str[index + 1];
                    index += 2;


                }
            }

            return Matriex;
        }
        public string convertMatToString(string[,] Matrix)
        {
            string str = "00";

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    str += Matrix[j, i];
                }
            }
            return str;
        }
        public string binToString(string s)
        {
            List<Byte> byteList = new List<Byte>();

            for (int i = 0; i < s.Length; i += 8)
            {
                byteList.Add(Convert.ToByte(s.Substring(i, 8), 2));
            }
            return Encoding.ASCII.GetString(byteList.ToArray());
        }
        public string xor(string mat1, string mat2)
        {
            string xOR = "";
            mat2 = mat2.PadLeft(mat1.Length, '0');
            for (int i = 0; i < mat1.Length; i++)
            {
                if (mat1[i] != mat2[i])
                {
                    xOR += '1';
                }
                else
                {
                    xOR += '0';
                }
            }
            return xOR;
        }
        public int convert_to_int(char stat)
        {
            stat = stat.ToString().ToLower()[0];
            switch (stat)
            {
                case 'a':
                    return 10;
                case 'b':
                    return 11;
                case 'c':
                    return 12;
                case 'd':
                    return 13;
                case 'e':
                    return 14;
                case 'f':
                    return 15;
                default:
                    return Convert.ToInt32(stat.ToString());
            }

        }
        public string[,] SBOXbuilder()
        {
            string[,] SBOX = new string[16, 16] {
           {"0x63","0x7c","0x77","0x7b","0xf2","0x6b","0x6f","0xc5","0x30","0x01","0x67","0x2b","0xfe","0xd7","0xab","0x76"},
           {"0xca","0x82","0xc9","0x7d","0xfa","0x59","0x47","0xf0","0xad","0xd4","0xa2","0xaf","0x9c","0xa4","0x72","0xc0" },
           {"0xb7","0xfd","0x93","0x26","0x36","0x3f","0xf7","0xcc","0x34","0xa5","0xe5","0xf1","0x71","0xd8","0x31","0x15" },
           {"0x04","0xc7","0x23","0xc3","0x18","0x96","0x05","0x9a","0x07","0x12","0x80","0xe2","0xeb","0x27","0xb2","0x75" },
           {"0x09","0x83","0x2c","0x1a","0x1b","0x6e","0x5a","0xa0","0x52","0x3b","0xd6","0xb3","0x29","0xe3","0x2f","0x84" },
           {"0x53","0xd1","0x00","0xed","0x20","0xfc","0xb1","0x5b","0x6a","0xcb","0xbe","0x39","0x4a","0x4c","0x58","0xcf" },
           {"0xd0","0xef","0xaa","0xfb","0x43","0x4d","0x33","0x85","0x45","0xf9","0x02","0x7f","0x50","0x3c","0x9f","0xa8" },
           {"0x51","0xa3","0x40","0x8f","0x92","0x9d","0x38","0xf5","0xbc","0xb6","0xda","0x21","0x10","0xff","0xf3","0xd2" },
           {"0xcd","0x0c","0x13","0xec","0x5f","0x97","0x44","0x17","0xc4","0xa7","0x7e","0x3d","0x64","0x5d","0x19","0x73" },
           {"0x60","0x81","0x4f","0xdc","0x22","0x2a","0x90","0x88","0x46","0xee","0xb8","0x14","0xde","0x5e","0x0b","0xdb" },
           {"0xe0","0x32","0x3a","0x0a","0x49","0x06","0x24","0x5c","0xc2","0xd3","0xac","0x62","0x91","0x95","0xe4","0x79" },
           {"0xe7","0xc8","0x37","0x6d","0x8d","0xd5","0x4e","0xa9","0x6c","0x56","0xf4","0xea","0x65","0x7a","0xae","0x08" },
           {"0xba","0x78","0x25","0x2e","0x1c","0xa6","0xb4","0xc6","0xe8","0xdd","0x74","0x1f","0x4b","0xbd","0x8b","0x8a" },
           {"0x70","0x3e","0xb5","0x66","0x48","0x03","0xf6","0x0e","0x61","0x35","0x57","0xb9","0x86","0xc1","0x1d","0x9e" },
           {"0xe1","0xf8","0x98","0x11","0x69","0xd9","0x8e","0x94","0x9b","0x1e","0x87","0xe9","0xce","0x55","0x28","0xdf" },
           {"0x8c","0xa1","0x89","0x0d","0xbf","0xe6","0x42","0x68","0x41","0x99","0x2d","0x0f","0xb0","0x54","0xbb","0x16" } };
            return SBOX;
        }
        public string[,] InvSBOXbuilder()
        {
            //inverse of SBOX
            string[,] iSBOX = new string[16, 16] {
           {"0x52", "0x09", "0x6a", "0xd5", "0x30", "0x36", "0xa5", "0x38", "0xbf", "0x40", "0xa3", "0x9e", "0x81", "0xf3", "0xd7", "0xfb" },
           {"0x7c", "0xe3", "0x39", "0x82", "0x9b", "0x2f", "0xff", "0x87", "0x34", "0x8e", "0x43", "0x44", "0xc4", "0xde", "0xe9", "0xcb" },
           {"0x54", "0x7b", "0x94", "0x32", "0xa6", "0xc2", "0x23", "0x3d", "0xee", "0x4c", "0x95", "0x0b", "0x42", "0xfa", "0xc3", "0x4e" },
           {"0x08", "0x2e", "0xa1", "0x66", "0x28", "0xd9", "0x24", "0xb2", "0x76", "0x5b", "0xa2", "0x49", "0x6d", "0x8b", "0xd1", "0x25" },
           {"0x72", "0xf8", "0xf6", "0x64", "0x86", "0x68", "0x98", "0x16", "0xd4", "0xa4", "0x5c", "0xcc", "0x5d", "0x65", "0xb6", "0x92" },
           {"0x6c", "0x70", "0x48", "0x50", "0xfd", "0xed", "0xb9", "0xda", "0x5e", "0x15", "0x46", "0x57", "0xa7", "0x8d", "0x9d", "0x84" },
           {"0x90", "0xd8", "0xab", "0x00", "0x8c", "0xbc", "0xd3", "0x0a", "0xf7", "0xe4", "0x58", "0x05", "0xb8", "0xb3", "0x45", "0x06" },
           {"0xd0", "0x2c", "0x1e", "0x8f", "0xca", "0x3f", "0x0f", "0x02", "0xc1", "0xaf", "0xbd", "0x03", "0x01", "0x13", "0x8a", "0x6b" },
           {"0x3a", "0x91", "0x11", "0x41", "0x4f", "0x67", "0xdc", "0xea", "0x97", "0xf2", "0xcf", "0xce", "0xf0", "0xb4", "0xe6", "0x73" },
           {"0x96", "0xac", "0x74", "0x22", "0xe7", "0xad", "0x35", "0x85", "0xe2", "0xf9", "0x37", "0xe8", "0x1c", "0x75", "0xdf", "0x6e" },
           {"0x47", "0xf1", "0x1a", "0x71", "0x1d", "0x29", "0xc5", "0x89", "0x6f", "0xb7", "0x62", "0x0e", "0xaa", "0x18", "0xbe", "0x1b" },
           {"0xfc", "0x56", "0x3e", "0x4b", "0xc6", "0xd2", "0x79", "0x20", "0x9a", "0xdb", "0xc0", "0xfe", "0x78", "0xcd", "0x5a", "0xf4" },
           {"0x1f", "0xdd", "0xa8", "0x33", "0x88", "0x07", "0xc7", "0x31", "0xb1", "0x12", "0x10", "0x59", "0x27", "0x80", "0xec", "0x5f" },
           {"0x60", "0x51", "0x7f", "0xa9", "0x19", "0xb5", "0x4a", "0x0d", "0x2d", "0xe5", "0x7a", "0x9f", "0x93", "0xc9", "0x9c", "0xef" },
           {"0xa0", "0xe0", "0x3b", "0x4d", "0xae", "0x2a", "0xf5", "0xb0", "0xc8", "0xeb", "0xbb", "0x3c", "0x83", "0x53", "0x99", "0x61" },
           {"0x17", "0x2b", "0x04", "0x7e", "0xba", "0x77", "0xd6", "0x26", "0xe1", "0x69", "0x14", "0x63", "0x55", "0x21", "0x0c", "0x7d" } };
            return iSBOX;
        }
        public string[,] StateGenerator(string s)
        {
            string[,] state = new string[4, 4];
            int row = 0; int col = 0;
            for (int i = 2; i < s.Length; i += 2)
            {
                state[row, col] = s[i].ToString();
                state[row, col] += s[i + 1].ToString();
                col++;
                if (col % 4 == 0)
                {
                    col = 0;
                    row++;
                }
            }
            return state;
        }
        public string HexToBin(string hex)
        {
            return Convert.ToString(Convert.ToInt32(hex, 16), 2).PadLeft(8, '0');
        }
        public string BinToHex(string bin)
        {
            return Convert.ToInt32(bin, 2).ToString("X");
        }
        public string GFMultiplier(string state, string constMatrix)
        {
            string sBin = HexToBin(state);
            string cBin = HexToBin(constMatrix);
            List<int> sCoef = new List<int>();
            List<int> cCoef = new List<int>();
            for (int i = 0; i < sBin.Length; i++)
            {
                if (sBin[i] == '1')
                {
                    sCoef.Add(7 - i);
                }
            }
            for (int i = 0; i < cBin.Length; i++)
            {
                if (cBin[i] == '1')
                {
                    cCoef.Add(7 - i);
                }
            }
            List<int> newSCoef = new List<int>();
            foreach (int ccoef in cCoef)
            {
                for (int i = 0; i < sCoef.Count; i++)
                {
                    newSCoef.Add(sCoef[i] + ccoef);
                }
            }
            HashSet<int> sCoefSet = new HashSet<int>(newSCoef);
            foreach (int coef in sCoefSet)
            {
                List<int> tempIdx = new List<int>();
                for (int i = 0; i < newSCoef.Count; i++)
                {
                    if (newSCoef[i] == coef)
                    {
                        tempIdx.Add(i);
                    }
                }
                if (tempIdx.Count > 1)
                {
                    if (tempIdx.Count % 2 == 0)
                    {
                        for (int j = 0; j < tempIdx.Count; j++)
                        {
                            newSCoef.Remove(coef);
                        }
                    }
                    else
                    {
                        for (int j = 0; j < tempIdx.Count - 1; j++)
                        {
                            newSCoef.Remove(coef);
                        }
                    }
                }
            }

            foreach (int coef in newSCoef)
            {
                Console.WriteLine("Old Coef: " + coef);
            }
            int[] checker = { 4, 3, 1, 0 };

            if (newSCoef[0] > 7)
            {
                foreach (int check in checker)
                {
                    bool found = false;
                    for (int i = 0; i < newSCoef.Count; i++)
                    {
                        if (newSCoef[i] == check)
                        {
                            found = true;
                            newSCoef.RemoveAt(i);
                            break;
                        }
                    }
                    if (!found)
                    {
                        newSCoef.Add(check);
                    }
                }
                newSCoef.RemoveAt(0);
            }
            foreach (int scoef in sCoef)
            {
                Console.WriteLine("NewCoef:" + scoef);
            }
            string result = "00000000";
            StringBuilder sb = new StringBuilder(result);

            foreach (int scoef in newSCoef)
            {
                sb[7 - scoef] = '1';
            }
            result = sb.ToString();
            Console.WriteLine(result);
            return result;
        }
        public string[,] MixCon()
        {
            string[,] Mix = new string[4, 4]
            {
            {"02","03","01","01"},
            {"01","02","03","01"},
            {"01","01","02","03"},
            {"03","01","01","02"}
            };
            return Mix;
        }
        public string[,] InvMixCon()
        {
            string[,] InvMix = new string[4, 4]
            {
            {"0e","0b","0d","09"},
            {"09","0e","0b","0d"},
            {"0d","09","0e","0b"},
            {"0b","0d","09","0e"}
            };
            return InvMix;
        }
        public string[,] stateXORcipherkey(string[,] state, string[,] cipherkey)
        {
            string[,] result = new string[4, 4];

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    result[i, j] = BinToHex(xor(HexToBin(state[i, j]), HexToBin(cipherkey[i, j]))).PadLeft(2, '0');
                }
            }

            return result;
        }

        public string[,] sub_byte(string[,] state, Func<string[,]> builder)
        {
            string[,] sbox = builder();
            string[,] stateByte = new string[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    int row = convert_to_int(state[i, j][0]);
                    int col = convert_to_int(state[i, j][1]);
                    stateByte[i, j] = sbox[row, col];
                }
            }
            return stateByte;
        }
        public string[,] shift_rows(string[,] state)
        {
            int r = 1;
            string temp = state[r, 0];
            state[r, 0] = state[r, 1];
            state[r, 1] = state[r, 2];
            state[r, 2] = state[r, 3];
            state[r, 3] = temp;
            r++;
            temp = state[r, 0];
            string temp2 = state[r, 1];
            state[r, 0] = state[r, 2];
            state[r, 1] = state[r, 3];
            state[r, 2] = temp;
            state[r, 3] = temp2;
            r++;
            temp = state[r, 0];
            temp2 = state[r, 1];
            string temp3 = state[r, 2];
            state[r, 0] = state[r, 3];
            state[r, 1] = temp;
            state[r, 2] = temp2;
            state[r, 3] = temp3;
            return state;
        }
        public string[,] inverse_shift_rows(string[,] state)
        {
            int r = 1;
            string temp = state[r, 3];
            state[r, 3] = state[r, 2];
            state[r, 2] = state[r, 1];
            state[r, 1] = state[r, 0];
            state[r, 0] = temp;
            r++;
            temp = state[r, 3];
            string temp2 = state[r, 2];
            state[r, 3] = state[r, 1];
            state[r, 2] = state[r, 0];
            state[r, 1] = temp;
            state[r, 0] = temp2;
            r++;
            temp = state[r, 1];
            temp2 = state[r, 2];
            string temp3 = state[r, 3];

            state[r, 3] = state[r, 0];
            state[r, 2] = temp3;
            state[r, 1] = temp2;
            state[r, 0] = temp;
            return state;
        }
        public string[,] MixColumn(string[,] state, Func<string[,]> ConstMatrix)
        {
            string[,] constant = ConstMatrix();
            string[,] result = new string[4, 4];
            for (int k = 0; k < 4; k++)
            {
                for (int i = 0; i < 4; i++)
                {
                    string res = "00000000";
                    for (int j = 0; j < 4; j++)
                    {
                        string temp = GFMultiplier(state[j, k], constant[i, j]);
                        res = xor(temp, res);
                    }
                    result[k, i] = BinToHex(res).PadLeft(2, '0');
                }
            }
            return result;
        }
        public string[,] AddRoundKey(string[,] cipherKey, int Iteration)
        {
            string[,] RCON = new string[4, 10]
            {
                  {  "01", "02", "04", "08", "10", "20", "40", "80", "1b", "36"},

                  {  "00", "00", "00", "00", "00", "00", "00", "00", "00", "00"},

                  {  "00", "00", "00", "00", "00", "00", "00", "00", "00", "00"},

                  {  "00", "00", "00", "00", "00", "00", "00", "00", "00", "00"}

            };
            string[,] sbox = SBOXbuilder();
            string[,] result = new string[4, 4];
            string[] rot = new string[4];

            rot[0] = sbox[convert_to_int(cipherKey[1, 3][0]), convert_to_int(cipherKey[1, 3][1])];
            rot[1] = sbox[convert_to_int(cipherKey[2, 3][0]), convert_to_int(cipherKey[2, 3][1])];
            rot[2] = sbox[convert_to_int(cipherKey[3, 3][0]), convert_to_int(cipherKey[3, 3][1])];
            rot[3] = sbox[convert_to_int(cipherKey[0, 3][0]), convert_to_int(cipherKey[0, 3][1])];
            for (int i = 0; i < 4; i++)
            {
                string temp = "00000000";
                temp = xor(temp, HexToBin(cipherKey[i, 0]));
                temp = xor(temp, HexToBin(rot[i]));
                temp = xor(temp, HexToBin(RCON[i, Iteration]));
                result[i, 0] = BinToHex(temp).PadLeft(2, '0');
            }


            for (int i = 1; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    result[j, i] = BinToHex(xor(HexToBin(cipherKey[j, i]), HexToBin(result[j, i - 1]))).PadLeft(2, '0');
                }
            }
            return result;
        }



    }
}
