using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RC4
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class RC4 : CryptographicTechnique
    {

        public int[] KeySchedule(int[] key, int ptLength)
        {
            int[] S = new int[256];
            int[] T = new int[256];
            for (int i = 0; i < S.Length; i++)
            {
                S[i] = i;
                T[i] = key[i % key.Length];
            }
            int j = 0;
            for (int i = 0; i < S.Length; i++)
            {
                j = (j + S[i] + T[i]) % S.Length;
                int temp = S[i];
                S[i] = S[j];
                S[j] = temp;
            }

            int ii = 0, index;
            j = 0;

            int[] newKey = new int[ptLength];
            for (int k = 0; k < ptLength; k++)
            {
                ii = (ii + 1) % S.Length;
                j = (j + S[ii]) % S.Length;
                int temp = S[ii];
                S[ii] = S[j];
                S[j] = temp;
                index = (S[ii] + S[j]) % S.Length;
                int h = S[index];
                newKey[k] = h;
            }

            return newKey;
        }
        public int[] StrToIntArr(string str)
        {
            int[] res;
            if (str[0] == '0' && str[1] == 'x')
            {
                res = new int[(str.Length - 2)/2];
                int index = 0;
                for (int i = 2; i < str.Length; i += 2)
                {
                    string temp = "";
                    temp += str[i];
                    temp += str[i + 1];
                    res[index] = int.Parse(temp, System.Globalization.NumberStyles.HexNumber);
                    index++;
                }
            }
            else
            {
                res = new int[str.Length];
                int i = 0;
                foreach (char c in str)
                {
                    res[i] = (int)c;
                    i++;
                }
            }
            return res;
        }
        public string IntToHex(int[] arr)
        {
            string res = "";
            foreach(int i in arr)
            {
                res += i.ToString("X");
            }
            return res;
        }
        public string HexToBin(string hex)
        {
            return Convert.ToString(Convert.ToInt32(hex, 16), 2).PadLeft(8, '0');
        }
        public string BinToHex(string bin)
        {
            return Convert.ToInt32(bin, 2).ToString("X");
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

        public override string Decrypt(string cipherText, string key)
        {
            return Encrypt(cipherText, key);
        }

        public override  string Encrypt(string plainText, string key)
        {
            int[] keyArr = StrToIntArr(key);
            int[] textArr = StrToIntArr(plainText);
            int[] newKey = KeySchedule(keyArr, textArr.Length);
            string hexPlain = IntToHex(textArr);
            string hexKey = IntToHex(newKey);
            string result = "";
            for(int i = 0; i < hexPlain.Length; i += 2)
            {
                string temp1 = "", temp2 = "";
                temp1 += hexPlain[i];
                temp1 += hexPlain[i + 1];
                temp2 += hexKey[i];
                temp2 += hexKey[i + 1];
                string res = xor(HexToBin(temp1), HexToBin(temp2));
                result += BinToHex(res).ToLower();
            }
            if (plainText[0] == '0' && plainText[1] == 'x')
            {
                return "0x" +result;
            }
            else
            {
                var bytes = new byte[result.Length / 2];
                for (var i = 0; i < bytes.Length; i++)
                {
                    bytes[i] = Convert.ToByte(result.Substring(i * 2, 2), 16);
                }

                return Encoding.Default.GetString(bytes);
            }
            //throw new NotImplementedException();
        }
    }
}
