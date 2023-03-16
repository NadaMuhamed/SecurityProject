using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographic_Technique<string, string>
    {
        public string Analyse(string cipherText)
        {
            throw new NotImplementedException();
        }
        public string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();
            cipherText = cipherText.ToLower();
            string pallet = "abcdefghiklmnopqrstuvwxyz";
            HashSet<char> all = new HashSet<char>();
            Dictionary<char, KeyValuePair<int, int>> table = new Dictionary<char, KeyValuePair<int, int>>();
            Dictionary<KeyValuePair<int, int>, char> invTable = new Dictionary<KeyValuePair<int, int>, char>();
            foreach (char c in key + pallet)
            {
                all.Add(c);
            }

            int row = 0;
            int col = 0;

            foreach (char c in all)
            {
                table[c] = new KeyValuePair<int, int>(row, col);
                invTable[new KeyValuePair<int, int>(row, col)] = c;
                col++;
                if (col == 5)
                {
                    col = 0;
                    row++;
                }
            }

            string plaintext = "";
            int i = 0;
            while (i < cipherText.Length)
            {
                char c1, c2;
                int i1 = table[cipherText[i]].Key;
                int j1 = table[cipherText[i]].Value;
                int i2 = table[cipherText[i + 1]].Key;
                int j2 = table[cipherText[i + 1]].Value;

                if (i1 == i2)
                {
                    c1 = invTable[new KeyValuePair<int, int>(i1, (j1 + 4) % 5)];
                    c2 = invTable[new KeyValuePair<int, int>(i2, (j2 + 4) % 5)];
                }
                else if (j1 == j2)
                {
                    c1 = invTable[new KeyValuePair<int, int>((i1 + 4) % 5, j1)];
                    c2 = invTable[new KeyValuePair<int, int>((i2 + 4) % 5, j2)];
                }
                else
                {
                    c1 = invTable[new KeyValuePair<int, int>(i1, j2)];
                    c2 = invTable[new KeyValuePair<int, int>(i2, j1)];
                }

                plaintext += c1;
                plaintext += c2;
                i += 2;
            }

            if (plaintext[plaintext.Length - 1] == 'x')
            {
                plaintext = plaintext.Remove(plaintext.Length - 1);
            }

            string vowels = "aeiou";

            for (int j = 1; j < plaintext.Length; j++)
            {
                if (plaintext[j] == 'x' && plaintext[j - 1] == plaintext[j + 1])
                {
                    if (plaintext[j - 1] != 'l')
                    {
                        plaintext = plaintext.Remove(j, 1);
                    }
                    else if (vowels.Contains(plaintext[j - 2]))
                    {
                        plaintext = plaintext.Remove(j, 1);
                    }

                }
            }
            return plaintext;
        }

        public string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();
            string pallet = "abcdefghiklmnopqrstuvwxyz";
            HashSet<char> all = new HashSet<char>();
            Dictionary<char, KeyValuePair<int, int>> table = new Dictionary<char, KeyValuePair<int, int>>();
            Dictionary<KeyValuePair<int, int>, char> invTable = new Dictionary<KeyValuePair<int, int>, char>();
            foreach (char c in key + pallet)
            {
                all.Add(c);
            }

            int row = 0;
            int col = 0;

            foreach (char c in all)
            {
                table[c] = new KeyValuePair<int, int>(row, col);
                invTable[new KeyValuePair<int, int>(row, col)] = c;
                col++;
                if (col == 5)
                {
                    col = 0;
                    row++;
                }
            }
            string newPlain = "";

            int i = 0;
            while (i < plainText.Length)
            {
                char c1, c2, test;
                try
                {
                    test = plainText[i + 1];
                }
                catch (Exception e)
                {
                    test = 'x';
                }
                bool different = true;
                if (plainText[i] == test)
                {
                    c1 = plainText[i];
                    c2 = 'x';
                    different = false;

                }
                else if (plainText[i] == 'j' && test == 'i' || plainText[i] == 'i' && test == 'j')
                {
                    c1 = plainText[i];
                    c2 = 'x';
                    different = false;
                }
                else
                {
                    c1 = plainText[i];
                    c2 = test;
                }

                if (c1 == 'j')
                {
                    c1 = 'i';
                }
                if (c2 == 'j')
                {
                    c2 = 'i';
                }
                newPlain += c1;
                newPlain += c2;
                if (different)
                {
                    i += 2;
                }
                else
                {
                    i++;
                }

            }


            string ciphertext = "";
            i = 0;
            while (i < newPlain.Length)
            {
                char c1, c2;
                int i1 = table[newPlain[i]].Key;
                int j1 = table[newPlain[i]].Value;
                int i2 = table[newPlain[i + 1]].Key;
                int j2 = table[newPlain[i + 1]].Value;

                if (i1 == i2)
                {
                    c1 = invTable[new KeyValuePair<int, int>(i1, (j1 + 1) % 5)];
                    c2 = invTable[new KeyValuePair<int, int>(i2, (j2 + 1) % 5)];
                }
                else if (j1 == j2)
                {
                    c1 = invTable[new KeyValuePair<int, int>((i1 + 1) % 5, j1)];
                    c2 = invTable[new KeyValuePair<int, int>((i2 + 1) % 5, j2)];
                }
                else
                {
                    c1 = invTable[new KeyValuePair<int, int>(i1, j2)];
                    c2 = invTable[new KeyValuePair<int, int>(i2, j1)];
                }

                ciphertext += c1;
                ciphertext += c2;
                i += 2;
            }
            return ciphertext.ToUpper();

        }
    }
}
