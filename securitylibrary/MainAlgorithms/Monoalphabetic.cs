using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{

    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {

        public string Analyse(string plainText, string cipherText)
        {
            string letters = "abcdefghijklmnopqrstuvwxyz";
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            StringBuilder
                alphabet = new StringBuilder(letters),
                     key = new StringBuilder("                          ");

            for (int i = 0; i < plainText.Length; i++)
            {
                for (int j = 0; j < letters.Length; j++)

                    if (letters[j] == plainText[i])
                        key[j] = cipherText[i];

                for (int j = 0; j < letters.Length; j++)

                    if (letters[j] == cipherText[i])
                        alphabet[j] = '0';
            }
            for (int i = 0; i < alphabet.Length; i++)

                for (int j = i; j < key.Length; j++)

                    if (alphabet[i] != '0' && key[j] == ' ')
                    {
                        key[j] = alphabet[i];
                        alphabet[i] = '0';
                    }
            return key.ToString();
        }

        public string Decrypt(string cipherText, string key)
        {
            string plain = "";
            char referance = 'a';
            cipherText = cipherText.ToLower();

            for (int i = 0; i < cipherText.Length; i++)

                if (char.IsLetter(cipherText[i]))
                    plain += (char)((int)key.IndexOf(cipherText[i]) + referance);

                else
                    plain += cipherText[i];

            return plain;
        }

        public string Encrypt(string plainText, string key)
        {
            string cipher = "";
            char referance = 'a';
            plainText = plainText.ToLower();

            for (int i = 0; i < plainText.Length; i++)

                if (char.IsLetter(plainText[i]))
                    cipher += key[plainText[i] - referance];

                else
                    cipher += plainText[i];

            return cipher;
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
            IDictionary<char, int> frq = new Dictionary<char, int>();


            return cipher;
        }
    }
}
