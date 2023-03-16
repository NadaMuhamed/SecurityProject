using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            int key = 1;
            plainText = plainText.ToUpper();
            cipherText = cipherText.ToUpper();
            string ct = "";
            for (int k = 1; k < plainText.Length; k++)
            {
                ct = "";
                for (int i = 0; i < k; i++)
                    for (int j = i; j < plainText.Length; j += k)
                        ct += plainText[j];
                if (ct == cipherText)
                {
                    key = k;
                    break;
                }
            }
            return key;
        }

        public string Decrypt(string cipherText, int key)
        {
            string pt = "";
            int n = (int)Math.Ceiling((float)cipherText.Length / key);
            for (int i = 0; i < n; i++)
                for (int j = i; j < cipherText.Length; j += n)
                    pt += cipherText[j];
            return pt;
        }

        public string Encrypt(string plainText, int key)
        {
            string ct = "";
            for (int k = 0; k < key; k++)
                for (int i = k; i < plainText.Length; i += key)
                    ct += plainText[i];
            return ct;
        }
    }
}