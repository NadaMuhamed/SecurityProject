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
    public class TripleDES : ICryptographicTechnique<string, List<string>>
    {
        public string Decrypt(string cipherText, List<string> key)
        {

            DES desobject = new DES();
            string tripledesresult = desobject.Decrypt(desobject.Encrypt(desobject.Decrypt(cipherText, key[0]), key[1]), key[0]);
            return tripledesresult;
        }

        public string Encrypt(string plainText, List<string> key)
        {
            DES desobject = new DES();


            string result = desobject.Encrypt(plainText, key[0]);

            string result2 = desobject.Decrypt(result, key[1]);

            return desobject.Encrypt(result2, key[0]); ;
        }

        public List<string> Analyse(string plainText, string cipherText)
        {
            throw new NotSupportedException();
        }

    }
}
