using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    
    public class AES : CryptographicTechnique
    {
        public override string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }

        public override string Encrypt(string plainText, string key)
        {
            throw new NotImplementedException();
        }
        
        public string xor(string mat1,string mat2)
        {
            string xOR = "";
            return xOR;
        }
        public string shift(string mat)
        {
            return mat;
        }
        public string galois(string mat)
        {
            return mat;
        }
        public string rotat(string mat)
        {
            return mat;
        }
        public string convert_to_hexa(string stat)
        {
            return stat;
        }
        public string convert_to_int(string stat)
        {
            return stat;
        }
        public string key_gen(string key,int iteration)
        {
            string new_key = "";

            string[,] Round_mat = new string[4, 10]
            {
                {  "01", "02", "04", "08", "10", "20", "40", "80", "1b", "36"},

                {  "00", "00", "00", "00", "00", "00", "00", "00", "00", "00"},

                {  "00", "00", "00", "00", "00", "00", "00", "00", "00", "00"},

                {  "00", "00", "00", "00", "00", "00", "00", "00", "00", "00"}

            };

            return new_key;
        }
       
        
        public string sub_byte(string stat)
        {

            return stat;
        }
        public string shift_rows(string key, string plantext)
        {
            string new_key = "";



            return new_key;
        }
        public string mix_columns(string key, string plantext)
        {
            string new_key = "";



            return new_key;
        }
        public string add_round_key(string key,string plantext)
        {
            string new_key = "";



            return new_key;
        }


    }
}
