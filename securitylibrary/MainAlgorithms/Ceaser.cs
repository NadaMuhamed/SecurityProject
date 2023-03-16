using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {

        //first step
        //assign numeric equivalent for each letter
        //second step
        //for each p.t letter substitute with c.t letter c where index of c
        //c=(index of p + key) mod 26
        public string Encrypt(string plainText, int key)
        {
            string LETTERS = "abcdefghijklmnopqrstuvwxyz";
            int ASSIGNNumber(char EACH_l)
            {
                int equivalentletter = 0;
                while (equivalentletter < 26)
                {
                    if (EACH_l == LETTERS[equivalentletter]) return equivalentletter;
                    equivalentletter++;
                }

                return -1;
            }
            int PlainTextLength = plainText.Length;
            string Cipher_Text = "";
            int counter = 0;
            while (counter < PlainTextLength)
            {
                if (char.IsLetter(plainText[counter]))
                {   //Equation
                    int plain_text_Index = ((key + ASSIGNNumber(plainText[counter])) % 26);
                    Cipher_Text += char.ToUpper(LETTERS[plain_text_Index]);
                }
                else
                {
                    Cipher_Text += plainText[counter];
                }
                counter++;
            }

            return Cipher_Text;

        }

        public string Decrypt(string cipherText, int key)
        {
            string LETTERS2 = "abcdefghijklmnopqrstuvwxyz";
            int ASSIGNNumber2(char EACH_l)
            {
                int equivalentletter = 0;
                while (equivalentletter < 26)
                {
                    if (EACH_l == LETTERS2[equivalentletter]) return equivalentletter;
                    equivalentletter++;
                }

                return -1;
            }
            cipherText = cipherText.ToLower();
            int CipherTextLength = cipherText.Length;
            string Plain_Text = "";
            int counter2 = 0;
            while (counter2 < CipherTextLength)
            {
                if (char.IsLetter(cipherText[counter2]))
                {
                    int cipherTextletterIndx = ((ASSIGNNumber2(cipherText[counter2]) - key) % 26);
                    if (cipherTextletterIndx < 0)
                    {
                        cipherTextletterIndx += 26;
                    }
                    Plain_Text += LETTERS2[cipherTextletterIndx];
                }
                else
                {
                    Plain_Text += cipherText[counter2];
                }
                counter2++;
            }

            return Plain_Text;
        }

        public int Analyse(string plainText, string cipherText)
        {
            string LETTERS3 = "abcdefghijklmnopqrstuvwxyz";
            int ASSIGNNumber3(char EACH_l)
            {
                int equivalentletter = 0;
                while (equivalentletter < 26)
                {
                    if (EACH_l == LETTERS3[equivalentletter]) return equivalentletter;
                    equivalentletter++;
                }

                return -1;
            }
            if (plainText.Length != cipherText.Length)
            { return -1; }
            int re1 = ASSIGNNumber3(plainText[0]);
            int re2 = ASSIGNNumber3(char.ToLower(cipherText[0]));
            int final = ((re2 - re1) < 0) ? (re2 - re1) + 26 : (re2 - re1) % 26;
            return final;
        }
    }
}
