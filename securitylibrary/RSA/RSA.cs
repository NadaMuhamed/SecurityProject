using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        public int Encrypt(int p, int q, int M, int e)
        {
            int number = p * q;
            int Result = 0;
            int index = 0;
            while (index < e)
            {

                if (index == 0)
                {
                    Result = M % number;
                }
                else
                {
                    Result = (Result * M) % number;

                }
                index++;

            }
            return Result;
        }

        public int Decrypt(int p, int q, int C, int e)
        {
            int GET_Gcd(int number1, int number2)
            {
                int gcd = 0;
                bool flag = false;
                if (number1 < number2)
                {
                    gcd = number1;
                    number1 = number2;
                    number2 = gcd;
                }
                if (number2 == 0)
                {
                    flag = true;
                }
                while (number2 != 0)
                {
                    gcd = number1 % number2;
                    number1 = number2;
                    number2 = gcd;
                }
                return number1;
            }

            int rakm = p * q;

            int cheakn = (p - 1) * (q - 1);

            int index1 = -1;

            int index2 = -1;

            index1 = 0;
            while (index1 < rakm)
            {
                int n = index1 * e;
                if (n % cheakn == 1)
                    break;
                index1++;
            }
            int index3 = 0;
            while (index3 < index1)
            {
                if (index3 == 0)
                {
                    index2 = C % rakm;
                }
                else
                {
                    int result = (index2 * C);
                    index2 = result % rakm;
                }
                index3++;
            }

            return index2;
        }
    }
}
