using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman 
    {
        public int mod(int a, int b, int c)
        {
            int result = 1;
            for (int i = 0; i < b; i++)
                result = (result * a) % c;
            
            return result;
        }
        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        { 
            List<int> result = new List<int>();
            int p = alpha;
            int ya, yb;
            int K1, K2;
            ya = mod(p, xa, q);
            yb = mod(p, xb, q);
            K1 = mod(yb, xa, q);
            K2 = mod(ya, xb, q);
            result.Add(K1);
            result.Add(K2);
            return result;
        }
    }
}
