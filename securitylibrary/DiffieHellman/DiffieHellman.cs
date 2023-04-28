using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman 
    {

        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        { 
            List<int> results = new List<int>();
            int result = 1;

            int p = alpha;
            int ya, yb;
            int K1, K2;

            for (int i = 0; i < xa; i++)
                result = (result * p) % q;
            ya=result;
            result=1;
            for (int i = 0; i < xb; i++)
                result = (result * p) % q;
            yb=result;
            result=1;
            for (int i = 0; i < xa; i++)
                result = (result * yb) % q;
            K1 = result;
            result = 1;
            for (int i = 0; i < xb; i++)
                result = (result * ya) % q;
            K2 = result;
            result = 1;
            results.Add(K1);
            results.Add(K2);
            return results;
        }
    }
}
