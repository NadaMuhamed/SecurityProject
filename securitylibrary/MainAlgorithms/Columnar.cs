using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            //PT: "computerscience"
            //CT: "cusnpremeieotcc"
            /*
             *c o m p
             *u t e r
             *s c i e
             *n c e
            */
            cipherText = cipherText.ToLower();
            List<int> key = new List<int>();
            int key_length = 0;
            for (int cut_length = 1; cut_length < plainText.Length - 1; cut_length++)
            {
                int l = 0;
                List<string> my_map = new List<string>();
                string str = "";
                foreach (char c in plainText)
                {
                    str += c;
                    l++;
                    if (l % cut_length == 0)
                    {
                        my_map.Add(str);
                        str = "";
                    }
                }
                my_map.Add(str);
                str = "";
                for (int i = 0; i < my_map.Count; i++)
                {
                    if (my_map[i] != "")
                    {
                        str += my_map[i][0];
                    }
                }
                if (cipherText.Contains(str))
                {
                    key_length = cut_length;
                    List<string> menna = new List<string>();
                    List<int> menna_idx = new List<int>();
                    Dictionary<int, int> menna_map = new Dictionary<int, int>();
                    for (int i = 0; i < key_length; i++)
                    {
                        string sub_str = "";
                        for (int j = 0; j < my_map.Count; j++)
                        {
                            try
                            {
                                sub_str += my_map[j][i];
                            }
                            catch (Exception e)
                            {

                            }
                        }
                        menna.Add(sub_str);
                        menna_idx.Add(cipherText.IndexOf(sub_str));
                    }
                    List<int> temp = new List<int>(menna_idx);
                    temp.Sort();
                    for (int i = 0; i < temp.Count; i++)
                    {
                        menna_map[temp[i]] = i + 1;
                    }
                    foreach (int idx in menna_idx)
                    {
                        key.Add(menna_map[idx]);
                    }
                    break;
                }
            }
            return key;
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            // CT : "ttna aptm tsuo aodw coi knl pet"
            // D: 3, R: 4
            // n_4 = 7 - 3 = 4
            // n_3 = 3
            // { 3, 2, 0, 1, 4, 5, 6 }
            /*
             *[0] [3] t t n a
             *[1] [2] a p t m
             *[2] [0] t s u o
             *[3] [1] a o d w
             *[4] [4] c o i
             *[5] [5] k n l
             *[6] [6] p e t
             */
            /*
             * a o d w
             * t s u o
             * t t n a
             * a p t m
             * c o i
             * k n l
             * p e t
             */
            // 
            // "attackpostponeduntiltwoam"
            int D = (int)Math.Floor((float)cipherText.Length / key.Count), R = cipherText.Length % key.Count;
            int NR = key.Count - D;
            if (R == 0)
            {
                R = D;
                NR = D;
            }

            Dictionary<int, int> index_mapping = new Dictionary<int, int>();
            for (int i = 0; i < key.Count; i++)
            {
                index_mapping[i] = key[i] - 1;
            }
            List<string> my_map = new List<string>();
            //for memory (Mnyla)
            Dictionary<int, string> menna = new Dictionary<int, string>();

            string str = "";
            int iter = 0, l = 0, L = R;
            foreach (char c in cipherText)
            {
                str += c;
                l++;
                if (l == L)
                {
                    l = 0;
                    my_map.Add(str);
                    iter++;
                    str = "";
                }
                if (iter == NR)
                {
                    L = D;
                }
            }
            int x;
            string pt = "";
            // { 3, 2, 0, 1, 4, 5, 6 }
            for (int i = 0; i < NR; i++)
            {
                foreach (int row in key)
                {
                    try
                    {
                        x = row - 1;
                        char c = my_map[x][i];
                        pt += c;
                    }
                    catch (Exception e)
                    {
                        break;
                    }
                }
            }
            return pt.ToLower();
        }

        public string Encrypt(string plainText, List<int> key)
        {
            //PT: "attackp ostpone duntilt woam"
            //{ 4, 3, 1, 2, 5, 6, 7 }
            /* 4 3 1 2 5 6 7
             * a t t a c k p
             * o s t p o n e
             * d u n t i l t
             * w o a m x x x
             */
            //ttna aptm tsuo aodw coix knlx petx
            string ct = "";
            int n = key.Max(), l = 0;
            int row_num = (int)Math.Ceiling((float)plainText.Length / n);
            List<string> my_map = new List<string>();
            string str = "";
            foreach (char c in plainText)
            {
                str += c;
                l++;
                if (l % n == 0)
                {
                    my_map.Add(str);
                    str = "";
                }
            }
            while (str.Length < n)
            {
                str += 'x';
            }
            my_map.Add(str);
            Dictionary<int, int> index_mapping = new Dictionary<int, int>();
            for (int i = 0; i < key.Count; i++)
            {
                index_mapping[key[i]] = i;
            }
            for (int i = 1; i <= n; i++)
            {
                string sub_str = "";
                for (int j = 0; j < row_num; j++)
                {
                    sub_str += my_map[j][index_mapping[i]];
                }
                ct += sub_str;
            }
            return ct.ToUpper();
        }
    }
}