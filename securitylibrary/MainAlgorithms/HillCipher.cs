using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class MatricesHelper
    {
        
        public List<int> StrMap(string s)
        {
            s = s.ToLower();
            List<int> list = new List<int>();
            foreach (char c in s)
            {
                list.Add(c - 'a');
            }
            return list;
        }
        public List<List<int>> Transpose(List<List<int>> list)
        {
            int row = list.Count;
            int col = list[0].Count;
            List<List<int>> res = new List<List<int>>();
            for(int i = 0; i < col; i++)
            {
                List<int> tmp = new List<int>();
                for(int j = 0; j < row; j++)
                {
                    tmp.Add(list[j][i]);
                }
                res.Add(tmp);
            }
            return res;
        }
        public int GCD(int num1, int num2)
        {
            if (num2 == 0) return num1; return GCD(num2, num1 % num2);
        }
        public int Mod(int x1, int x2)
        {
            if (x1 < 0)
                return ((x1 % x2) + x2) % x2;
            return x1 % x2;
        }
        public List<List<int>> SubList(List<List<int>> matrix, int row_idx, int col_idx)
        {
            List<List<int>> res = new List<List<int>>();
            for(int i = 0; i < matrix.Count; i++)
            {
                if(i != row_idx)
                {
                    List<int> temp = new List<int>();
                    for (int j = 0; j < matrix[i].Count; j++)
                    {
                        if (j != col_idx)
                        {
                            temp.Add(matrix[i][j]);
                        }
                    }
                    res.Add(temp);
                }
            }
            return res;
        }
        public int Det(List<List<int>> matrix)
        {
            int n = matrix.Count, det = 0;
            if (n == 1)
            {
                return matrix[0][0];
            } else if(n == 2)
            {
                return (matrix[0][0] * matrix[1][1]) - (matrix[1][0] * matrix[0][1]);
            }
            else
            {
                int sign = 1;
                for(int i = 0; i < n; i++)
                {
                    List<List<int>> sub = SubList(matrix, 0, i);
                    det += sign * matrix[0][i] * Det(sub);
                    sign *= -1;
                }
            }
            while(det < 0)
            {
                det += 26;
            }
            while (det >= 26)
            {
                det -= 26;
            }
            return det;
        }
        public List<List<int>> Multiply(List<List<int>> l1, List<List<int>> l2)
        {
            if (l1[0].Count != l2.Count)
            {
                throw new Exception();
            }
            int m = l1.Count, n = l2[0].Count;
            List<List<int>> res = new List<List<int>>();
            for(int i = 0; i < m; i++)
            {
                List<int> temp = new List<int>();
                for(int j = 0; j < n; j++)
                {
                    int val = 0;
                    for(int k = 0; k < m ; k++)
                    {
                        val += l1[i][k] * l2[k][j];
                    }
                    temp.Add(val % 26);
                }
                res.Add(temp);
            }
            return res;
        }
        public List<List<int>> GenerateMatrix(List<int> list, int m)
        {
            List<List<int>> matrix = new List<List<int>>();
            List<int> temp = new List<int>();
            for( int i = 0; i < list.Count; i++)
            {
                if(i % m == 0 && i != 0)
                {
                    matrix.Add(temp);
                    temp = new List<int>();
                }
                temp.Add(list[i]);
            }
            while(temp.Count != m)
            {
                temp.Add(23);
            }
            matrix.Add(temp);
            return matrix;
        }
        public List<List<int>> CloneMatrix(List<List<int>> l)
        {
            List<List<int>> res = new List<List<int>>();
            for(int i = 0; i < l.Count; i++)
            {
                List<int> temp = new List<int>();
                for(int j = 0; j < l[i].Count; j++)
                {
                    temp.Add(l[i][j]);
                }
                res.Add(temp);
            }
            return res;
        }
        public List<List<int>> Inverse(List<List<int>> matrix)
        {
            int det = Mod(Det(matrix),26);
            int b = 0;
            bool workable = false;
            if (GCD(det, 26) == 1 && det != 0)
            {
                for (int i = 1; i < 26; i++)
                {
                    if ((i * det) % 26 == 1)
                    {
                        b = i;
                        workable = true;
                        break;
                    }
                }
            }
            if(workable){
                List<List<int>> res = CloneMatrix(matrix);
                int sign = 1;
                
                for (int i = 0; i < matrix.Count; i++)
                {
                    for (int j = 0; j < matrix[i].Count; j++)
                    {
                        
                        try
                        {
                            List<List<int>> sub = SubList(matrix, i, j);
                            int k = Mod((sign*b*Mod(Det(sub),26)), 26);
                            sign *= -1;
                            //while(k >= 26)
                            //{
                            //    k -= 26;
                            //}
                            res[i][j] = k;
                        }
                        catch (DivideByZeroException d)
                        {
                            throw new Exception();
                        }
                    }
                }
                res = Transpose(res);
                return res;
            }
            throw new Exception();
        }
    }
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher :  ICryptographicTechnique<List<int>, List<int>>
    {
        
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            //List<int> l1 = new List<int>() { 17,17,5};
            //List<int> l2 = new List<int>() { 21,18,21 };
            //List<int> l3 = new List<int>() { 2,2,19};
            //List<int> l4 = new List<int>() {11,13,18,7,3,11,4,22,12,19,17,22};
            //List<int> l5 = new List<int>() {17,17,5,21,18,21,2,2,19};


            //List<List<int>> ll = new List<List<int>> { l1, l2, l3};

            ////List<List<int>> filter = new List<List<int>> {l4,l4,l4};

            //MatricesHelper helper = new MatricesHelper();
            ////List<List<int>> temp = helper.GenerateMatrix(l1, 3);
            //int x = helper.GCD(12, 9);
            ////List<int> temp = helper.StrMap("menna");
            //List<List<int>> temp = helper.Inverse(ll);
            //int n = helper.Mod(-100, 26);
            //List<int> mini_test = Decrypt(l4,l5);

            MatricesHelper helper = new MatricesHelper();
            int m = 2;

            List<List<int>> pt_matrix = helper.GenerateMatrix(plainText,m);
            List<List<int>> ct_matrix = helper.GenerateMatrix(cipherText, m);
            pt_matrix = helper.Inverse(pt_matrix);
            List<List<int>> key_matrix = helper.Multiply(ct_matrix, pt_matrix);

            List<int> key = new List<int>();
            for (int i = 0; i < key_matrix[0].Count; i++)
            {
                for (int j = 0; j < key_matrix.Count; j++)
                {
                    key.Add(helper.Mod(key_matrix[j][i], 26));
                }
            }
            return key;

            //int x = helper.Det(ll);
            throw new NotImplementedException();
        }


        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            MatricesHelper helper = new MatricesHelper();
            int m = (int)Math.Sqrt(key.Count);
            List<List<int>> key_matrix = helper.GenerateMatrix(key,m);
            List<List<int>> key_matrix_inverse = helper.Inverse(key_matrix);
            //key_matrix_inverse = helper.Transpose(key_matrix_inverse);
            List<List<int>> ct_matrix = helper.GenerateMatrix(cipherText, m);
            ct_matrix = helper.Transpose(ct_matrix);
            List<List<int>> pt_matrix = helper.Multiply(key_matrix_inverse, ct_matrix);
            //{ 19, 16, 18, 18, 24, 15, 10, 14, 16, 21, 8, 22 }
            List<int> pt = new List<int>();
            for (int i = 0; i < pt_matrix[0].Count; i++)
            {
                for (int j = 0; j < pt_matrix.Count; j++)
                {
                    pt.Add(helper.Mod(pt_matrix[j][i],26));
                }
            }
            return pt;

            throw new NotImplementedException();
        }


        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            //{1,2,3,4,5,6}
            MatricesHelper helper = new MatricesHelper();
            int m = (int) Math.Sqrt(key.Count);
            List<List<int>> key_matrix = helper.GenerateMatrix(key, m);
            List<List<int>> pt_matrix = helper.GenerateMatrix(plainText, m);
            pt_matrix = helper.Transpose(pt_matrix);
            List <List<int>> ct_matrix = helper.Multiply(key_matrix, pt_matrix);
            //{ 19, 16, 18, 18, 24, 15, 10, 14, 16, 21, 8, 22 }
            List<int> ct = new List<int>();
            for(int i = 0; i < ct_matrix[0].Count; i++)
            {
                for(int j = 0; j < ct_matrix.Count; j++)
                {
                    ct.Add(ct_matrix[j][i]);
                }
            }
            return ct;
            //throw new NotImplementedException();
        }


        public List<int> Analyse3By3Key(List<int> plainText, List<int> cipherText)
        {
            throw new NotImplementedException();
        }

    }
}
