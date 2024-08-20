using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman
    {
        public int fun_pow(int alpha, int priv_num, int prime)
        {
            int f_res = 1;
            for (int i = 0; i < priv_num; i++)
            {
                f_res *= alpha;
                f_res %= prime;
            }

            return f_res;
        }
        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            int prime = q;
            int priv_a = xa;
            int priv_b = xb;

            List<int> secret = new List<int>();
            int sec_a, sec_b;
            int pub_a, pub_b;

            pub_a = fun_pow(alpha, priv_a, prime);
            pub_b = fun_pow(alpha, priv_b, prime);

            sec_a = fun_pow(pub_b, priv_a, prime);
            sec_b = fun_pow(pub_a, priv_b, prime);

            secret.Add(sec_a);
            secret.Add(sec_b);
            return secret;

            //throw new NotImplementedException();
        }
    }
}
