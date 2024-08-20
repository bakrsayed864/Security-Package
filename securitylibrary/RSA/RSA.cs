using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RSA
{
    public class RSA
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

        public int Encrypt(int p, int q, int M, int e)
        {
            // M pow e mod n
            int n = p * q;
            int cipher;

            cipher = fun_pow(M, e, n);

            return cipher;
            //throw new NotImplementedException();
        }
        public AES.ExtendedEuclid EE = new AES.ExtendedEuclid();
        public int Decrypt(int p, int q, int C, int e)
        {
            int n = p * q;
            int euler = (p - 1) * (q - 1);
            int d;

            d = EE.GetMultiplicativeInverse(e, euler);
            int main_pain = fun_pow(C, d, n);

            return main_pain;

            //throw new NotImplementedException();
        }
    }
}
