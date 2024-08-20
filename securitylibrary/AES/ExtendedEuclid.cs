using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    public class ExtendedEuclid 
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="number"></param>
        /// <param name="baseN"></param>
        /// <returns>Mul inverse, -1 if no inv</returns>
        public int GetMultiplicativeInverse(int number, int baseN)
        {
            int A1 = 1, A2 = 0, A3 = baseN;
            int B1 = 0, B2 = 1, B3 = number;
            int Q = 0;
            int temp1=0, temp2=0, temp3=0;

            while (B3!=1 && B3!=0)
            {
                Q = A3 / B3;
                temp1 = A1 - (B1 * Q);
                temp2 = A2 - (B2 * Q);
                temp3 = A3 - (B3 * Q);

                A1 = B1;
                A2 = B2;
                A3 = B3;

                B1 = temp1;
                B2 = temp2;
                B3 = temp3;

            }
            if (B3 == 1)
            {
               while (B2 < 0)
                    B2 += baseN;
                
                return B2;
            }
            if (B3 == 0)
                return -1;

            //throw new NotImplementedException();
            return -1;
        }
    }
}
