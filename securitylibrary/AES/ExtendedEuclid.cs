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
            //throw new NotImplementedException();
            int divided = number;
            int divisor = baseN;
            int A1 = 1, A2 = 0, A3 = divisor;
            int B1 = 0, B2 = 1, B3 = divided;
            while (B3 != 0 && B3 != 1)
            {
                int Qres = A3 / B3;
                int temp1 = A1 - (Qres * B1);
                int temp2 = A2 - (Qres * B2);
                int temp3 = A3 - (Qres * B3);
                A1 = B1;
                A2 = B2;
                A3 = B3;
                B1 = temp1;
                B2 = temp2;
                B3 = temp3;
            }
            if (B3 == 0)
            {
                return -1;
            }
            else if (B3 == 1)
            {
                if (B2 < -1)
                {
                    return B2 + baseN;
                }
                else
                {
                    return B2;
                }
            }
            return -1;
        }
    }
}
