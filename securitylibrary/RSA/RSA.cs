using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SecurityLibrary.DiffieHellman;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        public int Encrypt(int p, int q, int M, int e)
        {
            DiffieHellman.DiffieHellman dh = new DiffieHellman.DiffieHellman();
            int C = dh.helperfun(M, e, p * q);
            return C;
        }

        public int Decrypt(int p, int q, int C, int e)
        {
            DiffieHellman.DiffieHellman d = new DiffieHellman.DiffieHellman();
            AES.ExtendedEuclid extendedEuclid = new AES.ExtendedEuclid();
            int mi = extendedEuclid.GetMultiplicativeInverse(e, (p-1) * (q-1));
            int M = d.helperfun(C, mi, p * q);
            return M;
        }
    }
}
