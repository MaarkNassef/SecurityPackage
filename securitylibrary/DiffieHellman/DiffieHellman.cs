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
            int ya = helperfun(alpha, xa,q);
            int yb = helperfun(alpha, xb, q);
            List<int> keys = new List<int>();
            keys.Add(helperfun(yb, xa, q));
            keys.Add(helperfun(ya, xb, q));
            return keys;
        }
        public int helperfun(int x, int y, int z)
        {
            int result = 1;
            for (int i = 0; i < y; i++)
            {
                result = (result * x) % z;
            }
            return result;
        }
    }
}
