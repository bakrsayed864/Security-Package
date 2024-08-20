using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            String c_test;
            int indx = 0;
            for (int i = 1; i <= plainText.Length; i++)
            {
                c_test = Encrypt(plainText, i);
                if (c_test.Equals(cipherText))
                {
                    indx = i;
                    break;
                }
            }
            return indx;
        }

        public string Decrypt(string cipherText, int key)
        {

            String p_text = cipherText.ToUpper();
            int column;
            if (p_text.Length % key == 0)
                column = p_text.Length / key;
            else
                column = (p_text.Length + 1) / key;
            char[,] arr = new char[key, column];
            int ind = 0;
            for (int i = 0; i < key; i++)
            {
                for (int j = 0; j < column; j++)
                {
                    if (p_text.Length % key != 0 && (i == key - 1) && j == column - 1)
                        break;

                    else
                        arr[i, j] = p_text[ind];
                    if (ind != p_text.Length)
                        ind++;
                }
            }
            ind = 0;
            StringBuilder s = new StringBuilder(p_text);
            for (int i = 0; i < column; i++)
            {
                for (int j = 0; j < key; j++)
                {
                    if (p_text.Length % key != 0 && i == column - 1 && j == key - 1)
                        break;
                    else
                        s[ind] = arr[j, i];
                    if (ind != p_text.Length)
                        ind++;

                }
            }
            return s.ToString();
        }

        public string Encrypt(string plainText, int key)
        {

            String p_text = plainText.ToUpper();
            int column;
            if (p_text.Length % key == 0)
                column = p_text.Length / key;
            else
                column = (p_text.Length + 1) % key == 0 ? (p_text.Length + 1) / key : (p_text.Length + 2) / key;
            char[,] arr = new char[key, column];
            int ind = 0;
            for (int i = 0; i < column; i++)
            {
                for (int j = 0; j < key; j++)
                {
                    if (p_text.Length % key != 0 && i == column - 1 && (j == key - 1 || (key >= 3 && j == key - 2)))
                        continue;
                    else
                    {
                        arr[j, i] = p_text[ind];
                        if (ind != p_text.Length)
                            ind++;
                    }
                }
            }
            ind = 0;
            StringBuilder s = new StringBuilder(p_text);
            for (int i = 0; i < key; i++)
            {
                for (int j = 0; j < column; j++)
                {
                    if (p_text.Length % key != 0 && (i == key - 1 || (key >= 3 && i == key - 2)) && j == column - 1)
                        continue;
                    else
                    {
                        s[ind] = arr[i, j];
                        if (ind != p_text.Length)
                            ind++;
                    }
                }
            }
            return s.ToString();
        }
    }
}
