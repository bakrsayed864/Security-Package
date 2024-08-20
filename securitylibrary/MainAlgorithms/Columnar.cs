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

            List<int> key = new List<int>();
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            char first = cipherText[0], second = cipherText[1];
            int col = 1;
            int start = 0, end = 0;

            if (first == second)
            {
                start = plainText.IndexOf(first);
                end = plainText.IndexOf(second, start + 1);
                if (end - start == 1)
                {
                    start++;
                    end = plainText.IndexOf(second, start + 1);
                    col = end - start;

                }
                else
                    col = end - start;


            }
            else
            {
                start = plainText.IndexOf(first);
                end = plainText.IndexOf(second);
                if (end - start == 1)
                {
                    start++;
                    end = plainText.IndexOf(second, start + 1);
                    col = end - start;
                }
                else
                    col = end - start;


            }


            int row = 0;
            if (plainText.Length % col == 0)
                row = plainText.Length / col;
            else
            {
                int dif = col - (plainText.Length / col);
                for (int i = 0; i < dif; i++)
                    plainText += "0";

                row = (plainText.Length / col);
            }

            char[,] arr_plain = new char[row, col];
            int index_plain = 0;
            for (int i = 0; i < row; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    arr_plain[i, j] = plainText[index_plain];
                    index_plain++;
                }
            }


            string[] subs = new string[col];
            int index_subs = 0;
            for (int j = 0; j < col; j++)
            {
                for (int i = 0; i < row; i++)
                {
                    if (arr_plain[i, j] == '0')
                        continue;
                    else
                    {
                        subs[index_subs] += arr_plain[i, j];

                    }

                }

                index_subs++;
            }


            double k = 0;
            double w = 0;
            for (int i = 0; i < col; i++)
            {
                k = cipherText.IndexOf(subs[i]);

                w = k / (double)row;

                w = Math.Ceiling(w);

                w++;
                key.Add((int)w);

            }

            return key;
        }

        public string Decrypt(string cipherText, List<int> key)
        {


            cipherText = cipherText.ToLower();
            int size_key = key.Count();

            int size_cipher = cipherText.Length;

            int dif = size_key - (size_cipher % size_key);

            int row;
            bool find = false;
            if (size_cipher % size_key != 0)
            {
                row = (size_cipher / size_key) + 1;
                find = true;
            }
            else
                row = (size_cipher / size_key);


            int col = size_key;

            int col_change = col - dif;
            int index = 0;
            char[,] arr = new char[row, col];

            int place = 0;

            for (int j = 1; j <= size_key; j++)
            {
                place = key.IndexOf(j);
                for (int i = 0; i < row; i++)
                {
                    if (j > col_change && i == row - 1 && find == true)
                    {
                        arr[i, place] = '0';
                    }
                    else
                    {
                        arr[i, place] = cipherText[index];
                        index++;
                    }

                }
            }

            string plain = "";


            for (int k = 0; k < row; k++)
            {

                for (int j = 0; j < col; j++)
                {
                    if (arr[k, j] == '0')
                        continue;
                    else
                        plain += arr[k, j];
                }

            }

            return plain;

        }




        public string Encrypt(string plainText, List<int> key)
        {

            plainText = plainText.ToLower();
            int size_key = key.Count();

            int size_plain = plainText.Length;

            int dif = size_key - (size_plain / size_key);

            int row;

            if (size_plain % size_key != 0)
            {
                row = (size_plain / size_key) + 1;
                for (int j = 0; j < dif; j++)
                {
                    plainText += "x";
                }
            }
            else
                row = (size_plain / size_key);


            int col = size_key;
            int index = 0;
            char[,] arr = new char[row, col];

            for (int i = 0; i < row; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    arr[i, j] = plainText[index];
                    index++;
                }
            }


            string cipher = "";


            int key_value = 0;

            for (int k = 1; k <= col; k++)
            {
                key_value = key.IndexOf(k);
                for (int j = 0; j < row; j++)
                {
                    if (arr[j, key_value] == 'x')
                        continue;
                    else
                        cipher += arr[j, key_value];
                }

            }

            return cipher;
        }
    }
}
