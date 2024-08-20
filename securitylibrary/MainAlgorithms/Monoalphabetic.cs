using System;
using System.Collections.Generic;
using System.Linq;
//using System.Numerics;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();

            string new_plain = "";


            foreach (char value in plainText)
            {

                if (new_plain.IndexOf(value) == -1)
                {

                    new_plain += value;
                }
            }

            string new_cipher = "";


            foreach (char value in cipherText)
            {

                if (new_cipher.IndexOf(value) == -1)
                {

                    new_cipher += value;
                }
            }

            char[] key = new char[26];
            int index;
            char i;
            int count = 0;






            int[] extention = new int[26 - new_plain.Length];


            int count_extention = 0;
            for (char c = 'a'; c <= 'z'; c++)
            {
                index = plainText.IndexOf(c);
                if (index != -1)
                {
                    i = cipherText[index];
                    key[count] = i;
                }
                else
                {
                    extention[count_extention] = count;
                    count_extention++;
                }
                count++;

            }

            int size = 26 - new_plain.Length;
            int x;
            int y = 0;
            for (char j = 'a'; j < 'z'; j++)
            {
                if (new_cipher.IndexOf(j) == -1)
                {
                    x = extention[y];
                    key[x] = j;
                    y++;

                }


            }

            return new string(key).ToLower();
        }




        public string Decrypt(string cipherText, string key)
        {
            string alpha = "abcdefghijklmnopqrstuvwxyz";
            key = key.ToLower();
            cipherText = cipherText.ToLower();
            char[] plain_text = new char[cipherText.Length];
            int index;
            for (int i = 0; i < cipherText.Length; i++)
            {

                index = key.IndexOf(cipherText[i]);
                plain_text[i] = alpha[index];

            }


            return new string(plain_text).ToLower();
        }

        public string Encrypt(string plainText, string key)
        {

            string alpha = "abcdefghijklmnopqrstuvwxyz";
            key = key.ToLower();
            plainText = plainText.ToLower();
            char[] cipher = new char[plainText.Length];
            int index;
            for (int i = 0; i < plainText.Length; i++)
            {

                index = alpha.IndexOf(plainText[i]);
                cipher[i] = key[index];

            }

            return new string(cipher).ToLower();

        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        /// 
        public struct mix
        {
            public int num;
            public char s;
        }
        public string AnalyseUsingCharFrequency(string cipher)
        {


            mix[] arr = new mix[26];
            string alpha = "etaoinsrhldcumfpgwybvkxjqz";
            cipher = cipher.ToLower();
            char[] cipher_text = cipher.ToCharArray();
            int count = 0;
            for (char c = 'a'; c <= 'z'; c++)
            {
                var res = cipher_text.Count(x => x == c);
                arr[count].num = res;
                arr[count].s = c;
                count++;
            }

            char charater = 'a';
            int max_freq = -55;
            int index_remove = 0;
            string text = "";

            for (int j = 0; j < 26; j++)
            {
                max_freq = -55;
                for (int i = 0; i < arr.Length; i++)
                {

                    if (arr[i].num > max_freq)
                    {
                        max_freq = arr[i].num;
                        charater = arr[i].s;
                        index_remove = i;
                    }

                }

                text += charater;

                arr = arr.Where((source, index) => index != index_remove).ToArray();

            }


            string plain_text = "";
            int size = cipher_text.Length;
            int indx = 0;
            char q;
            for (int i = 0; i < size; i++)
            {
                q = cipher_text[i];
                indx = text.IndexOf(q);
                plain_text += alpha[indx];

            }

            return plain_text;

        }
    }
}
