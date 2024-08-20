using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        public string Encrypt(string plainText, int key)
        {

            char[] alphabet = new char[] { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };
            plainText = plainText.ToLower();
            char[] p_text = plainText.ToCharArray();
            char[] Cipher_TEXT = new char[p_text.Length];
            for (int i = 0; i < p_text.Length; i++)
            {
                int index = Array.IndexOf(alphabet, p_text[i]);
                int c_char_pos = (index + key) % 26;
                Cipher_TEXT[i] = alphabet[c_char_pos];

            }
            return new string(Cipher_TEXT).ToLower();




        }

        public string Decrypt(string cipherText, int key)
        {
            char[] alphabet = new char[] { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };
            cipherText = cipherText.ToLower();
            char[] ciph_text = cipherText.ToCharArray();
            char[] plain_text = new char[ciph_text.Length];
            for (int i = 0; i < ciph_text.Length; i++)
            {
                int index = Array.IndexOf(alphabet, ciph_text[i]);
                int index_plain = (index - key) % 26;
                if (index_plain < 0)
                {
                    index_plain += 26;

                }
                plain_text[i] = alphabet[index_plain];
            }
            return new string(plain_text).ToLower();

        }

        public int Analyse(string plainText, string cipherText)
        {
            int key = 0;
            char[] alphabet = new char[] { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };
            plainText = plainText.ToLower();
            char[] p_text = plainText.ToCharArray();
            cipherText = cipherText.ToLower();
            char[] ciph_text = cipherText.ToCharArray();
            int i = 0;
            int c_index = Array.IndexOf(alphabet, ciph_text[i]);
            int p_index = Array.IndexOf(alphabet, p_text[i]);
            key = c_index - p_index;
            if (key < 0)
            {
                return key + 26;
            }
            else
                return key;

        }



    }

}

