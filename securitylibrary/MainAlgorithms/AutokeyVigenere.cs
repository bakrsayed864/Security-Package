using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            char[] alphabet = new char[] { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            char[] p_text = plainText.ToCharArray();
            char[] c_text = cipherText.ToCharArray();
            char[] keyStream = new char[c_text.Length];
            char[] key = new char[c_text.Length];
            for (int i = 0; i < c_text.Length; i++)
            {
                int c_index = Array.IndexOf(alphabet, c_text[i]);
                int p_index = Array.IndexOf(alphabet, p_text[i]);
                int k_index = (c_index - p_index + 26) % 26;
                keyStream[i] = alphabet[k_index];

            }
            for (int i = 0; i < keyStream.Length; i++)
            {
                if (keyStream[i] == plainText[0] && keyStream[i + 1] == plainText[1])
                    break;
                else
                {
                    key[i] = keyStream[i];


                }
            }
            return new string(key).ToLower();


        }

        public string Decrypt(string cipherText, string key)
        {

            char[] alphabet = new char[] { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };
            cipherText = cipherText.ToLower();
            key = key.ToLower();
            char[] k_text = key.ToCharArray();
            char[] c_text = cipherText.ToCharArray();
            char[] plaint_TEXT = new char[c_text.Length];

            int c_text_length = c_text.Length;
            char[] key_stream = new char[c_text_length];
            int k_text_length = k_text.Length;
            int dif = c_text_length - k_text_length;
            if (dif != 0)
            {

                for (int i = 0; i < k_text_length; i++)
                {
                    key_stream[i] = k_text[i];
                }
                int idx = key_stream.Length - dif;
                for (int i = 0; i < c_text_length; i++)
                {


                    int c_index = Array.IndexOf(alphabet, c_text[i]);
                    int k_index = Array.IndexOf(alphabet, key_stream[i]);
                    int p_index = (c_index - k_index + 26) % 26;
                    plaint_TEXT[i] = alphabet[p_index];
                    if (idx < c_text_length)
                    {
                        key_stream[idx] = plaint_TEXT[i];
                        idx++;
                    }






                }
                return new string(plaint_TEXT).ToLower();


            }



            else
            {
                for (int i = 0; i < c_text_length; i++)
                {
                    int c_index = Array.IndexOf(alphabet, c_text[i]);
                    int k_index = Array.IndexOf(alphabet, k_text[i]);
                    int p_index = (c_index - k_index + 26) % 26;
                    plaint_TEXT[i] = alphabet[p_index];


                }
                return new string(plaint_TEXT).ToLower();
            }





        }

        public string Encrypt(string plainText, string key)
        {

            char[] alphabet = new char[] { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };
            plainText = plainText.ToLower();
            key = key.ToLower();
            char[] p_text = plainText.ToCharArray();
            char[] k_text = key.ToCharArray();
            char[] Cipher_TEXT = new char[p_text.Length];
            char[] key_stream = new char[100];
            int p_text_length = p_text.Length;
            int k_text_length = k_text.Length;
            int dif = p_text_length - k_text_length;
            if (dif != 0)
            {
                int j = 0;
                for (int i = 0; i < k_text_length; i++)
                {
                    key_stream[i] = k_text[i];
                }
                for (int i = 0; i <= dif; i++)
                {
                    key_stream[k_text_length + j] = p_text[i];
                    j++;


                }
                for (int i = 0; i < p_text_length; i++)
                {
                    int p_index = Array.IndexOf(alphabet, p_text[i]);
                    int k_index = Array.IndexOf(alphabet, key_stream[i]);
                    int c_index = (p_index + k_index) % 26;
                    Cipher_TEXT[i] = alphabet[c_index];


                }
                return new string(Cipher_TEXT).ToLower();

            }
            else
            {
                for (int i = 0; i < p_text_length; i++)
                {
                    int p_index = Array.IndexOf(alphabet, p_text[i]);
                    int k_index = Array.IndexOf(alphabet, k_text[i]);
                    int c_index = (p_index + k_index) % 26;
                    Cipher_TEXT[i] = alphabet[c_index];


                }
                return new string(Cipher_TEXT).ToLower();
            }



        }
    }
}
