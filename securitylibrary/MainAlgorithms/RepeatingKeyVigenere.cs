using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        char[,] ALpha = new char[,]
          { {'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z'},
              {'B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','A'},
              {'C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','A','B'},
              {'D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','A','B','C'},
              {'E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','A','B','C','D'},
              {'F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','A','B','C','D','E'},
              {'G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','A','B','C','D','E','F'},
              {'H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','A','B','C','D','E','F','G'},
              {'I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','A','B','C','D','E','F','G','H'},
              {'J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','A','B','C','D','E','F','G','H','I'},
              {'K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','A','B','C','D','E','F','G','H','I','J'},
              {'L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','A','B','C','D','E','F','G','H','I','J','K'},
              {'M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','A','B','C','D','E','F','G','H','I','J','K','L'},
              {'N','O','P','Q','R','S','T','U','V','W','X','Y','Z','A','B','C','D','E','F','G','H','I','J','K','L','M'},
              {'O','P','Q','R','S','T','U','V','W','X','Y','Z','A','B','C','D','E','F','G','H','I','J','K','L','M','N'},
              {'P','Q','R','S','T','U','V','W','X','Y','Z','A','B','C','D','E','F','G','H','I','J','K','L','M','N','O'},
              {'Q','R','S','T','U','V','W','X','Y','Z','A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P'},
              {'R','S','T','U','V','W','X','Y','Z','A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q'},
              {'S','T','U','V','W','X','Y','Z','A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R'},
              {'T','U','V','W','X','Y','Z','A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S'},
              {'U','V','W','X','Y','Z','A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T'},
              {'V','W','X','Y','Z','A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U'},
              {'W','X','Y','Z','A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V'},
              {'X','Y','Z','A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W'},
              {'Y','Z','A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X'},
              {'Z','A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y'} };
        public string Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            cipherText = cipherText.ToUpper();
            plainText = plainText.ToUpper();
            string Key_Stream = "";
            string key = "";
            var temp_key = new StringBuilder();
            int plain_index = 0, cipher_index = 0;
            //Get Key Stream:)
            while (plain_index != plainText.Length)
            {
                for (int i = 0; i < 26; i++)
                {
                    if (plainText[plain_index] == ALpha[i, 0])
                    {
                        for (int j = 0; j < 26; j++)
                        {
                            if (cipherText[cipher_index] == ALpha[i, j])
                            {
                                temp_key.Append(ALpha[0, j]);
                                cipher_index++;
                                break;
                            }
                        }
                    }
                }
                plain_index++;
            }
            Key_Stream = temp_key.ToString();
            //Get Key:)
            var t = new StringBuilder();
            int count = 0;
            t.Append(Key_Stream[0]);
            for (int i = 1; i < Key_Stream.Length; i++)
            {
                //Because Need To Remove 1st Letter And Last Letter:)
                if (Key_Stream[0] == Key_Stream[i] && count == Key_Stream.Length - 2)
                {
                    break;
                }
                if (Key_Stream[0] == Key_Stream[i] && Key_Stream[1] == Key_Stream[i + 1])
                {
                    break;
                }

                else
                {
                    t.Append(Key_Stream[i]);
                    count++;
                }

            }
            key = t.ToString();
            return key;
        }

        public string Decrypt(string cipherText, string key)
        {
            //Convert Caracters To Upper:)
            cipherText = cipherText.ToUpper();
            key = key.ToUpper();
            //Variables:)
            string Key_Stream = "";
            string PlainText = "";
            var temp_keyStram = new StringBuilder();
            var temp_PlainText = new StringBuilder();
            //Copy Key Into Temp:)
            for (int i = 0; i < key.Length; i++)
            {
                temp_keyStram.Append(key[i]);
            }
            //Complete KeyStream With Key:)
            int count = 0;
            for (int i = key.Length; i < cipherText.Length; i++)
            {
                if (count == key.Length)
                {
                    count = 0;
                }
                temp_keyStram.Append(key[count]);
                count++;
            }
            Key_Stream = temp_keyStram.ToString();
            //Get PlainText:)
            int Key_Index = 0, CipherText_Index = 0;
            while (Key_Index != Key_Stream.Length)
            {
                for (int j = 0; j < 26; j++)
                {
                    if (Key_Stream[Key_Index] == ALpha[0, j])
                    {
                        for (int i = 0; i < 26; i++)
                        {
                            if (cipherText[CipherText_Index] == ALpha[i, j])
                            {
                                temp_PlainText.Append(ALpha[i, 0]);
                                CipherText_Index++;
                                break;
                            }
                        }
                    }
                }
                Key_Index++;
            }
            PlainText = temp_PlainText.ToString();
            return PlainText;
        }
        public string Encrypt(string plainText, string key)
        {
            //Convert Caracters To Upper:)
            plainText = plainText.ToUpper();
            key = key.ToUpper();
            //Variables:)
            int P_text_size = plainText.Length;
            int P_key_size = key.Length;
            string Key_Stream = "";
            string CipherText = "";
            //Temp To Hold Data:)
            var Temp_Key = new StringBuilder();
            var Temp_Cipher = new StringBuilder();
            // put the Key In Temp:)
            for (int i = 0; i < P_key_size; i++)
            {
                Temp_Key.Append(key[i]);
            }
            //Repeat The Key caracters Untill Pain Text:)
            int count = 0;
            for (int j = P_key_size; j < P_text_size; j++)
            {
                if (count == key.Length)
                {
                    count = 0;
                }
                Temp_Key.Append(key[count]);
                count++;
            }
            Key_Stream = Temp_Key.ToString();
            //Get CipherText:)
            int PlainText_index = 0, Key_Index = 0;
            while (PlainText_index != P_text_size)
            {
                for (int i = 0; i < 26; i++)
                {
                    if (plainText[PlainText_index] == ALpha[i, 0])
                    {
                        for (int j = 0; j < 26; j++)
                        {
                            if (Key_Stream[Key_Index] == ALpha[0, j])
                            {

                                Temp_Cipher.Append(ALpha[i, j]);
                                Key_Index++;
                                break;
                            }
                        }
                    }

                }
                PlainText_index++;
            }
            CipherText = Temp_Cipher.ToString();
            return CipherText;
        }

    }
}