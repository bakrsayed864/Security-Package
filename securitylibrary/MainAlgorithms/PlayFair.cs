using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographicTechnique<string, string>
    {
        /// <summary>
        /// The most common diagrams in english (sorted): TH, HE, AN, IN, ER, ON, RE, ED, ND, HA, AT, EN, ES, OF, NT, EA, TI, TO, IO, LE, IS, OU, AR, AS, DE, RT, VE
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="cipherText"></param>
        /// <returns></returns>
        public string Analyse(string plainText)
        {
            throw new NotImplementedException();
        }

        public string Analyse(string plainText, string cipherText)
        {
            throw new NotSupportedException();
        }

        public string Decrypt(string cipherText, string key)
        {
            //
            StringBuilder CT_string = new StringBuilder(cipherText.ToUpper());
            for (int count1 = 0; count1 < CT_string.Length; count1 += 1)
            {
                if (CT_string[count1] == 'J')
                {
                    CT_string[count1] = 'I';
                }
            }
            // String key_n = key;
            StringBuilder tmp_key = new StringBuilder(key.ToUpper());

            for (int cntr1 = 0; cntr1 < tmp_key.Length; cntr1 += 1)
            {


                if (tmp_key[cntr1] == 'J')
                {
                    tmp_key[cntr1] = 'I';
                }
            }
            for (int cntr1 = 0; cntr1 < tmp_key.Length; cntr1++)
            {

                for (int cntr2 = 0; cntr2 < cntr1; cntr2++)
                {

                    if (tmp_key[cntr1] == tmp_key[cntr2])
                    {
                        tmp_key = tmp_key.Remove(cntr1, 1);
                        cntr1--;
                        break;
                    }

                }

            }

            int keyword_stored_flag = 0;
            int exists_in_keyord = 0;

            char[,] matrix = new char[5, 5];


            for (int row_count = 0, alphabet_counter = 0; row_count < 5; row_count++)
            {

                for (int col_count = 0; col_count < 5; col_count++)
                {


                    if ((((row_count * 5) + col_count) < tmp_key.Length) && (keyword_stored_flag == 0))
                    {
                        matrix[row_count, col_count] = tmp_key[(row_count * 5) + col_count];
                    }
                    else
                    {
                        keyword_stored_flag = 1;
                        exists_in_keyord = 0;


                        for (int count1 = 0; count1 < tmp_key.Length; count1++)
                        {

                            if ('A' + alphabet_counter == tmp_key[count1])
                            {
                                exists_in_keyord = 1;
                                break;
                            }

                        }


                        if ((exists_in_keyord == 0) && (('A' + alphabet_counter) != 'J'))
                        {
                            matrix[row_count, col_count] = (char)((int)'A' + alphabet_counter);
                        }
                        else
                        {
                            col_count--;
                        }

                        alphabet_counter++;
                    }

                }

            }


            int letter1_row = 0, letter1_col = 0, letter2_row = 0, letter2_col = 0;

            for (int m_count = 0; m_count < CT_string.Length; m_count += 2)
            {

                get_index(matrix, CT_string[m_count], ref letter1_row, ref letter1_col);
                get_index(matrix, CT_string[m_count + 1], ref letter2_row, ref letter2_col);

                if (letter1_row == letter2_row)
                {
                    CT_string[m_count] = matrix[letter1_row, (letter1_col + 4) % 5];
                    CT_string[m_count + 1] = matrix[letter2_row, (letter2_col + 4) % 5];
                }
                else if (letter1_col == letter2_col)
                {
                    CT_string[m_count] = matrix[(letter1_row + 4) % 5, letter1_col];
                    CT_string[m_count + 1] = matrix[(letter2_row + 4) % 5, letter2_col];
                }
                else
                {
                    CT_string[m_count] = matrix[letter1_row, letter2_col];
                    CT_string[m_count + 1] = matrix[letter2_row, letter1_col];
                }


            }
            //

            for (int i = CT_string.Length - 1; i >= 0; i--)
            {
                if (CT_string[i] == 'X')
                {
                    if (i > 0)
                    {
                        if (i == (CT_string.Length - 1))
                        {
                            CT_string.Remove(i, 1);
                        }
                        else if (CT_string[i - 1] == CT_string[i + 1] && i % 2 != 0)
                        {
                            CT_string.Remove(i, 1);
                        }
                    }
                }
            }


            String Plain_Text = CT_string.ToString();
            return Plain_Text;
        }

        public string Encrypt(string plainText, string key)
        {
            StringBuilder PT_string = new StringBuilder(plainText.ToUpper());

            for (int count1 = 0; count1 < PT_string.Length; count1 += 1)
            {


                if (PT_string[count1] == 'J')
                {
                    PT_string[count1] = 'I';
                }

            }
            for (int count1 = 0; ((count1 < PT_string.Length) && ((count1 + 1) < PT_string.Length)); count1 += 2)
            {

                if (PT_string[count1] == PT_string[count1 + 1])
                {
                    PT_string.Insert(count1 + 1, "x");
                }

            }
            if ((PT_string.Length % 2) == 1)
            {
                PT_string.Append("x");
            }
            for (int count1 = 0; count1 < PT_string.Length; count1++)
            {

                if (PT_string[count1] >= 'a' && PT_string[count1] <= 'z')
                {
                    PT_string[count1] -= (char)((int)'a' - (int)'A');
                }

            }

            //String n_key = key;
            StringBuilder tmp_key = new StringBuilder(key);
            for (int count1 = 0; count1 < tmp_key.Length; count1 += 1)
            {



                if (tmp_key[count1] == 'J')
                {
                    tmp_key[count1] = 'I';
                }

            }
            for (int count1 = 0; count1 < tmp_key.Length; count1++)
            {

                for (int count2 = 0; count2 < count1; count2++)
                {

                    if (tmp_key[count1] == tmp_key[count2])
                    {
                        tmp_key = tmp_key.Remove(count1, 1);
                        count1--;
                        break;
                    }

                }

            }

            for (int count1 = 0; count1 < tmp_key.Length; count1++)
            {

                if (tmp_key[count1] >= 'a' && tmp_key[count1] <= 'z')
                {
                    tmp_key[count1] -= (char)((int)'a' - (int)'A');
                }

            }

            int keyword_stored_flag = 0;
            int exists_in_keyord = 0;

            char[,] matrix = new char[5, 5];
            for (int row_count = 0, alphabet_counter = 0; row_count < 5; row_count++)
            {

                for (int col_count = 0; col_count < 5; col_count++)
                {

                    if ((((row_count * 5) + col_count) < tmp_key.Length) && (keyword_stored_flag == 0))
                    {
                        matrix[row_count, col_count] = tmp_key[(row_count * 5) + col_count];
                    }
                    else
                    {
                        keyword_stored_flag = 1;
                        exists_in_keyord = 0;


                        for (int count1 = 0; count1 < tmp_key.Length; count1++)
                        {

                            if ('A' + alphabet_counter == tmp_key[count1])
                            {
                                exists_in_keyord = 1;
                                break;
                            }

                        }


                        if ((exists_in_keyord == 0) && (('A' + alphabet_counter) != 'J'))
                        {
                            matrix[row_count, col_count] = (char)((int)'A' + alphabet_counter);
                        }
                        else
                        {
                            col_count--;
                        }

                        alphabet_counter++;
                    }

                }

            }



            int letter1_row = 0, letter1_col = 0, letter2_row = 0, letter2_col = 0;

            for (int m_count = 0; m_count < PT_string.Length; m_count += 2)
            {
                get_index(matrix, PT_string[m_count], ref letter1_row, ref letter1_col);
                get_index(matrix, PT_string[m_count + 1], ref letter2_row, ref letter2_col);

                if (letter1_row == letter2_row)
                {
                    PT_string[m_count] = matrix[letter1_row, (letter1_col + 1) % 5];
                    PT_string[m_count + 1] = matrix[letter2_row, (letter2_col + 1) % 5];
                }
                else if (letter1_col == letter2_col)
                {
                    PT_string[m_count] = matrix[(letter1_row + 1) % 5, letter1_col];
                    PT_string[m_count + 1] = matrix[(letter2_row + 1) % 5, letter2_col];
                }
                else
                {
                    PT_string[m_count] = matrix[letter1_row, letter2_col];
                    PT_string[m_count + 1] = matrix[letter2_row, letter1_col];
                }

            }

            plainText = PT_string.ToString();

            return plainText;

        }
        private static void get_index(char[,] matrix, char chr, ref int row, ref int col)
        {

            for (int row_count = 0, char_match_flag = 0; char_match_flag == 0; row_count++)
            {

                for (int col_count = 0; col_count < 5; col_count++)
                {

                    if (matrix[row_count, col_count] == chr)
                    {
                        char_match_flag = 1;
                        col = col_count;
                        row = row_count;
                        break;
                    }

                }

            }
        }
    }
}
