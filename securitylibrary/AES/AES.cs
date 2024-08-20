using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO;
namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {        
        //  1ST step subistitution with SBOX
        public static string Sub_Word(string round_plain)
        {
            string[,] SBOX =
            {
                { "63", "7C", "77", "7B", "F2", "6B", "6F", "C5", "30", "01", "67", "2B", "FE", "D7", "AB", "76" },
                { "CA", "82", "C9", "7D", "FA", "59", "47", "F0", "AD", "D4", "A2", "AF", "9C", "A4", "72", "C0" },
                { "B7", "FD", "93", "26", "36", "3F", "F7", "CC", "34", "A5", "E5", "F1", "71", "D8", "31", "15" },
                { "04", "C7", "23", "C3", "18", "96", "05", "9A", "07", "12", "80", "E2", "EB", "27", "B2", "75" },
                { "09", "83", "2C", "1A", "1B", "6E", "5A", "A0", "52", "3B", "D6", "B3", "29", "E3", "2F", "84" },
                { "53", "D1", "00", "ED", "20", "FC", "B1", "5B", "6A", "CB", "BE", "39", "4A", "4C", "58", "CF" },
                { "D0", "EF", "AA", "FB", "43", "4D", "33", "85", "45", "F9", "02", "7F", "50", "3C", "9F", "A8" },
                { "51", "A3", "40", "8F", "92", "9D", "38", "F5", "BC", "B6", "DA", "21", "10", "FF", "F3", "D2" },
                { "CD", "0C", "13", "EC", "5F", "97", "44", "17", "C4", "A7", "7E", "3D", "64", "5D", "19", "73" },
                { "60", "81", "4F", "DC", "22", "2A", "90", "88", "46", "EE", "B8", "14", "DE", "5E", "0B", "DB" },
                { "E0", "32", "3A", "0A", "49", "06", "24", "5C", "C2", "D3", "AC", "62", "91", "95", "E4", "79" },
                { "E7", "C8", "37", "6D", "8D", "D5", "4E", "A9", "6C", "56", "F4", "EA", "65", "7A", "AE", "08" },
                {  "BA", "78", "25", "2E", "1C", "A6", "B4", "C6", "E8", "DD", "74", "1F", "4B", "BD", "8B","8A" },
                { "70", "3E", "B5", "66", "48", "03", "F6", "0E", "61", "35", "57", "B9", "86", "C1", "1D", "9E" },
                { "E1", "F8", "98", "11", "69", "D9", "8E", "94", "9B", "1E", "87", "E9", "CE", "55", "28", "DF" },
                { "8C", "A1", "89", "0D", "BF", "E6", "42", "68", "41", "99", "2D", "0F", "B0", "54", "BB", "16" }
            };

            List<string> temp_plain = new List<string>();
            List<string> sub_plain = new List<string>();
            //replace letters with its numbeers in hexadeci,mal
            for (int i = 0; i < round_plain.Length; i++)
            {
                if (round_plain[i] == 'A' || round_plain[i] == 'a')
                    temp_plain.Add("10");
                else if (round_plain[i] == 'B' || round_plain[i] == 'b')
                    temp_plain.Add("11");
                else if (round_plain[i] == 'C' || round_plain[i] == 'c')
                    temp_plain.Add("12");
                else if (round_plain[i] == 'D' || round_plain[i] == 'd')
                    temp_plain.Add("13");
                else if (round_plain[i] == 'E' || round_plain[i] == 'e')
                    temp_plain.Add("14");
                else if (round_plain[i] == 'F' || round_plain[i] == 'f')
                    temp_plain.Add("15");
                else
                    temp_plain.Add(round_plain[i].ToString());
            }

            //replac values of the state with correponding vlaues in SBOX
            int row, col;
            for (int k = 0; k < temp_plain.Count - 1; k += 2)
            {
                row = int.Parse(temp_plain[k]);
                col = int.Parse(temp_plain[k + 1]);
                sub_plain.Add(SBOX[row, col]);
            }
            string new_round_plain = "";
            for (int i = 0; i < sub_plain.Count; i++)
            {
                new_round_plain += sub_plain[i];
            }

            return new_round_plain;
        }

        //2ND step shift rows
        public static string shift_rows(string s)
        {
            string temp = "";
            temp += s[0]; temp += s[1];
            temp += s[10]; temp += s[11];
            temp += s[20]; temp += s[21];
            temp += s[30]; temp += s[31];
            temp += s[8]; temp += s[9];
            temp += s[18]; temp += s[19];
            temp += s[28]; temp += s[29];
            temp += s[6]; temp += s[7];

            temp += s[16]; temp += s[17];
            temp += s[26]; temp += s[27];
            temp += s[4]; temp += s[5];
            temp += s[14]; temp += s[15];
            temp += s[24]; temp += s[25];
            temp += s[2]; temp += s[3];
            temp += s[12]; temp += s[13];
            temp += s[22]; temp += s[23];

            return temp;
        }
        // 3rd step mix coloumns
        private static int Mult_by_01(int num)
        {
            return num;
        }

        private static int Mult_by_02(int num)
        {
          
            num *= 2;
            if (num >= 256)
            {
                num -= 256;
                num ^= 27;
            }
            
            return num;
        }

        private static int Mult_by_03(int num)
        {
            return (Mult_by_02(num) ^ num);
        }

        public static string mix_col(string str)
        {
            int[,] mixed = new int[4, 4];
            string[,] Mix_col_matrix = new string[4, 4];
            string[,] shift_tmp = new string[4, 4];
            int count = 0;

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    string str1 = str[count].ToString();
                    string str2 = str[count + 1].ToString();
                    shift_tmp[j, i] = str1 + str2;
                    count += 2;
                }
            }
            for (int i = 0; i < 4; i++)
            {
                // convert from hexadecimal to decimal
                int a0 = int.Parse(Convert.ToInt32 (shift_tmp[0, i],16).ToString());
                int a1 = int.Parse(Convert.ToInt32(shift_tmp[1, i], 16).ToString());
                int a2 = int.Parse(Convert.ToInt32(shift_tmp[2, i], 16).ToString());
                int a3 = int.Parse(Convert.ToInt32(shift_tmp[3, i], 16).ToString());

                mixed[0, i] = Mult_by_02(a0) ^ Mult_by_03(a1) ^ Mult_by_01(a2) ^ Mult_by_01(a3);
                mixed[1, i] = Mult_by_01(a0) ^ Mult_by_02(a1) ^ Mult_by_03(a2) ^ Mult_by_01(a3);
                mixed[2, i] = Mult_by_01(a0) ^ Mult_by_01(a1) ^ Mult_by_02(a2) ^ Mult_by_03(a3);
                mixed[3, i] = Mult_by_03(a0) ^ Mult_by_01(a1) ^ Mult_by_01(a2) ^ Mult_by_02(a3);
            }
            for (int i = 0; i < 4; i++)
            {
                // convert from decimal to hexadecimal again
                for (int j = 0; j < 4; j++)
                    Mix_col_matrix[i, j] = mixed[i, j].ToString("X");
            }
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    if (Mix_col_matrix[i, j].Length < 2)
                        Mix_col_matrix[i, j] = "0" + Mix_col_matrix[i, j];
                }
            }
            string str_n = "";
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                    str_n += Mix_col_matrix[j, i];
            }
            return str_n;
        }

        // 4th step ADD round KEY
        public static string add_round_Key(string plain, string key)
        {
            string res = "";

            for (int i = 0; i < plain.Length; i += 2)
            {
                //convert to decimal to make xor operation
                int plain_dec = Convert.ToInt32(plain.Substring(i, 2), 16);
                int key_dec = Convert.ToInt32(key.Substring(i + 2, 2), 16);
                int xor_res = plain_dec ^ key_dec;

                string str = "";
                if (xor_res < 16)
                    str = "0" + Convert.ToString(xor_res, 16);
                else
                    str = Convert.ToString(xor_res, 16);

                res += str;

            }
            return res;
        }

        // KEY EXPANSION step
        public static string[] Rot_Word(string[] Last_col)
        {
            string[] rotated = new string[4];
            rotated[0] = Last_col[1];
            rotated[1] = Last_col[2];
            rotated[2] = Last_col[3];
            rotated[3] = Last_col[0];
            return rotated;
        }
        public static string key_expansion(string key, int round)
        {
            string[,] S_box =
            {
                {"63","7c","77","7b","f2","6b","6f","c5","30","01","67","2b","fe","d7","ab","76"},
                {"ca","82","c9","7d","fa","59","47","f0","ad","d4","a2","af","9c","a4","72","c0"},
                {"b7","fd","93","26","36","3f","f7","cc","34","a5","e5","f1","71","d8","31","15"},
                {"04","c7","23","c3","18","96","05","9a","07","12","80","e2","eb","27","b2","75"},
                {"09","83","2c","1a","1b","6e","5a","a0","52","3b","d6","b3","29","e3","2f","84"},
                {"53","d1","00","ed","20","fc","b1","5b","6a","cb","be","39","4a","4c","58","cf"},
                {"d0","ef","aa","fb","43","4d","33","85","45","f9","02","7f","50","3c","9f","a8"},
                {"51","a3","40","8f","92","9d","38","f5","bc","b6","da","21","10","ff","f3","d2"},
                {"cd","0c","13","ec","5f","97","44","17","c4","a7","7e","3d","64","5d","19","73"},
                {"60","81","4f","dc","22","2a","90","88","46","ee","b8","14","de","5e","0b","db"},
                {"e0","32","3a","0a","49","06","24","5c","c2","d3","ac","62","91","95","e4","79"},
                {"e7","c8","37","6d","8d","d5","4e","a9","6c","56","f4","ea","65","7a","ae","08"},
                {"ba","78","25","2e","1c","a6","b4","c6","e8","dd","74","1f","4b","bd","8b","8a"},
                {"70","3e","b5","66","48","03","f6","0e","61","35","57","b9","86","c1","1d","9e"},
                {"e1","f8","98","11","69","d9","8e","94","9b","1e","87","e9","ce","55","28","df"},
                {"8c","a1","89","0d","bf","e6","42","68","41","99","2d","0f","b0","54","bb","16"}
            };

            string[,] R_con =
            {
                { "01" , "02" , "04" , "08" , "10" , "20" , "40" , "80" , "1b" , "36" },
                { "00" , "00" , "00" , "00" , "00" , "00" , "00" , "00" , "00" , "00" },
                { "00" , "00" , "00" , "00" , "00" , "00" , "00" , "00" , "00" , "00" },
                { "00" , "00" , "00" , "00" , "00" , "00" , "00" , "00" , "00" , "00" }
            };
            // make the key ====>  matrix 4x4
            string[,] new_key = new string[4, 4];
            for (int i = 0, o = 2; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    string str = key[o].ToString() + key[o + 1].ToString();
                    new_key[j, i] = str;
                    o += 2;
                }
            }

            //construct last col
            string[] temp_key = new string[4];
            for (int i = 0; i < 4; i++)
            {
                temp_key[i] = new_key[i, 3];
            }

            //rottion of first byte in last col
            temp_key = Rot_Word(temp_key);

            string rot_col = "";
            for (int i = 0; i < 4; i++)
            {
                rot_col += temp_key[i];
            }

            string subtemp = "";
            rot_col = rot_col.ToUpper();
            for (int i = 0; i < rot_col.Length; i += 2)
            {
                //convert from letters {A B C D E F } TO {10,11 12 13 14 15} TO AXIS SBOX EASILY
                int row_i = rot_col[i] - '0';
                if (row_i > 15)
                    row_i -= 7;

                int col_i = rot_col[i + 1] - '0';
                if (col_i > 15)
                    col_i -= 7;

                subtemp += S_box[row_i, col_i];
            }

            string[,] round_key = new string[4, 4];
            for (int i = 0, j = 0; i < 4; i++, j += 2)
            {
                int k_xor = Convert.ToInt32(new_key[i, 0], 16);
                int sub_xor = Convert.ToInt32(subtemp.Substring(j, 2), 16);
                int rcon_xor = Convert.ToInt32(R_con[i, round], 16);

                int temp = k_xor ^ sub_xor ^ rcon_xor;

                string str = Convert.ToString(temp, 16);
                if (temp < 16)
                    round_key[i, 0] = "0" + str;
                else
                    round_key[i, 0] = str;
            }
            for (int i = 1; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    int reskey_xor = Convert.ToInt32(round_key[j, i - 1], 16);
                    int ky_xor = Convert.ToInt32(new_key[j, i], 16);
                    int temp = ky_xor ^ reskey_xor;

                    string str = Convert.ToString(temp, 16);
                    if (temp < 16)
                        round_key[j, i] = "0" + str;
                    else
                        round_key[j, i] = str;
                }
            }
            string Res_round_Key = "0x";
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    Res_round_Key += round_key[j, i];

            return Res_round_Key;
        }

        // decrypt functions
        //inverse of subword
        public static string Sub_Word_inv(string round_cipher)
        {
            string[,] Sbox_inv =
            {
                {"52","09","6a","d5","30","36","a5","38","bf","40","a3","9e","81","f3","d7","fb"},
                {"7c","e3","39","82","9b","2f","ff","87","34","8e","43","44","c4","de","e9","cb"},
                {"54","7b","94","32","a6","c2","23","3d","ee","4c","95","0b","42","fa","c3","4e"},
                {"08","2e","a1","66","28","d9","24","b2","76","5b","a2","49","6d","8b","d1","25"},
                {"72","f8","f6","64","86","68","98","16","d4","a4","5c","cc","5d","65","b6","92"},
                {"6c","70","48","50","fd","ed","b9","da","5e","15","46","57","a7","8d","9d","84"},
                {"90","d8","ab","00","8c","bc","d3","0a","f7","e4","58","05","b8","b3","45","06"},
                {"d0","2c","1e","8f","ca","3f","0f","02","c1","af","bd","03","01","13","8a","6b"},
                {"3a","91","11","41","4f","67","dc","ea","97","f2","cf","ce","f0","b4","e6","73"},
                {"96","ac","74","22","e7","ad","35","85","e2","f9","37","e8","1c","75","df","6e"},
                {"47","f1","1a","71","1d","29","c5","89","6f","b7","62","0e","aa","18","be","1b"},
                {"fc","56","3e","4b","c6","d2","79","20","9a","db","c0","fe","78","cd","5a","f4"},
                {"1f","dd","a8","33","88","07","c7","31","b1","12","10","59","27","80","ec","5f"},
                {"60","51","7f","a9","19","b5","4a","0d","2d","e5","7a","9f","93","c9","9c","ef"},
                {"a0","e0","3b","4d","ae","2a","f5","b0","c8","eb","bb","3c","83","53","99","61"},
                {"17","2b","04","7e","ba","77","d6","26","e1","69","14","63","55","21","0c","7d"},
            };

            List<string> temp_cipher = new List<string>();
            List<string> sub_cipher = new List<string>();
            //replace letters with its numbeers in hexadeci,mal
            for (int i = 0; i < round_cipher.Length; i++)
            {
                if (round_cipher[i] == 'A' || round_cipher[i] == 'a')
                    temp_cipher.Add("10");
                else if (round_cipher[i] == 'B' || round_cipher[i] == 'b')
                    temp_cipher.Add("11");
                else if (round_cipher[i] == 'C' || round_cipher[i] == 'c')
                    temp_cipher.Add("12");
                else if (round_cipher[i] == 'D' || round_cipher[i] == 'd')
                    temp_cipher.Add("13");
                else if (round_cipher[i] == 'E' || round_cipher[i] == 'e')
                    temp_cipher.Add("14");
                else if (round_cipher[i] == 'F' || round_cipher[i] == 'f')
                    temp_cipher.Add("15");
                else
                    temp_cipher.Add(round_cipher[i].ToString());


            }
            //replac values of the state with correponding vlaues in SBOX
            int row, col;
            for (int k = 2; k < temp_cipher.Count - 1; k += 2)
            {
                row = int.Parse(temp_cipher[k]);
                col = int.Parse(temp_cipher[k + 1]);
                sub_cipher.Add(Sbox_inv[row, col]);
            }
            string new_round_cipher = "0x";
            for (int i = 0; i < sub_cipher.Count; i++)
            {
                new_round_cipher += sub_cipher[i];
            }

            return new_round_cipher;
        }

        // inverse of shift rows
        public static string Shift_Rows_inv(string s)
        {
            if (s[1] == 'x' || s[1] == 'X')
                s = s.Substring(2, 32);

            string temp = "0x";
            temp += s[0]; temp += s[1];
            temp += s[26]; temp += s[27];
            temp += s[20]; temp += s[21];
            temp += s[14]; temp += s[15];
            temp += s[8]; temp += s[9];
            temp += s[2]; temp += s[3];
            temp += s[28]; temp += s[29];
            temp += s[22]; temp += s[23];


            temp += s[16]; temp += s[17];
            temp += s[10]; temp += s[11];
            temp += s[4]; temp += s[5];
            temp += s[30]; temp += s[31];
            temp += s[24]; temp += s[25];
            temp += s[18]; temp += s[19];
            temp += s[12]; temp += s[13];
            temp += s[6]; temp += s[7];

            return temp;

        }

        // inverse of mix columns
        
        public static int mult_by_0b(int num)
        {
            return (Mult_by_02(Mult_by_02(Mult_by_02(num))) ^
                           Mult_by_02(num) ^
                           num);
        }
        public static int mult_by_0d(int num)
        {
            return (Mult_by_02(Mult_by_02(Mult_by_02(num))) ^
                           Mult_by_02(Mult_by_02(num)) ^
                           (num));
        }
        public static int mult_by_09(int num)
        {
            return (Mult_by_02(Mult_by_02(Mult_by_02(num)))
                ^ num);
        }
        public static int mult_by_0e(int num)
        {
            return (Mult_by_02(Mult_by_02(Mult_by_02(num))) ^
                           Mult_by_02(Mult_by_02(num)) ^
                           Mult_by_02(num));
        }

        public string mix_columns_inv(string str)
        {
            string[,] str_matrix = new string[4, 4];
            string[,] inv_mix_matrix = new string[4, 4];
            int[,] mat_of_int = new int[4, 4];
            int counter = 2;
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    str_matrix[j, i] = str[counter].ToString() + str[counter + 1].ToString();
                    counter += 2;
                }
            }
            for (int i = 0; i < 4; ++i)
            {
                //conveert from hexadecimal to decimal
                int a0 = int.Parse(Convert.ToInt32(str_matrix[0, i], 16).ToString());
                int a1 = int.Parse(Convert.ToInt32(str_matrix[1, i], 16).ToString());
                int a2 = int.Parse(Convert.ToInt32(str_matrix[2, i], 16).ToString());
                int a3 = int.Parse(Convert.ToInt32(str_matrix[3, i], 16).ToString());

                mat_of_int[0, i] = mult_by_0e(a0) ^ mult_by_0b(a1) ^ mult_by_0d(a2) ^ mult_by_09(a3);
                mat_of_int[1, i] = mult_by_09(a0) ^ mult_by_0e(a1) ^ mult_by_0b(a2) ^ mult_by_0d(a3);
                mat_of_int[2, i] = mult_by_0d(a0) ^ mult_by_09(a1) ^ mult_by_0e(a2) ^ mult_by_0b(a3);
                mat_of_int[3, i] = mult_by_0b(a0) ^ mult_by_0d(a1) ^ mult_by_09(a2) ^ mult_by_0e(a3);
            }
            //convert frrom decimal to hexadecimal agian
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    inv_mix_matrix[i, j] = mat_of_int[i, j].ToString("X");
                }

            }
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    if (inv_mix_matrix[i, j].Length < 2)
                    {
                        inv_mix_matrix[i, j] = "0" + inv_mix_matrix[i, j];
                    }
                }

            }
            string result_str = "0x";
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                    result_str += inv_mix_matrix[j, i];
            }
            return result_str;
        }

        public override string Decrypt(string cipherText, string key)
        {
            string[] key_matrix = new string[15];
            //constrauct and stores all keys in  matrix
            key_matrix[0] = key;
            for (int i = 0; i < 10; i++) 
                key_matrix[i + 1] = key_expansion(key_matrix[i], i);
           
            string cipher = cipherText;
            //remove "0x"
            if (cipherText[1] == 'x' || cipherText[1] == 'X')
                cipherText = cipherText.Substring(2, 32);
            
            cipher = cipherText;

            cipherText = add_round_Key(cipher, key_matrix[10]);
            if (cipherText[1] != 'x' && cipherText[1] != 'X') 
                cipherText = "0x" + cipherText;

            cipherText = Shift_Rows_inv(cipherText);
            cipherText = Sub_Word_inv(cipherText);
            
            // mmake encrypt steps in reverse order
            for (int i = 9; i > 0; i--)
            {
                if (cipherText[1] == 'x' || cipherText[1] == 'X') cipherText = cipherText.Substring(2, 32);
                
                cipher = cipherText;
                cipherText = add_round_Key(cipher, key_matrix[i]);
                if (cipherText[1] != 'x' && cipherText[1] != 'X') cipherText = "0x" + cipherText;
                cipherText = mix_columns_inv(cipherText);
                
                cipherText = Shift_Rows_inv(cipherText);
                cipherText = Sub_Word_inv(cipherText);
            }

            if (cipherText[1] == 'x' || cipherText[1] == 'X') 
                cipherText = cipherText.Substring(2, 32);
            
            cipher = cipherText;
            cipherText = add_round_Key(cipher, key_matrix[0]);
            string plain_txt = "0x" + cipherText;

            return plain_txt;
            
            //throw new NotImplementedException();
        }
        public override string Encrypt(string plainText, string key)
        {
            //remove "0x"
            string plain1 = plainText; ;
            if (plainText[1] == 'x' || plainText[1] == 'X')
                plainText = plainText.Substring(2, 32);

            plain1 = plainText;
            // first key 
            plainText = add_round_Key(plain1, key);
            for (int i = 0; i < 9; i++)
            {
                plainText = Sub_Word(plainText);
                plainText = shift_rows(plainText);
                plainText = mix_col(plainText);
                if (plainText[1] == 'x' || plainText[1] == 'X') plainText = plainText.Substring(2, 32);
                key = key_expansion(key, i);

                plain1 = plainText;
                plainText = add_round_Key(plain1, key);
            }
            //10th round 
            plainText = Sub_Word(plainText);
            plainText = shift_rows(plainText);
            key = key_expansion(key, 9);


            plain1 = plainText;
            plainText = add_round_Key(plain1, key);
            string cipher_txt =  "0x"+plainText;
            
            return cipher_txt;

           // throw new NotImplementedException();
        }

    }
}