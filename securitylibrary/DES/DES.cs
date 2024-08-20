using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class DES : CryptographicTechnique
    {
        public override string Decrypt(string cipherText, string key)
        {

            // pc1 , pc2 used for key permutations
            int[,] PC_1 = new int[8, 7] { { 57, 49, 41, 33, 25, 17, 9 }, { 1, 58, 50, 42, 34, 26, 18 }, { 10, 2, 59, 51, 43, 35, 27 }, { 19, 11, 3, 60, 52, 44, 36 }, { 63, 55, 47, 39, 31, 23, 15 }, { 7, 62, 54, 46, 38, 30, 22 }, { 14, 6, 61, 53, 45, 37, 29 }, { 21, 13, 5, 28, 20, 12, 4 } };
            int[,] PC_2 = new int[8, 6] { { 14, 17, 11, 24, 1, 5 }, { 3, 28, 15, 6, 21, 10 }, { 23, 19, 12, 4, 26, 8 }, { 16, 7, 27, 20, 13, 2 }, { 41, 52, 31, 37, 47, 55 }, { 30, 40, 51, 45, 33, 48 }, { 44, 49, 39, 56, 34, 53 }, { 46, 42, 50, 36, 29, 32 } };

            // initial permutation for plain text and inverse 
            int[,] IP = new int[8, 8] { { 58, 50, 42, 34, 26, 18, 10, 2 }, { 60, 52, 44, 36, 28, 20, 12, 4 }, { 62, 54, 46, 38, 30, 22, 14, 6 }, { 64, 56, 48, 40, 32, 24, 16, 8 }, { 57, 49, 41, 33, 25, 17, 9, 1 }, { 59, 51, 43, 35, 27, 19, 11, 3 }, { 61, 53, 45, 37, 29, 21, 13, 5 }, { 63, 55, 47, 39, 31, 23, 15, 7 } };
            int[,] IP_inv = new int[8, 8] { { 40, 8, 48, 16, 56, 24, 64, 32 }, { 39, 7, 47, 15, 55, 23, 63, 31 }, { 38, 6, 46, 14, 54, 22, 62, 30 }, { 37, 5, 45, 13, 53, 21, 61, 29 }, { 36, 4, 44, 12, 52, 20, 60, 28 }, { 35, 3, 43, 11, 51, 19, 59, 27 }, { 34, 2, 42, 10, 50, 18, 58, 26 }, { 33, 1, 41, 9, 49, 17, 57, 25 } };

            // expand from 32 bit to 48 bit
            int[,] Expansion = new int[8, 6] { { 32, 1, 2, 3, 4, 5 }, { 4, 5, 6, 7, 8, 9 }, { 8, 9, 10, 11, 12, 13 }, { 12, 13, 14, 15, 16, 17 }, { 16, 17, 18, 19, 20, 21 }, { 20, 21, 22, 23, 24, 25 }, { 24, 25, 26, 27, 28, 29 }, { 28, 29, 30, 31, 32, 1 } };

            // reduce from 48 bit to 32 bit using sboxes 
            int[,] sb1 = new int[4, 16] { { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 }, { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 }, { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 }, { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 } };
            int[,] sb2 = new int[4, 16] { { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 }, { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 }, { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 }, { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 } };
            int[,] sb3 = new int[4, 16] { { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 }, { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 }, { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 }, { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 } };
            int[,] sb4 = new int[4, 16] { { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 }, { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 }, { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 }, { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 } };
            int[,] sb5 = new int[4, 16] { { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 }, { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 }, { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 }, { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 } };
            int[,] sb6 = new int[4, 16] { { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 }, { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 }, { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 }, { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 } };
            int[,] sb7 = new int[4, 16] { { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 }, { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 }, { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 }, { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 } };
            int[,] sb8 = new int[4, 16] { { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 }, { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 }, { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 }, { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 } };

            // permutation after usung sboxes
            int[,] P = new int[8, 4] { { 16, 7, 20, 21 }, { 29, 12, 28, 17 }, { 1, 15, 23, 26 }, { 5, 18, 31, 10 }, { 2, 8, 24, 14 }, { 32, 27, 3, 9 }, { 19, 13, 30, 6 }, { 22, 11, 4, 25 } };


            string cipher_binary = Convert.ToString(Convert.ToInt64(cipherText, 16), 2).PadLeft(64, '0');
            string key_binary = Convert.ToString(Convert.ToInt64(key, 16), 2).PadLeft(64, '0');

            string perm_key = "";
            int pc_i = 0;
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 7; j++)
                {
                    pc_i = PC_1[i, j] - 1;
                    perm_key += key_binary[pc_i];
                }
            }

            //  list for c and d from 0 ===> 16
            List<string> C = new List<string>();
            List<string> D = new List<string>();
            string c_temp = perm_key.Substring(0, 28);
            string d_temp = perm_key.Substring(28, 28);
            string t = "";
            for (int i = 0; i <= 16; i++)
            {
                C.Add(c_temp);
                D.Add(d_temp);
                t = "";
                if (i == 0 || i == 1 || i == 8 || i == 15)
                {
                    t = t + c_temp[0];
                    c_temp = c_temp.Remove(0, 1);
                    c_temp += t;
                    t = "";

                    t = t + d_temp[0];
                    d_temp = d_temp.Remove(0, 1);
                    d_temp += t;
                }

                else
                {
                    t = t + c_temp.Substring(0, 2);
                    c_temp = c_temp.Remove(0, 2);
                    c_temp += t;
                    t = "";

                    t = t + d_temp.Substring(0, 2);
                    d_temp = d_temp.Remove(0, 2);
                    d_temp += t;
                }
            }

            List<string> temp_key = new List<string>();
            string kstr = "";
            for (int i = 0; i < D.Count; i++)
            {
                kstr = C[i] + D[i];
                temp_key.Add(kstr);
            }


            // permute 16 keys by pc2
            List<string> keys = new List<string>();
            string s1 = "";
            string s2 = "";
            int pc2_i = 0;
            for (int k = 1; k < temp_key.Count; k++)
            {
                s1 = "";
                s2 = "";
                s1 = temp_key[k];
                for (int i = 0; i < 8; i++)
                {
                    for (int j = 0; j < 6; j++)
                    {
                        pc2_i = PC_2[i, j] - 1;
                        s2 = s2 + s1[pc2_i];
                    }
                }

                keys.Add(s2);
            }
            // end of key construction

            // plain text permutation by IP
            string ip = "";
            int ip_i = 0;
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 8; j++)
                {
                    ip_i = IP[i, j] - 1;
                    ip += cipher_binary[ip_i];
                }
            }

            List<string> L = new List<string>();
            List<string> R = new List<string>();
            string l_temp = ip.Substring(0, 32);
            string r_temp = ip.Substring(32, 32);

            L.Add(l_temp);
            R.Add(r_temp);
            List<string> sboxes = new List<string>();
            string sb_in = "";
            string expan = "";
            string xor_str = "";
            string t1 = "";
            string t2 = "";
            string p_str = "";
            string sb_val_bi = "";
            string new_str = "";

            int expan_i = 0;
            int p_i = 0;
            int sb_row = 0;
            int sb_col = 0;
            int sb_val = 0;
            for (int i = 0; i < 16; i++)
            {
                L.Add(r_temp);
                sboxes.Clear();
                sb_in = "";
                expan = "";
                xor_str = "";
                p_str = "";
                sb_val_bi = "";
                sb_row = 0;
                sb_col = 0;
                new_str = "";
                // loop to expand r from 32 to 48 bit
                for (int j = 0; j < 8; j++)
                {
                    for (int k = 0; k < 6; k++)
                    {
                        expan_i = Expansion[j, k] - 1;
                        expan += r_temp[expan_i];
                    }
                }
                // loop for xor process
                for (int x = 0; x < expan.Length; x++)
                    xor_str += (keys[keys.Count - 1 - i][x] ^ expan[x]).ToString();

                //divide r into 8 blocks to reduce them to 32 bit again
                for (int q = 0; q < xor_str.Length; q += 6)
                {
                    sb_in = "";
                    for (int w = q; w < 6 + q; w++)
                    {
                        if (6 + q <= xor_str.Length)
                            sb_in += xor_str[w];
                    }
                    sboxes.Add(sb_in);
                }
                sb_in = "";
                sb_val = 0;
                for (int s = 0; s < sboxes.Count; s++)
                {
                    sb_in = sboxes[s];
                    t1 = sb_in[0].ToString() + sb_in[5];
                    t2 = sb_in[1].ToString() + sb_in[2] + sb_in[3] + sb_in[4];

                    sb_row = Convert.ToInt32(t1, 2);
                    sb_col = Convert.ToInt32(t2, 2);

                    if (s == 0)
                        sb_val = sb1[sb_row, sb_col];

                    if (s == 1)
                        sb_val = sb2[sb_row, sb_col];

                    if (s == 2)
                        sb_val = sb3[sb_row, sb_col];

                    if (s == 3)
                        sb_val = sb4[sb_row, sb_col];

                    if (s == 4)
                        sb_val = sb5[sb_row, sb_col];

                    if (s == 5)
                        sb_val = sb6[sb_row, sb_col];

                    if (s == 6)
                        sb_val = sb7[sb_row, sb_col];

                    if (s == 7)
                        sb_val = sb8[sb_row, sb_col];
                    sb_val_bi += Convert.ToString(sb_val, 2).PadLeft(4, '0');
                }
                t1 = "";
                t2 = "";

                // permutation using p mat
                for (int q = 0; q < 8; q++)
                {
                    for (int w = 0; w < 4; w++)
                    {
                        p_i = P[q, w] - 1;
                        p_str += sb_val_bi[p_i];
                    }
                }
                // xor left with result of mangler fun
                for (int q = 0; q < p_str.Length; q++)
                    new_str += (p_str[q] ^ l_temp[q]);

                r_temp = new_str;
                R.Add(r_temp);
                l_temp = L[i + 1];
            }
            // swap left with right
            string swap = R[16] + L[16];
            string pt = "";
            int ipinv_i = 0;
            //  last permutation usin  IP INVERSE
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 8; j++)
                {
                    ipinv_i = IP_inv[i, j] - 1;
                    pt += swap[ipinv_i];
                }
            }
            string plain_text = "0x" + Convert.ToInt64(pt, 2).ToString("X").PadLeft(16,'0') ;

            return plain_text;



           // throw new NotImplementedException();
        }

        public override string Encrypt(string plainText, string key)
        {
            // pc1 , pc2 used for key permutations
            int[,] PC_1 = new int[8, 7] { { 57, 49, 41, 33, 25, 17, 9 }, { 1, 58, 50, 42, 34, 26, 18 }, { 10, 2, 59, 51, 43, 35, 27 }, { 19, 11, 3, 60, 52, 44, 36 }, { 63, 55, 47, 39, 31, 23, 15 }, { 7, 62, 54, 46, 38, 30, 22 }, { 14, 6, 61, 53, 45, 37, 29 }, { 21, 13, 5, 28, 20, 12, 4 } };
            int[,] PC_2 = new int[8, 6] { { 14, 17, 11, 24, 1, 5 }, { 3, 28, 15, 6, 21, 10 }, { 23, 19, 12, 4, 26, 8 }, { 16, 7, 27, 20, 13, 2 }, { 41, 52, 31, 37, 47, 55 }, { 30, 40, 51, 45, 33, 48 }, { 44, 49, 39, 56, 34, 53 }, { 46, 42, 50, 36, 29, 32 } };

            // initial permutation for plain text and inverse 
            int[,] IP = new int[8, 8] { { 58, 50, 42, 34, 26, 18, 10, 2 }, { 60, 52, 44, 36, 28, 20, 12, 4 }, { 62, 54, 46, 38, 30, 22, 14, 6 }, { 64, 56, 48, 40, 32, 24, 16, 8 }, { 57, 49, 41, 33, 25, 17, 9, 1 }, { 59, 51, 43, 35, 27, 19, 11, 3 }, { 61, 53, 45, 37, 29, 21, 13, 5 }, { 63, 55, 47, 39, 31, 23, 15, 7 } };
            int[,] IP_inv = new int[8, 8] { { 40, 8, 48, 16, 56, 24, 64, 32 }, { 39, 7, 47, 15, 55, 23, 63, 31 }, { 38, 6, 46, 14, 54, 22, 62, 30 }, { 37, 5, 45, 13, 53, 21, 61, 29 }, { 36, 4, 44, 12, 52, 20, 60, 28 }, { 35, 3, 43, 11, 51, 19, 59, 27 }, { 34, 2, 42, 10, 50, 18, 58, 26 }, { 33, 1, 41, 9, 49, 17, 57, 25 } };

            // expand from 32 bit to 48 bit
            int[,] Expansion = new int[8, 6] { { 32, 1, 2, 3, 4, 5 }, { 4, 5, 6, 7, 8, 9 }, { 8, 9, 10, 11, 12, 13 }, { 12, 13, 14, 15, 16, 17 }, { 16, 17, 18, 19, 20, 21 }, { 20, 21, 22, 23, 24, 25 }, { 24, 25, 26, 27, 28, 29 }, { 28, 29, 30, 31, 32, 1 } };

            // reduce from 48 bit to 32 bit using sboxes 
            int[,] sb1 = new int[4, 16] { { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 }, { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 }, { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 }, { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 } };
            int[,] sb2 = new int[4, 16] { { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 }, { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 }, { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 }, { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 } };
            int[,] sb3 = new int[4, 16] { { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 }, { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 }, { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 }, { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 } };
            int[,] sb4 = new int[4, 16] { { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 }, { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 }, { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 }, { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 } };
            int[,] sb5 = new int[4, 16] { { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 }, { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 }, { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 }, { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 } };
            int[,] sb6 = new int[4, 16] { { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 }, { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 }, { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 }, { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 } };
            int[,] sb7 = new int[4, 16] { { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 }, { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 }, { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 }, { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 } };
            int[,] sb8 = new int[4, 16] { { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 }, { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 }, { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 }, { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 } };

            // permutation after usung sboxes
            int[,] P = new int[8, 4] { { 16, 7, 20, 21 }, { 29, 12, 28, 17 }, { 1, 15, 23, 26 }, { 5, 18, 31, 10 }, { 2, 8, 24, 14 }, { 32, 27, 3, 9 }, { 19, 13, 30, 6 }, { 22, 11, 4, 25 } };


            string plain_binary = Convert.ToString(Convert.ToInt64(plainText, 16), 2).PadLeft(64, '0');
            string key_binary = Convert.ToString(Convert.ToInt64(key, 16), 2).PadLeft(64, '0');

            // key  permutation  by pc1

            string perm_key = "";
            int pc_i = 0;
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 7; j++)
                {
                    pc_i = PC_1[i, j] - 1;
                    perm_key += key_binary[pc_i];
                }
            }

            //  list for c and d from 0 ===> 16
            List<string> C = new List<string>();
            List<string> D = new List<string>();
            string c_temp = perm_key.Substring(0, 28);
            string d_temp = perm_key.Substring(28, 28);
            string t = "";
            for (int i = 0; i <= 16; i++)
            {
                C.Add(c_temp);
                D.Add(d_temp);
                t = "";
                if (i == 0 || i == 1 || i == 8 || i == 15)
                {
                    t = t + c_temp[0];
                    c_temp = c_temp.Remove(0, 1);
                    c_temp += t;
                    t = "";

                    t = t + d_temp[0];
                    d_temp = d_temp.Remove(0, 1);
                    d_temp += t;
                }

                else
                {
                    t= t + c_temp.Substring(0, 2);
                    c_temp = c_temp.Remove(0, 2);
                    c_temp += t;
                    t = "";

                    t = t + d_temp.Substring(0, 2);
                    d_temp = d_temp.Remove(0, 2);
                    d_temp += t;
                }
            }

            List<string> temp_key = new List<string>();
            string kstr = "";
            for (int i = 0; i < D.Count; i++)
            {
                kstr = C[i] + D[i];
                temp_key.Add(kstr);
            }


            // permute 16 keys by pc2
            List<string> keys = new List<string>();
            string s1 = "";
            string s2 = "";
            int pc2_i = 0;
            for (int k = 1; k < temp_key.Count; k++)
            {
                s1 = "";
                s2 = "";
                s1 = temp_key[k];
                for (int i = 0; i < 8; i++)
                {
                    for (int j = 0; j < 6; j++)
                    {
                        pc2_i = PC_2[i, j] - 1;
                        s2 = s2 + s1[pc2_i];
                    }
                }

                keys.Add(s2);
            }
            // end of key construction
            

            // plain text permutation by IP
            string ip = "";
            int ip_i = 0;
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 8; j++)
                {
                    ip_i = IP[i, j] - 1;
                    ip += plain_binary[ip_i];
                }
            }

            List<string> L = new List<string>();
            List<string> R = new List<string>();
            string l_temp = ip.Substring(0, 32);
            string r_temp = ip.Substring(32, 32);

            L.Add(l_temp);
            R.Add(r_temp);
            List<string> sboxes = new List<string>();
            string sb_in = "";
            string expan = "";
            string xor_str = "";
            string t1 = "";
            string t2 = "";
            string p_str = "";
            string sb_val_bi = "";
            string new_str = "";

            int expan_i = 0;
            int p_i = 0;
            int sb_row = 0;
            int sb_col = 0;
            int sb_val = 0;
            for (int i = 0; i < 16; i++)
            {
                L.Add(r_temp);
                sboxes.Clear();
                sb_in = "";
                expan = "";
                xor_str = "";
                p_str = "";
                sb_val_bi = "";
                sb_row = 0;
                sb_col = 0;
                new_str = "";
                // loop to expand r from 32 to 48 bit
                for (int j = 0; j < 8; j++)
                {
                    for (int k = 0; k < 6; k++)
                    {
                        expan_i = Expansion[j, k] - 1;
                        expan += r_temp[expan_i];
                    }
                }
                // loop for xor process
                for (int x = 0; x < expan.Length; x++)
                    xor_str += (keys[i][x] ^ expan[x]).ToString();

                //divide r into 8 blocks to reduce them to 32 bit again
                for (int q = 0; q < xor_str.Length; q += 6)
                {
                    sb_in = "";
                    for (int w = q; w < 6 + q; w++)
                    {
                        if (6 + q <= xor_str.Length)
                            sb_in += xor_str[w];
                    }
                    sboxes.Add(sb_in);
                }
                sb_in = "";
                sb_val = 0;
                for (int s = 0; s < sboxes.Count; s++)
                {
                    sb_in = sboxes[s];
                    t1 = sb_in[0].ToString() + sb_in[5];
                    t2 = sb_in[1].ToString() + sb_in[2] + sb_in[3] + sb_in[4];

                    sb_row = Convert.ToInt32(t1, 2);
                    sb_col = Convert.ToInt32(t2, 2);

                    if (s == 0)
                        sb_val = sb1[sb_row, sb_col];

                    if (s == 1)
                        sb_val = sb2[sb_row, sb_col];

                    if (s == 2)
                        sb_val = sb3[sb_row, sb_col];

                    if (s == 3)
                        sb_val = sb4[sb_row, sb_col];

                    if (s == 4)
                        sb_val = sb5[sb_row, sb_col];

                    if (s == 5)
                        sb_val = sb6[sb_row, sb_col];

                    if (s == 6)
                        sb_val = sb7[sb_row, sb_col];

                    if (s == 7)
                        sb_val = sb8[sb_row, sb_col];
                    sb_val_bi += Convert.ToString(sb_val, 2).PadLeft(4, '0');
                }
                t1 = "";
                t2 = "";

                // permutation using p mat
                for (int q = 0; q < 8; q++)
                {
                    for (int w = 0; w < 4; w++)
                    {
                        p_i = P[q, w] - 1;
                        p_str += sb_val_bi[p_i];
                    }
                }
                // xor left with result of mangler fun
                for (int q = 0; q < p_str.Length; q++)
                    new_str += (p_str[q] ^ l_temp[q]);

                r_temp = new_str;
                R.Add(r_temp);
                l_temp = L[i + 1];
            }
            // swap left with right
            string swap = R[16] + L[16];
            string ct = "";
            int ipinv_i = 0;
            //  last permutation usin  IP INVERSE
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 8; j++)
                {
                    ipinv_i = IP_inv[i, j] - 1;
                    ct += swap[ipinv_i];
                }
            }
            string cipher_text = "0x" + Convert.ToInt64(ct, 2).ToString("X");

            return cipher_text;
            // throw new NotImplementedException();
        }
    }
}
