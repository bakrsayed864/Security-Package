using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher : ICryptographicTechnique<string, string>, ICryptographicTechnique<List<int>, List<int>>
    {
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            //throw new NotImplementedException();
            int plain_len = plainText.Count;
            int no_col = plain_len / 2;
            int index = 0;
            int temp = 0;
            int temp2 = 0;
            int index2 = 1;
            int p2 = 0;
            int count = 0;
            int count2 = 0;
            int p = 0;
            bool flag1 = false;
            bool flag2 = false;
            // elements 
            int e1 = 0, e2 = 0, e3 = 0, e4 = 0;
            
            List<int> key_temp = new List<int>();
            for (int f =0;f<26;f++)
            {
                for (int s=0;s<26;s++)
                {
                    index = 0;
                    p = 0;
                    count = 0;
                    
                    for (int i=0;i<no_col;i++)
                    {
                        temp = plainText[p] * f + plainText[p + 1] * s;
                        temp = temp % 26;
                        if (temp == cipherText[index])
                        { count++; }
                        else
                            break;
                        index += 2;
                        p += 2;
                    }
                    if (count == no_col)
                    {
                        e1=f;
                        e2=s;
                        count = 0;
                        flag1 = true;
                    }
                    p2 = 0;
                    index2 = 1;
                    count2 = 0;
                    for (int i = 0; i < no_col; i++)
                    {
                        temp2 = plainText[p2] * f + plainText[p2 + 1] * s;
                        temp2 = temp2 % 26;
                        if (temp2 == cipherText[index2])
                        { count2++; }
                        else
                            break;
                        index2 += 2;
                        p2 += 2;
                    }
                    if (count2==no_col)
                    {
                        e3 = f;
                        e4 = s;
                        flag2 = true;
                        count2 = 0;
                    }



                }
                if (flag1==true && flag2==true)
                {
                    key_temp.Add(e1);
                    key_temp.Add(e2);
                    key_temp.Add(e3);
                    key_temp.Add(e4);

                    
                    break;
                }
            }
            if (key_temp.Count == 0)
                throw new SecurityLibrary.InvalidAnlysisException();

            return key_temp;
        }

        public string Analyse(string plainText, string cipherText)
        {
            throw new NotImplementedException();
        }

        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            //throw new NotImplementedException();
            List<int> P_T = new List<int>();
            List<int> temp_mat = new List<int>();
            List<int> adj_mat = new List<int>();
            int key_len = key.Count;
            int cipher_len = cipherText.Count;
            if (key_len == 9)
            {
                int det = (key[0] * (key[4] * key[8] - key[7] * key[5])) -
                          (key[1] * (key[3] * key[8] - key[5] * key[6])) +
                          (key[2] * (key[3] * key[7] - key[4] * key[6]));
                det = det % 26;
                if (det < 0) det += 26;
                // adding extra elements in matrix in last extra twoo columns 
                for (int i=0;i<9;i++)
                {
                    temp_mat.Add(key[i]);
                    if (i == 2 )
                    {
                        temp_mat.Add(key[0]);
                        temp_mat.Add(key[1]);
                    }
                    else if (i == 5)
                    {
                        temp_mat.Add(key[3]);
                        temp_mat.Add(key[4]);
                    }
                    else if (i == 8)
                    {
                        temp_mat.Add(key[6]);
                        temp_mat.Add(key[7]);
                    }
                }
                //adding extra elemnts in last extra two rows
                temp_mat.Add(key[0]);
                temp_mat.Add(key[1]);
                temp_mat.Add(key[2]);
                temp_mat.Add(key[0]);
                temp_mat.Add(key[1]);

                temp_mat.Add(key[3]);
                temp_mat.Add(key[4]);
                temp_mat.Add(key[5]);
                temp_mat.Add(key[3]);
                temp_mat.Add(key[4]);
                // creating adjoint
                int temp_adj;
                // 1st row
                temp_adj = (temp_mat[6] * temp_mat[12]) - (temp_mat[7] * temp_mat[11]);
                adj_mat.Add(temp_adj);

                temp_adj = (temp_mat[11] * temp_mat[17]) - (temp_mat[12] * temp_mat[16]);
                adj_mat.Add(temp_adj);

                temp_adj = (temp_mat[16] * temp_mat[22]) - (temp_mat[21] * temp_mat[17]);
                adj_mat.Add(temp_adj);
                //2nd row
                temp_adj = (temp_mat[7] * temp_mat[13]) - (temp_mat[8] * temp_mat[12]);
                adj_mat.Add(temp_adj);

                temp_adj = (temp_mat[12] * temp_mat[18]) - (temp_mat[13] * temp_mat[17]);
                adj_mat.Add(temp_adj);

                temp_adj = (temp_mat[17] * temp_mat[23]) - (temp_mat[18] * temp_mat[22]);
                adj_mat.Add(temp_adj);
                //3rd row
                temp_adj = (temp_mat[8] * temp_mat[14]) - (temp_mat[9] * temp_mat[13]);
                adj_mat.Add(temp_adj);

                temp_adj = (temp_mat[13] * temp_mat[19]) - (temp_mat[14] * temp_mat[18]);
                adj_mat.Add(temp_adj);

                temp_adj = (temp_mat[18] * temp_mat[24]) - (temp_mat[19] * temp_mat[23]);
                adj_mat.Add(temp_adj);

                //muliplicative inverse of det
                int M_I=0;
                for (int i =1; i < 26;i++)
                {
                    if (i*det % 26 ==1)
                    {
                        M_I = i;
                        break;
                    }
                }
                //  mod 26 adjoint matrix
                for (int i= 0;i<9;i++)
                {
                    adj_mat[i] = adj_mat[i] % 26;
                    if (adj_mat[i] < 0)
                        adj_mat[i] += 26;
                }
                //multiply multiplicative inverse to the  key matrix
                for (int i=0;i<9;i++)
                {
                    adj_mat[i] = adj_mat[i] * M_I;
                    adj_mat[i] = adj_mat[i] % 26;
                }

                int temp1;
                for (int i = 0; i < cipher_len; i += 3)
                {
                    for (int j = 0; j < 9; j += 3)
                    {
                        temp1 = (adj_mat[j] * cipherText[i] + adj_mat[j + 1] * cipherText[i + 1] + adj_mat[j + 2] * cipherText[i + 2]) % 26;
                        if (temp1 < 0) temp1 += 26;
                        P_T.Add(temp1);
                    }
                }
            }
           else if (key_len == 4)
            {
                int det = ((key[0] * key[3]) - (key[1] * key[2]));
               // det = det % 26;
               // if (det < 0) det += 26;

                 // checking key if validate
                 //chex=cking +ve and smaller than 26
                 for (int i=0;i<4;i++)
                {
                    if (key[i] < 0 || key[i] > 26)
                        throw new System.Exception ();
                }
                 //  checking gcd = 1
                 if (det % 26 ==0 ||  det == 0)
                    throw new System.Exception();
                 
                 if (26 % det ==0 && det !=1 && det != -1)
                    throw new System.Exception();
               


                bool valid = false;
                int newdet=0;
                if (det < 0)
                    newdet = det * -1;
                //checking det has multiplicative inverse mod 26
                 for (int i=1;i<26;i++)
                {
                    if (i * newdet % 26 == 1)
                        valid = true;
                }
                 if (valid == false)
                    throw new System.Exception();

                int temp;
                int temp1;
                // changi elements
                temp = key[0];
                key[0] = key[3];
                key[3] = temp;

                key[1] = -key[1];
                key[2] = -key[2];

                for (int i=0;i<4;i++)
                {
                    key[i] = key[i] * 1 / det;
                }
                for (int i=0;i<cipher_len;i+=2)
                {
                    for (int j=0;j<4;j+=2)
                    {
                        temp1= (key[j] * cipherText[i] + key[j + 1] * cipherText[i + 1]) % 26;
                        if (temp1 < 0) temp1 += 26;
                        P_T.Add(temp1);
                    }
                }
            }
            return P_T;
        }

        public string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }

        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
           int key_len = key.Count;
            int plain_len = plainText.Count;
            List<int> C_T = new List<int>();
            if (key_len == 9)
            {
                int temp1;
                for (int i=0; i<plain_len;i+=3)
                {
                    for (int j=0;j<9;j+=3)
                    {
                        temp1= (key[j] * plainText[i] + key[j + 1] * plainText[i + 1] + key[j + 2] * plainText[i + 2]) % 26;
                        C_T.Add(temp1);
                    }
                }
            }
            else if (key_len == 4)
            {
                int temp;
                
                for (int i= 0; i<plain_len;i+=2)
                {
                    for (int j=0; j<4;j+=2)
                    {
                        temp = (key[j] * plainText[i] + key[j + 1] * plainText[i + 1]) % 26;
                        C_T.Add(temp);
                    }
                }
                
            }
            return C_T;

            //throw new NotImplementedException();
        }

        public string Encrypt(string plainText, string key)
        {
            throw new NotImplementedException();
        }

        public List<int> Analyse3By3Key(List<int> plain3, List<int> cipher3)
        {
            //throw new NotImplementedException();
            int plain_len = plain3.Count;
            int no_col = plain_len / 3;
            //1st
            int index = 0;
            int p = 0;
            int count = 0;
            int temp = 0;
            bool flag1 = false;
            //2nd
            int temp2 = 0;
            int index2 = 1;
            int p2 = 0;
            int count2 = 0;
            bool flag2 = false;
            //3rd
            int index3 = 2;
            int p3 = 0;
            int count3 = 0;
            int temp3 = 0;
            bool flag3 = false;

            // elements 
            int e1 = 0, e2 = 0, e3 = 0, e4 = 0, e5 = 0, e6 = 0, e7 = 0, e8 = 0, e9 = 0;

            List<int> key_temp = new List<int>();
            for (int f = 0; f < 26; f++)
            {
                for(int s =0;s<26;s++)
                {
                    for (int thrd = 0; thrd < 26; thrd++)
                    {
                        index = 0;
                        p = 0;
                        count = 0;

                        for (int i = 0; i < no_col; i++)
                        {
                            temp = plain3[p] * f + plain3[p + 1] * s + plain3[p + 2] * thrd;
                            temp = temp % 26;
                            if (temp == cipher3[index])
                            { count++; }
                            else
                                break;
                            index += 3;
                            p += 3;
                        }
                        if (count == no_col)
                        {
                            e1 = f;
                            e2 = s;
                            e3 = thrd;
                            count = 0;
                            flag1 = true;
                        }
                        p2 = 0;
                        index2 = 1;
                        count2 = 0;
                        for (int i = 0; i < no_col; i++)
                        {
                            temp2 = plain3[p2] * f + plain3[p2 + 1] * s + plain3[p2 + 2] * thrd;
                            temp2 = temp2 % 26;
                            if (temp2 == cipher3[index2])
                            { count2++; }
                            else
                                break;
                            index2 += 3;
                            p2 += 3;
                        }
                        if (count2 == no_col)
                        {
                            e4 = f;
                            e5 = s;
                            e6 = thrd;
                            flag2 = true;
                            count2 = 0;
                        }
                        p3 = 0;
                        index3 = 2;
                        count3 = 0;
                        for (int i = 0; i < no_col; i++)
                        {
                            temp3 = plain3[p3] * f + plain3[p3 + 1] * s + plain3[p3 + 2] * thrd;
                            temp3 = temp3 % 26;
                            if (temp3 == cipher3[index3])
                            { count3++; }
                            else
                                break;
                            index3 += 3;
                            p3 += 3;
                        }
                        if (count3 == no_col)
                        {
                            e7 = f;
                            e8 = s;
                            e9 = thrd;
                            flag3 = true;
                            count3 = 0;
                        }



                    }
                }
                
                if (flag1 == true && flag2 == true && flag3==true)
                {
                    key_temp.Add(e1);
                    key_temp.Add(e2);
                    key_temp.Add(e3);
                    key_temp.Add(e4);
                    key_temp.Add(e5);
                    key_temp.Add(e6);
                    key_temp.Add(e7);
                    key_temp.Add(e8);
                    key_temp.Add(e9);

                    break;
                }
            }
            return key_temp;
        }

        public string Analyse3By3Key(string plain3, string cipher3)
        {
            throw new NotImplementedException();
        }
    }
}
