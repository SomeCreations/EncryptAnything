using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.IO;
using System.Threading;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

namespace EncryptAnything
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        [DllImport("KERNEL32.DLL", EntryPoint = "RtlZeroMemory")]
        public static extern bool ZeroMemory(IntPtr Destination, int Length);

        private void Form1_Load(object sender, EventArgs e)
        {
           
        }

        public byte[] AES_Encrypt(byte[] bytesToBeEncrypted, byte[] passwordBytes)
        {
            byte[] encryptedBytes = null;

            byte[] saltBytes = Encoding.ASCII.GetBytes(textBox5.Text);

            using (MemoryStream ms = new MemoryStream())
            {
                using (RijndaelManaged AES = new RijndaelManaged())
                {
                    AES.KeySize = 256;
                    AES.BlockSize = 128;

                    var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);
                    AES.Key = key.GetBytes(AES.KeySize / 8);
                    AES.IV = key.GetBytes(AES.BlockSize / 8);

                    AES.Mode = CipherMode.CBC;

                    using (var cs = new CryptoStream(ms, AES.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(bytesToBeEncrypted, 0, bytesToBeEncrypted.Length);
                        cs.Close();
                    }
                    encryptedBytes = ms.ToArray();
                }
            }
            return encryptedBytes;
        }

        public byte[] AES_Decrypt(byte[] bytesToBeDecrypted, byte[] passwordBytes)
        {
            byte[] decryptedBytes = null;

            byte[] saltBytes = Encoding.ASCII.GetBytes(textBox5.Text);

            using (MemoryStream ms = new MemoryStream())
            {
                using (RijndaelManaged AES = new RijndaelManaged())
                {
                    AES.KeySize = 256;
                    AES.BlockSize = 128;

                    var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);
                    AES.Key = key.GetBytes(AES.KeySize / 8);
                    AES.IV = key.GetBytes(AES.BlockSize / 8);

                    AES.Mode = CipherMode.CBC;

                    using (var cs = new CryptoStream(ms, AES.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(bytesToBeDecrypted, 0, bytesToBeDecrypted.Length);
                        cs.Close();
                    }
                    decryptedBytes = ms.ToArray();
                }
            }
            return decryptedBytes;
        }

        private void button2_Click(object sender, EventArgs e)
        {
            byte[] passwordBytes = System.Text.Encoding.UTF8.GetBytes(textBox3.Text);
            byte[] saltBytes = new byte[] { 141, 112, 71, 9, 43, 89, 195, 22, 222, 137, 1, 160, 6, 3, 1 };

            FileStream fsCrypt = new FileStream(textBox2.Text, FileMode.Open);
            fsCrypt.Read(saltBytes, 0, saltBytes.Length);

            RijndaelManaged AES = new RijndaelManaged();
            AES.KeySize = 256;
            AES.BlockSize = 128;
            var key = new Rfc2898DeriveBytes(passwordBytes.ToString(), saltBytes, 50000);
            AES.Key = key.GetBytes(AES.KeySize / 8);
            AES.IV = key.GetBytes(AES.BlockSize / 8);
            AES.Padding = PaddingMode.PKCS7;
            AES.Mode = CipherMode.CFB;

            CryptoStream cs = new CryptoStream(fsCrypt, AES.CreateDecryptor(), CryptoStreamMode.Read);

            string output1 = textBox2.Text;
            string output = output1.Replace(".aes", "");

            FileStream fsOut = new FileStream(output, FileMode.Create);

            int read;
            byte[] buffer = new byte[1048576];

            try
            {
                while ((read = cs.Read(buffer, 0, buffer.Length)) > 0)
                {
                    Application.DoEvents();
                    fsOut.Write(buffer, 0, read);
                }
            }
            catch (CryptographicException ex_CryptographicException)
            {
                Console.WriteLine("CryptographicException error: " + ex_CryptographicException.Message);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex.Message);
            }

            try
            {
                cs.Close();
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error by closing CryptoStream: " + ex.Message);
            }
            finally
            {
                fsOut.Close();
                fsCrypt.Close();
            }

            File.Delete(textBox2.Text);
        }

        private void button3_Click(object sender, EventArgs e)
        {
            int length = 125;

            string valid = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!£$%^&*()_+{}:@~<>?-=[];'#,./|";

            StringBuilder res = new StringBuilder();
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                byte[] uintBuffer = new byte[sizeof(uint)];

                while (length-- > 0)
                {
                    rng.GetBytes(uintBuffer);
                    uint numm = BitConverter.ToUInt32(uintBuffer, 0);
                    res.Append(valid[(int)(numm % (uint)valid.Length)]);
                }
            }
            textBox3.Text = res.ToString();
        }

        private void panel1_Click(object sender, EventArgs e)
        {
            OpenFileDialog ofd = new OpenFileDialog();
            if (ofd.ShowDialog() == System.Windows.Forms.DialogResult.OK)
            {
                textBox1.Text = ofd.FileName;
            }
        }

        private void button1_Click(object sender, EventArgs e)
        {
            Thread.Sleep(124);

            byte[] saltBytes = new byte[] { 141, 112, 71, 9, 43, 89, 195, 22, 222, 137, 1, 160, 6, 3, 1 };

            
            FileStream fsCrypt = new FileStream(textBox1.Text + ".aes", FileMode.Create);

            
            byte[] passwordBytes = System.Text.Encoding.UTF8.GetBytes(textBox3.Text);

            //Set Rijndael symmetric encryption algorithm
            RijndaelManaged AES = new RijndaelManaged();
            AES.KeySize = 256;
            AES.BlockSize = 128;
            AES.Padding = PaddingMode.PKCS7;

            
            //"What it does is repeatedly hash the user password along with the salt." High iteration counts.
            var key = new Rfc2898DeriveBytes(passwordBytes.ToString(), saltBytes, 50000);
            AES.Key = key.GetBytes(AES.KeySize / 8);
            AES.IV = key.GetBytes(AES.BlockSize / 8);

            
            AES.Mode = CipherMode.CFB;

            // write salt to the begining of the output file, so in this case can be random every time
            fsCrypt.Write(saltBytes, 0, saltBytes.Length);

            CryptoStream cs = new CryptoStream(fsCrypt, AES.CreateEncryptor(), CryptoStreamMode.Write);

            FileStream fsIn = new FileStream(textBox1.Text, FileMode.Open);

            //create a buffer (1mb) so only this amount will allocate in the memory and not the whole file
            byte[] buffer = new byte[1048576];
            int read;

            try
            {
                while ((read = fsIn.Read(buffer, 0, buffer.Length)) > 0)
                {
                    Application.DoEvents();
                    cs.Write(buffer, 0, read);
                }

                
                fsIn.Close();
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex.Message);
            }
            finally
            {
                cs.Close();
                fsCrypt.Close();
            }

            File.Delete(textBox1.Text);
        }

        private void panel2_Click(object sender, EventArgs e)
        {
            OpenFileDialog ofd = new OpenFileDialog();
            if (ofd.ShowDialog() == System.Windows.Forms.DialogResult.OK)
            {
                textBox2.Text = ofd.FileName;
            }
        }

        private void button4_Click(object sender, EventArgs e)
        {
            Thread.Sleep(124);

            byte[] bytesToBeEncrypted = Encoding.UTF8.GetBytes(textBox4.Text);
            byte[] passwordBytes = Encoding.UTF8.GetBytes(textBox3.Text);

            
            passwordBytes = SHA256.Create().ComputeHash(passwordBytes);

            byte[] bytesEncrypted = AES_Encrypt(bytesToBeEncrypted, passwordBytes);

            string result = Convert.ToBase64String(bytesEncrypted);

            textBox4.Text = result;
        }

        private void button5_Click(object sender, EventArgs e)
        {
            Thread.Sleep(214);

            byte[] bytesToBeDecrypted = Convert.FromBase64String(textBox4.Text);
            byte[] passwordBytes = Encoding.UTF8.GetBytes(textBox3.Text);
            passwordBytes = SHA256.Create().ComputeHash(passwordBytes);

            byte[] bytesDecrypted = AES_Decrypt(bytesToBeDecrypted, passwordBytes);

            string result = Encoding.UTF8.GetString(bytesDecrypted);
            textBox4.Text = result;
        }

        private void button7_Click(object sender, EventArgs e)
        {
            int length = 30;

            string valid = "1234567890";

            StringBuilder res = new StringBuilder();
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                byte[] uintBuffer = new byte[sizeof(uint)];

                while (length-- > 0)
                {
                    rng.GetBytes(uintBuffer);
                    uint numm = BitConverter.ToUInt32(uintBuffer, 0);
                    res.Append(valid[(int)(numm % (uint)valid.Length)]);
                }
            }


            //int[] numbers = new int[5];

            //Random random = new Random();
            //for (int i = 0; i < 5; i++)
            //{
            //    numbers[i] = random.Next(100, 200);
            //}
            //MessageBox.Show(numbers.ToString());
            string outs = Regex.Replace(res.ToString(), ".{2}", "$0, ");
            //string messa = outs + numbers;
            
            //var rnd = new Random();

            //var randomized = outs.OrderBy(item => rnd.Next());

            textBox5.Text = outs.ToString();
        }

        private void button9_Click(object sender, EventArgs e)
        {
            textBox3.Text = "";
        }

        private void button8_Click(object sender, EventArgs e)
        {
            textBox4.Text = "";
        }
    }
}