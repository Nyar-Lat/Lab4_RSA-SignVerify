using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Numerics;
using static Lab4_RSA_SignVerify.Utils;
using static System.Windows.Forms.VisualStyles.VisualStyleElement;
using System.Security.Cryptography;
using System.Globalization;

namespace Lab4_RSA_SignVerify
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        private void Form1_Load(object sender, EventArgs e)
        {

        }

        private void button1_Click(object sender, EventArgs e)
        {
            int digits = 20;
            if (!string.IsNullOrEmpty(textBox1.Text))
            {
                digits = Convert.ToInt32(textBox1.Text);
            }

            BigInteger min = BigInteger.Pow(10, digits - 1);
            BigInteger max = BigInteger.Pow(10, digits) - 1;

            BigInteger p;
            do
            {
                BigInteger randP = RandomBigInteger(max - min + 1) + min;
                p = FindNextPrimeM(randP);
            }
            while (p.ToString().Length != digits);

            BigInteger q;

            do
            {
                BigInteger randQ = RandomBigInteger(max - min + 1) + min;
                q = FindNextPrimeM(randQ);
            }
            while (q.ToString().Length != digits);

            textBox2.Text = p.ToString();
            textBox3.Text = q.ToString();

            BigInteger n = p * q;
            int eDigits = (digits * 2 + 1) / 2;
            BigInteger minE = BigInteger.Pow(10, eDigits - 1);
            BigInteger maxE = BigInteger.Pow(10, eDigits) - 1;

            BigInteger d;
            BigInteger phi = (p - 1) * (q - 1);

            do
            {
                d = RandomBigInteger(maxE - minE + 1) + minE;
            }
            while (d >= phi || d.ToString().Length != eDigits);

            while (NOD(phi, d) != BigInteger.One)
            {
                d++;
                if (d >= phi)
                {
                    d %= phi;
                }
            }

            BigInteger c = ObrMod(d, phi);

            textBox4.Text = n.ToString();
            textBox5.Text = d.ToString();
            textBox6.Text = c.ToString();

        }

        private void button4_Click(object sender, EventArgs e)
        {
            textBox1.Text = "";
            textBox2.Text = "";
            textBox3.Text = "";
            textBox4.Text = "";
            textBox5.Text = "";
            textBox6.Text = "";
            textBox7.Text = "";
            textBox8.Text = "";
            textBox9.Text = "";
            textBox10.Text = "";
            textBox11.Text = "";

        }

        private void button2_Click(object sender, EventArgs e)
        {
            if (string.IsNullOrWhiteSpace(textBox7.Text))
            {
                MessageBox.Show("Введите сообщение m!", "Ошибка", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            else
            {
                string message = textBox7.Text;
                textBox9.Text = ComMD5(message);
                textBox8.Text = message;

                BigInteger hashDecimal = HexToBigInteger(textBox9.Text);
                textBox9.Text = hashDecimal.ToString();

                BigInteger d = BigInteger.Parse(textBox6.Text);
                BigInteger n = BigInteger.Parse(textBox4.Text);

                BigInteger s = StepenMod(hashDecimal, d, n);
                textBox10.Text = s.ToString();
            }
        }

        private void button3_Click(object sender, EventArgs e)
        {
            // Берём исходное сообщение из textBox26
            string M = textBox8.Text;

            // Считаем его MD5 и сразу выводим в textBox29
            textBox11.Text = ComMD5(M);

            // Парсим подпись s из textBox28
            BigInteger s = BigInteger.Parse(textBox10.Text);

            // Парсим модуль n и открытый экспонент E
            BigInteger n = BigInteger.Parse(textBox4.Text);
            BigInteger ee = BigInteger.Parse(textBox5.Text);

            // Преобразуем hex‑строку MD5‑хэша в BigInteger
            BigInteger hashDecimal = HexToBigInteger(textBox11.Text);
            textBox11.Text = hashDecimal.ToString();  // обновляем textBox29, показывая десятичное значение хэша

            // Вычисляем w = s^E mod n
            BigInteger w = StepenMod(s, ee, n);
            textBox12.Text = w.ToString();
        }
    }
}
