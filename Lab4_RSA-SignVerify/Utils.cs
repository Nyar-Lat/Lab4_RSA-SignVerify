﻿using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Numerics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Globalization;

namespace Lab4_RSA_SignVerify
{
    internal class Utils
    {





    public static BigInteger NOD(BigInteger a, BigInteger b)
        {
            a = BigInteger.Abs(a);
            b = BigInteger.Abs(b);
            return b == BigInteger.Zero ? a : NOD(b, a % b);
        }

        public static BigInteger StepenMod(BigInteger @base, BigInteger exp, BigInteger mod)
        {
            BigInteger result = 1;
            @base %= mod;
            while (exp > 0)
            {
                if (exp % 2 != 0)
                    result = (result * @base) % mod;
                @base = (@base * @base) % mod;
                exp /= 2;
            }
            return result;
        }

        public static BigInteger ObrMod(BigInteger a, BigInteger m)
        {
            if (NOD(a, m) != BigInteger.One)
                return -1;
            BigInteger x = 1, y = 0;
            BigInteger m0 = m, t, q;
            while (a > 1)
            {
                q = a / m;
                t = m;
                m = a % m;
                a = t;
                t = y;
                y = x - q * y;
                x = t;
            }
            if (x < 0)
                x += m0;
            return x;
        }

        public static string Encode(string message)
        {
            string result = "";
            foreach (char c in message)
            {
                result += ((int)c + 100).ToString();
            }
            return result;
        }

        public static string Decode(string encodedMessage)
        {
            string decodedMessage = "";
            string temp = "";

            foreach (char ch in encodedMessage)
            {
                temp += ch;

                if (temp.Length >= 3)
                {
                    if (int.TryParse(temp, out int value))
                    {
                        char decodedChar = (char)(value - 100);
                        decodedMessage += decodedChar;
                        temp = "";
                    }
                    else
                    {
                        throw new FormatException($"Не удалось преобразовать \"{temp}\" в число.");
                    }
                }
            }

            return decodedMessage;
        }


        public static List<BigInteger> EncryptBlocks(string input, BigInteger exp, BigInteger n)
        {
            var encrypted = new List<BigInteger>();
            string current = "";
            foreach (char c in input)
            {
                current += c;
                BigInteger value = BigInteger.Parse(current);
                if (value >= n)
                {
                    current = current.Remove(current.Length - 1);
                    BigInteger block = BigInteger.Parse(current);
                    encrypted.Add(StepenMod(block, exp, n));
                    current = c.ToString();
                }
            }
            if (current.Length > 0)
            {
                BigInteger block = BigInteger.Parse(current);
                encrypted.Add(StepenMod(block, exp, n));
            }
            return encrypted;
        }

        public static List<BigInteger> ParseEncryptedText(string inputText)
        {
            var result = new List<BigInteger>();
            var parts = inputText.Split(' ');
            foreach (var part in parts)
            {
                if (!string.IsNullOrWhiteSpace(part))
                {
                    result.Add(BigInteger.Parse(part));
                }
            }
            return result;
        }

        public static string DecryptBlocks(List<BigInteger> encrypted, BigInteger d, BigInteger n)
        {
            string result = "";
            foreach (BigInteger block in encrypted)
            {
                BigInteger decrypted = StepenMod(block, d, n);
                result += decrypted.ToString();
            }
            return result;
        }

        public static bool IsPrime(BigInteger number)
        {
            if (number < 2) return false;    // 0 и 1 не простые
            if (number == 2 || number == 3) return true;  // 2 и 3 простые
            if (number % 2 == 0) return false;  // четные > 2 не простые

            BigInteger boundary = (BigInteger)Math.Floor(Math.Sqrt((double)number));

            for (BigInteger i = 3; i <= boundary; i += 2)
            {
                if (number % i == 0)
                    return false;
            }
            return true;
        }

        public static BigInteger RandomBigInteger(BigInteger max)
        {
            byte[] bytes = max.ToByteArray();
            BigInteger value;

            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                do
                {
                    rng.GetBytes(bytes);
                    bytes[bytes.Length - 1] &= 0x7F; // убрать знак
                    value = new BigInteger(bytes);
                } while (value >= max);
            }

            return value;
        }

        public static bool MillerRabinTest(BigInteger n, BigInteger d, int s)
        {
            BigInteger a = 2 + RandomBigInteger(n - 4);
            BigInteger x = StepenMod(a, d, n);
            if (x == 1 || x == n - 1) return true;
            for (int r = 1; r < s; ++r)
            {
                x = (x * x) % n;
                if (x == 1) return false;
                if (x == n - 1) return true;
            }
            return false;
        }

        public static bool IsPrimeM(BigInteger n, int iterations = 40)
        {
            if (n <= 1 || n % 2 == 0) return false;
            if (n == 2 || n == 3) return true;

            BigInteger d = n - 1;
            int s = 0;
            while (d % 2 == 0)
            {
                d /= 2;
                ++s;
            }
            for (int i = 0; i < iterations; ++i)
            {
                if (!MillerRabinTest(n, d, s)) return false;
            }
            return true;
        }

        public static BigInteger FindNextPrime(BigInteger n)
        {
            if (n < 2) return 2;
            if (n % 2 == 0) n += 1;
            while (true)
            {
                if (IsPrime(n)) return n;
                n += 2;
            }
        }

        public static BigInteger FindNextPrimeM(BigInteger n)
        {
            if (n < 2) return 2;
            if (n % 2 == 0) n += 1;
            while (true)
            {
                if (IsPrimeM(n)) return n;
                n += 2;
            }
        }


        public static string ComMD5(string input)
        {
            using (var md5 = MD5.Create())
            {
                byte[] hashBytes = md5.ComputeHash(Encoding.UTF8.GetBytes(input));
                // Встроенный метод BitConverter преобразует байты в строку, но с дефолтными дефисами и заглавными буквами,
                // поэтому используем ToLower и заменяем дефисы:
                return BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();
            }
        }

        public static BigInteger HexToBigInteger(string hex)
        {
            if (string.IsNullOrWhiteSpace(hex))
                return BigInteger.Zero;

            // Убираем префикс "0x"/"0X"
            if (hex.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                hex = hex.Substring(2);

            // Делаем длину чётной, добавляя ведущий '0' при необходимости
            if (hex.Length % 2 != 0)
                hex = "0" + hex;

            // Разбираем в массив байт big-endian
            int byteCount = hex.Length / 2;
            byte[] temp = new byte[byteCount];
            for (int i = 0; i < byteCount; i++)
            {
                string byteHex = hex.Substring(i * 2, 2);
                temp[i] = byte.Parse(byteHex, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            }

            // Переворачиваем в little-endian для конструктора BigInteger(byte[])
            Array.Reverse(temp);

            // Если старший бит (в последнем элементе little-endian массива) = 1,
            // добавляем нулевой байт, чтобы число осталось положительным
            if ((temp[temp.Length - 1] & 0x80) != 0)
            {
                Array.Resize(ref temp, temp.Length + 1);
                temp[temp.Length - 1] = 0x00;
            }

            return new BigInteger(temp);
        }

    }
    }
