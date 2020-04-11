using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace CEncyption_v1._1
{
    /// <summary>
    /// Base CEncryption class
    /// </summary>
    class CEncryptionUtil : IDisposable
    {
        public bool disposed { get; private set; }

        /// <summary>
        /// Decryption method for the more-secure seeded and workfactor algorithm.
        /// </summary>
        /// <param name="data">Data to decrypt(as string)</param>
        /// <param name="password">Password to use while encrypting(Recommended to create randomly with an RSA!)</param>
        /// <param name="seed">Also an value to make it harder to brute-crack</param>
        /// <param name="workFactor">Too high value with too many bytes can cause major slowdowns</param>
        /// <exception cref="System.NullReferenceException">Thrown when <paramref name="data"/> is equal to null</exception>
        /// <exception cref="System.NullReferenceException">Thrown when <paramref name="password"/> is equal to null</exception>
        public string DecryptToString(byte[] data, string password, int workFactor, int seed)
        {
            if (disposed)
            {
                throw new ObjectDisposedException("The CEncryptionUtil has already been disposed");
            }

            int iterationValue = 0;
            byte[] bytes = data;
            byte[] passwordBytes = Encoding.ASCII.GetBytes(password);
            int passwordShiftIndex = 0;

            int it = 0;
            for (int j = 0; j < workFactor; j++)
            {
                it += 5;
                iterationValue+=it;
                for (int i = 0; i < bytes.Length; i++)
                {
                    bytes[i] = (byte)(bytes[i] - workFactor * (passwordBytes[passwordShiftIndex] + seed ^
                        (workFactor % (iterationValue + seed))));
                    passwordShiftIndex = (passwordShiftIndex + 1) % passwordBytes.Length;
                }
            }

            return Encoding.ASCII.GetString(bytes);
        }

        public byte[] DecryptToBytes(byte[] data, string password, int iterations, int seed)
        {
            if (disposed)
            {
                throw new ObjectDisposedException("The CEncryptionUtil has already been disposed");
            }

            int iterationValue = 0;
            byte[] bytes = data;
            byte[] passwordBytes = Encoding.ASCII.GetBytes(password);
            int passwordShiftIndex = 0;
            int workFactor = (iterations * iterations * iterations * iterations) / 10;
            int it = 0;
            for (int j = 0; j < workFactor; j++)
            {
                it += 5;
                iterationValue += it;
                for (int i = 0; i < bytes.Length; i++)
                {
                    bytes[i] = (byte)(bytes[i] - workFactor * (passwordBytes[passwordShiftIndex] + seed ^
                        (workFactor % (iterationValue + seed))));
                    passwordShiftIndex = (passwordShiftIndex + 1) % passwordBytes.Length;
                }
            }

            return bytes;
        }

        /// <summary>
        /// More-secure system, bit slower, but drastic improvement in security(Still use fucking RSA or Bcrypt for password storing).
        /// </summary>
        /// <param name="bytes">Data to encrypt(as byte[], so you can even encrypt an file.)</param>
        /// <param name="password">Password to use while encrypting(Recommended to create randomly with an RSA!)</param>
        /// <param name="workFactor">Too high value with too many bytes can cause major slowdowns</param>
        /// <param name="seed">Also an value to make it harder to brute-crack</param>
        /// <exception cref="System.NullReferenceException">Thrown when <paramref name="data"/> is equal to null</exception>
        /// <exception cref="System.NullReferenceException">Thrown when <paramref name="password"/> is equal to null</exception>
        public byte[] Encrypt(byte[] bytes, string password, int iterations, int seed = 0)
        {
            if (disposed)
            {
                throw new ObjectDisposedException("The CEncryptionUtil has already been disposed");
            }

            int iterationValue = 0;
            var passwordBytes = Encoding.ASCII.GetBytes(password);
            int passwordShiftIndex = 0;

            int workFactor = (iterations * iterations * iterations * iterations) / 10;

            int it = 0;

            for (int j = 0; j < workFactor; j++)
            {
                it += 5;
                iterationValue+=it;
                for (int i = 0; i < bytes.Length; i++)
                {
                    bytes[i] = (byte)(bytes[i] + workFactor * (passwordBytes[passwordShiftIndex] + seed ^
                        (workFactor % (iterationValue + seed))));
                    passwordShiftIndex = (passwordShiftIndex + 1) % passwordBytes.Length;
                }
            }
            return bytes;
        }

        /// <summary>
        /// Creates random key.
        /// </summary>
        /// <returns>string</returns>
        public string CreateKey()
        {
            return CreateKey(0, new Random().Next());
        }

        private Aes aesA;

        /// <summary>
        /// Creates an random key.
        /// </summary>
        /// <param name="iterations">How many times it should shuffle the key.</param>
        /// <returns></returns>
        public string CreateKey(int iterations, int seed)
        {
            aesA = Aes.Create();
            aesA.GenerateKey();
            byte[] aes = aesA.Key;

            var key = Encoding.ASCII.GetString(aes);

            aesA.GenerateIV();
            byte[] aes1 = aesA.IV;

            byte[] shuffledKey = aes;

            seed += 1;

            foreach (byte b in aes)
            {
                for (int i = 0; i < iterations; i++)
                {
                    shuffledKey[new Random(seed).Next(0, shuffledKey.Length)] = aes[new Random(seed).Next(0, aes.Length)];
                }
            }

            var key1 = Encoding.ASCII.GetString(aes1);
            var shuffledKeyStr = Encoding.ASCII.GetString(shuffledKey);

            shuffledKeyStr = shuffledKeyStr.Substring(shuffledKeyStr.Length - 6);

            key += key1;
            key += shuffledKeyStr;

            return key;
        }

        /// <summary>
        /// Creates standard key without an iteration value;
        /// </summary>
        /// <returns>byte[]</returns>
        public byte[] CreateKeyBytes()
        {
            return CreateKeyBytes(0, new Random().Next());
        }

        /// <summary>
        /// Creates an key returned in bytes.
        /// </summary>
        /// <param name="iterations">How many times it should shuffle the returned key.</param>
        /// <returns>byte[]</returns>
        public byte[] CreateKeyBytes(int iterations, int seed)
        {
            aesA = Aes.Create();

            aesA.GenerateKey();
            byte[] aes = aesA.Key;
            var key = Encoding.ASCII.GetString(aes);

            aesA.GenerateIV();
            byte[] aes1 = aesA.IV;

            byte[] shuffledKey = aes;

            foreach (byte b in aes)
            {
                for (int i = 0; i < iterations; i++)
                {
                    shuffledKey[new Random(seed).Next(0, shuffledKey.Length)] = aes[new Random(seed).Next(0, aes.Length)];
                }
            }

            var key1 = aes1;
            var shuffledKeyStr = Encoding.ASCII.GetString(shuffledKey);
            shuffledKeyStr = shuffledKeyStr.Substring(shuffledKeyStr.Length - 6);
            key += key1;
            key += shuffledKeyStr;

            return Encoding.ASCII.GetBytes(key);
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposed)
            {
                throw new ObjectDisposedException("The CEncryptionUtil has already been disposed");
            }

            if (disposing)
            {
                aesA.Dispose();
                aesA = null;
                disposed = true;
            }
        }
    }
}
