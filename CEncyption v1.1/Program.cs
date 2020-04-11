using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace CEncyption_v1._1
{
    class Program
    {
        static void Main(string[] args)
        {
            Stopwatch watch = new Stopwatch();
            watch.Start();

            var cEncryptor = new CEncryptionUtil();

            string key = cEncryptor.CreateKey(100, new Random().Next(40, 50));

            Console.WriteLine("Key: " + key);


            var cEncrypted = cEncryptor.Encrypt(Encoding.ASCII.GetBytes("Huts1234"), key, 55, 584);
            Console.WriteLine("Encrypted: " + Encoding.ASCII.GetString(cEncrypted));

            var cDecrypted = cEncryptor.DecryptToBytes(cEncrypted, key, 55, 584);
            Console.WriteLine("Decrypted: " + Encoding.ASCII.GetString(cDecrypted));
            watch.Stop();

            cEncryptor.Dispose();

            Console.WriteLine("Executed Encryption and decryption in " + watch.ElapsedMilliseconds + "ms \nCEncryptionUtil " + 
                (cEncryptor.disposed ? "has been disposed." : "has not been disposed."));

            while(true)
            {
                Thread.Sleep(1);
            }
        }
    }
}
