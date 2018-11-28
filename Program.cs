using System;
using System.Security.Cryptography;

namespace totp
{
   // Ref: https://stackoverflow.com/a/7135008
   public class Base32Encoding
   {
      public static byte[] ToBytes(string input)
      {
         if (string.IsNullOrEmpty(input))
         {
            throw new ArgumentNullException("input");
         }

         input = input.TrimEnd('='); //remove padding characters
         int byteCount = input.Length * 5 / 8; //this must be TRUNCATED
         byte[] returnArray = new byte[byteCount];

         byte curByte = 0, bitsRemaining = 8;
         int mask = 0, arrayIndex = 0;

         foreach (char c in input)
         {
            int cValue = CharToValue(c);

            if (bitsRemaining > 5)
            {
               mask = cValue << (bitsRemaining - 5);
               curByte = (byte)(curByte | mask);
               bitsRemaining -= 5;
            }
            else
            {
               mask = cValue >> (5 - bitsRemaining);
               curByte = (byte)(curByte | mask);
               returnArray[arrayIndex++] = curByte;
               curByte = (byte)(cValue << (3 + bitsRemaining));
               bitsRemaining += 3;
            }
         }

         //if we didn't end with a full byte
         if (arrayIndex != byteCount)
         {
            returnArray[arrayIndex] = curByte;
         }

         return returnArray;
      }

      public static string ToString(byte[] input)
      {
         if (input == null || input.Length == 0)
         {
            throw new ArgumentNullException("input");
         }

         int charCount = (int)Math.Ceiling(input.Length / 5d) * 8;
         char[] returnArray = new char[charCount];

         byte nextChar = 0, bitsRemaining = 5;
         int arrayIndex = 0;

         foreach (byte b in input)
         {
            nextChar = (byte)(nextChar | (b >> (8 - bitsRemaining)));
            returnArray[arrayIndex++] = ValueToChar(nextChar);

            if (bitsRemaining < 4)
            {
               nextChar = (byte)((b >> (3 - bitsRemaining)) & 31);
               returnArray[arrayIndex++] = ValueToChar(nextChar);
               bitsRemaining += 5;
            }

            bitsRemaining -= 3;
            nextChar = (byte)((b << bitsRemaining) & 31);
         }

         //if we didn't end with a full char
         if (arrayIndex != charCount)
         {
            returnArray[arrayIndex++] = ValueToChar(nextChar);
            while (arrayIndex != charCount) returnArray[arrayIndex++] = '='; //padding
         }

         return new string(returnArray);
      }

      private static int CharToValue(char c)
      {
         int value = (int)c;

         //65-90 == uppercase letters
         if (value < 91 && value > 64)
         {
            return value - 65;
         }
         //50-55 == numbers 2-7
         if (value < 56 && value > 49)
         {
            return value - 24;
         }
         //97-122 == lowercase letters
         if (value < 123 && value > 96)
         {
            return value - 97;
         }

         throw new ArgumentException("Character is not a Base32 character.", "c");
      }

      private static char ValueToChar(byte b)
      {
         if (b < 26)
         {
            return (char)(b + 65);
         }

         if (b < 32)
         {
            return (char)(b + 24);
         }

         throw new ArgumentException("Byte is not a value Base32 value.", "b");
      }

   }

   class Program
   {
      struct Config
      {
         public string Method;
         public string Secret;
         public string Algorithm;
         public long Counter;
         public int Digits;
         public int Period;
      }

      static byte[] UnpackInt64(long value)
      {
         var current_value = value;
         var output = new byte[8];

         for (int i = 7; i >= 0; i--)
         {
            output[i] = (byte)(current_value & 0xffL);
            current_value >>= 8;
         }

         return output;
      }

      static long UnixTimestamp()
      {
         var span = (DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0));
         return (long) span.TotalSeconds;
      }

      static string GenerateHOTPCode(Config config)
      {
         var secret = config.Secret.ToUpper();
         var padding = 8 - (secret.Length % 8);
         if (padding == 8) {
            padding = 0;
         }

         secret = secret + new String('=', padding);
         var secret_bytes = Base32Encoding.ToBytes(secret);
         var counter_bytes = UnpackInt64(config.Counter);

         var hmac = GetHMACInstance(config.Algorithm);
         hmac.Key = secret_bytes;
         var digest = hmac.ComputeHash(counter_bytes);

         var offset = digest[digest.Length - 1] & 0xf;
         var base_code =
            (((digest[offset] & 0x7f) << 24) |
             ((digest[offset + 1] & 0xff) << 16) |
             ((digest[offset + 2] & 0xff) << 8) |
             (digest[offset + 3] & 0xff));

         var digits = base_code % (int)Math.Pow(10, config.Digits);
         return digits.ToString("D" + config.Digits);
      }

      static string GenerateTOTPCode(Config config)
      {
         config.Counter = UnixTimestamp() / config.Period;
         return GenerateHOTPCode(config);
      }

      static Config ParseArguments(string[] args)
      {
         var config = new Config();
         config.Algorithm = "sha1";
         config.Counter = -1;
         config.Digits = 6;
         config.Period = 30;

         int i = 0;
         try
         {
            while (i < args.Length)
            {
               switch (args[i])
               {
                  case "-t":
                     config.Method = "totp";
                     break;
                  case "-h":
                     config.Method = "hotp";
                     break;
                  case "-c":
                     i++;
                     config.Counter = long.Parse(args[i]);
                     break;
                  case "-s":
                     i++;
                     config.Secret = args[i];
                     break;
                  case "-a":
                     i++;
                     config.Algorithm = args[i];
                     break;
                  case "-d":
                     i++;
                     config.Digits = int.Parse(args[i]);
                     break;
                  case "-p":
                     i++;
                     config.Period = int.Parse(args[i]);
                     break;
               }

               i++;
            }
         }
         catch (IndexOutOfRangeException)
         {
            Console.Error.WriteLine("totp (-t | -h -c COUNTER) -s SECRET [-a ALGORITHM] [-d DIGITS] [-p PERIOD]");
            Environment.Exit(1);
         }
         catch (FormatException)
         {
            Console.Error.WriteLine("Integer expected for argument {}, got {} instead", i, args[i]);
            Console.Error.WriteLine("totp (-t | -h -c COUNTER) -s SECRET [-a ALGORITHM] [-d DIGITS] [-p PERIOD]");
            Environment.Exit(1);
         }

         if (config.Method == null)
         {
            Console.Error.WriteLine("Either -h or -t must be provided");
            Console.Error.WriteLine("totp (-t | -h -c COUNTER) -s SECRET [-a ALGORITHM] [-d DIGITS] [-p PERIOD]");
            Environment.Exit(1);
         }

         if (config.Algorithm != "sha1" &&
             config.Algorithm != "sha256" &&
             config.Algorithm != "sha512")
         {
            Console.Error.WriteLine("Argument of -a must be 'sha1', 'sha256' or 'sha512'");
            Console.Error.WriteLine("totp (-t | -h -c COUNTER) -s SECRET [-a ALGORITHM] [-d DIGITS] [-p PERIOD]");
            Environment.Exit(1);
         }

         if (config.Counter < 0 && config.Method != "totp")
         {
            Console.Error.WriteLine("Non-negative counter must be provided if -h is in use");
            Console.Error.WriteLine("totp (-t | -h -c COUNTER) -s SECRET [-a ALGORITHM] [-d DIGITS] [-p PERIOD]");
            Environment.Exit(1);
         }

         if (config.Digits <= 0)
         {
            Console.Error.WriteLine("Argument of -d must be positive");
            Console.Error.WriteLine("totp (-t | -h -c COUNTER) -s SECRET [-a ALGORITHM] [-d DIGITS] [-p PERIOD]");
            Environment.Exit(1);
         }

         if (config.Period <= 0)
         {
            Console.Error.WriteLine("Argument of -p must be positive");
            Console.Error.WriteLine("totp (-t | -h -c COUNTER) -s SECRET [-a ALGORITHM] [-d DIGITS] [-p PERIOD]");
            Environment.Exit(1);
         }

         return config;
      }

      static HMAC GetHMACInstance(string algorithm)
      {
         switch (algorithm)
         {
            case "sha1":
               return new HMACSHA1();

            case "sha256":
               return new HMACSHA256();

            case "sha512":
               return new HMACSHA512();
         }

         return null;
      }

      static void Main(string[] args)
      {
         Config config = ParseArguments(args);

         switch (config.Method)
         {
            case "hotp":
               Console.WriteLine(GenerateHOTPCode(config));
               break;

            case "totp":
               Console.WriteLine(GenerateTOTPCode(config));
               break;
         }
      }
   }
}
