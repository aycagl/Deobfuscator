using System;
using System.Linq;
using System.Reflection.Emit;
using System.Security.Cryptography;
using System.Text;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace ConsoleApp1
{
    internal class Deobfuscator
    {
        // Decrypts the given obfuscated string using a predefined key and Rijndael (AES) algorithm
        public static string DecryptString(string encryptedString, string key)
        {
            using (RijndaelManaged rijndaelManaged = new RijndaelManaged())
            using (MD5CryptoServiceProvider md5CryptoServiceProvider = new MD5CryptoServiceProvider())
            {
                // Hash the static key with MD5 to create the decryption key
                byte[] keyArray = new byte[32];
                byte[] hashArray = md5CryptoServiceProvider.ComputeHash(Encoding.UTF8.GetBytes(key));

                //Copy the first 16 bytes into the first half of the key array
                Array.Copy(hashArray, 0, keyArray, 0, 16);
                // Copy the first 16 bytes again into the second half 
                Array.Copy(hashArray, 0, keyArray, 15, 16);

                // Set the Rijndael key and mode to ECB
                rijndaelManaged.Key = keyArray;
                rijndaelManaged.Mode = CipherMode.ECB;

                // Create a decryptor with the given key
                ICryptoTransform decryptor = rijndaelManaged.CreateDecryptor();

                // Convert the Base64 encrypted string into bytes and decrypt it
                byte[] encryptedBytes = Convert.FromBase64String(encryptedString);
                byte[] decryptedBytes = decryptor.TransformFinalBlock(encryptedBytes, 0, encryptedBytes.Length);

                return Encoding.UTF8.GetString(decryptedBytes);
            }
        }

        // Extracts the value of a specific field from the given module
        static string GetFieldValue(ModuleDefMD module, string fieldName)
        {
            foreach (TypeDef type in module.Types)
            {
                foreach (MethodDef method in type.Methods)
                {
                    if (!method.HasBody) continue; // Skip methods without body
                    for (int i = 0; i < method.Body.Instructions.Count; i++)
                    {
                        // Find the Stsfld opcode (sets a static field) and check the field name
                        if (method.Body.Instructions[i].OpCode == OpCodes.Stsfld &&
                            method.Body.Instructions[i].Operand.ToString() == fieldName)
                        {
                            // Return the previous operand which holds the value being assigned to the field
                            return method.Body.Instructions[i - 1].Operand.ToString();
                        }
                    }
                }
            }
            return string.Empty;
        }

        // Decrypting and replacing obfuscated strings
        static void ReplaceEncryptedStrings(ModuleDefMD module, string key)
        {
            // Loop through all types in the module
            foreach (TypeDef type in module.Types)
            {
                if (!type.HasMethods) continue; // Skip types without methods

                // Loop through all methods of the type
                foreach (MethodDef method in type.Methods)
                {
                    if (!method.HasBody) continue;
                    for (int i = 0; i < method.Body.Instructions.Count; i++)
                    {
                        if (method.Body.Instructions[i].OpCode == OpCodes.Call)
                        {
                            string functionName = method.Body.Instructions[i].Operand.ToString();

                            // Look for the obfuscated decryption function
                            if (functionName.Contains("Sf3ygLwXizFpQcdEafah6RmRmvi94yTN3n3UpcJF") ||
                                functionName.Contains("rcGLP28muXxfBxK3uFwoeAtSCKBUh59TpsFfzA1jtrEEczzNWbt7mki"))
                            {
                                // Get the encrypted string from the previous instruction
                                string fieldValue = method.Body.Instructions[i - 1].Operand.ToString();
                                Console.WriteLine(fieldValue);

                                // Decrypt the value and replace the instruction with the decrypted string
                                string decryptedString = DecryptString(GetFieldValue(module, fieldValue), key);

                                method.Body.Instructions[i - 1].OpCode = OpCodes.Nop; // Clear the original instruction
                                method.Body.Instructions[i].OpCode = OpCodes.Ldstr; // Load the decrypted string instead
                                method.Body.Instructions[i].Operand = decryptedString;
                            }
                        }
                    }
                }
            }
        }

        static void Main(string[] args)
        {
            string filePath = @"C:\Users\aycagl\Desktop\buidl.exe";
            string key = "N0BNPIHTRtK9oiyP";

            ModuleDefMD module = ModuleDefMD.Load(filePath);

            ReplaceEncryptedStrings(module, key);

            // Write the deobfuscated code to a new file
            module.Write(@"C:\Users\aycagl\Desktop\clean.exe");

            Console.WriteLine("Deobfuscation completed.");
            Console.ReadKey();
        }
    }
}

