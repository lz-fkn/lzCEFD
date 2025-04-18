// Finalized C# version of pyCEFD with GUI threading, progress bar, and registry settings
using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows.Forms;
using Microsoft.Win32;

namespace CefdSharp
{
    public partial class MainForm : Form
    {
        private string compressionMethod = null!;
        private int compressionLevel;
        private string sevenZipPath = "7za.x64.exe";
        private const string FileSignature = "lzCEFDv1\n";
        private const string RegistryPath = "Software\\Elzzie\\lzCEFD";

        private TextBox inputBox = null!;
        private TextBox keyBox = null!;
        private ProgressBar progressBar = null!;
        private Button encryptBtn = null!;
        private Button decryptBtn = null!;

        public MainForm()
        {
            // InitializeComponent();
            LoadSettings();
            InitUI();
        }

        private void InitUI()
        {
            this.Text = "lzCEFD - Secure Compression";
            this.Size = new System.Drawing.Size(600, 200);

            Label inputLabel = new Label() { Text = "Input File", Top = 10, Left = 10 };
            inputBox = new TextBox() { Top = 30, Left = 10, Width = 400 };
            Button browseInput = new Button() { Text = "Browse", Top = 28, Left = 420 };
            browseInput.Click += (s, e) =>
            {
                OpenFileDialog dlg = new OpenFileDialog();
                if (dlg.ShowDialog() == DialogResult.OK)
                    inputBox.Text = dlg.FileName;
            };

            Label keyLabel = new Label() { Text = "Key File", Top = 60, Left = 10 };
            keyBox = new TextBox() { Top = 80, Left = 10, Width = 400 };
            Button browseKey = new Button() { Text = "Browse", Top = 78, Left = 420 };
            browseKey.Click += (s, e) =>
            {
                OpenFileDialog dlg = new OpenFileDialog();
                if (dlg.ShowDialog() == DialogResult.OK)
                    keyBox.Text = dlg.FileName;
            };

            encryptBtn = new Button() { Text = "Encrypt", Top = 120, Left = 10, Width = 80 };
            decryptBtn = new Button() { Text = "Decrypt", Top = 120, Left = 100, Width = 80 };
            progressBar = new ProgressBar() { Top = 120, Left = 200, Width = 300 };

            encryptBtn.Click += async (s, e) => await Task.Run(() => EncryptFile(inputBox.Text, keyBox.Text));
            decryptBtn.Click += async (s, e) => await Task.Run(() => DecryptFile(inputBox.Text, keyBox.Text));

            this.Controls.AddRange(new Control[]
            {
                inputLabel, inputBox, browseInput,
                keyLabel, keyBox, browseKey,
                encryptBtn, decryptBtn, progressBar
            });
        }

        private void LoadSettings()
        {
            using var key = Registry.CurrentUser.CreateSubKey(RegistryPath);
            compressionMethod = key.GetValue("CompressionMethod", "lzma2").ToString();
            compressionLevel = Convert.ToInt32(key.GetValue("CompressionLevel", 5));
        }

        private void SaveSettings()
        {
            using var key = Registry.CurrentUser.CreateSubKey(RegistryPath);
            key.SetValue("CompressionMethod", compressionMethod);
            key.SetValue("CompressionLevel", compressionLevel);
        }

        private void EncryptFile(string inputPath, string publicKeyPath)
        {
            if (!File.Exists(inputPath) || !File.Exists(publicKeyPath)) return;
            SaveSettings();
            progressBar.Invoke(() => progressBar.Value = 0);

            string compressedPath = Path.GetTempFileName() + ".7z";
            CompressFile(inputPath, compressedPath);

            byte[] aesKey = RandomNumberGenerator.GetBytes(16);

            byte[] encryptedData;
            byte[] iv;
            using (Aes aes = Aes.Create())
            {
                aes.Key = aesKey;
                aes.GenerateIV();
                iv = aes.IV;
                aes.Mode = CipherMode.CBC;
                using var ms = new MemoryStream();
                using var cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write);
                using (var fs = File.OpenRead(compressedPath))
                    fs.CopyTo(cs);
                cs.FlushFinalBlock();
                encryptedData = ms.ToArray();
            }
            progressBar.Invoke(() => progressBar.Value = 50);

            string originalFileName = Path.GetFileName(inputPath);
            string aesKeyB64 = Convert.ToBase64String(aesKey);
            string crc32 = GetCRC32(inputPath);
            string metadata = JsonSerializer.Serialize(new
            {
                fn = originalFileName,
                k = aesKeyB64,
                c = compressionMethod,
                h = crc32
            });
            byte[] metadataBytes = Encoding.UTF8.GetBytes(metadata);
            byte[] encryptedMeta;
            using (RSA rsa = RSA.Create())
            {
                rsa.ImportFromPem(File.ReadAllText(publicKeyPath));
                encryptedMeta = rsa.Encrypt(metadataBytes, RSAEncryptionPadding.OaepSHA256);
            }

            string outputPath = $"encrypted_{Guid.NewGuid():N}.cefd";
            using var outStream = new FileStream(outputPath, FileMode.Create);
            using var writer = new BinaryWriter(outStream);
            writer.Write(Encoding.ASCII.GetBytes(FileSignature));
            writer.Write(BitConverter.GetBytes(encryptedMeta.Length));
            writer.Write(encryptedMeta);
            writer.Write(iv);
            writer.Write(encryptedData);

            progressBar.Invoke(() => progressBar.Value = 100);
            MessageBox.Show($"Encrypted file saved as {outputPath}");
        }

        private void DecryptFile(string inputPath, string privateKeyPath)
        {
            if (!File.Exists(inputPath) || !File.Exists(privateKeyPath)) return;
            progressBar.Invoke(() => progressBar.Value = 0);

            using var stream = new FileStream(inputPath, FileMode.Open);
            using var reader = new BinaryReader(stream);

            string signature = Encoding.ASCII.GetString(reader.ReadBytes(FileSignature.Length));
            if (signature != FileSignature)
            {
                MessageBox.Show("Invalid file signature.");
                return;
            }

            int metaLength = reader.ReadInt32();
            byte[] encryptedMeta = reader.ReadBytes(metaLength);
            byte[] iv = reader.ReadBytes(16);
            byte[] encryptedData = reader.ReadBytes((int)(stream.Length - stream.Position));

            byte[] metadataJson;
            using (RSA rsa = RSA.Create())
            {
                rsa.ImportFromPem(File.ReadAllText(privateKeyPath));
                metadataJson = rsa.Decrypt(encryptedMeta, RSAEncryptionPadding.OaepSHA256);
            }

            var metadata = JsonSerializer.Deserialize<JsonElement>(metadataJson);
            string originalFilename = metadata.GetProperty("fn").GetString();
            string aesKeyB64 = metadata.GetProperty("k").GetString();
            string compression = metadata.GetProperty("c").GetString();
            string crc = metadata.GetProperty("h").GetString();

            byte[] decryptedData;
            using (Aes aes = Aes.Create())
            {
                aes.Key = Convert.FromBase64String(aesKeyB64);
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                using var ms = new MemoryStream();
                using var cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write);
                cs.Write(encryptedData);
                cs.FlushFinalBlock();
                decryptedData = ms.ToArray();
            }
            progressBar.Invoke(() => progressBar.Value = 50);

            string tempFile = Path.GetTempFileName();
            File.WriteAllBytes(tempFile, decryptedData);

            string outputDir = Path.GetDirectoryName(inputPath);
            var proc = new Process()
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = sevenZipPath,
                    Arguments = $"x \"{tempFile}\" -o\"{outputDir}\" -y",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };
            proc.Start();
            proc.WaitForExit();

            progressBar.Invoke(() => progressBar.Value = 100);
            MessageBox.Show($"Decrypted to {outputDir}");
        }

        private void CompressFile(string inputPath, string outputPath)
        {
            string args = compressionMethod switch
            {
                "lzma2" => $"a -t7z -mx={compressionLevel} \"{outputPath}\" \"{inputPath}\"",
                "gzip" => $"a -tgzip -mx={compressionLevel} \"{outputPath}\" \"{inputPath}\"",
                "bzip" => $"a -tbzip2 -mx={compressionLevel} \"{outputPath}\" \"{inputPath}\"",
                "deflate" => $"a -tzip -mx={compressionLevel} \"{outputPath}\" \"{inputPath}\"",
                "none" => $"a -ttar -mx=0 \"{outputPath}\" \"{inputPath}\"",
                _ => throw new ArgumentException("Unsupported compression method")
            };

            var proc = new Process()
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = sevenZipPath,
                    Arguments = args,
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };
            proc.Start();
            proc.WaitForExit();
        }

        private string GetCRC32(string filePath)
        {
            using var fs = File.OpenRead(filePath);
            using var crc32 = new Crc32();
            byte[] hash = crc32.ComputeHash(fs);
            return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
        }
    }

    public static class ControlExtensions
    {
        public static void Invoke(this Control control, Action action)
        {
            if (control.InvokeRequired) control.Invoke(new MethodInvoker(action));
            else action();
        }
    }
}
