using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Windows.Forms;
using VirusTotalNet;
using VirusTotalNet.Results;
using VT_UI_Demo.Properties;

namespace VT_UI_Demo
{
    public partial class Form1 : Form
    {

        readonly List<Control> title = new List<Control>();
        readonly List<Control> content = new List<Control>();

        public string url;

        public Form1()
        {
            InitializeComponent();
            title.AddRange(new Control[] { bunifuLabel1, bunifuLabel2, bunifuPictureBox1, bunifuTextBox1, bunifuTextBox2, bunifuButton22 });
            content.AddRange(new Control[] { bunifuTextBox1, bunifuTextBox2, bunifuButton22, bunifuLabel3, bunifuButton23, bunifuPictureBox2 });

        }

        public const int WM_NCLBUTTONDOWN = 0xA1;
        public const int HT_CAPTION = 0x2;

        [System.Runtime.InteropServices.DllImport("user32.dll")]
        public static extern int SendMessage(IntPtr hWnd, int Msg, int wParam, int lParam);
        [System.Runtime.InteropServices.DllImport("user32.dll")]
        public static extern bool ReleaseCapture();

        private void Form1_MouseDown(object sender, System.Windows.Forms.MouseEventArgs e)
        {
            if (e.Button == MouseButtons.Left && e.Y < 25)
            {
                ReleaseCapture();
                SendMessage(Handle, WM_NCLBUTTONDOWN, HT_CAPTION, 0);
            }
        }

        private void BunifuButton21_Click(object sender, EventArgs e)
        {
            Application.Exit();
        }

        private void Form1_Shown(object sender, EventArgs e)
        {
            title.ForEach(c => bunifuTransition1.Show(c, true));
        }

        private void BunifuTextBox2_Click(object sender, EventArgs e)
        {
            OpenFileDialog fd = new OpenFileDialog();
            if (fd.ShowDialog() == DialogResult.OK)
            {
                // Get the selected file path
                string selectedFilePath = fd.FileName;
                bunifuTextBox2.Text = selectedFilePath;
            }
        }

        private void BunifuButton22_Click(object sender, EventArgs e)
        {
            if (bunifuTextBox2.Text.Length > 2 && bunifuTextBox2.PlaceholderText != bunifuTextBox2.Text && bunifuTextBox1.Text.Length > 36)
            {
                FileStream fs = File.OpenRead(bunifuTextBox2.Text);
                using (MD5 md5 = MD5.Create())
                {
                    Scan(BitConverter.ToString(md5.ComputeHash(fs)).Replace("-", String.Empty));
                }

            }
        }
        public async void Scan(string MD5)
        {
            if (String.IsNullOrEmpty(MD5))
            {
                bunifuLabel3.Text = "Invalid file selected.";
                return;
            }
            content.ForEach(c => c.Visible = false);
            bunifuLoader1.Visible = true;

            VirusTotal virusTotal = new VirusTotal(bunifuTextBox1.Text)
            {
                UseTLS = true
            };

            // NEED MD5, SHA256, ScanID;
            FileReport fr = await virusTotal.GetFileReportAsync(MD5);

            if (fr.ResponseCode == VirusTotalNet.ResponseCodes.FileReportResponseCode.Present)
            {
                bunifuLoader1.Visible = false;
                bunifuLabel3.Text = "File report present: " + fr.Positives + " detections";
                if (fr.Positives > 0 && fr.Positives <= 3)
                {
                    bunifuPictureBox2.Image = Resources.triangle;
                }
                else if (fr.Positives > 3)
                {
                    bunifuPictureBox2.Image = Resources.x;
                }
                else
                {
                    bunifuPictureBox2.Image = Resources.check;
                }
                url = fr.Permalink;
                content.ForEach(c => bunifuTransition1.Show(c, true));
            }
            else
            {
                try
                {
                    ScanResult sr = await virusTotal.ScanFileAsync(bunifuTextBox2.Text);
                    bunifuLoader1.Visible = false;
                    bunifuLabel3.Text = "Scan report created: " + fr.Positives + " detections";
                    url = sr.Permalink;
                    content.ForEach(c => bunifuTransition1.Show(c, true));
                }
                catch (Exception)
                {
                    bunifuLoader1.Visible = false;
                    bunifuLabel3.Text = "Unable to scan file. Please try a different file.";
                    content.ForEach(c => bunifuTransition1.Show(c, true));
                }
            }
        }

        private void BunifuButton23_Click(object sender, EventArgs e)
        {
            if (!String.IsNullOrEmpty(url))
            {
                System.Diagnostics.Process.Start(url);
            }
        }
    }

}
