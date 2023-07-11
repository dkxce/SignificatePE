//
// C# 
// dkxce.SignForm
// http://github.com/dkxce/SignificatePE
// en,ru,1251,utf-8
//

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Threading;
using System.Windows.Forms;

namespace dkxce
{
    public partial class SignForm : Form
    {
        #region DLLIMPORTs

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr GetSystemMenu(IntPtr hWnd, bool bRevert);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern bool AppendMenu(IntPtr hMenu, int uFlags, int uIDNewItem, string lpNewItem);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern bool InsertMenu(IntPtr hMenu, int uPosition, int uFlags, int uIDNewItem, string lpNewItem);

        #endregion DLLIMPORTs

        public SignForm()
        {
            InitializeComponent();
            this.AllowDrop = true;
            this.DragEnter += new DragEventHandler(Form_DragEnter);
            this.DragDrop += new DragEventHandler(Form_DragDrop);
            fList.DrawMode = DrawMode.OwnerDrawFixed;

            Assembly assembly = Assembly.GetExecutingAssembly();
            FileVersionInfo fvi = FileVersionInfo.GetVersionInfo(assembly.Location);
            this.Text += $" v{fvi.FileVersion}";
        }

        protected override void OnHandleCreated(EventArgs e)
        {
            base.OnHandleCreated(e);
            IntPtr hSysMenu = GetSystemMenu(this.Handle, false);
            AppendMenu(hSysMenu, 0x800, 0x00, string.Empty);
            AppendMenu(hSysMenu, 0x000, 0x01, "Author: dkxce");
            AppendMenu(hSysMenu, 0x000, 0x02, "Open Windows CertMgr... ");
        }

        protected override void WndProc(ref Message m)
        {
            base.WndProc(ref m);
            if ((m.Msg == 0x112) && ((int)m.WParam == 0x01)) // Author
            {
                OpenAbout();                
            };            
            if ((m.Msg == 0x112) && ((int)m.WParam == 0x02))
            {
                try { Process.Start("certmgr.msc"); } catch { };
            };            
        }

        private void Form_DragEnter(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop)) e.Effect = DragDropEffects.Copy;
        }

        private void Form_DragDrop(object sender, DragEventArgs e)
        {
            string[] files = (string[])e.Data.GetData(DataFormats.FileDrop);
            string certFile = null;
            List<string> signFiles = new List<string>();
            foreach (string file in files)
            {
                string ext = Path.GetExtension(file).ToLower();
                if (ext == ".pfx" || ext == ".p12")
                    certFile = file;
                else if (ext == ".exe" || ext == ".dll" || ext == ".msi")
                    signFiles.Add(file);
            };
            if (!string.IsNullOrEmpty(certFile))
            {
                pfxEdit.Text = certFile;
                selMode.SelectedIndex = 1;
            };
            if (signFiles.Count > 0)
            {
                if (selMode.SelectedIndex == 0)
                    selMode.SelectedIndex = 1;
                DropFiles(signFiles.ToArray());
            };
        }

        private void CmdLnArFrm_Load(object sender, EventArgs e)
        {
            selMode.SelectedIndex = 0;
            selHash.SelectedIndex = 0;
            LoadCfg();            
            Run(true, "/s /w=0 /?");
        }

        private void runBtn_Click(object sender, EventArgs e)
        {
            Run(true);
            SaveCfg();
        }

        private void Run(bool proceed = false, string mycommand = null)
        {
            string fileName = Environment.GetCommandLineArgs()[0];
            ProcessStartInfo psi = new ProcessStartInfo(fileName);            
            psi.UseShellExecute = false;
            psi.RedirectStandardOutput = true;

            string tmpfn = null;

            if (string.IsNullOrEmpty(mycommand))
            {
                if (selMode.SelectedIndex == 0 /* HELP */)
                    psi.Arguments = "/s /w=0 /?";
                if (selMode.SelectedIndex == 1 /* SIGN BY FILE */)
                {
                    try { if (!File.Exists(pfxEdit.Text.Trim())) return; } catch { return; };
                    psi.Arguments = $"/s /w=0 \"/c={pfxEdit.Text}\" /p={passEdit.Text}";
                };
                if (selMode.SelectedIndex == 2 /* SIGN BY THUMB */)
                {
                    if (string.IsNullOrEmpty(eThumb.Text.Trim())) return;
                    psi.Arguments = $"/s /w=0 \"/t={eThumb.Text.Trim()}\"";
                };
                if (selMode.SelectedIndex == 3 /* VERIFY */)
                    psi.Arguments = "/s /w=0 /v";
                if (selMode.SelectedIndex == 4 /* REMOVE */)
                    psi.Arguments = "/s /w=0 /r";
                if (selMode.SelectedIndex == 1 || selMode.SelectedIndex == 2 /* SIGN */)
                {
                    if (selHash.SelectedIndex > 0)
                    {
                        string[] ha = new string[] { "s256", "sha", "s256", "s512" };
                        psi.Arguments += $" /a={ha[selHash.SelectedIndex]}";
                    };
                    string ts = selTimeServer.Text.Trim();
                    if (!string.IsNullOrEmpty(ts))
                        psi.Arguments += $" /h={ts}";
                };
                if (selMode.SelectedIndex > 0)
                {
                    if (fList.Items.Count == 0)
                        psi.Arguments += " *";
                    else if (fList.Items.Count == 1)
                        psi.Arguments += $" \"{(fList.Items[0] as FileItem).FileName}\"";
                    else
                    {
                        tmpfn = Path.GetTempFileName();
                        List<string> files = new List<string>();
                        foreach (FileItem fi in fList.Items)
                            files.Add(fi.FileName);
                        File.WriteAllLines(tmpfn, files);
                        psi.Arguments += $" \"@{tmpfn}\"";
                    };
                };

                log.Clear();
                log.Text = $"MODE: {selMode.Text}\r\n\r\n{Path.GetFileName(psi.FileName)} {psi.Arguments}\r\n\r\n";

                if(selMode.SelectedIndex == 1 && fList.Items.Count == 1)
                {
                    string ts = selTimeServer.Text.Trim();
                    if (string.IsNullOrEmpty(ts))
                        ts += selTimeServer.Items[0];
                    string[] ha = new string[] { "SHA256", "SHA1", "SHA256", "SHA512" };
                    string al = ha[selHash.SelectedIndex];
                    log.Text += $"signtool.exe sign /d %INFO_DESC% /du %INFO_HTTP% /f \"{pfxEdit.Text}\" /p \"{passEdit.Text}\" /tr {ts} /td {al} /fd {al} \"{(fList.Items[0] as FileItem).FileName}\"\r\n\r\n";
                };
            }
            else
            {
                log.Clear();
                psi.Arguments = mycommand;
            };

            if (proceed)
            {
                runBtn.Enabled = false;
                try
                {
                    Process proc = new Process() { StartInfo = psi };
                    proc.OutputDataReceived += (s, e) => AppendTextBox($"{e.Data}\r\n");
                    proc.Start();
                    proc.BeginOutputReadLine();
                    proc.WaitForExit();
                }
                catch (Exception ex)
                {
                    AppendTextBox($"Error: {ex.Message}\r\n");
                };
                runBtn.Enabled = true;
            }
            else if (!string.IsNullOrEmpty(tmpfn))
            {
                AppendTextBox($"; {tmpfn} has been deleted!\r\n");
            };

            if (!string.IsNullOrEmpty(tmpfn) && File.Exists(tmpfn)) File.Delete(tmpfn);

            Application.DoEvents();
            log.SelectionStart = log.TextLength;
            log.ScrollToCaret();
        }

        public void AppendTextBox(string value)
        {
            System.Threading.Thread.Sleep(10);
            BeginInvoke(new ThreadStart(delegate {
                try { 
                    log.Text += value;
                    //log.SelectionStart = log.TextLength;
                    //log.ScrollToCaret();
                } catch { }; }));
            Application.DoEvents();
        }

        private void eThumb_TextChanged(object sender, EventArgs e)
        {
            int ss = eThumb.SelectionStart;
            eThumb.Text = Regex.Replace(eThumb.Text.ToUpper(),"[^A-Za-z0-9]","");
            eThumb.SelectionStart = ss;
        }

        private void selMode_SelectedIndexChanged(object sender, EventArgs e)
        {
            gbPfx.Enabled = selMode.SelectedIndex == 1;
            gbThumb.Enabled = selMode.SelectedIndex == 2;
            gFiles.Enabled = selMode.SelectedIndex != 0;
            gHash.Enabled = selMode.SelectedIndex == 1 || selMode.SelectedIndex == 2;
            gTimeServer.Enabled = selMode.SelectedIndex == 1 || selMode.SelectedIndex == 2;
        }

        private void pfxBtn_Click(object sender, EventArgs e)
        {
            OpenFileDialog ofd = new OpenFileDialog();
            ofd.Title = "Select Certificate from File";
            ofd.DefaultExt = ".pfx";
            ofd.Filter = "PFX Files (*.pfx;*.p12)|*.pfx;*.p12|All Types (*.*)|*.*";
            try { ofd.FileName = pfxEdit.Text.Trim(); } catch { };
            if (ofd.ShowDialog() == DialogResult.OK) pfxEdit.Text = ofd.FileName;
            ofd.Dispose();
        }

        private void removeFilesToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (fList.Items.Count == 0 || fList.SelectedItems.Count == 0) return;
            for (int i = fList.Items.Count - 1; i >= 0; i--)
                if (fList.SelectedIndices.IndexOf(i) >= 0)
                    fList.Items.RemoveAt(i);
            UpdateFiles();
        }

        private void addFilesToolStripMenuItem_Click(object sender, EventArgs e)
        {
            OpenFileDialog ofd = new OpenFileDialog();
            ofd.Title = "Select Files";
            ofd.DefaultExt = ".exe;.dll;.msi";
            ofd.Filter = "PE, DLL, MSI (*.exe;.dll;.msi)|*.exe;.dll;.msi";
            ofd.Multiselect = true;
            if (ofd.ShowDialog() == DialogResult.OK)
                DropFiles(ofd.FileNames);
            ofd.Dispose();
            UpdateFiles();
        }

        private void clearListToolStripMenuItem_Click(object sender, EventArgs e)
        {
            fList.Items.Clear();
            UpdateFiles();
        }

        private void DropFiles(string[] files)
        {
            if (files == null || files.Length == 0) return;
            foreach (string f in files)
            {
                bool ex = false;
                foreach (FileItem fi in fList.Items)
                    if (fi.FileName == f)
                        ex = true;
                if (!ex) fList.Items.Add(new FileItem(f));
            };
            UpdateFiles();
        }

        private void UpdateFiles()
        {
            gFiles.Text = $"Files (Total: {fList.Items.Count}):";
        }

        private void clsBtn_Click(object sender, EventArgs e)
        {
            log.Clear();
        }

        private void LoadCfg(bool empty = false, string fileName = null)
        {
            try
            {
                SignConfig cfg = empty ? new SignConfig() : (string.IsNullOrEmpty(fileName) ? SignConfig.Load("SignificatePE.ini") : SignConfig.Load(fileName));
                selMode.SelectedIndex = cfg.MODE;
                pfxEdit.Text = cfg.CERTIFICATE;
                try { passEdit.Text = PassCrypt.Decrypt(cfg.PASSWORD.Trim(), "SignificatePE::dkxce.SignForm"); } catch { passEdit.Text = ""; };
                eThumb.Text = cfg.THUMBPRINT;
                selHash.SelectedIndex = cfg.HASHALG;
                fList.Items.Clear();
                if (cfg.FILES != null && cfg.FILES.Count > 0)
                    DropFiles(cfg.FILES.ToArray());
            }
            catch { };
        }

        private void SaveCfg(string fileName = null)
        {
            if (selMode.SelectedIndex == 0 && string.IsNullOrEmpty(fileName)) return;
            SignConfig cfg = new SignConfig()
            {
                MODE = (byte)selMode.SelectedIndex,
                CERTIFICATE = pfxEdit.Text.Trim(),
                PASSWORD = PassCrypt.Encrypt(passEdit.Text.Trim(), "SignificatePE::dkxce.SignForm"),
                THUMBPRINT = eThumb.Text.Trim(),
                HASHALG = (byte)selHash.SelectedIndex,
                TIMESERVER = selTimeServer.Text.Trim()
            };
            foreach (FileItem fi in fList.Items)
                cfg.FILES.Add(fi.FileName);
            try { if (string.IsNullOrEmpty(fileName)) SignConfig.SaveHere("SignificatePE.ini", cfg); else SignConfig.Save(fileName, cfg); } catch { };
        }

        private void button1_Click(object sender, EventArgs e)
        {
            contextMenuStrip2.Show((Control)sender, new Point(0, 0));
        }

        private void fList_DrawItem(object sender, DrawItemEventArgs e)
        {
            e.DrawBackground();

            FileItem fi = e.Index >= 0 ? fList.Items[e.Index] as FileItem : null;
            if (fi != null)
            {
                string fnm = Path.GetFileName(fi.FileName);
                string dir = Path.GetDirectoryName(fi.FileName);

                if (dir.Length > 40) dir = dir.Substring(0, 15) + " ... " + dir.Substring(dir.Length - 15);
                if (fnm.Length > 40) fnm = fnm.Substring(0, 15) + " ... " + fnm.Substring(fnm.Length - 15);
                dir = dir.Trim();
                fnm = fnm.Trim();
                SizeF sfn = e.Graphics.MeasureString(fnm, e.Font);

                e.Graphics.DrawString(fnm, e.Font, Brushes.Black, e.Bounds);
                e.Graphics.DrawString(dir, e.Font, Brushes.Maroon, new RectangleF(e.Bounds.Left + sfn.Width, e.Bounds.Top, e.Bounds.Width, e.Bounds.Height));
            };

            e.DrawFocusRectangle();
        }

        private void cmdBtn_Click(object sender, EventArgs e)
        {
            Run(false);
            SaveCfg();
        }

        private void aboutToolStripMenuItem_Click(object sender, EventArgs e)
        {
            OpenAbout();
        }

        private void OpenAbout()
        {
            try { Process.Start("http://github.com/dkxce/SignificatePE"); } catch { };
        }

        private void newConfigurationToolStripMenuItem_Click(object sender, EventArgs e)
        {
            LoadCfg(true);
        }

        private void openWindowsCertMgrToolStripMenuItem_Click(object sender, EventArgs e)
        {
            try { Process.Start("certmgr.msc"); } catch { };
        }

        private void openConfigurationToolStripMenuItem_Click(object sender, EventArgs e)
        {
            OpenFileDialog fd = new OpenFileDialog();
            fd.Filter = "Ini Files (*.ini)|*.ini";
            fd.DefaultExt = ".ini";
            fd.InitialDirectory = Path.GetDirectoryName(Environment.GetCommandLineArgs()[0]);
            if (fd.ShowDialog() == DialogResult.OK)
                LoadCfg(false, fd.FileName);
            fd.Dispose();
        }

        private void saveConfigurationToolStripMenuItem_Click(object sender, EventArgs e)
        {
            string suffix = selMode.Text;
            if(selMode.SelectedIndex == 1 && !string.IsNullOrEmpty(pfxEdit.Text.Trim()) && File.Exists(pfxEdit.Text))
                suffix = Path.GetFileName(pfxEdit.Text);
            if (selMode.SelectedIndex == 2 && !string.IsNullOrEmpty(eThumb.Text.Trim()))
                suffix = eThumb.Text.Trim();

            SaveFileDialog fd = new SaveFileDialog();
            fd.FileName = $"Cfg [{suffix}].ini";
            fd.Filter = "Ini Files (*.ini)|*.ini";
            fd.DefaultExt = ".ini";
            fd.InitialDirectory = Path.GetDirectoryName(Environment.GetCommandLineArgs()[0]);
            if (fd.ShowDialog() == DialogResult.OK)
                SaveCfg(fd.FileName);
            fd.Dispose();
        }

        private void contextMenuStrip2_Opening(object sender, System.ComponentModel.CancelEventArgs e)
        {
            configsItem.DropDownItems.Clear();
            string path = Path.GetDirectoryName(Environment.GetCommandLineArgs()[0]);
            string[] files = Directory.GetFiles(path, "*.ini", SearchOption.AllDirectories);
            configsItem.Enabled = files.Length > 0;
            foreach (string f in files)
            {
                string nm = f.Substring(path.Length).Trim('\\');
                if (nm == "SignificatePE.ini") nm += " (Last Launched)";
                ToolStripMenuItem mi = new ToolStripMenuItem(nm,this.Icon.ToBitmap());
                mi.Click += (object s, EventArgs a) => LoadCfg(false, f);
                configsItem.DropDownItems.Add(mi);
            };
        }
    }

    public class FileItem
    {
        public string FileName { get; set; }
        public FileItem() { }
        public FileItem(string FileName) { this.FileName = FileName; }

        public override string ToString()
        {
            string dir = Path.GetDirectoryName(FileName);
            string fnm = Path.GetFileName(FileName);
            if (dir.Length > 40) dir = dir.Substring(0, 15) + " ... " + dir.Substring(dir.Length - 15);
            if (fnm.Length > 40) fnm = fnm.Substring(0, 15) + " ... " + fnm.Substring(fnm.Length - 15);
            return $"{fnm} - at {dir}";
        }
    }


    [IniSection("CONFIG")]
    public class SignConfig: IniSaved<SignConfig>
    {
        public byte MODE;
        public string CERTIFICATE;
        public string PASSWORD;
        public string THUMBPRINT;
        public byte HASHALG;
        public string TIMESERVER;
        public List<string> FILES = new List<string>();
    }
}
