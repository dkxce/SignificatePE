//
// C# 
// dkxce.SignForm
// http://github.com/dkxce/SignificatePE
// en,ru,1251,utf-8
//

using SignificatePE;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
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

        AutoCompleteStringCollection eThumbCache = new AutoCompleteStringCollection();
        AutoCompleteStringCollection pfxCache = new AutoCompleteStringCollection();
        Task TSATask = null;
        object tsaServer = null;

        public List<string> TimeServers = new List<string>() { 
            "NO_TIMESTAMP",
            "INTERNAL",
            "http://timestamp.digicert.com",
            "http://timestamp.comodoca.com",
            "http://timestamp.sectigo.com",
            "http://tsa.starfieldtech.com",
            "http://freetsa.org/tsr",
            "http://time.certum.pl",
            "http://timestamp.geotrust.com/tsa",
            "http://timestamp.globalsign.com/scripts/timstamp.dll",
            "http://tsa.starfieldtech.com",
            "https://teszt.e-szigno.hu:440/tsa",            
        };

        public SignForm()
        {
            InitializeComponent();
            this.AllowDrop = true;
            this.DragEnter += new DragEventHandler(Form_DragEnter);
            this.DragDrop += new DragEventHandler(Form_DragDrop);
            fList.DrawMode = DrawMode.OwnerDrawFixed;

            Assembly assembly = Assembly.GetExecutingAssembly();
            FileVersionInfo fvi = FileVersionInfo.GetVersionInfo(assembly.Location);
            this.Text += $" v{fvi.FileVersion} ST TSA";

            selTimeServer.Items.AddRange(TimeServers.ToArray());           
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
            //MessageBox.Show(DateTime.UtcNow.ToString());

            eThumb.AutoCompleteSource = AutoCompleteSource.CustomSource;
            eThumb.AutoCompleteMode = AutoCompleteMode.SuggestAppend;
            eThumb.AutoCompleteCustomSource = eThumbCache;

            pfxEdit.AutoCompleteSource = AutoCompleteSource.CustomSource;
            pfxEdit.AutoCompleteMode = AutoCompleteMode.SuggestAppend;
            pfxEdit.AutoCompleteCustomSource = pfxCache;

            selMode.SelectedIndex = 0;
            selHash.SelectedIndex = 0;
            msiMode.SelectedIndex = 0;
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
            List<FileItem> INTFILES = new List<FileItem>();
            List<FileItem> MSIFILES = new List<FileItem>();

            if (fList.Items.Count > 0)
            {
                foreach (FileItem item in fList.Items)
                    if ((selMode.SelectedIndex == 1 || selMode.SelectedIndex == 2) && msiMode.SelectedIndex == 1 && Path.GetExtension(item.FileName).ToLower().Trim('.') == "msi") 
                        MSIFILES.Add(item);
                    else 
                        INTFILES.Add(item);
            };

            string fileName = Environment.GetCommandLineArgs()[0];
            ProcessStartInfo psi = new ProcessStartInfo(fileName);            
            psi.UseShellExecute = false;
            psi.RedirectStandardOutput = true;
            string[] ha = new string[] { "s256", "sha", "s256", "s512", "sha,s256", "sha,s512", "s256,s512", "sha,s256,s512" };

            string tmpfn = null;

            DateTime? retroactDT = null; // sign with expired cert //
            if (string.IsNullOrEmpty(mycommand))
            {
                int wait = (selMode.SelectedIndex == 1 || selMode.SelectedIndex == 2) && (selHash.SelectedIndex > 4 || fList.Items.Count > 1) ? 500 : 0;
                if (selMode.SelectedIndex == 0 /* HELP */)
                    psi.Arguments = $"/s /w={wait} /?";
                if (selMode.SelectedIndex == 1 /* SIGN BY FILE */)
                {
                    try { if (!File.Exists(pfxEdit.Text.Trim())) return; } catch { return; };
                    psi.Arguments = $"/s /w={wait} \"/c={pfxEdit.Text}\" /p={passEdit.Text}";
                    if (ovMode.SelectedIndex == 1) psi.Arguments += " /n";
                    if (ovMode.SelectedIndex == 2) psi.Arguments += " /m";
                };
                if (selMode.SelectedIndex == 2 /* SIGN BY THUMB */)
                {
                    if (string.IsNullOrEmpty(eThumb.Text.Trim())) return;
                    psi.Arguments = $"/s /w={wait} \"/t={eThumb.Text.Trim()}\"";
                    if (ovMode.SelectedIndex == 1) psi.Arguments += " /n";
                    if (ovMode.SelectedIndex == 2) psi.Arguments += " /m";
                };
                if (selMode.SelectedIndex == 3 /* VERIFY */)
                    psi.Arguments = $"/s /w={wait} /v";
                if (selMode.SelectedIndex == 4 /* REMOVE */)
                    psi.Arguments = $"/s /w={wait} /r";
                if (selMode.SelectedIndex == 1 || selMode.SelectedIndex == 2 /* SIGN */)
                {
                    if (selHash.SelectedIndex > 0)
                    {                        
                        psi.Arguments += $" /A={ha[selHash.SelectedIndex]}";
                    };
                    string ts = selTimeServer.Text.Trim();
                    if (!string.IsNullOrEmpty(ts))
                    {
                        if (DateTime.TryParse(selTimeServer.Text.Trim(), out DateTime radt))
                        {                            
                            retroactDT = radt;
                            if (tsYes.Checked)
                            {
                                string radts = radt.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss");
                                psi.Arguments += $" /h=http://localhost:{TSAServer.TSAPort}{TSAServer.TSAPath}{radts}";
                            }
                            else
                                psi.Arguments += $" /h=NO_TIMESTAMP";
                        }
                        else
                        {
                            if (ts == "INTERNAL")
                                psi.Arguments += $" /h=http://localhost:{TSAServer.TSAPort}{TSAServer.TSAPath}";
                            else
                                psi.Arguments += $" /h={ts}";
                        };
                    };
                };

                if (selMode.SelectedIndex > 0)
                {
                    if (fList.Items.Count == 0)   // No files at all
                        psi.Arguments += " *";
                    else if (INTFILES.Count == 1) // 1 non .msi file
                        psi.Arguments += $" \"{(INTFILES[0] as FileItem).FileName}\"";
                    else
                    {
                        tmpfn = CreateTempFile(null);
                        List<string> files = new List<string>();
                        foreach (FileItem fi in INTFILES)
                            files.Add(fi.FileName);
                        File.WriteAllLines(tmpfn, files);
                        psi.Arguments += $" \"@{tmpfn}\"";
                    };
                };

                log.Clear();
                log.Text = $"MODE: {selMode.Text}\r\n\r\n{Path.GetFileName(psi.FileName)} {psi.Arguments}\r\n\r\n";


                for (int mi = 0; mi < MSIFILES.Count; mi++)
                {
                    if (selMode.SelectedIndex == 1)
                    {
                        string ts = selTimeServer.Text.Trim();
                        if (string.IsNullOrEmpty(ts))
                            ts += selTimeServer.Items[0];
                        string al = ha[selHash.SelectedIndex];
                        string INFO_DESC = string.IsNullOrEmpty(msiDesc.Text) ? "%INFO_DESC%" : msiDesc.Text;
                        string INFO_HTTP = string.IsNullOrEmpty(msiHttp.Text) ? "%INFO_HTTP%" : msiHttp.Text;
                        log.Text += $"signtool.exe sign /d \"{INFO_DESC}\" /du \"{INFO_HTTP}\" /f \"{pfxEdit.Text}\" /p \"{passEdit.Text}\" /tr {ts} /td SHA256 /fd SHA256 \"{(MSIFILES[mi] as FileItem).FileName}\"\r\n\r\n";
                    };
                    if (selMode.SelectedIndex == 2)
                    {
                        string ts = selTimeServer.Text.Trim();
                        if (string.IsNullOrEmpty(ts))
                            ts += selTimeServer.Items[0];
                        string al = ha[selHash.SelectedIndex];
                        string INFO_DESC = string.IsNullOrEmpty(msiDesc.Text) ? "%INFO_DESC%" : msiDesc.Text;
                        string INFO_HTTP = string.IsNullOrEmpty(msiHttp.Text) ? "%INFO_HTTP%" : msiHttp.Text;
                        log.Text += $"signtool.exe sign /sha1 \"{eThumb.Text.Trim()}\" \"{INFO_DESC}\" /du \"{INFO_HTTP}\" /tr {ts} /td SHA256 /fd SHA256 \"{(MSIFILES[mi] as FileItem).FileName}\"\r\n\r\n";
                    };
                    if (selMode.SelectedIndex == 3)
                    {
                        string ts = selTimeServer.Text.Trim();
                        if (string.IsNullOrEmpty(ts))
                            ts += selTimeServer.Items[0];
                        string al = ha[selHash.SelectedIndex];
                        log.Text += $"signtool.exe verify /all /v /pa \"{(MSIFILES[mi] as FileItem).FileName}\"\r\n\r\n";
                    };
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
                if (!string.IsNullOrEmpty(mycommand)) /* LAUNCH ONLY COMMAND */
                {
                    try
                    {                        
                        Process proc = new Process() { StartInfo = psi };                        
                        proc.OutputDataReceived += (s, e) => AppendTextBox($"{e.Data}\r\n");
                        proc.Start();
                        proc.BeginOutputReadLine();
                        proc.WaitForExit();
                    }
                    catch (Exception ex) { AppendTextBox($"Error: {ex.Message}\r\n"); };
                }
                else /* IF FILES */
                {
                    if (fList.Items.Count == 0 /* any */ || INTFILES.Count > 0 /* specified */)
                    {
                        string tmpf = null;
                        try
                        {                            
                            if (retroactDT.HasValue)
                            {
                                tmpf = CreateTempFile(".exe");
                                File.WriteAllBytes(tmpf, global::SignificatePE.Properties.Resources.RunAsDate);

                                // RunAsDate Utility
                                //   https://www.nirsoft.net/utils/run_as_date.html
                                // Examples:
                                //   RunAsDate.exe 22\10\2002 12:35:22 "C:\Program Files\Microsoft Office\OFFICE11\OUTLOOK.EXE"
                                //   RunAsDate.exe 14\02\2005 "c:\temp\myprogram.exe" param1 param2
                                //   RunAsDate.exe /movetime 11\08\2004 16:21:42 "C:\Program Files\Microsoft Office\OFFICE11\OUTLOOK.EXE"
                                //   RunAsDate.exe /movetime / returntime 15 10\12\2001 11:41:26 "c:\temp\myprogram.exe"
                                //   RunAsDate.exe Hours:-10 "C:\Program Files\Microsoft Office\OFFICE11\OUTLOOK.EXE"
                                //   RunAsDate.exe 22\03\2008 10:10:25 Attach: Outlook.exe
                                //   RunAsDate.exe 20\08\2003 20:20:45 Attach: 2744

                                string dtf = retroactDT.Value.ToString(@"dd\\MM\\yyyy HH:mm:ss");
                                string cd = IniSaved<int>.CurrentDirectory().TrimEnd('\\');
                                psi.Arguments = $"/movetime /startin \"{cd}\" {dtf} {psi.FileName} {psi.Arguments}";
                                psi.FileName = tmpf;
                            };

                            Process proc = new Process() { StartInfo = psi };
                            proc.OutputDataReceived += (s, e) => AppendTextBox($"{e.Data}\r\n");
                            proc.Start();
                            proc.BeginOutputReadLine();
                            proc.WaitForExit();
                            
                        }
                        catch (Exception ex) { AppendTextBox($"Error: {ex.Message}\r\n"); }
                        finally { if (tmpf != null) try { File.Delete(tmpf); } catch { }; };
                    };
                    if (MSIFILES.Count > 0 /* .msi files by signtool */)
                    {
                        int cnts = 0;

                        // https://learn.microsoft.com/ru-ru/dotnet/framework/tools/signtool-exe //
                        string tmpf = CreateTempFile(".exe");
                        File.WriteAllBytes(tmpf, global::SignificatePE.Properties.Resources.signtool);

                        ProcessStartInfo stsi = new ProcessStartInfo(tmpf);
                        stsi.UseShellExecute = false;
                        stsi.RedirectStandardOutput = true;                        

                        foreach (FileItem msif in MSIFILES)
                        {
                            Application.DoEvents();
                            AppendTextBox($"PROCESS FILE WITH SIGNTOOL:\r\n{{\r\n  ");
                            try
                            {
                                stsi.Arguments = "sign ";
                                if (selMode.SelectedIndex == 1) stsi.Arguments += $"/f \"{pfxEdit.Text.Trim()}\" /p \"{passEdit.Text.Trim()}\" ";
                                if (selMode.SelectedIndex == 2) stsi.Arguments += $"/sha1 \"{eThumb.Text.Trim()}\" ";
                                stsi.Arguments += "/fd SHA256 /td SHA256 "; // only sha256 support
                                if (!string.IsNullOrEmpty(msiDesc.Text)) stsi.Arguments += $"/d \"{msiDesc.Text}\" ";
                                if (!string.IsNullOrEmpty(msiHttp.Text)) stsi.Arguments += $"/du \"{msiHttp.Text}\" ";
                                if (!string.IsNullOrEmpty(selTimeServer.Text)) stsi.Arguments += $"/tr {selTimeServer.Text} "; else stsi.Arguments += $"/tr http://timestamp.comodoca.com ";
                                stsi.Arguments += $"\"{msif.FileName}\"";

                                AppendTextBox($"Name: {Path.GetFileName(msif.FileName)}\r\n  Path: {msif.FileName}\r\n  ");
                                AppendTextBox($"Cmd: signtool {stsi.Arguments}\r\n\r\n  Results:\r\n\r\n  ");

                                Process proc = new Process() { StartInfo = stsi };
                                proc.Start(); proc.WaitForExit();
                                string res = proc.StandardOutput.ReadToEnd();
                                if (!string.IsNullOrEmpty(res)) AppendTextBox(res.Replace("\r\n", "\r\n  ").TrimEnd(new char[] { '\r', '\n', ' ' }));
                                string oktext = proc.ExitCode == 1 ? "Error" : "OK";
                                AppendTextBox($"\r\n  ExitCode: {proc.ExitCode} {oktext}\r\n");
                                if (proc.ExitCode != 1) cnts++;
                            }
                            catch (Exception ex) { AppendTextBox($"  Error: {ex.Message}\r\n"); };
                            try
                            {
                                stsi.Arguments = $"verify /v /pa \"{msif.FileName}\"";
                                Process proc = new Process() { StartInfo = stsi };
                                proc.OutputDataReceived += (s, e) => AppendTextBox($"{e.Data}\r\n");
                                proc.Start(); proc.WaitForExit();
                                string res = proc.StandardOutput.ReadToEnd();
                                if (!string.IsNullOrEmpty(res)) AppendTextBox(res.Replace("\r\n", "\r\n  ").TrimEnd(new char[] { '\r', '\n', ' ' }));
                            }
                            catch (Exception ex) { AppendTextBox($"  Error: {ex.Message}\r\n"); };
                            AppendTextBox("\r\n}\r\n");
                        };

                        try { File.Delete(tmpf); } catch { };
                        AppendTextBox("***************************************************************\r\n");
                        AppendTextBox($"**************************FILES:{cnts:D6}*************************\r\n");
                        AppendTextBox("***************************************************************\r\n");
                    };
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
            ovMode.Enabled = selMode.SelectedIndex == 1 || selMode.SelectedIndex == 2;
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
                tsYes.Checked = cfg.WITTS;
                selTimeServer.Text = cfg.TIMESERVER;
                fList.Items.Clear();
                ovMode.SelectedIndex = cfg.APPEND;
                msiDesc.Text = cfg.MSIDESC;
                msiHttp.Text = cfg.MSIHTTP;
                msiPanel.Visible = mSISetingsToolStripMenuItem.Checked = cfg.MSIVIS;
                msiMode.SelectedIndex = cfg.MSIMODE;
                if (cfg.FILES != null && cfg.FILES.Count > 0)
                {
                    DropFiles(cfg.FILES.ToArray());
                };
                if(string.IsNullOrEmpty(fileName) && cfg.ThumbList != null && cfg.ThumbList.Count > 0)
                {
                    eThumbCache.Clear();
                    eThumbCache.AddRange(cfg.ThumbList.ToArray());
                };
                if (string.IsNullOrEmpty(fileName) && cfg.PfxList != null && cfg.PfxList.Count > 0)
                {
                    pfxCache.Clear();
                    foreach (string f in cfg.PfxList)
                        if (File.Exists(f))
                            pfxCache.Add(f);
                };
            }
            catch { };
        }

        private void SaveCfg(string fileName = null)
        {            
            if (selMode.SelectedIndex == 0 && string.IsNullOrEmpty(fileName)) return;
            if (selMode.SelectedIndex == 1 && !string.IsNullOrEmpty(pfxEdit.Text.Trim()))
            {
                string filePfx = pfxEdit.Text.Trim();
                if (File.Exists(filePfx) && !pfxCache.Contains(filePfx)) pfxCache.Add(filePfx);
            };
            if (selMode.SelectedIndex == 2 && !string.IsNullOrEmpty(eThumb.Text.Trim()))
            {
                string thmprnt = eThumb.Text.Trim();
                if(!eThumbCache.Contains(thmprnt)) eThumbCache.Add(thmprnt);
            };
            SignConfig cfg = new SignConfig()
            {
                MODE = (byte)selMode.SelectedIndex,
                CERTIFICATE = pfxEdit.Text.Trim(),
                PASSWORD = PassCrypt.Encrypt(passEdit.Text.Trim(), "SignificatePE::dkxce.SignForm"),
                THUMBPRINT = eThumb.Text.Trim(),
                HASHALG = (byte)selHash.SelectedIndex,
                TIMESERVER = selTimeServer.Text.Trim(),
                APPEND = (byte)ovMode.SelectedIndex,
                MSIDESC = msiDesc.Text,
                MSIHTTP = msiHttp.Text,
                MSIMODE = (byte)msiMode.SelectedIndex,
                MSIVIS = msiPanel.Visible,
                WITTS = tsYes.Checked,
        };
            if (string.IsNullOrEmpty(fileName))
            {
                foreach (string s in eThumbCache)
                    cfg.ThumbList.Add(s);
                foreach (string s in pfxCache)
                    cfg.PfxList.Add(s);
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

        private void ovMode_SelectedIndexChanged(object sender, EventArgs e)
        {
            selHash.Refresh();
        }

        private void selHash_DrawItem(object sender, DrawItemEventArgs e)
        {
            e.DrawBackground();
            if (!selHash.Enabled)
            {
                e.Graphics.DrawString(selHash.Items[e.Index].ToString(), selHash.Font, Brushes.White, e.Bounds);
            }
            else if ((ovMode.SelectedIndex == 0 && e.Index > 3) || (ovMode.SelectedIndex == 2 && e.Index <= 3))
            {
                e.Graphics.DrawString(selHash.Items[e.Index].ToString(), selHash.Font, Brushes.LightGray, e.Bounds);
            }
            else
            {                
                e.Graphics.DrawString(selHash.Items[e.Index].ToString(), selHash.Font, Brushes.Black, e.Bounds);
                e.DrawFocusRectangle();
            };
        }

        private void mSISetingsToolStripMenuItem_Click(object sender, EventArgs e)
        {
            msiPanel.Visible = mSISetingsToolStripMenuItem.Checked = !mSISetingsToolStripMenuItem.Checked;
        }

        private void msiMode_SelectedIndexChanged(object sender, EventArgs e)
        {
            msiHttp.Enabled = msiDesc.Enabled = msiMode.SelectedIndex == 1;
        }

        private void SignForm_Resize(object sender, EventArgs e)
        {
            if(gFiles.Height > 260)
            {
                msiPanel.Parent = gFiles;                
                msiPanel.Dock = DockStyle.Bottom;
                msiPanel.Height = 160;
            }
            else
            {
                msiPanel.Parent = this;
                msiPanel.Dock = DockStyle.Right;
            };
        }

        private void retroactively_Click(object sender, EventArgs e)
        {
            DateTime dt = DateTime.Now;
            if (DateTime.TryParse(selTimeServer.Text.Trim(), out DateTime res)) dt = res;
            string dtf = "yyyy-MM-dd HH:mm:ss";
            if (InputBox.QueryDateTime("Sign Retroactively", "Select Date and Time:", dtf, ref dt) != DialogResult.OK) return;
            selTimeServer.Text = dt.ToString(dtf);
        }

        private void createCertificateToolStripMenuItem_Click(object sender, EventArgs e)
        {

        }

        private void editConfigToolStripMenuItem_Click(object sender, EventArgs e)
        {

        }

        private void editConfigurationToolStripMenuItem_Click(object sender, EventArgs e)
        {
            SaveSignificatePEXml(out string fName);
            try
            {
                System.Diagnostics.Process.Start("notepad.exe", fName);
            }
            catch (Exception ex) 
            { 
                MessageBox.Show(ex.Message, "Configuration Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            };
        }

        private void SaveSignificatePEXml(out string fName, bool force = false)
        {
            fName = Path.Combine(IniSaved<int>.CurrentDirectory(), "SignificatePE.xml");
            if (force || !File.Exists(fName))
            {
                try
                {
                    File.WriteAllBytes(fName, global::SignificatePE.Properties.Resources.xmlb);
                }
                catch { };
            };
        }
       
        private void makecerFileToolStripMenuItem_Click(object sender, EventArgs e)
        {
            SaveFileDialog ofd = new SaveFileDialog();
            ofd.Filter = "CER Files (*.cer)|*.cer|PFX Files (*.pfx)|*.pfx";
            ofd.DefaultExt = ".cer";
            if (ofd.ShowDialog() != DialogResult.OK) { ofd.Dispose(); return; };
            string fn = ofd.FileName;
            ofd.Dispose();
            string fe = Path.GetExtension(fn).ToLower();
            bool isPfx = fe == ".pfx";
            string cerf = Path.Combine(Path.GetDirectoryName(fn), $"{Path.GetFileNameWithoutExtension(fn)}.cer");

            SaveSignificatePEXml(out _);
            MakeCertConfig ck = MakeCertConfig.Defaults();
            List<string> files2del = new List<string>();
            try
            {
                string pvkf = Path.Combine(Path.GetDirectoryName(fn), $"{Path.GetFileNameWithoutExtension(fn)}.pvk");
                string pfxf = Path.Combine(Path.GetDirectoryName(fn), $"{Path.GetFileNameWithoutExtension(fn)}.pfx");

                try { File.Delete(cerf); } catch { };
                try { File.Delete(pvkf); } catch { };
                try { File.Delete(pfxf); } catch { };
                Thread.Sleep(500);

                string txtRes = "";
                if (isPfx)
                {                                        
                    string cmdl = ck.CmdLine + $" -ss my -sv {pvkf} {cerf}";                    
                    /* MakeCert */ 
                    {
                        string tmpf = CreateTempFile(".exe");
                        files2del.Add(tmpf);
                        File.WriteAllBytes(tmpf, global::SignificatePE.Properties.Resources.MakeCert);
                        {
                            ProcessStartInfo psi = new ProcessStartInfo(tmpf, cmdl);
                            psi.WindowStyle = ProcessWindowStyle.Hidden;
                            psi.CreateNoWindow = true;
                            psi.UseShellExecute = false;
                            psi.RedirectStandardOutput = true;
                            Process proc = new Process() { StartInfo = psi };
                            proc.OutputDataReceived += (_, ed) => txtRes += $"{ed.Data}\r\n";
                            proc.Start();
                            proc.BeginOutputReadLine();
                            { int wait = 90000; while ((!proc.HasExited) && wait > 0) { Thread.Sleep(200); wait -= 200; }; }; // pData.WaitForExit(30000);
                        };
                    };
                    /* pvk2pfx */ 
                    {                                                
                        string tmpf = CreateTempFile(".exe");
                        files2del.Add(tmpf);
                        File.WriteAllBytes(tmpf, global::SignificatePE.Properties.Resources.pvk2pfx);
                        {
                            ProcessStartInfo psi = new ProcessStartInfo(tmpf, $"-pvk \"{pvkf}\" -spc \"{cerf}\" -pfx \"{pfxf}\"");
                            psi.WindowStyle = ProcessWindowStyle.Hidden;
                            psi.CreateNoWindow = true;
                            psi.UseShellExecute = false;
                            psi.RedirectStandardOutput = true;
                            Process proc = new Process() { StartInfo = psi };
                            proc.OutputDataReceived += (_, ed) => txtRes += $"{ed.Data}\r\n";
                            proc.Start();
                            proc.BeginOutputReadLine();
                            { int wait = 300000 /* 5 min */; while ((!proc.HasExited) && wait > 0) { Thread.Sleep(200); wait -= 200; }; }; // pData.WaitForExit(30000);
                        };
                    };
                }
                else
                {
                    string cmdl = ck.CmdLine + $" -ss my {cerf}";
                    /* MakeCert */ 
                    {
                        string tmpf = CreateTempFile(".exe");
                        files2del.Add(tmpf);
                        File.WriteAllBytes(tmpf, global::SignificatePE.Properties.Resources.MakeCert);
                        {
                            ProcessStartInfo psi = new ProcessStartInfo(tmpf, cmdl);
                            psi.WindowStyle = ProcessWindowStyle.Hidden;
                            psi.CreateNoWindow = true;
                            psi.UseShellExecute = false;
                            psi.RedirectStandardOutput = true;
                            Process proc = new Process() { StartInfo = psi };
                            proc.OutputDataReceived += (_, ed) => txtRes += $"{ed.Data}\r\n";
                            proc.Start();
                            proc.BeginOutputReadLine();
                            { int wait = 300000 /* 5 min */; while ((!proc.HasExited) && wait > 0) { Thread.Sleep(200); wait -= 200; }; }; // pData.WaitForExit(30000);
                        };
                    };                    
                };
                txtRes = txtRes.TrimEnd(new char[] { '\r', '\n' });
                // try { Process.Start("rundll32.exe", $"cryptext.dll, CryptExtOpenCER {cerf}"); } catch { };
                MessageBox.Show(txtRes, "Make .cer or .pfx file ...", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "Make .cer or .pfx file ...", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                foreach (string f in files2del) try { File.Delete(f); } catch { };
            };
        }
        
        private static string CreateTempFile(string extention)
        {
            string tmpf = Path.GetTempFileName();
            if (!string.IsNullOrEmpty(extention))
            {
                File.Move(tmpf, tmpf + extention);
                tmpf += extention;
            };
            return tmpf;
        }

        private void SignForm_FormClosing(object sender, FormClosingEventArgs e)
        {
            KillTSAServer();
        }

        private void selTimeServer_SelectedIndexChanged(object sender, EventArgs e) => UpdateWITTS();
        private void toolStripStatusLabel2_Click(object sender, EventArgs e) => OnClickInternalTSA();
        private void toolStripStatusLabel1_Click(object sender, EventArgs e) => OnClickInternalTSA();
        private void selTimeServer_TextChanged(object sender, EventArgs e) => UpdateWITTS();

        #region INTERNAL TSA Server

        private void StartTSAServer()
        {
            if (tsaServer != null) return;
            if (TSATask != null) return;

            TSATask = new Task(() =>
            {
                toolStripStatusLabel2.Text = "Loading";
                this.BeginInvoke((Action)(() => toolStripStatusLabel2.ForeColor = Color.Navy));
                tsaServer = true;
                TSAServer tsas = new TSAServer();
                toolStripStatusLabel2.Text = "Initializing";
                int port = tsas.Start(out Exception ex);
                toolStripStatusLabel2.Text = tsas.IsRunning ? $"Running, {tsas.Url}" : $"{ex}";
                if (tsas.IsRunning)
                {
                    this.BeginInvoke((Action)(() =>
                    {
                        toolStripStatusLabel2.ForeColor = Color.Green;
                        statusStrip1.Cursor = Cursors.Hand;
                    }));
                };
                tsaServer = tsas;
                TSATask = null;
            });
            TSATask.Start();
        }

        private void StopTSAServer()
        {
            if (tsaServer == null) return;
            if (TSATask != null) return;

            TSATask = new Task(() =>
            {
                try
                {
                    TSAServer tsas = (TSAServer)tsaServer;
                    toolStripStatusLabel2.Text = "Stopping";
                    this.BeginInvoke((Action)(() => toolStripStatusLabel2.ForeColor = Color.Maroon));
                    tsas.Stop();
                    Thread.Sleep(250);
                    toolStripStatusLabel2.Text = tsas.IsRunning ? $"Running, {tsas.Url}" : "Stopped";
                    this.BeginInvoke((Action)(() =>
                    {
                        toolStripStatusLabel2.ForeColor = Color.Black;
                        statusStrip1.Cursor = Cursors.Default;
                    }));
                    tsaServer = null;
                }
                catch { };
                TSATask = null;
            });
            TSATask.Start();
        }

        private void KillTSAServer()
        {
            try { if (TSATask != null) TSATask.Dispose(); } catch { };
            if (tsaServer != null)
            {
                try { ((TSAServer)tsaServer).Stop(); } catch { };
                tsaServer = null;
            };
            TSAServer.KillAll();
        }        
        
        private void OnClickInternalTSA()
        {
            if (toolStripStatusLabel2.Text.StartsWith("Running, "))
                Process.Start(toolStripStatusLabel2.Text.Substring(9));
        }

        private void UpdateWITTS()
        {
            string tsaText = selTimeServer.Text.Trim();
            tsYes.Visible = tsYes.Enabled = tsNo.Visible = tsNo.Enabled = DateTime.TryParse(tsaText, out _);

            if (string.IsNullOrEmpty(tsaText))
                tsHelp.Text = "Random Available Server";
            else if (tsaText == "INTERNAL")
                tsHelp.Text = $"Use internal Timestamp Server";
            else if (tsaText == "NO_TIMESTAMP")
                tsHelp.Text = "Signature without timestamp";
            else if (tsYes.Enabled)
                tsHelp.Text = "Using Timestamp:";
            else
                tsHelp.Text = "RFC3161";

            if (tsaText == "INTERNAL" || (tsYes.Enabled && tsYes.Checked))
                StartTSAServer();
            else
                StopTSAServer();
        }

        #endregion INTERNAL TSA Server

        private void tsYes_CheckedChanged(object sender, EventArgs e) => UpdateWITTS();

        private void tsNo_CheckedChanged(object sender, EventArgs e) => UpdateWITTS();
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
        public byte APPEND;
        public byte MSIMODE;
        public string MSIDESC;
        public string MSIHTTP;
        public bool MSIVIS;
        public bool WITTS;
        public List<string> FILES = new List<string>();
        public List<string> PfxList = new List<string>();
        public List<string> ThumbList = new List<string>();
    }
}
