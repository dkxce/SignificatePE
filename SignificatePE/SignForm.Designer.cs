namespace dkxce
{
    partial class SignForm
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.components = new System.ComponentModel.Container();
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(SignForm));
            this.lPanel = new System.Windows.Forms.Panel();
            this.gFiles = new System.Windows.Forms.GroupBox();
            this.fList = new System.Windows.Forms.ListBox();
            this.contextMenuStrip1 = new System.Windows.Forms.ContextMenuStrip(this.components);
            this.addFilesToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.removeFilesToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.toolStripMenuItem1 = new System.Windows.Forms.ToolStripSeparator();
            this.clearListToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.bottomPanel = new System.Windows.Forms.Panel();
            this.cmdBtn = new System.Windows.Forms.Button();
            this.button1 = new System.Windows.Forms.Button();
            this.contextMenuStrip2 = new System.Windows.Forms.ContextMenuStrip(this.components);
            this.newConfigurationToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.openConfigurationToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.saveConfigurationToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.toolStripMenuItem4 = new System.Windows.Forms.ToolStripSeparator();
            this.configsItem = new System.Windows.Forms.ToolStripMenuItem();
            this.toolStripMenuItem2 = new System.Windows.Forms.ToolStripSeparator();
            this.openWindowsCertMgrToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.toolStripMenuItem3 = new System.Windows.Forms.ToolStripSeparator();
            this.aboutToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.clsBtn = new System.Windows.Forms.Button();
            this.runBtn = new System.Windows.Forms.Button();
            this.topPanel = new System.Windows.Forms.Panel();
            this.label3 = new System.Windows.Forms.Label();
            this.ovMode = new System.Windows.Forms.ComboBox();
            this.gTimeServer = new System.Windows.Forms.GroupBox();
            this.selTimeServer = new System.Windows.Forms.ComboBox();
            this.gHash = new System.Windows.Forms.GroupBox();
            this.selHash = new System.Windows.Forms.ComboBox();
            this.gbThumb = new System.Windows.Forms.GroupBox();
            this.eThumb = new System.Windows.Forms.TextBox();
            this.gbPfx = new System.Windows.Forms.GroupBox();
            this.label2 = new System.Windows.Forms.Label();
            this.passEdit = new System.Windows.Forms.TextBox();
            this.pfxBtn = new System.Windows.Forms.Button();
            this.pfxEdit = new System.Windows.Forms.TextBox();
            this.selMode = new System.Windows.Forms.ComboBox();
            this.label1 = new System.Windows.Forms.Label();
            this.log = new System.Windows.Forms.TextBox();
            this.lPanel.SuspendLayout();
            this.gFiles.SuspendLayout();
            this.contextMenuStrip1.SuspendLayout();
            this.bottomPanel.SuspendLayout();
            this.contextMenuStrip2.SuspendLayout();
            this.topPanel.SuspendLayout();
            this.gTimeServer.SuspendLayout();
            this.gHash.SuspendLayout();
            this.gbThumb.SuspendLayout();
            this.gbPfx.SuspendLayout();
            this.SuspendLayout();
            // 
            // lPanel
            // 
            this.lPanel.Controls.Add(this.gFiles);
            this.lPanel.Controls.Add(this.bottomPanel);
            this.lPanel.Controls.Add(this.topPanel);
            this.lPanel.Dock = System.Windows.Forms.DockStyle.Left;
            this.lPanel.Location = new System.Drawing.Point(0, 0);
            this.lPanel.Name = "lPanel";
            this.lPanel.Size = new System.Drawing.Size(320, 465);
            this.lPanel.TabIndex = 0;
            // 
            // gFiles
            // 
            this.gFiles.Controls.Add(this.fList);
            this.gFiles.Dock = System.Windows.Forms.DockStyle.Fill;
            this.gFiles.Location = new System.Drawing.Point(0, 298);
            this.gFiles.Name = "gFiles";
            this.gFiles.Size = new System.Drawing.Size(320, 138);
            this.gFiles.TabIndex = 9;
            this.gFiles.TabStop = false;
            this.gFiles.Text = "Files";
            // 
            // fList
            // 
            this.fList.ContextMenuStrip = this.contextMenuStrip1;
            this.fList.Dock = System.Windows.Forms.DockStyle.Fill;
            this.fList.FormattingEnabled = true;
            this.fList.Location = new System.Drawing.Point(3, 16);
            this.fList.Name = "fList";
            this.fList.SelectionMode = System.Windows.Forms.SelectionMode.MultiExtended;
            this.fList.Size = new System.Drawing.Size(314, 119);
            this.fList.TabIndex = 3;
            this.fList.DrawItem += new System.Windows.Forms.DrawItemEventHandler(this.fList_DrawItem);
            // 
            // contextMenuStrip1
            // 
            this.contextMenuStrip1.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.addFilesToolStripMenuItem,
            this.removeFilesToolStripMenuItem,
            this.toolStripMenuItem1,
            this.clearListToolStripMenuItem});
            this.contextMenuStrip1.Name = "contextMenuStrip1";
            this.contextMenuStrip1.Size = new System.Drawing.Size(186, 76);
            // 
            // addFilesToolStripMenuItem
            // 
            this.addFilesToolStripMenuItem.Name = "addFilesToolStripMenuItem";
            this.addFilesToolStripMenuItem.ShortcutKeys = ((System.Windows.Forms.Keys)((System.Windows.Forms.Keys.Control | System.Windows.Forms.Keys.O)));
            this.addFilesToolStripMenuItem.Size = new System.Drawing.Size(185, 22);
            this.addFilesToolStripMenuItem.Text = "Add File(s) ...";
            this.addFilesToolStripMenuItem.Click += new System.EventHandler(this.addFilesToolStripMenuItem_Click);
            // 
            // removeFilesToolStripMenuItem
            // 
            this.removeFilesToolStripMenuItem.Name = "removeFilesToolStripMenuItem";
            this.removeFilesToolStripMenuItem.ShortcutKeys = System.Windows.Forms.Keys.Delete;
            this.removeFilesToolStripMenuItem.Size = new System.Drawing.Size(185, 22);
            this.removeFilesToolStripMenuItem.Text = "Remove File(s)";
            this.removeFilesToolStripMenuItem.Click += new System.EventHandler(this.removeFilesToolStripMenuItem_Click);
            // 
            // toolStripMenuItem1
            // 
            this.toolStripMenuItem1.Name = "toolStripMenuItem1";
            this.toolStripMenuItem1.Size = new System.Drawing.Size(182, 6);
            // 
            // clearListToolStripMenuItem
            // 
            this.clearListToolStripMenuItem.Name = "clearListToolStripMenuItem";
            this.clearListToolStripMenuItem.ShortcutKeys = ((System.Windows.Forms.Keys)((System.Windows.Forms.Keys.Control | System.Windows.Forms.Keys.X)));
            this.clearListToolStripMenuItem.Size = new System.Drawing.Size(185, 22);
            this.clearListToolStripMenuItem.Text = "Clear List";
            this.clearListToolStripMenuItem.Click += new System.EventHandler(this.clearListToolStripMenuItem_Click);
            // 
            // bottomPanel
            // 
            this.bottomPanel.Controls.Add(this.cmdBtn);
            this.bottomPanel.Controls.Add(this.button1);
            this.bottomPanel.Controls.Add(this.clsBtn);
            this.bottomPanel.Controls.Add(this.runBtn);
            this.bottomPanel.Dock = System.Windows.Forms.DockStyle.Bottom;
            this.bottomPanel.Location = new System.Drawing.Point(0, 436);
            this.bottomPanel.Name = "bottomPanel";
            this.bottomPanel.Size = new System.Drawing.Size(320, 29);
            this.bottomPanel.TabIndex = 8;
            // 
            // cmdBtn
            // 
            this.cmdBtn.Location = new System.Drawing.Point(165, 3);
            this.cmdBtn.Name = "cmdBtn";
            this.cmdBtn.Size = new System.Drawing.Size(75, 23);
            this.cmdBtn.TabIndex = 6;
            this.cmdBtn.Text = "Make Cmd";
            this.cmdBtn.UseVisualStyleBackColor = true;
            this.cmdBtn.Click += new System.EventHandler(this.cmdBtn_Click);
            // 
            // button1
            // 
            this.button1.ContextMenuStrip = this.contextMenuStrip2;
            this.button1.Location = new System.Drawing.Point(3, 3);
            this.button1.Name = "button1";
            this.button1.Size = new System.Drawing.Size(75, 23);
            this.button1.TabIndex = 5;
            this.button1.Text = "MENU";
            this.button1.UseVisualStyleBackColor = true;
            this.button1.Click += new System.EventHandler(this.button1_Click);
            // 
            // contextMenuStrip2
            // 
            this.contextMenuStrip2.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.newConfigurationToolStripMenuItem,
            this.openConfigurationToolStripMenuItem,
            this.saveConfigurationToolStripMenuItem,
            this.toolStripMenuItem4,
            this.configsItem,
            this.toolStripMenuItem2,
            this.openWindowsCertMgrToolStripMenuItem,
            this.toolStripMenuItem3,
            this.aboutToolStripMenuItem});
            this.contextMenuStrip2.Name = "contextMenuStrip2";
            this.contextMenuStrip2.Size = new System.Drawing.Size(215, 154);
            this.contextMenuStrip2.Opening += new System.ComponentModel.CancelEventHandler(this.contextMenuStrip2_Opening);
            // 
            // newConfigurationToolStripMenuItem
            // 
            this.newConfigurationToolStripMenuItem.Name = "newConfigurationToolStripMenuItem";
            this.newConfigurationToolStripMenuItem.Size = new System.Drawing.Size(214, 22);
            this.newConfigurationToolStripMenuItem.Text = "New configuration";
            this.newConfigurationToolStripMenuItem.Click += new System.EventHandler(this.newConfigurationToolStripMenuItem_Click);
            // 
            // openConfigurationToolStripMenuItem
            // 
            this.openConfigurationToolStripMenuItem.Name = "openConfigurationToolStripMenuItem";
            this.openConfigurationToolStripMenuItem.Size = new System.Drawing.Size(214, 22);
            this.openConfigurationToolStripMenuItem.Text = "Open Configuration ...";
            this.openConfigurationToolStripMenuItem.Click += new System.EventHandler(this.openConfigurationToolStripMenuItem_Click);
            // 
            // saveConfigurationToolStripMenuItem
            // 
            this.saveConfigurationToolStripMenuItem.Name = "saveConfigurationToolStripMenuItem";
            this.saveConfigurationToolStripMenuItem.Size = new System.Drawing.Size(214, 22);
            this.saveConfigurationToolStripMenuItem.Text = "Save Configuration ...";
            this.saveConfigurationToolStripMenuItem.Click += new System.EventHandler(this.saveConfigurationToolStripMenuItem_Click);
            // 
            // toolStripMenuItem4
            // 
            this.toolStripMenuItem4.Name = "toolStripMenuItem4";
            this.toolStripMenuItem4.Size = new System.Drawing.Size(211, 6);
            // 
            // configsItem
            // 
            this.configsItem.Name = "configsItem";
            this.configsItem.Size = new System.Drawing.Size(214, 22);
            this.configsItem.Text = "Configs:";
            // 
            // toolStripMenuItem2
            // 
            this.toolStripMenuItem2.Name = "toolStripMenuItem2";
            this.toolStripMenuItem2.Size = new System.Drawing.Size(211, 6);
            // 
            // openWindowsCertMgrToolStripMenuItem
            // 
            this.openWindowsCertMgrToolStripMenuItem.Name = "openWindowsCertMgrToolStripMenuItem";
            this.openWindowsCertMgrToolStripMenuItem.Size = new System.Drawing.Size(214, 22);
            this.openWindowsCertMgrToolStripMenuItem.Text = "Open Windows CertMgr ...";
            this.openWindowsCertMgrToolStripMenuItem.Click += new System.EventHandler(this.openWindowsCertMgrToolStripMenuItem_Click);
            // 
            // toolStripMenuItem3
            // 
            this.toolStripMenuItem3.Name = "toolStripMenuItem3";
            this.toolStripMenuItem3.Size = new System.Drawing.Size(211, 6);
            // 
            // aboutToolStripMenuItem
            // 
            this.aboutToolStripMenuItem.Name = "aboutToolStripMenuItem";
            this.aboutToolStripMenuItem.Size = new System.Drawing.Size(214, 22);
            this.aboutToolStripMenuItem.Text = "About ...";
            this.aboutToolStripMenuItem.Click += new System.EventHandler(this.aboutToolStripMenuItem_Click);
            // 
            // clsBtn
            // 
            this.clsBtn.Location = new System.Drawing.Point(84, 3);
            this.clsBtn.Name = "clsBtn";
            this.clsBtn.Size = new System.Drawing.Size(75, 23);
            this.clsBtn.TabIndex = 4;
            this.clsBtn.Text = "CLEAR";
            this.clsBtn.UseVisualStyleBackColor = true;
            this.clsBtn.Click += new System.EventHandler(this.clsBtn_Click);
            // 
            // runBtn
            // 
            this.runBtn.Location = new System.Drawing.Point(243, 3);
            this.runBtn.Name = "runBtn";
            this.runBtn.Size = new System.Drawing.Size(75, 23);
            this.runBtn.TabIndex = 3;
            this.runBtn.Text = "RUN";
            this.runBtn.UseVisualStyleBackColor = true;
            this.runBtn.Click += new System.EventHandler(this.runBtn_Click);
            // 
            // topPanel
            // 
            this.topPanel.Controls.Add(this.label3);
            this.topPanel.Controls.Add(this.ovMode);
            this.topPanel.Controls.Add(this.gTimeServer);
            this.topPanel.Controls.Add(this.gHash);
            this.topPanel.Controls.Add(this.gbThumb);
            this.topPanel.Controls.Add(this.gbPfx);
            this.topPanel.Controls.Add(this.selMode);
            this.topPanel.Controls.Add(this.label1);
            this.topPanel.Dock = System.Windows.Forms.DockStyle.Top;
            this.topPanel.Location = new System.Drawing.Point(0, 0);
            this.topPanel.Name = "topPanel";
            this.topPanel.Size = new System.Drawing.Size(320, 298);
            this.topPanel.TabIndex = 7;
            // 
            // label3
            // 
            this.label3.AutoSize = true;
            this.label3.Location = new System.Drawing.Point(13, 43);
            this.label3.Name = "label3";
            this.label3.Size = new System.Drawing.Size(47, 13);
            this.label3.TabIndex = 14;
            this.label3.Text = "Append:";
            // 
            // ovMode
            // 
            this.ovMode.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.ovMode.FormattingEnabled = true;
            this.ovMode.Items.AddRange(new object[] {
            "OVERWRITE (1 signature in file)",
            "APPEND (multiple signatures in file)"});
            this.ovMode.Location = new System.Drawing.Point(65, 40);
            this.ovMode.Name = "ovMode";
            this.ovMode.Size = new System.Drawing.Size(238, 21);
            this.ovMode.TabIndex = 13;
            // 
            // gTimeServer
            // 
            this.gTimeServer.Controls.Add(this.selTimeServer);
            this.gTimeServer.Enabled = false;
            this.gTimeServer.Location = new System.Drawing.Point(12, 245);
            this.gTimeServer.Name = "gTimeServer";
            this.gTimeServer.Size = new System.Drawing.Size(291, 50);
            this.gTimeServer.TabIndex = 12;
            this.gTimeServer.TabStop = false;
            this.gTimeServer.Text = "Time Server";
            // 
            // selTimeServer
            // 
            this.selTimeServer.FormattingEnabled = true;
            this.selTimeServer.Items.AddRange(new object[] {
            "http://timestamp.digicert.com",
            "http://timestamp.comodoca.com",
            "http://timestamp.sectigo.com",
            "http://tsa.starfieldtech.com"});
            this.selTimeServer.Location = new System.Drawing.Point(6, 19);
            this.selTimeServer.Name = "selTimeServer";
            this.selTimeServer.Size = new System.Drawing.Size(279, 21);
            this.selTimeServer.TabIndex = 9;
            // 
            // gHash
            // 
            this.gHash.Controls.Add(this.selHash);
            this.gHash.Enabled = false;
            this.gHash.Location = new System.Drawing.Point(12, 193);
            this.gHash.Name = "gHash";
            this.gHash.Size = new System.Drawing.Size(291, 50);
            this.gHash.TabIndex = 11;
            this.gHash.TabStop = false;
            this.gHash.Text = "Hash Algorythm";
            // 
            // selHash
            // 
            this.selHash.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.selHash.FormattingEnabled = true;
            this.selHash.Items.AddRange(new object[] {
            "[DEFAULT]",
            "SHA",
            "SHA256",
            "SHA512",
            "SHA,SHA256",
            "SHA,SHA512",
            "SHA256,SHA512",
            "SHA,SHA256,SHA512"});
            this.selHash.Location = new System.Drawing.Point(6, 19);
            this.selHash.Name = "selHash";
            this.selHash.Size = new System.Drawing.Size(279, 21);
            this.selHash.TabIndex = 9;
            // 
            // gbThumb
            // 
            this.gbThumb.Controls.Add(this.eThumb);
            this.gbThumb.Enabled = false;
            this.gbThumb.Location = new System.Drawing.Point(12, 141);
            this.gbThumb.Name = "gbThumb";
            this.gbThumb.Size = new System.Drawing.Size(291, 50);
            this.gbThumb.TabIndex = 10;
            this.gbThumb.TabStop = false;
            this.gbThumb.Text = "Thumbprint";
            // 
            // eThumb
            // 
            this.eThumb.Location = new System.Drawing.Point(6, 19);
            this.eThumb.Name = "eThumb";
            this.eThumb.Size = new System.Drawing.Size(279, 20);
            this.eThumb.TabIndex = 3;
            this.eThumb.TextChanged += new System.EventHandler(this.eThumb_TextChanged);
            // 
            // gbPfx
            // 
            this.gbPfx.Controls.Add(this.label2);
            this.gbPfx.Controls.Add(this.passEdit);
            this.gbPfx.Controls.Add(this.pfxBtn);
            this.gbPfx.Controls.Add(this.pfxEdit);
            this.gbPfx.Enabled = false;
            this.gbPfx.Location = new System.Drawing.Point(12, 67);
            this.gbPfx.Name = "gbPfx";
            this.gbPfx.Size = new System.Drawing.Size(291, 72);
            this.gbPfx.TabIndex = 9;
            this.gbPfx.TabStop = false;
            this.gbPfx.Text = "Certificate File";
            // 
            // label2
            // 
            this.label2.AutoSize = true;
            this.label2.Location = new System.Drawing.Point(6, 49);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(56, 13);
            this.label2.TabIndex = 8;
            this.label2.Text = "Password:";
            // 
            // passEdit
            // 
            this.passEdit.Location = new System.Drawing.Point(83, 45);
            this.passEdit.Name = "passEdit";
            this.passEdit.PasswordChar = '*';
            this.passEdit.Size = new System.Drawing.Size(202, 20);
            this.passEdit.TabIndex = 6;
            // 
            // pfxBtn
            // 
            this.pfxBtn.Location = new System.Drawing.Point(6, 18);
            this.pfxBtn.Name = "pfxBtn";
            this.pfxBtn.Size = new System.Drawing.Size(75, 23);
            this.pfxBtn.TabIndex = 5;
            this.pfxBtn.Text = "Browse ...";
            this.pfxBtn.UseVisualStyleBackColor = true;
            this.pfxBtn.Click += new System.EventHandler(this.pfxBtn_Click);
            // 
            // pfxEdit
            // 
            this.pfxEdit.Location = new System.Drawing.Point(83, 19);
            this.pfxEdit.Name = "pfxEdit";
            this.pfxEdit.Size = new System.Drawing.Size(202, 20);
            this.pfxEdit.TabIndex = 4;
            // 
            // selMode
            // 
            this.selMode.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.selMode.FormattingEnabled = true;
            this.selMode.Items.AddRange(new object[] {
            "HELP (CMD LINE INFO)",
            "SIGN FILE(S) BY CERTIFICATE (PKCS#12 .pfx)",
            "SIGN FILE(S) BY THUMBPRINT",
            "VERIFY FILE(S) SIGNATURE",
            "DESIGN FILE(S) (REMOVE SIGNATURE)"});
            this.selMode.Location = new System.Drawing.Point(65, 17);
            this.selMode.Name = "selMode";
            this.selMode.Size = new System.Drawing.Size(238, 21);
            this.selMode.TabIndex = 8;
            this.selMode.SelectedIndexChanged += new System.EventHandler(this.selMode_SelectedIndexChanged);
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(12, 20);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(37, 13);
            this.label1.TabIndex = 7;
            this.label1.Text = "Mode:";
            // 
            // log
            // 
            this.log.BackColor = System.Drawing.Color.Black;
            this.log.Dock = System.Windows.Forms.DockStyle.Fill;
            this.log.Font = new System.Drawing.Font("Consolas", 11F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(204)));
            this.log.ForeColor = System.Drawing.Color.White;
            this.log.Location = new System.Drawing.Point(320, 0);
            this.log.Multiline = true;
            this.log.Name = "log";
            this.log.ReadOnly = true;
            this.log.ScrollBars = System.Windows.Forms.ScrollBars.Vertical;
            this.log.Size = new System.Drawing.Size(542, 465);
            this.log.TabIndex = 1;
            // 
            // SignForm
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(862, 465);
            this.Controls.Add(this.log);
            this.Controls.Add(this.lPanel);
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.Name = "SignForm";
            this.Text = "PE Significator by dkxce (github.com/dkxce)";
            this.Load += new System.EventHandler(this.CmdLnArFrm_Load);
            this.lPanel.ResumeLayout(false);
            this.gFiles.ResumeLayout(false);
            this.contextMenuStrip1.ResumeLayout(false);
            this.bottomPanel.ResumeLayout(false);
            this.contextMenuStrip2.ResumeLayout(false);
            this.topPanel.ResumeLayout(false);
            this.topPanel.PerformLayout();
            this.gTimeServer.ResumeLayout(false);
            this.gHash.ResumeLayout(false);
            this.gbThumb.ResumeLayout(false);
            this.gbThumb.PerformLayout();
            this.gbPfx.ResumeLayout(false);
            this.gbPfx.PerformLayout();
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.Panel lPanel;
        private System.Windows.Forms.Panel topPanel;
        private System.Windows.Forms.ComboBox selMode;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.TextBox log;
        private System.Windows.Forms.Panel bottomPanel;
        private System.Windows.Forms.Button runBtn;
        private System.Windows.Forms.GroupBox gbThumb;
        private System.Windows.Forms.TextBox eThumb;
        private System.Windows.Forms.GroupBox gbPfx;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.TextBox passEdit;
        private System.Windows.Forms.Button pfxBtn;
        private System.Windows.Forms.TextBox pfxEdit;
        private System.Windows.Forms.GroupBox gFiles;
        private System.Windows.Forms.ListBox fList;
        private System.Windows.Forms.ContextMenuStrip contextMenuStrip1;
        private System.Windows.Forms.ToolStripMenuItem addFilesToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem removeFilesToolStripMenuItem;
        private System.Windows.Forms.ToolStripSeparator toolStripMenuItem1;
        private System.Windows.Forms.ToolStripMenuItem clearListToolStripMenuItem;
        private System.Windows.Forms.GroupBox gHash;
        private System.Windows.Forms.ComboBox selHash;
        private System.Windows.Forms.GroupBox gTimeServer;
        private System.Windows.Forms.ComboBox selTimeServer;
        private System.Windows.Forms.Button clsBtn;
        private System.Windows.Forms.Button button1;
        private System.Windows.Forms.Button cmdBtn;
        private System.Windows.Forms.ContextMenuStrip contextMenuStrip2;
        private System.Windows.Forms.ToolStripMenuItem newConfigurationToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem openConfigurationToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem saveConfigurationToolStripMenuItem;
        private System.Windows.Forms.ToolStripSeparator toolStripMenuItem2;
        private System.Windows.Forms.ToolStripMenuItem aboutToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem openWindowsCertMgrToolStripMenuItem;
        private System.Windows.Forms.ToolStripSeparator toolStripMenuItem3;
        private System.Windows.Forms.ToolStripSeparator toolStripMenuItem4;
        private System.Windows.Forms.ToolStripMenuItem configsItem;
        private System.Windows.Forms.Label label3;
        private System.Windows.Forms.ComboBox ovMode;
    }
}