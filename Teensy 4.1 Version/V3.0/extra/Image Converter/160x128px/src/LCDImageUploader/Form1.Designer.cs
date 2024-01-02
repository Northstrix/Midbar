namespace LCDImageUploader
{
    partial class Form1
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
            this.cbPorts = new System.Windows.Forms.ComboBox();
            this.openFileDialog1 = new System.Windows.Forms.OpenFileDialog();
            this.picPreview = new System.Windows.Forms.PictureBox();
            this.btnOpenImg = new System.Windows.Forms.Button();
            this.btnUpload = new System.Windows.Forms.Button();
            this.lblPreview = new System.Windows.Forms.Label();
            this.label2 = new System.Windows.Forms.Label();
            this.btnRefreshPorts = new System.Windows.Forms.Button();
            this.pbUpload = new System.Windows.Forms.ProgressBar();
            this.convert_button = new System.Windows.Forms.Button();
            ((System.ComponentModel.ISupportInitialize)(this.picPreview)).BeginInit();
            this.SuspendLayout();
            // 
            // cbPorts
            // 
            this.cbPorts.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(36)))), ((int)(((byte)(36)))), ((int)(((byte)(36)))));
            this.cbPorts.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            this.cbPorts.ForeColor = System.Drawing.Color.FromArgb(((int)(((byte)(238)))), ((int)(((byte)(238)))), ((int)(((byte)(238)))));
            this.cbPorts.FormattingEnabled = true;
            this.cbPorts.Location = new System.Drawing.Point(311, 174);
            this.cbPorts.Name = "cbPorts";
            this.cbPorts.Size = new System.Drawing.Size(83, 21);
            this.cbPorts.TabIndex = 0;
            // 
            // openFileDialog1
            // 
            this.openFileDialog1.Title = "Open image";
            this.openFileDialog1.FileOk += new System.ComponentModel.CancelEventHandler(this.openFileDialog1_FileOk);
            // 
            // picPreview
            // 
            this.picPreview.BackColor = System.Drawing.Color.Black;
            this.picPreview.Location = new System.Drawing.Point(12, 25);
            this.picPreview.Name = "picPreview";
            this.picPreview.Size = new System.Drawing.Size(160, 128);
            this.picPreview.TabIndex = 1;
            this.picPreview.TabStop = false;
            // 
            // btnOpenImg
            // 
            this.btnOpenImg.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(0)))), ((int)(((byte)(131)))), ((int)(((byte)(235)))));
            this.btnOpenImg.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            this.btnOpenImg.ForeColor = System.Drawing.Color.FromArgb(((int)(((byte)(238)))), ((int)(((byte)(238)))), ((int)(((byte)(238)))));
            this.btnOpenImg.Location = new System.Drawing.Point(207, 25);
            this.btnOpenImg.Name = "btnOpenImg";
            this.btnOpenImg.Size = new System.Drawing.Size(79, 38);
            this.btnOpenImg.TabIndex = 2;
            this.btnOpenImg.Text = "Open image";
            this.btnOpenImg.UseVisualStyleBackColor = false;
            this.btnOpenImg.Click += new System.EventHandler(this.btnOpenImg_Click);
            // 
            // btnUpload
            // 
            this.btnUpload.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(0)))), ((int)(((byte)(131)))), ((int)(((byte)(235)))));
            this.btnUpload.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            this.btnUpload.ForeColor = System.Drawing.Color.FromArgb(((int)(((byte)(238)))), ((int)(((byte)(238)))), ((int)(((byte)(238)))));
            this.btnUpload.Location = new System.Drawing.Point(207, 69);
            this.btnUpload.Name = "btnUpload";
            this.btnUpload.Size = new System.Drawing.Size(79, 38);
            this.btnUpload.TabIndex = 3;
            this.btnUpload.Text = "Upload";
            this.btnUpload.UseVisualStyleBackColor = false;
            this.btnUpload.Click += new System.EventHandler(this.btnUpload_Click);
            // 
            // lblPreview
            // 
            this.lblPreview.AutoSize = true;
            this.lblPreview.ForeColor = System.Drawing.Color.FromArgb(((int)(((byte)(238)))), ((int)(((byte)(238)))), ((int)(((byte)(238)))));
            this.lblPreview.Location = new System.Drawing.Point(12, 9);
            this.lblPreview.Name = "lblPreview";
            this.lblPreview.Size = new System.Drawing.Size(45, 13);
            this.lblPreview.TabIndex = 4;
            this.lblPreview.Text = "Preview";
            // 
            // label2
            // 
            this.label2.AutoSize = true;
            this.label2.ForeColor = System.Drawing.Color.FromArgb(((int)(((byte)(238)))), ((int)(((byte)(238)))), ((int)(((byte)(238)))));
            this.label2.Location = new System.Drawing.Point(312, 147);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(26, 13);
            this.label2.TabIndex = 5;
            this.label2.Text = "Port";
            // 
            // btnRefreshPorts
            // 
            this.btnRefreshPorts.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(0)))), ((int)(((byte)(131)))), ((int)(((byte)(235)))));
            this.btnRefreshPorts.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            this.btnRefreshPorts.ForeColor = System.Drawing.Color.FromArgb(((int)(((byte)(238)))), ((int)(((byte)(238)))), ((int)(((byte)(238)))));
            this.btnRefreshPorts.Location = new System.Drawing.Point(311, 69);
            this.btnRefreshPorts.Name = "btnRefreshPorts";
            this.btnRefreshPorts.Size = new System.Drawing.Size(79, 38);
            this.btnRefreshPorts.TabIndex = 6;
            this.btnRefreshPorts.Text = "Refresh ports";
            this.btnRefreshPorts.UseVisualStyleBackColor = false;
            this.btnRefreshPorts.Click += new System.EventHandler(this.btnRefreshPorts_Click);
            // 
            // pbUpload
            // 
            this.pbUpload.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(36)))), ((int)(((byte)(36)))), ((int)(((byte)(36)))));
            this.pbUpload.Location = new System.Drawing.Point(12, 172);
            this.pbUpload.Name = "pbUpload";
            this.pbUpload.Size = new System.Drawing.Size(160, 23);
            this.pbUpload.TabIndex = 7;
            // 
            // convert_button
            // 
            this.convert_button.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(0)))), ((int)(((byte)(131)))), ((int)(((byte)(235)))));
            this.convert_button.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            this.convert_button.ForeColor = System.Drawing.Color.FromArgb(((int)(((byte)(238)))), ((int)(((byte)(238)))), ((int)(((byte)(238)))));
            this.convert_button.Location = new System.Drawing.Point(207, 113);
            this.convert_button.Name = "convert_button";
            this.convert_button.Size = new System.Drawing.Size(79, 38);
            this.convert_button.TabIndex = 10;
            this.convert_button.Text = "Convert";
            this.convert_button.UseVisualStyleBackColor = false;
            this.convert_button.Click += new System.EventHandler(this.convert_button_Click);
            // 
            // Form1
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(32)))), ((int)(((byte)(32)))), ((int)(((byte)(32)))));
            this.ClientSize = new System.Drawing.Size(415, 220);
            this.Controls.Add(this.convert_button);
            this.Controls.Add(this.pbUpload);
            this.Controls.Add(this.btnRefreshPorts);
            this.Controls.Add(this.label2);
            this.Controls.Add(this.lblPreview);
            this.Controls.Add(this.btnUpload);
            this.Controls.Add(this.btnOpenImg);
            this.Controls.Add(this.picPreview);
            this.Controls.Add(this.cbPorts);
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedSingle;
            this.MaximizeBox = false;
            this.Name = "Form1";
            this.Text = "LCD Image Uploader";
            this.Load += new System.EventHandler(this.Form1_Load);
            ((System.ComponentModel.ISupportInitialize)(this.picPreview)).EndInit();
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.ComboBox cbPorts;
        private System.Windows.Forms.OpenFileDialog openFileDialog1;
        private System.Windows.Forms.PictureBox picPreview;
        private System.Windows.Forms.Button btnOpenImg;
        private System.Windows.Forms.Button btnUpload;
        private System.Windows.Forms.Label lblPreview;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.Button btnRefreshPorts;
        private System.Windows.Forms.ProgressBar pbUpload;
        private System.Windows.Forms.Button convert_button;
    }
}

