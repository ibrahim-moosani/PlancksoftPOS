﻿using MaterialSkin.Controls;
using MaterialSkin;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using Dependencies;
using PlancksoftPOS.Properties;
using System.Reflection.Emit;
using static System.Windows.Forms.VisualStyles.VisualStyleElement.Button;

namespace PlancksoftPOS
{
    public partial class frmClientCard : MaterialForm
    {
        Connection Connection = new Connection();
        public Client Client = new Client();
        public DialogResult dialogResult;
        public List<Item> saleItems = new List<Item>();
        public static LanguageChoice.Languages pickedLanguage = LanguageChoice.Languages.Arabic;

        public frmClientCard()
        {
            InitializeComponent();

            Program.materialSkinManager.AddFormToManage(this);

            frmLogin.pickedLanguage = (LanguageChoice.Languages)Settings.Default.pickedLanguage;

            if (frmLogin.pickedLanguage == LanguageChoice.Languages.Arabic)
            {
                RightToLeft = RightToLeft.Yes;
                RightToLeftLayout = true;
            }
            else if (frmLogin.pickedLanguage == LanguageChoice.Languages.English)
            {
                RightToLeft = RightToLeft.No;
                RightToLeftLayout = false;
            }

            applyLocalizationOnUI();
        }

        public void applyLocalizationOnUI()
        {
            if (frmLogin.pickedLanguage == LanguageChoice.Languages.Arabic)
            {
                Text = "شاشة بطاقة العميل";
                lblClientName.Text = "إسم العميل";
                lblClientID.Text = "رقم العميل";
                lblItemName.Text = "إسم الماده";
                btnClear.Text = "مسح";
                btnSearch.Text = "بحث";
                btnClose.Text = "خروج";
                dgvClients.Columns["Column1"].HeaderText = "إسم العميل";
                dgvClients.Columns["Column2"].HeaderText = "رمز العميل";
                dgvClients.Columns["Column3"].HeaderText = "اسم الماده";
                dgvClients.Columns["Column4"].HeaderText = "سعر العميل";
                dgvClients.Columns["Column5"].HeaderText = "باركود الماده";
                RightToLeft = RightToLeft.Yes;
                RightToLeftLayout = true;
            }
            else if (frmLogin.pickedLanguage == LanguageChoice.Languages.English)
            {
                Text = "Client Card Module";
                lblClientName.Text = "Client Name";
                lblClientID.Text = "Client ID";
                lblItemName.Text = "Item Name";
                btnClear.Text = "Clear";
                btnSearch.Text = "Search";
                btnClose.Text = "Close";
                dgvClients.Columns["Column1"].HeaderText = "Client Name";
                dgvClients.Columns["Column2"].HeaderText = "Client ID";
                dgvClients.Columns["Column3"].HeaderText = "Item Name";
                dgvClients.Columns["Column4"].HeaderText = "Client Price";
                dgvClients.Columns["Column5"].HeaderText = "Item Barcode";
                RightToLeft = RightToLeft.No;
                RightToLeftLayout = false;
            }
        }

        private void btnClear_Click(object sender, EventArgs e)
        {
            txtClientName.Text = "";
            txtItemName.Text = "";
        }

        private void btnSearch_Click(object sender, EventArgs e)
        {
            try
            {
                if (txtClientName.Text == "")
                {
                    if (frmLogin.pickedLanguage == LanguageChoice.Languages.Arabic)
                    {
                        MaterialMessageBox.Show(".الرجاء إدخال إسم عميل", false, FlexibleMaterialForm.ButtonsPosition.Center);
                    }
                    else if (frmLogin.pickedLanguage == LanguageChoice.Languages.English)
                    {
                        MaterialMessageBox.Show("Please enter a valid client name.", false, FlexibleMaterialForm.ButtonsPosition.Center);
                    }
                    return;
                }
                DataTable RetrievedClients = Connection.server.SearchClients(txtClientName.Text, txtClientID.Text, txtItemName.Text);
                dgvClients.DataSource = RetrievedClients;

                if (frmLogin.pickedLanguage == LanguageChoice.Languages.Arabic)
                {
                    dgvClients.Columns["Column1"].HeaderText = "اسم العميل";
                    dgvClients.Columns["Column2"].HeaderText = "رمز العميل";
                    dgvClients.Columns["Column3"].HeaderText = "اسم الماده";
                    dgvClients.Columns["Column4"].HeaderText = "سعر العميل";
                    dgvClients.Columns["Column5"].HeaderText = "باركود الماده";
                }
                else if (frmLogin.pickedLanguage == LanguageChoice.Languages.English)
                {
                    dgvClients.Columns["Column1"].HeaderText = "Client Name";
                    dgvClients.Columns["Column2"].HeaderText = "Client ID";
                    dgvClients.Columns["Column3"].HeaderText = "Item Name";
                    dgvClients.Columns["Column4"].HeaderText = "Client Price";
                    dgvClients.Columns["Column5"].HeaderText = "Item Barcode";
                }
            } catch (Exception exc)
            {

                if (frmLogin.pickedLanguage == LanguageChoice.Languages.Arabic)
                {
                    MaterialMessageBox.Show(".لم نستطع العثور على ماده خصم للعميل بالبيانات المدخله", false, FlexibleMaterialForm.ButtonsPosition.Center);
                }
                else if (frmLogin.pickedLanguage == LanguageChoice.Languages.English)
                {
                    MaterialMessageBox.Show("We were unable to find an item on sale corresponding with the input data.", false, FlexibleMaterialForm.ButtonsPosition.Center);
                }
            }
        }

        private void btnClose_Click(object sender, EventArgs e)
        {
            dialogResult = DialogResult.Cancel;
            this.Close();
        }

        private void dgvClients_RowHeaderMouseDoubleClick(object sender, DataGridViewCellMouseEventArgs e)
        {
            try
            {
                Client.ClientName = dgvClients.Rows[e.RowIndex].Cells[0].Value.ToString();
                Client.ClientID = Convert.ToInt32(dgvClients.Rows[e.RowIndex].Cells[1].Value.ToString());


                bool found = false;
                foreach (DataGridViewRow item in dgvClients.Rows)
                {
                    if (!item.IsNewRow && !found)
                    {
                        Item newItem = new Item();
                        if (item.Selected)
                        {
                            newItem.SetName(item.Cells[2].Value.ToString());
                            newItem.SetBarCode(item.Cells[3].Value.ToString());
                            newItem.ClientPrice = Convert.ToDecimal(item.Cells[4].Value.ToString());
                            saleItems.Add(newItem);

                            found = true;
                            dialogResult = DialogResult.OK;
                            this.Close();
                        }
                    }
                    else
                    {
                        if (!found)
                        {
                            if (frmLogin.pickedLanguage == LanguageChoice.Languages.Arabic)
                            {
                                MaterialMessageBox.Show(".الرجاء اختيار ماده من الجدول اعلاه", false, FlexibleMaterialForm.ButtonsPosition.Center);
                            }
                        }
                        else if (frmLogin.pickedLanguage == LanguageChoice.Languages.English)
                        {
                            MaterialMessageBox.Show("Please pick an item from the grid above.", false, FlexibleMaterialForm.ButtonsPosition.Center);
                        }
                    }
                }

                dialogResult = DialogResult.OK;
                this.Close();
            }
            catch (Exception error)
            {
                if (frmLogin.pickedLanguage == LanguageChoice.Languages.Arabic)
                {
                    MaterialMessageBox.Show(".لم نستطع اختيار مادة العميل", false, FlexibleMaterialForm.ButtonsPosition.Center);
                }
                else if (frmLogin.pickedLanguage == LanguageChoice.Languages.English)
                {
                    MaterialMessageBox.Show("Unable to choose Client item.", false, FlexibleMaterialForm.ButtonsPosition.Center);
                }
            }
        }

        private void txtClientName_TextChanged(object sender, EventArgs e)
        {
            DataTable RetrievedClients = Connection.server.SearchClients(txtClientName.Text, "", "");
            dgvClients.DataSource = RetrievedClients;
        }

        private void frmClientCard_FormClosing(object sender, FormClosingEventArgs e)
        {
            if (!Program.exited)
            {
                Program.exited = true;
                this.Close();
            }
        }

        private void frmClientCard_FormClosed(object sender, FormClosedEventArgs e)
        {
            Program.exited = false;
            Program.materialSkinManager.RemoveFormToManage(this);
        }
    }
}
