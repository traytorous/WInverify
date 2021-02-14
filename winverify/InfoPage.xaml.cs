using System;
using System.Collections.Generic;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;
// Below are libraries implemented by Tray change if need be
using System.ServiceProcess;
using System.Diagnostics;
using System.Threading;
using System.IO;
//Firewall manager libarary
using FirewallManager;
using System.Collections;
// Library used for checking for windows update. Had to get the dll
using WUApiLib;
using System.Management;

//@Author Tray Keller 
namespace winverify
{


    /// <summary>
    /// Interaction logic for InfoPage.xaml
    /// </summary>
    public partial class InfoPage : Window
    {
        private bool[] statusArray = { false, false, false, false };
        public InfoPage()
        {
            InitializeComponent();
            checkDangerousService();
            checkFirewalls();
            installAndDownloadUpdate();
            antiVirusChecker();
            checkingSystemSecurityStatus();
        }

        private void checkDangerousService()
        {
            txtScan.Text += "Scanning process for well known malicious processes!\n";
            String processResults = null;
            String[] susProcesses = File.ReadAllLines("..//..//..//..//winverify//resources//maliciousProcesses.txt");

            Process[] currentProcessList = Process.GetProcesses();


            foreach (Process x in currentProcessList)
            {
                if (Array.Exists(susProcesses, proc => proc == x.ProcessName))
                {
                    processResults += x.ProcessName + "\n";
                }
            }
            txtScan.Text += (processResults == null) ? "No well known malicious process found! GREAT JOB!" : processResults;
            if (processResults != null)
            {
                txtScan.Text += "Malicious processes have been found!";
            }
            else
            {
                statusArray[0] = true;
            }
            txtScan.Text += "\n---------------------------------------------------------------\n";
        }

        private void checkFirewalls()
        {
            // Do not touch this code without consulting me first please - Tray 

            FirewallCom x = new FirewallCom();

            // Checks if firewalls are setup. If it is not setup then it will fix it
            if (x.GetFirewallEnable(ProfileType.Public) == false)
            {
                x.SetFirewallEnable(ProfileType.Public, true);
                txtScan.Text += "Setting up Public firewall \n ";

            }
            if (x.GetFirewallEnable(ProfileType.Private) == false)
            {
                x.SetFirewallEnable(ProfileType.Private, true);
                txtScan.Text += "Setting up Private firewall \n ";
            }
            if (x.GetFirewallEnable(ProfileType.Domain) == false)
            {
                x.SetFirewallEnable(ProfileType.Domain, true);
                txtScan.Text += "Setting up Domain firewall \n ";
            }


            // Prints out status of firewalls
            ArrayList portNumber = new ArrayList();
            txtScan.Text += "Public Firewall enabled = " + x.GetFirewallEnable(ProfileType.Public) + "\n";
            txtScan.Text += "Private Firewall enabled = " + x.GetFirewallEnable(ProfileType.Private) + "\n";
            txtScan.Text += "Domain Firewall enabled = " + x.GetFirewallEnable(ProfileType.Domain) + "\n";


            // Shows failures if it did not set up correctly
            if (x.GetFirewallEnable(ProfileType.Public) == false)
            {

                txtScan.Text += "Failed to set up Public firewall \n ";

            }
            if (x.GetFirewallEnable(ProfileType.Private) == false)
            {

                txtScan.Text += "Failed to setup Private firewall \n ";
            }
            if (x.GetFirewallEnable(ProfileType.Domain) == false)
            {

                txtScan.Text += "Failed to setup Domain firewall \n ";
            }


            foreach (OpenPort port in x.GetOpenPorts())
            {
                portNumber.Add(port.Port);

            }
            if (portNumber.Count == 0)
            {
                txtScan.Text += "Firewall is safe. There are no ports open\n---------------------------------------------------------------\n";
                statusArray[1] = true;
            }
            else
            {
                txtScan.Text += "Ports were found open. Closing ports now\n---------------------------------------------------------------\n";
                // Will implement in future implemenation

            }


        }

        // -------------------------------------------------------------------------------------------



        private bool NeedsUpdate()
        {
            UpdateSession UpdateSession = new UpdateSession();
            IUpdateSearcher UpdateSearchResult = UpdateSession.CreateUpdateSearcher();
            UpdateSearchResult.Online = true;//checks for updates online
            ISearchResult SearchResults = UpdateSearchResult.Search("IsInstalled=0 AND IsPresent=0");
            //for the above search criteria refer to 
            //http://msdn.microsoft.com/en-us/library/windows/desktop/aa386526(v=VS.85).aspx
            //Check the remakrs section
            if (SearchResults.Updates.Count > 0)
            {
                txtScan.Text += "System needs to be updated. Updating system now!\n---------------------------------------------------------------\n";
                return true;
            }
            else
            {
                txtScan.Text += "System is up to date with the latest Windows update!\n---------------------------------------------------------------\n";
                statusArray[2] = true;
                return false;
            }
        }
        private UpdateCollection DownloadUpdates()
        {
            UpdateSession UpdateSession = new UpdateSession();
            IUpdateSearcher SearchUpdates = UpdateSession.CreateUpdateSearcher();
            ISearchResult UpdateSearchResult = SearchUpdates.Search("IsInstalled=0 and IsPresent=0");
            UpdateCollection UpdateCollection = new UpdateCollection();
            //Accept Eula code for each update
            for (int i = 0; i < UpdateSearchResult.Updates.Count; i++)
            {
                IUpdate Updates = UpdateSearchResult.Updates[i];
                if (Updates.EulaAccepted == false)
                {
                    Updates.AcceptEula();
                }
                UpdateCollection.Add(Updates);
            }
            //Accept Eula ends here
            //if it is zero i am not sure if it will trow an exception -- I havent tested it.
            if (UpdateSearchResult.Updates.Count > 0)
            {
                UpdateCollection DownloadCollection = new UpdateCollection();
                UpdateDownloader Downloader = UpdateSession.CreateUpdateDownloader();

                for (int i = 0; i < UpdateCollection.Count; i++)
                {
                    DownloadCollection.Add(UpdateCollection[i]);
                }

                Downloader.Updates = DownloadCollection;
                Console.WriteLine("Downloading Updates... This may take several minutes.");


                IDownloadResult DownloadResult = Downloader.Download();
                UpdateCollection InstallCollection = new UpdateCollection();
                for (int i = 0; i < UpdateCollection.Count; i++)
                {
                    if (DownloadCollection[i].IsDownloaded)
                    {
                        InstallCollection.Add(DownloadCollection[i]);
                    }
                }
                Console.WriteLine("Download Finished");
                return InstallCollection;
            }
            else
                return UpdateCollection;
        }
        private void InstallUpdates(UpdateCollection DownloadedUpdates)
        {
            Console.WriteLine("Installing updates now...");
            UpdateSession UpdateSession = new UpdateSession();
            UpdateInstaller InstallAgent = UpdateSession.CreateUpdateInstaller() as UpdateInstaller;
            InstallAgent.Updates = DownloadedUpdates;

            //Starts a synchronous installation of the updates.
            // http://msdn.microsoft.com/en-us/library/windows/desktop/aa386491(v=VS.85).aspx#methods
            if (DownloadedUpdates.Count > 0)
            {
                IInstallationResult InstallResult = InstallAgent.Install();
                if (InstallResult.ResultCode == OperationResultCode.orcSucceeded)
                {
                    Console.WriteLine("Updates installed succesfully");
                    if (InstallResult.RebootRequired == true)
                    {
                        Console.WriteLine("Reboot is required for one of more updates.");
                    }
                }
                else
                {
                    Console.WriteLine("Updates failed to install do it manually");
                }
            }
            else
            {
                Console.WriteLine("The computer that this script was executed is up to date");
            }

        }
        private void EnableUpdateServices()
        {
            IAutomaticUpdates updates = new AutomaticUpdates();
            if (!updates.ServiceEnabled)
            {
                updates.EnableService();

            }

        }

        //--------------------------------------------------------------------------------------------------------------------------------------

        private void installAndDownloadUpdate()
        {
            if (NeedsUpdate()) // Checks if we need to update the windows computer
            {
                EnableUpdateServices();//enables everything windows need in order to make an update
                InstallUpdates(DownloadUpdates()); // Donwlad and installs updates
                txtScan.Text += "Windows is now updated-----------------------------------------------\n";
                statusArray[2] = true;
            }
        }
        private void antiVirusChecker()
        {
            /* Added a way to check for anti-virus
             * Must add a way to check for antivirus versions and make sure it's updated at least for windows defender. Then will check for other verions product state code
             * 
             */
            txtScan.Text += "Checking for antivirus scanner. Scanners will be shown below. \n";
            // Gets Antivirus resuts and use it to create an object
            ManagementObjectSearcher wmiData = new ManagementObjectSearcher(@"root\SecurityCenter2", "SELECT * FROM AntiVirusProduct");
            // Puts the data into the management object
            ManagementObjectCollection data = wmiData.Get();

            // Looks through data to get a dictionary / hashmap
            bool hasAntivius = false;
            List<String> antivirusList = new List<string>();
            Dictionary<String, String> serviceCodes = new Dictionary<String, String>();

            foreach (ManagementObject virusChecker in data)
            {
                if (virusChecker["displayName"] != null)
                {
                    if (hasAntivius == false)
                    {
                        hasAntivius = true;
                    }
                    txtScan.Text += "Antivirus found = " + virusChecker["displayName"] + "\n";
                    //This works but you need to know the prodcut stateCode to know what's going on with the antivirus software
                    //virusChecker["productState"]);
                    string listObject = virusChecker["displayName"].ToString();
                    string listObject2 = virusChecker["productState"].ToString();

                    antivirusList.Add(listObject);
                    serviceCodes.Add(listObject, listObject2);
                }

            }
            if (hasAntivius == false)
            {
                txtScan.Text += "No antivirus was found. Please install one. \n";
                // Lines of code below is irrelevant because there is no antivirus scanner
            }
            else
            {
                txtScan.Text += "Antivirus was found. Checking status of Antivirus product. Status will be shown below. \n";
            }

            // Below is to check windows service code about windows defender. We will Add more antivirus software later. Examples would be avast or windows essentials security
            if (antivirusList.Contains("Windows Defender"))
            {
                String serviceCode = serviceCodes["Windows Defender"];
                switch (serviceCode)
                {
                    case "393472":
                        txtScan.Text += "Windows Defender is disabled and up to date.\n";
                        if (antivirusList.Count == 1)
                        {
                            txtScan.Text += "Please enable Windows Defender or install a new Antivirus scanner.\n---------------------------------------------------------------\n";
                        }
                        if (antivirusList.Count > 1)
                        {
                            txtScan.Text += "Please enable Windows Defender or enable any existing anti-viruses software.\n---------------------------------------------------------------\n";
                        }
                        break;
                    case "397584":
                        txtScan.Text += "Windows Defender is enabled and out of date. Please update windows defender.\n---------------------------------------------------------------\n";
                        // Maybe I can update it using .net Will try to implement later
                        // Code below creates a new process and runs the following command. Should run
                        Process cmd = new Process();
                        cmd.StartInfo.FileName = "cmd.exe";
                        cmd.StartInfo.RedirectStandardInput = true;
                        cmd.StartInfo.RedirectStandardOutput = true;
                        cmd.StartInfo.CreateNoWindow = true;
                        cmd.StartInfo.UseShellExecute = false;
                        cmd.Start();

                        cmd.StandardInput.WriteLine("\"C:\\Program Files\\Windows Defender\\MpCmdRun.exe\" - SignatureUpdate");
                        cmd.StandardInput.Flush();
                        cmd.StandardInput.Close();
                        cmd.WaitForExit();
                        // Will implement into a log file later Console.WriteLine(cmd.StandardOutput.ReadToEnd());
                        break;
                    case "397568":
                        txtScan.Text += "Windows Defender is enabled and up to date. Great Job!\n---------------------------------------------------------------\n";
                        statusArray[3] = true;
                        break;
                    default:
                        txtScan.Text += "Windows Defender code cannot be read. Service code = " + serviceCode + ". Please look it up if you need to.\n---------------------------------------------------------------\n";
                        break;
                }

            }
        }

        public void checkingSystemSecurityStatus()
        {
            bool exists = Array.Exists(statusArray, delegate (bool s) { return s.Equals(false); });
            if (exists == true)
            {
                txtScan.Text += "There is an System not completely secured. Please read through the statuses to see what needs to be fixed.";           
            }
            else
            {
                txtScan.Text += "System passed our security check! Please run Antivirus scanner to be sure.";
            }

        }


    }
}

