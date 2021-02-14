using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.IO;
using System.Xml;
using Newtonsoft.Json;
using System.Threading;

namespace winverify
{
  
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
           // readXml();
        }

        private void Button_Click(object sender, RoutedEventArgs e)
        {
            // To interact with the different windows you must create an object of the form

            // created a threadopject

            // Thread t1 = new Thread(new ThreadStart(progressbar));
          

            InfoPage info = new InfoPage();

            // Closes window
            Close();
            // Pops up the info page
            info.Show();
        }
        /*
         * Method does not work due to the way I put the code in infopage and how the initialize method works. When you press the button it seems to ignores everything.
         *
        private void progressbar()
        {
            // Method for for creating progress bar while it is loading. This will be to prevent end users from thinking the program is frozen.
            progressbarTitle.Visibility = Visibility.Visible;
            progressbarTitle.IsIndeterminate = true;
        }


        */
        private void readXml()
        {
            var nistStig = File.ReadAllText("..//..//..//..//winverify//resources//MS_Windows_10_V2R1_STIG_SCAP.xml");
            XmlDocument document = new XmlDocument();
            document.LoadXml(nistStig);
            var json = JsonConvert.SerializeXmlNode(document);
            // Code below is meant for debugging but does not show. Read on to see how I debugged it
           // Console.WriteLine(json);
           
            // The line below is for you to test out the json code on the title page since I can't find where the console line is for "Console.write"
          //lblTitle.Content = json;

            
            // Or figure out how to use the data types for selecting profiles and rules in this library
            XCCDFParser.Container ee = JsonConvert.DeserializeObject<XCCDFParser.Container>(json);
            //  Console.Write(ee.Benchmark.Profile.Contains.);


        }

        private void ProgressBar_ValueChanged(object sender, RoutedPropertyChangedEventArgs<double> e)
        {
            
        }
    }
}
