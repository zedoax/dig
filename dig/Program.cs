using System;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;

namespace dig
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                // Set Defaults
                IPAddress dnsserver = GetDefaultDns();
                var type = DnsRequest.QueryType.a;
                var hostname = "";
                
                // Parse User Input to Override Defaults
                switch (args.Length)
                {
                    case 3:
                        dnsserver = IPAddress.Parse(args[0]);
                        type = (DnsRequest.QueryType)Enum.Parse(typeof(DnsRequest.QueryType), args[1]);
                        hostname = args[2];
                        break;
                    case 2:
                        if (args[0].Length > 4)
                        {
                            dnsserver = IPAddress.Parse(args[0]);
                        }
                        else {
                            type = (DnsRequest.QueryType) Enum.Parse(typeof(DnsRequest.QueryType), args[0]);
                        }

                        hostname = args[1];
                        break;
                    case 1:
                        hostname = args[0];
                        break;
                }
                
                // Retrieve Response
                var response = new DnsRequest(dnsserver, type, hostname).TransactQuery();
                
                // Print out Response
                Console.WriteLine("<<>> dig 0.0.1 <<>> " + hostname);
                Console.WriteLine("Got answer: ");
                Console.WriteLine(response);
                
            } catch {
                // Print Help on Wrong Inputs
                Console.WriteLine("Usage: dig <DNSServer> <Type> hostname");
                Console.WriteLine("");
                Console.WriteLine("Where:  DNSServer is The DNS Server to query [default:current dns]");
                Console.WriteLine("        Type      is one of (a, aaaa, cname) [default:a]");
                Console.WriteLine("        hostname  the hostname for the target record");
                
            }
            
        }

        /// <summary>
        /// Iterate Current DNS Servers to Find Working One
        /// </summary>
        public static IPAddress GetDefaultDns()
        {
            {
                NetworkInterface[] networkInterfaces = NetworkInterface.GetAllNetworkInterfaces();

                foreach (NetworkInterface networkInterface in networkInterfaces)
                {
                    if (networkInterface.OperationalStatus == OperationalStatus.Up)
                    {
                        IPInterfaceProperties ipProperties = networkInterface.GetIPProperties();
                        IPAddressCollection dnsAddresses = ipProperties.DnsAddresses;

                        foreach (IPAddress dnsAdress in dnsAddresses)
                        {
                            try
                            {
                                // Test Connection and Return
                                var conn = new UdpClient();
                                conn.Connect(dnsAdress, 53);
                                conn.Close();
                                return dnsAdress;
                            } catch {}
                            // Check Next One
                        }
                    }
                }

                // Print Error If Unable to Find Default DNS
                Console.Error.WriteLine("Unable to Locate DNS Server");
                return null;
            }
        }
        
        
    }

    /// <summary>
    /// Class For Request Made, Sending the Request, Returning the Response
    /// </summary>
    public class DnsRequest
    {
        private IPAddress _dnsserver;
        private QueryType _type;
        private string _hostname;

        public DnsRequest(IPAddress dnsserver, QueryType type, string hostname)
        {
            _dnsserver = dnsserver;
            _type = type;
            _hostname = hostname;
        }

        /// <summary>
        /// Build and Send Query, Return Response
        /// </summary>
        public string TransactQuery()
        {
            try
            {
                // Generate the Request
                var hostnameParts = _hostname.Split(".");
                var request = new byte[41 + _hostname.Length + hostnameParts.Length];

                request[0] = 33;
                request[1] = 33;

                request[2] = 1;
                request[3] = 32;
                request[5] = 1;
                request[11] = 1;

                var bitIdx = 12;
                for (int partIdx = 0; partIdx < hostnameParts.Length; partIdx++)
                {
                    request[bitIdx] = BitConverter.GetBytes(hostnameParts[partIdx].Length)[0];
                    bitIdx++;
                    foreach (var chr in hostnameParts[partIdx])
                    {
                        request[bitIdx] = BitConverter.GetBytes(chr)[0];
                        bitIdx++;
                    }

                }

                request[bitIdx] = 0;
                bitIdx++;
                request[bitIdx] = 0;
                bitIdx++;
                switch (_type)
                {
                    case QueryType.a:
                        request[bitIdx] = 1;
                        break;
                    case QueryType.aaaa:
                        request[bitIdx] = 28;
                        break;
                    case QueryType.cname:
                        request[bitIdx] = 5;
                        break;
                }
                bitIdx++;
                request[bitIdx] = 0;
                bitIdx++;
                request[bitIdx] = 1;
                bitIdx+=3;
                request[bitIdx] = 41;
                bitIdx++;
                request[bitIdx] = 16;
                bitIdx += 7;
                request[bitIdx] = 12;
                bitIdx += 2;
                request[bitIdx] = 10;
                bitIdx += 2;
                request[bitIdx] = 8;
                bitIdx++;
                request[bitIdx] = 78;
                bitIdx++;
                request[bitIdx] = 31;
                bitIdx++;
                request[bitIdx] = 252;
                bitIdx++;
                request[bitIdx] = 130;
                bitIdx++;
                request[bitIdx] = 235;
                bitIdx++;
                request[bitIdx] = 126;
                bitIdx++;
                request[bitIdx] = 94;
                bitIdx++;
                request[bitIdx] = 41;

                
                // Initialize the client by binding the socket
                var client = new UdpClient(_dnsserver.AddressFamily.Equals(AddressFamily.InterNetwork) ? AddressFamily.InterNetwork : AddressFamily.InterNetworkV6);
                var ep = new IPEndPoint(_dnsserver, 53);

                // Send the Query and Retrieve the Result
                var requestMade = DateTime.Now;
                var timer = new Stopwatch();
                timer.Start();
                client.Send(request, request.Length, ep);
                var response = client.Receive(ref ep);
                timer.Stop();

                // Parse the Response
                DnsResponse res = OutputData(response);

                // Format the Request/Response
                var responseString = 
                    "->>HEADER<<- " + res + "\nQUESTION SECTION:\n" + res.QuestionsToString() + "\nANSWER SECTION:\n" + res.AnswersToString() + "\n";
                responseString += "Query time: " + timer.ElapsedMilliseconds + " msec\nSERVER: " + _dnsserver + "#53(" + _dnsserver + ")\n";
                responseString += "WHEN: " + String.Format("{0:ddd MMM dd HH:mm:ss} EDT {1:yyyy}", requestMade, requestMade) + "\nMSG SIZE rcvd: " + response.Length;
                return responseString;

            }
            catch (Exception)
            {
                // Connection Error Occured so return that instead of null valued strings
                return "Error: Unable To Connect To DNS Server";
            }

        }

        // Parse the data returned by the server, and output it.
        public DnsResponse OutputData(byte[] response)
        {   
            // Header Section
            var transactionId = "" + (char)response[0] + (char)response[1];
            var flags = new int[] { response[2], response[3] };
            var questionCount = (response[4]<<8) | response[5];
            var answerCount = response[6] + response[7];
            var authorityCount = (response[8]<<8) | response[9];
            var additionalCount = (response[10]<<8) | response[11];

            var answerIdx = 12;
            
            // Question Section
            var questions = new Question[questionCount];
            for (int i = 0; i < questionCount; i++)
            {
                var domainName = StringAtSection(response, answerIdx);
                answerIdx += StringSizeAtSection(response, answerIdx);
                var type = (response[answerIdx] << 8) | response[answerIdx + 1];
                answerIdx += 2;
                var tclass = (response[answerIdx] << 8) | response[answerIdx + 1];
                answerIdx += 2;
                questions[i] = new Question(domainName, type, tclass);
            }
            

            Answer[] answers = new Answer[answerCount];
            // Answer Section
            for (int i = 0; i < answers.Length; i++)
            {
                string host = StringAtSection(response, answerIdx);
                answerIdx += StringSizeAtSection(response, answerIdx);
                var type = (response[answerIdx]<<8) | response[answerIdx + 1];
                answerIdx += 2;
                var typeClass = (response[answerIdx]<<8) | response[answerIdx + 1];
                answerIdx += 2;
                var timetolive = (response[answerIdx]<<16) | (response[answerIdx + 1]<<12) | (response[answerIdx + 2]<<8) | response[answerIdx + 3];
                answerIdx += 4;
                int datalength = (response[answerIdx]<<8) | response[answerIdx + 1];
                answerIdx += 2;

                var data = "";

                if ((QueryType) type == QueryType.a || (QueryType) type == QueryType.aaaa)
                {
                    var ipType = (QueryType) type == QueryType.a ? IP.IPv4 : IP.IPv6;
                    data = ParseIP(response.Subarray(answerIdx, answerIdx + datalength), ipType);
                    answerIdx += datalength;
                    
                }
                else if ((QueryType) type == QueryType.cname)
                {
                    data = StringAtSection(response, answerIdx);
                    answerIdx += StringSizeAtSection(response, answerIdx);
                    
                }

                answers[i] = new Answer(host, type, typeClass, timetolive, data);
            }
            
            // Create new DNS Response from Parsed Data
            return new DnsResponse
                (transactionId, flags[0], flags[1], questionCount, answerCount, authorityCount, additionalCount, questions, answers);

        }

        /// <summary>
        /// Returns the String At a Given Section in Network Packet (Follows Pointers)
        /// </summary>
        private string StringAtSection(byte[] response, int index)
        {
            // Init temp and return values
            var stringSection = "";
            int sectionLength = response[index];
            index++;
            
            // Follow Pointer
            if (sectionLength == 192)
            {
                return StringAtSection(response, response[index]);
            }
            
            // Loop Through String until a 0 or pointer is found
            while (sectionLength > 0)
            {
                stringSection += new string(Encoding.ASCII.GetChars(response.Subarray(index, index + sectionLength)));
                index += sectionLength;
                sectionLength = response[index];
                index++;
                stringSection += sectionLength > 0 ? "." : "";
                if (sectionLength == 192)
                {
                    stringSection += StringAtSection(response, response[index]);
                    return stringSection;
                }
                
            }

            // Return the string built by iteration and recursion
            return stringSection;
        }

        /// <summary>
        /// Returns Size of String at any given section in a network packet
        /// </summary>
        private int StringSizeAtSection(byte[] response, int index)
        {
            // Init temp and return values
            int length = 1;
            int sectionLength = response[index];
            
            // Skip over pointer
            if (sectionLength == 192)
                return 2;
            
            // Iterate the section until you find a pointer or a 0 byte and return the found length
            while (sectionLength > 0)
            {
                length += sectionLength + 1;
                index += sectionLength + 1;
                sectionLength = response[index];
                if (sectionLength == 192)
                {
                    length += 1;
                    return length;
                }
                
            }

            return length;

        }

        /// <summary>
        /// Converts section of network packet to IPv4 or IPv6
        /// </summary>
        public string ParseIP(byte[] addressBytes, IP type)
        {
            var address = "";
            switch (type)
            {
                    case IP.IPv4:
                        for (int i = 0; i < addressBytes.Length; i++)
                        {
                            address += addressBytes[i];
                            if (i < addressBytes.Length - 1) address += ".";
                        }
                        break;
                    case IP.IPv6:
                        for (int i = 0; i < addressBytes.Length; i += 2)
                        {
                            var part = addressBytes[i].ToString("x2") + addressBytes[i+1].ToString("x2");
                            part = part.TrimStart('0').PadLeft(1, '0');
                            address += part;
                            if (i < addressBytes.Length - 2) address += ":";
                        }
                        break;
            }

            return address;
        }

        /// <summary>
        /// Class for Storing and Outputting the Response
        /// </summary>
        public class DnsResponse
        {
            public string Id { get; set; }
            public int FlagOne { get; set; }
            public int FlagTwo { get; set; }
            public int QuestionCount { get; set; }
            public int AnswerCount { get; set; }
            public int Authorityrrs { get; set; }
            public int Additionalrrs { get; set; }
            public Answer[] Answers { get; set; }
            public Question[] Questions { get; set; }

            public DnsResponse(string id, int flagOne, int flagTwo, int questionCount, int answerCount, int authorityrrs, int additionalrrs, Question[] questions, Answer[] answers)
            {
                Id = id;
                FlagOne = flagOne;
                FlagTwo = flagTwo;
                QuestionCount = questionCount;
                AnswerCount = answerCount;
                Authorityrrs = authorityrrs;
                Additionalrrs = additionalrrs;
                Questions = questions;
                Answers = answers;
            }

            public string QuestionsToString()
            {
                return Questions.Aggregate("", (current, question) => current + (question + "\n"));
            }

            public string AnswersToString()
            {
                return Answers.Aggregate("", (current, question) => current + (question + "\n"));
            }

            public override string ToString()
            {
                // Opcode
                var op = (FlagOne & 120) >> 3;
                // Status
                var status = FlagTwo & 15;
                // Query Response Flag
                var qr = (FlagOne & 128) >> 7 == 1;
                // Recursion Desired Flag
                var rd = (FlagOne & 1) == 1;
                // Recursion Available Flag
                var ra = (FlagTwo & 128) >> 7 == 1;
                return
                    "opcode: " + (Opcode)op + ", status: " + (Status)status +
                    ", id: " + Id +
                    ", flags: " + (qr ? "qr " : "") + (rd ? "rd " : "") + (ra ? "ra " : "") + 
                    ", QUERY: " + QuestionCount + ", ANSWER: " + AnswerCount +
                    ", AUTHORITY: " + Authorityrrs +
                    ", ADDITIONAL: " + Additionalrrs;
            }
            
            private enum Opcode { QUERY=0 }
            private enum Status { NOERROR=0, ERROR=1 }
        }

        /// <summary>
        /// Class for Storing and Outputting a Question
        /// </summary>
        public class Question
        {
            private string Host { get; }
            private QueryType Type { get; }
            private Class TClass { get; }

            public Question(string host, int type, int @class)
            {
                Host = host;
                Type = (QueryType)type;
                TClass = (Class)@class;
            }

            public override string ToString()
            {
                return Host + ".\t" + TClass + "\t" + Type;
            }
        }

        /// <summary>
        /// Class for Storing and Outputting an Answer
        /// </summary>
        public class Answer
        {
            private string Host { get; set; }
            private QueryType Type { get; set; }
            private Class TClass { get; set; }
            private int Ttl { get; set; }
            private string IPaddr { get; set; }

            public Answer(string host, int type, int tclass, int ttl, string ipaddr)
            {
                Host = host;
                Type = (QueryType)type;
                TClass = (Class)tclass;
                Ttl = ttl;
                IPaddr = ipaddr;
            }

            public override string ToString()
            {
                return Host + ".\t" + Ttl + "\t" + Type + "\t" + TClass + "\t" + IPaddr;
            }
            
        }
        
        public enum QueryType { a = 1, aaaa = 28, cname = 5 }
        
        public enum IP { IPv4, IPv6 }
        
        private enum Class { IN = 1 }
        
    }

    /// <summary>
    /// Extension for Arrays to Create a SubArray
    /// </summary>
    public static class Extensions
    {
        public static T[] Subarray<T>(this T[] arr, int start, int end)
        {
            if (start >= end) return new T[0];
            T[] newArr = new T[end - start];
            for (int i = 0; i < newArr.Length; i++)
            {
                newArr[i] = arr[start + i];
            }

            return newArr;
        }
    }
    
}