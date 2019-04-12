import time,re
from dics import URLCatDic,MalwareDictionary


def RunLine(logline):

    ResultLists = []
    for line in logline:
        ResultList = []
        Formatted=re.split(r"<|>",line)[0].split(" ")
        ScanResultList=re.split(r"<|>",line)[1]
        AfterScanResultList=re.split(r"<|>",line)[2].strip().split(" ")

        #0
        strtime=time.strftime("%Y-%m-%d %H:%M:%S",time.localtime(float(Formatted[0])))
        ResultList.append(strtime)

        #1
        if int(Formatted[1]) <1000:
            delay=Formatted[1]
            ResultList.append(delay+' ms')
        else:
            delay=str(round(int(Formatted[1])/1000,3))
            ResultList.append(delay+' s')

        #2
        ResultList.append(Formatted[2])

        #3
        ResultList.append(Formatted[3])

        #4
        if int(Formatted[4]) <1024:
            delay=Formatted[4]
            ResultList.append(delay+' B')
        elif int(Formatted[4])>=1024 and int(Formatted[4])<1024000:
            delay=str(round(int(Formatted[4])/1024,3))
            ResultList.append(delay+' KB')
        else:
            delay = str(round(int(Formatted[4]) / 1024000, 3))
            ResultList.append(delay+' MB')
        #5
        ResultList.append(Formatted[5])

        #6
        ResultList.append(Formatted[6])

        #7
        ResultList.append(Formatted[7])

        #8
        ResultList.append(Formatted[8])

        #9
        ResultList.append(Formatted[9])

        #10
        DecisionList=Formatted[10].split('-')

        #10.0
        ResultList.append(DecisionList[0])

        #10.1
            #Policy Type
        PolicyType=Formatted[6].split(':')[0]
        def CheckPolicyType():
            if PolicyType=="http" or PolicyType=="https":
                return ("Access Policy")
            elif PolicyType=="tunnel":
                return ("Decryption Policies")
            else:
                return ("Other")

            #Policy Name
        ResultList.append(DecisionList[1]+":"+CheckPolicyType())

        #10.2
        ResultList.append(DecisionList[2])

        #10.3
        ResultList.append(DecisionList[3])

        #10.4
        ResultList.append(DecisionList[4])

        #10.5
        ResultList.append(DecisionList[5])

        #10.6
        ResultList.append(DecisionList[6])

        #11
        ScanList=ScanResultList.strip("<|>").split(',')

        #11.0
        def CheckURLCat(listid):
            if ScanList[listid] == "nc":
                return ("NONE")
            elif ScanList[listid] == "-":
                return ("NONE")
            else:
                return URLCatDic[ScanList[listid].split("_")[1]]

        ResultList.append(CheckURLCat(0))

        #11.1
        def CheckURLRepu():
            if ScanList[1] == "ns":
                return ("NONE")
            else:
                return ScanList[1]

        ResultList.append(CheckURLRepu())

        #11.2


        def CheckScanResult(listid):
            if ScanList[listid] == "-":
                return ("NONE")
            else:
                return MalwareDictionary[ScanList[listid]]
        ResultList.append(CheckScanResult(2))

        #11.3
        ResultList.append(ScanList[3].strip("\""))

        #11.4
        ResultList.append(ScanList[4])

        #11.5
        ResultList.append(ScanList[5])

        #11.6
        ResultList.append(ScanList[6])

        #11.7

        ResultList.append(CheckScanResult(7))

        #11.8
        ResultList.append(ScanList[8])

        #11.9
        ResultList.append(ScanList[9])

        #11.10
        ResultList.append(ScanList[10])

        #11.11
        ResultList.append(ScanList[11])

        #11.12
        ResultList.append(ScanList[12])

        #11.13
        ResultList.append(CheckScanResult(13))

        #11.14
        ResultList.append(ScanList[14])

        #11.15
        ResultList.append(ScanList[15])

        #11.16
        ResultList.append(ScanList[16].strip("\""))

        #11.17
        CiscoDataSecurityResult={
            "-":"NONE",
            "0":"Allow",
            "1":"Block"
        }
        ResultList.append(CiscoDataSecurityResult[ScanList[17]])

        #11.18
        ExternalDLP={
            "-":"NONE",
            "0":"Allow",
            "1":"Block"
        }
        ResultList.append(ExternalDLP[ScanList[18]])

        #11.19
        ResultList.append(CheckURLCat(19))

        #11.20
        ResultList.append(CheckURLCat(20))

        #11.21
        ResultList.append(ScanList[21])

        #11.22
        ResultList.append(ScanList[22])

        #11.23
        ResultList.append(ScanList[23])

        #11.24
        ResultList.append(ScanList[24])

        #11.25
        ResultList.append(ScanList[25])

        #11.26
        ResultList.append(ScanList[26])

        #11.27
        ResultList.append(ScanList[27]+" Kb/s")

        #11.28
        def CheckBandwidth():
            if ScanList[28] == "0":
                return ('NO')
            else:
                return ('YES')
        ResultList.append(CheckBandwidth())

        #11.29
        def CheckAnyconnect():
            if ScanList[29] == "-":
                return "Disabled"
            else:
                return ("Enabled->"+ScanList[29])
        ResultList.append(CheckAnyconnect())

        #11.30
        ResultList.append(ScanList[30])

        #11.31
        ResultList.append(ScanList[31])

        #11.32
        def CheckAmp():
            if  ScanList[32] == "-":
                return ("Disabled")
            elif ScanList[32] == "0":
                return ("File is not malicious")
            elif ScanList[32] == "1":
                return ("File was not scanned because of its file type")
            elif ScanList[32] == "2":
                return ("File scan timed out")
            elif ScanList[32] == "3":
                return ("Scan error")
            else:
                return ("File is malicious")
        ResultList.append(CheckAmp())

        #11.33
        ResultList.append(ScanList[33])

        #11.34
        ResultList.append(ScanList[34])

        #11.35
        def CheckIfUpload():
            if ScanList[35] == '-':
                return ("-")
            elif ScanList[35] == '0':
                return ("NO")
            elif ScanList[35] == '1':
                return ("YES")
        ResultList.append(CheckIfUpload())

        #11.36
        ResultList.append(ScanList[36])

        #11.37
        ResultList.append(ScanList[37])
        #
        # for index,i in enumerate(AfterScanResultList[1:]):
        #     ResultList.append("Pending")
        ResultLists.append(ResultList)

    # print(ResultLists)
    return ResultLists