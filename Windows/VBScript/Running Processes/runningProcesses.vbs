Dim ProTFPath, ProTF, StrPrInfo, StrPrInfoA, PrInfo

Set WshShell = WScript.CreateObject("Wscript.Shell")
Set FSO = WScript.CreateObject("Scripting.FileSystemObject")

ProTFPath = "C:\PROCESSES.txt"

WshShell.Run "CMD /C TASKLIST /V /FO LIST > """ + ProTFPath + """", 0, True
' Here Run is used instead Exec to avoid console window flashes.

If FSO.FileExists(ProTFPath) Then
  Set ProTF = FSO.OpenTextFile(ProTFPath, 1, False)
End If

StrPrInfoA = ProTF.ReadAll

PrInfo = Split(StrPrInfoA, VbCrLf + VbCrLf)

For I = 0 To UBound(PrInfo)
  WScript.StdOut.WriteLine PrInfo(I)
Next

Erase PrInfo
ProTF.Close