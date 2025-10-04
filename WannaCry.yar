import "pe"

rule WannaCry_StaticBehavior_Analysis
{
    meta:
        description = "Detects WannaCry ransomware using static and behavioral indicators"
        author = "Shira Borochovich"
        date = "2025-03-07"
        version = "3.0"
        references = "Figure 1, Figure 12, Chapter 6, Host-Based Indicators section"

    strings:
        // Static indicators
        $s1 = "WannaDecryptor" wide ascii
        $s2 = "tasksche.exe" ascii
        $s3 = "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" ascii
        $s4 = ".WNCRY" ascii

        // Behavioral / API indicators
        $api1 = "InternetOpenUrlA" ascii
        $api2 = "CreateServiceA" ascii
        $api3 = "recv" ascii
        $api4 = "send" ascii
        $api5 = "socket" ascii

    condition:
        pe.is_pe and           // השתמש במודול PE במקום בדיקת ה-MZ הישנה
        3 of ($s*) and
        2 of ($api*)
}
