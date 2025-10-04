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
        $s1 = "WannaDecryptor" wide ascii               // Figure 1: Ransomware message string
        $s2 = "tasksche.exe" ascii                      // Host-Based Indicators: Dropped payload
        $s3 = "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" ascii // Chapter 6: Kill-switch domain
        $s4 = ".WNCRY" ascii                            // Figure 12: Encrypted file extension

        // Behavioral / API indicators
        $api1 = "InternetOpenUrlA" ascii                // Cutter: Kill-switch logic
        $api2 = "CreateServiceA" ascii                  // PE Studio: Persistence mechanism
        $api3 = "recv" ascii                            // PE Studio: Network activity
        $api4 = "send" ascii                            // PE Studio: Network propagation
        $api5 = "socket" ascii                          // PE Studio: Network comms

    condition:
        pe.is_pe and                        // Ensure it's a PE file (MZ header)
        3 of ($s*) and                                 // At least 3 static indicators
        2 of ($api*)                                   // At least 2 behavioral indicators
}

