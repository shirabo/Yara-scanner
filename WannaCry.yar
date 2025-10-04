import "pe"
import "math"

rule WannaCry_StaticBehavior_Analysis_v3
{
    meta:
        description = "Detects WannaCry-like samples using strings + imports + entropy (balanced heuristics)"
        author = "Shira Borochovich"
        date = "2025-10-05"
        version = "3.1"
        references = "Figure 1, Figure 12, Chapter 6, Host-Based Indicators section"

    strings:
        // Static indicators
        $s1 = "WannaDecryptor" wide ascii
        $s2 = "tasksche.exe" ascii
        $s3 = "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" ascii
        $s4 = ".WNCRY" ascii

        // Behavioral / API indicator strings (fallback)
        $api1 = "InternetOpenUrlA" ascii
        $api2 = "CreateServiceA" ascii
        $api3 = "recv" ascii
        $api4 = "send" ascii
        $api5 = "socket" ascii

    condition:
        pe.is_pe and                  /* ensure PE file */
        2 of ($s*) and                /* at least 2 static indicators (not too strict) */

        (
            /* path A: string-based behavioral indicators (simple and permissive) */
            2 of ($api*)

            or

            /* path B: stronger PE-based heuristic: an important import + elevated entropy */
            (
                (
                    pe.imports("ws2_32.dll", "recv") or
                    pe.imports("ws2_32.dll", "send") or
                    pe.imports("ws2_32.dll", "socket") or
                    pe.imports("wininet.dll", "InternetOpenUrlA") or
                    pe.imports("advapi32.dll", "CreateServiceA")
                )
                and
                math.entropy(0, filesize) > 6.5   /* heuristic: >6.5 suggests packing/encryption; adjustable */
            )
        )
}
