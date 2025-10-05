import "pe"      // Use PE module for real executable structure checks (more precise than raw MZ)
import "math"    // Use entropy heuristics to spot packed/encrypted payloads
import "magic"   // Use libmagic to confirm file type by content, not extension
// import "hash"  // OPTIONAL: enable if you want whitelist/blacklist via MD5/SHA256

rule WannaCry_StaticBehavior_Analysis_v3_3 : ransomware wannacry win32
{
    meta:
        description = "Detects WannaCry-like samples using strings + API imports + section entropy + file-type sanity"
        author = "Shira Borochovich"
        date = "2025-10-05"
        version = "3.3"
        references = "Figure 1, Figure 12, Chapter 6, Host-Based Indicators section"

    strings:
        // --- Static indicators (unique text artifacts of WannaCry) ---
        $s1 = "WannaDecryptor" wide ascii     // Use wide+ascii to catch Unicode and ANSI
        $s2 = ".WNCRY" ascii fullword         // Encrypted extension marker
        $s3 = "tasksche.exe" ascii nocase     // Dropped payload name (case-insensitive)
        $s4 = /iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea\.com/i // Kill-switch domain (regex+i)

        // --- Behavioral strings (fallback if imports are hidden/packed) ---
        $api1 = "InternetOpenUrlA" ascii      // Network / kill-switch check
        $api2 = "CreateServiceA" ascii        // Persistence via service
        $api3 = "recv" ascii                  // Winsock recv
        $api4 = "send" ascii                  // Winsock send
        $api5 = "socket" ascii                // Winsock socket

    condition:
        // --- Fast pre-filters to reduce noise & speed scanning ---
        filesize < 50MB and                                   // Skip huge blobs; most malware is << 50MB
        pe.is_pe and                                          // Ensure valid PE structure (not just 'MZ')
        magic.mime_type() contains "application/x-dosexec" and// Confirm file-type by content via libmagic
        pe.number_of_sections >= 3 and pe.number_of_sections <= 12 and // Reasonable section count sanity

        // --- Require at least two core static WannaCry indicators ---
        2 of ($s*) and

        // --- Two alternative paths (OR) so rule isn't over-tight ---
        (
            // Path A: simple, permissive behavioral strings (works on unpacked samples)
            2 of ($api*)

            or

            // Path B: stronger heuristic — real imports + elevated code-section entropy (catches packed)
            (
                (
                    pe.imports("ws2_32.dll", "recv") or       // Real API imports (behavioral signal)
                    pe.imports("ws2_32.dll", "send") or
                    pe.imports("ws2_32.dll", "socket") or
                    pe.imports("wininet.dll", "InternetOpenUrlA") or
                    pe.imports("advapi32.dll", "CreateServiceA")
                )
                and
                (
                    // Prefer entropy on .text section (less false positives than whole file)
                    for any i in (0..pe.number_of_sections - 1) :
                        ( pe.sections[i].name == ".text" and
                          math.entropy(pe.sections[i].raw_data_pointer,
                                       pe.sections[i].raw_data_size) > 6.5 )
                    or
                    // Fallback: whole-file entropy if .text not found (slightly higher threshold)
                    math.entropy(0, filesize) > 7.0
                )
            )
        )

        // --- OPTIONAL hash-based whitelist/blacklist (uncomment and fill as needed) ---
        // and not hash.sha256(0, filesize) in ( "KNOWN_GOOD_SHA256_1", "KNOWN_GOOD_SHA256_2" ) // Whitelist
        // and hash.sha256(0, filesize) in ( "KNOWN_BAD_SHA256_A", "KNOWN_BAD_SHA256_B" )        // IOC pinning
}
