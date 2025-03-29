rule SilentBanker : Trojan
{
    meta:
        description = "Detects SilentBanker Trojan"
    strings:
        $a = "BankingMalware"
    condition:
        $a
}
