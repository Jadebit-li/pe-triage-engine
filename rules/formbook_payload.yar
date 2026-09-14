import "pe"

rule Formbook_Payload_Injection_Indicators
{
    meta:
        author = "Heeba"
        description = "Detects Formbook-style payload via process injection API combo and duplicate .text section anomaly, based on manual PE teardown of sample 337463b6..."
        date = "2026-09-14"
        reference = "SHA256: 337463b61d271e4826a1c570e565fe58f42548247b20c9cc8d52e7342943606e"

    condition:
        pe.imports("KERNEL32.dll", "VirtualAllocEx") and
        pe.imports("KERNEL32.dll", "WriteProcessMemory") and
        pe.number_of_sections >= 2 and
        for any i in (0..pe.number_of_sections - 1) : (
            for any j in (i+1..pe.number_of_sections - 1) : (
                pe.sections[i].name == pe.sections[j].name
            )
        )
}