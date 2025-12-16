import "pe"

rule MAL_Compromised_Cert_SmokedHam_GlobalSign_5C5A8861E945052570898682 {
   meta:
      description         = "Detects SmokedHam with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-02-07"
      version             = "1.0"

      hash                = "1b7cffb25778e9fd9c6e5f2622e6bd7a05dfd721aef908bcc4b16ccda1a74d23"
      malware             = "SmokedHam"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Sinyoo Technology (Wuxi) Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "5c:5a:88:61:e9:45:05:25:70:89:86:82"
      cert_thumbprint     = "C6A2C0667553F13446381D8075AFBE4905031C1B"
      cert_valid_from     = "2025-02-07"
      cert_valid_to       = "2026-02-08"

      country             = "CN"
      state               = "Jiangsu"
      locality            = "Wuxi"
      email               = "???"
      rdn_serial_number   = "91320214MA23M0M621"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "5c:5a:88:61:e9:45:05:25:70:89:86:82"
      )
}
