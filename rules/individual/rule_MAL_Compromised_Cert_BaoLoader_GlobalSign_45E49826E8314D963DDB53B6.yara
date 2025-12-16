import "pe"

rule MAL_Compromised_Cert_BaoLoader_GlobalSign_45E49826E8314D963DDB53B6 {
   meta:
      description         = "Detects BaoLoader with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-03-06"
      version             = "1.0"

      hash                = "6a08f7bfe8e62249990f97ad0b1e386218b60cace5c336a656f514f7f4df2c9f"
      malware             = "BaoLoader"
      malware_type        = "Backdoor"
      malware_notes       = "This malware was originally used for adfraud but is a risk due to an arbitrary backdoor. For more information see https://expel.com/blog/the-history-of-appsuite-the-certs-of-the-baoloader-developer/ and https://www.gdatasoftware.com/blog/2025/08/38257-appsuite-pdf-editor-backdoor-analysis"

      signer              = "Digital Promotions Sdn. Bhd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "45:e4:98:26:e8:31:4d:96:3d:db:53:b6"
      cert_thumbprint     = "11335A27C95A34A8F6985C2E29CA102BA941FF8E"
      cert_valid_from     = "2024-03-06"
      cert_valid_to       = "2027-03-07"

      country             = "MY"
      state               = "Johor"
      locality            = "Skudai"
      email               = "???"
      rdn_serial_number   = "1505433-P"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "45:e4:98:26:e8:31:4d:96:3d:db:53:b6"
      )
}
