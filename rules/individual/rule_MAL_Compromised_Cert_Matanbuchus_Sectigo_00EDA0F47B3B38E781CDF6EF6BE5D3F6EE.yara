import "pe"

rule MAL_Compromised_Cert_Matanbuchus_Sectigo_00EDA0F47B3B38E781CDF6EF6BE5D3F6EE {
   meta:
      description         = "Detects Matanbuchus with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2022-04-26"
      version             = "1.0"

      hash                = "67a9e8599ab71865a97e75dae9be438c24d015a93e6a12fb5b450ec558528290"
      malware             = "Matanbuchus"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "ADVANCED ACCESS SERVICES LTD"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "00:ed:a0:f4:7b:3b:38:e7:81:cd:f6:ef:6b:e5:d3:f6:ee"
      cert_thumbprint     = "16DDF43DC302F8FFBD637DD89068FFE62713BF80"
      cert_valid_from     = "2022-04-26"
      cert_valid_to       = "2023-04-26"

      country             = "GB"
      state               = "Ayrshire"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "00:ed:a0:f4:7b:3b:38:e7:81:cd:f6:ef:6b:e5:d3:f6:ee"
      )
}
