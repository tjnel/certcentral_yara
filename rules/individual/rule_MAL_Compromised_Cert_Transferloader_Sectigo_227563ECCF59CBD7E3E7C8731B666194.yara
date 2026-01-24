import "pe"

rule MAL_Compromised_Cert_Transferloader_Sectigo_227563ECCF59CBD7E3E7C8731B666194 {
   meta:
      description         = "Detects Transferloader with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-05"
      version             = "1.0"

      hash                = "a4380e9ac13668d4ff6fc30fdc1efcbfba9e6c1d73bbc994dba34bef605086fc"
      malware             = "Transferloader"
      malware_type        = "Loader"
      malware_notes       = "Malware was distributed disguised as a resume."

      signer              = "Xiamen Jialan Guang Information Technology Service Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "22:75:63:ec:cf:59:cb:d7:e3:e7:c8:73:1b:66:61:94"
      cert_thumbprint     = "A759B97E4F156E1E9D51C0C3121D0C65C2A2D05E"
      cert_valid_from     = "2025-12-05"
      cert_valid_to       = "2026-12-05"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "22:75:63:ec:cf:59:cb:d7:e3:e7:c8:73:1b:66:61:94"
      )
}
