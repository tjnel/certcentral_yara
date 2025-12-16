import "pe"

rule MAL_Compromised_Cert_Amadey_stage2_Sectigo_2D1DC3C2E0B0682AB3594E5237DD7C23 {
   meta:
      description         = "Detects Amadey_stage2 with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-22"
      version             = "1.0"

      hash                = "bb42bdcbed3f8053184470cf1cef5173b39fb8876cf1bba3958da07c905c6df9"
      malware             = "Amadey_stage2"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Dongguan Yingping Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "2d:1d:c3:c2:e0:b0:68:2a:b3:59:4e:52:37:dd:7c:23"
      cert_thumbprint     = "7440B35E9B9E3140A702AA5A182A7D1869F73462"
      cert_valid_from     = "2025-10-22"
      cert_valid_to       = "2027-01-20"

      country             = "CN"
      state               = "Guangdong Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "2d:1d:c3:c2:e0:b0:68:2a:b3:59:4e:52:37:dd:7c:23"
      )
}
