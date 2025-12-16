import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_00BDC81BC76090DAE0EEE2E1EB744A4F9A {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2020-01-24"
      version             = "1.0"

      hash                = "892f8de40ffec90d9316a37e3a7cea1a137aa278c733fd599333f3ba0f5e4157"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "ALM4U GmbH"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:bd:c8:1b:c7:60:90:da:e0:ee:e2:e1:eb:74:4a:4f:9a"
      cert_thumbprint     = "AA41AC7A5B40A4140D72ABC136226973098F5330"
      cert_valid_from     = "2020-01-24"
      cert_valid_to       = "2021-01-23"

      country             = "AT"
      state               = "Lower Austria"
      locality            = "Langenrohr"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:bd:c8:1b:c7:60:90:da:e0:ee:e2:e1:eb:74:4a:4f:9a"
      )
}
