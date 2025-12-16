import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_00FE41941464B9992A69B7317418AE8EB7 {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2020-09-08"
      version             = "1.0"

      hash                = "9668bf80c1521a42cebce4a8c81da28fd5b10d846af370b2ad7c0ccda415c258"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "Milsean Software Limited"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:fe:41:94:14:64:b9:99:2a:69:b7:31:74:18:ae:8e:b7"
      cert_thumbprint     = "552EABCAF5B6D26BCD9D584346701C45C3FDA18C"
      cert_valid_from     = "2020-09-08"
      cert_valid_to       = "2021-09-08"

      country             = "IE"
      state               = "???"
      locality            = "Waterford"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:fe:41:94:14:64:b9:99:2a:69:b7:31:74:18:ae:8e:b7"
      )
}
