import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_0092D9B92F8CF7A1BA8B2C025BE730C300 {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2020-08-22"
      version             = "1.0"

      hash                = "18462e94cec35c1bf5be85d3473631829e1aea7ab283df694606d8a5057e538a"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "UPLagga Systems s.r.o."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:92:d9:b9:2f:8c:f7:a1:ba:8b:2c:02:5b:e7:30:c3:00"
      cert_thumbprint     = "58B677149BC75D71CDC97A4E1BD56534ADA8FBCC"
      cert_valid_from     = "2020-08-22"
      cert_valid_to       = "2021-08-22"

      country             = "CZ"
      state               = "???"
      locality            = "Praha"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:92:d9:b9:2f:8c:f7:a1:ba:8b:2c:02:5b:e7:30:c3:00"
      )
}
