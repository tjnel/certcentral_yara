import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_00D3356318924C8C42959BF1D1574E6482 {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-02-11"
      version             = "1.0"

      hash                = "e38dfd919696b891fad1c1e5e0d69bcda08a044b526db42f68a149cd5d871bfb"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "ADV TOURS d.o.o."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:d3:35:63:18:92:4c:8c:42:95:9b:f1:d1:57:4e:64:82"
      cert_thumbprint     = "E21F261F5CF7C2856BD9DA5A5ED2C4E2B2EF4C9A"
      cert_valid_from     = "2021-02-11"
      cert_valid_to       = "2022-02-11"

      country             = "SI"
      state               = "???"
      locality            = "Velenje"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:d3:35:63:18:92:4c:8c:42:95:9b:f1:d1:57:4e:64:82"
      )
}
